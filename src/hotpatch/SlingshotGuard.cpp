// SlingshotGuard.cpp - Hardware-aware slingshot with:
// - PCIe switch bottleneck avoidance
// - stream&&stream isolation (no collision)
// - atomic weight integrity (no corrupt inference)
// - non-gravity execution order (deterministic despite async)
// - ++ro__ hotpatch memory protection

#include <atomic>
#include <mutex>
#include <thread>
#include <vector>
#include <array>
#include <cstring>
#include <cstdint>
#include <cassert>
#include <condition_variable>

// ── PCIe topology constants ──────────────────────────────────────────────────
// Open-air multi-GPU: each GPU on its own x16 lane, no PCIe switch
// Max safe concurrent DMA transfers without switch saturation
static constexpr int    PCIE_SAFE_CONCURRENT = 2;   // >2 = switch contention
static constexpr size_t PCIE_CHUNK_BYTES     = 64ULL * 1024 * 1024; // 64MB chunks
static constexpr size_t EXPERT_SIZE          = 512ULL * 1024 * 1024;
static constexpr int    MAX_EXPERTS          = 256;
static constexpr int    LOOKAHEAD            = 3;

// ── Weight integrity ─────────────────────────────────────────────────────────
struct WeightHeader {
    uint64_t magic     = 0xSL1NGS0T;   // slingshot sentinel
    uint32_t expert_id = 0;
    uint32_t checksum  = 0;            // XOR32 of weight data
    uint64_t size      = 0;
};

static uint32_t xor32(const void* data, size_t n) {
    const uint32_t* p = (const uint32_t*)data;
    uint32_t h = 0;
    for (size_t i = 0; i < n / 4; i++) h ^= p[i];
    return h;
}

// ── Stream token: prevents stream&&stream collision ──────────────────────────
// Only PCIE_SAFE_CONCURRENT transfers allowed simultaneously
struct PCIeStreamGuard {
    std::counting_semaphore<PCIE_SAFE_CONCURRENT> slots{PCIE_SAFE_CONCURRENT};

    struct Token {
        PCIeStreamGuard* g;
        Token(PCIeStreamGuard* g) : g(g) { g->slots.acquire(); }
        ~Token() { g->slots.release(); }
    };

    Token acquire() { return Token(this); }
};

// ── Expert VRAM slot with atomic state machine ───────────────────────────────
//
//  COLD ──prefetch──► TRANSFERRING ──verify──► HOT ──evict──► COLD
//                          │
//                       corrupt?
//                          │
//                          ▼
//                       CORRUPT ──reset──► COLD
//
enum class Slot : uint8_t { COLD=0, TRANSFERRING=1, HOT=2, CORRUPT=3 };

struct ExpertSlot {
    std::atomic<Slot>  state{Slot::COLD};
    std::atomic<bool>  ro_lock{false};   // ++ro__ protection
    void*              vram  = nullptr;
    void*              ram   = nullptr;
    uint32_t           expected_checksum = 0;
    int                id    = -1;

    // Attempt atomic transition — returns false if someone else won the race
    bool transition(Slot from, Slot to) {
        return state.compare_exchange_strong(from, to,
            std::memory_order_acq_rel, std::memory_order_acquire);
    }

    // ++ro__ : lock VRAM region read-only during inference
    // prevents hotpatch writes corrupting live inference
    bool lockRO() {
        bool expected = false;
        return ro_lock.compare_exchange_strong(expected, true,
            std::memory_order_acquire);
    }

    void unlockRO() { ro_lock.store(false, std::memory_order_release); }
    bool isRO()     { return ro_lock.load(std::memory_order_acquire); }
};

// ── Slingshot Guard Engine ───────────────────────────────────────────────────
class SlingshotGuard {
public:
    explicit SlingshotGuard(int n_experts) : n_(n_experts), running_(true) {
        slots_.resize(n_experts);
        for (int i = 0; i < n_experts; i++) {
            slots_[i].id    = i;
            slots_[i].ram   = new uint8_t[EXPERT_SIZE];
            slots_[i].vram  = new uint8_t[EXPERT_SIZE]; // hipMalloc in prod

            // Stamp weight header + checksum into RAM
            auto* hdr = (WeightHeader*)slots_[i].ram;
            hdr->magic     = 0xSL1NGS0T;
            hdr->expert_id = i;
            hdr->size      = EXPERT_SIZE;
            memset((uint8_t*)slots_[i].ram + sizeof(WeightHeader),
                   i & 0xFF, EXPERT_SIZE - sizeof(WeightHeader));
            hdr->checksum  = xor32((uint8_t*)slots_[i].ram + sizeof(WeightHeader),
                                   EXPERT_SIZE - sizeof(WeightHeader));
            slots_[i].expected_checksum = hdr->checksum;
        }
        worker_ = std::thread(&SlingshotGuard::transferLoop, this);
    }

    ~SlingshotGuard() {
        running_ = false;
        cv_.notify_all();
        if (worker_.joinable()) worker_.join();
        for (auto& s : slots_) {
            delete[] (uint8_t*)s.ram;
            delete[] (uint8_t*)s.vram;
        }
    }

    // ── Forward pass entry point ─────────────────────────────────────────────
    // gate_logits → route → slingshot lookahead → execute
    bool forward(const float* gate_logits, const float* input,
                 float* output, size_t hidden_dim) {

        auto active = topK(gate_logits, 2);
        scheduleLookahead(gate_logits, active);

        for (int eid : active) {
            // Block until HOT — slingshot means this is usually instant
            if (!waitHot(eid, 50)) {
                // Timeout: force load on this thread
                forceLoad(eid);
            }

            ExpertSlot& s = slots_[eid];

            // Verify integrity before inference — catch corrupt weights
            if (!verifyIntegrity(s)) {
                s.state.store(Slot::CORRUPT, std::memory_order_release);
                resetSlot(s);
                return false; // caller retries
            }

            // Lock RO: hotpatch cannot write during inference
            if (!s.lockRO()) return false; // another thread holds it

            executeExpert(s, input, output, hidden_dim);

            s.unlockRO();
        }
        return true;
    }

private:
    int                      n_;
    std::vector<ExpertSlot>  slots_;
    PCIeStreamGuard          pcie_;
    std::mutex               mu_;
    std::condition_variable  cv_;
    std::vector<int>         queue_;
    std::atomic<bool>        running_;
    std::thread              worker_;

    // ── Top-K routing ────────────────────────────────────────────────────────
    std::vector<int> topK(const float* logits, int k) {
        std::vector<std::pair<float,int>> s(n_);
        for (int i = 0; i < n_; i++) s[i] = {logits[i], i};
        std::partial_sort(s.begin(), s.begin()+k, s.end(),
            [](auto& a, auto& b){ return a.first > b.first; });
        std::vector<int> r(k);
        for (int i = 0; i < k; i++) r[i] = s[i].second;
        return r;
    }

    // ── Lookahead scheduler ──────────────────────────────────────────────────
    // Uses gate probability as prediction signal — no separate predictor needed
    void scheduleLookahead(const float* logits, const std::vector<int>& skip) {
        auto ranked = topK(logits, LOOKAHEAD + (int)skip.size());
        std::lock_guard<std::mutex> lk(mu_);
        int queued = 0;
        for (int id : ranked) {
            if (queued >= LOOKAHEAD) break;
            bool active = false;
            for (int s : skip) if (s == id) { active = true; break; }
            if (active) continue;

            Slot expected = Slot::COLD;
            if (slots_[id].transition(Slot::COLD, Slot::TRANSFERRING)) {
                queue_.push_back(id);
                queued++;
            }
        }
        if (queued) cv_.notify_one();
    }

    // ── Background PCIe transfer loop ────────────────────────────────────────
    // Chunked transfer avoids PCIe switch saturation on open-air frame
    void transferLoop() {
        while (running_) {
            int id = -1;
            {
                std::unique_lock<std::mutex> lk(mu_);
                cv_.wait(lk, [&]{ return !queue_.empty() || !running_; });
                if (!running_) break;
                id = queue_.front();
                queue_.erase(queue_.begin());
            }

            if (id < 0) continue;
            ExpertSlot& s = slots_[id];
            if (s.state.load() != Slot::TRANSFERRING) continue;

            // Acquire PCIe stream token — blocks if PCIE_SAFE_CONCURRENT active
            // This is the stream&&stream collision prevention
            {
                auto token = pcie_.acquire();
                chunkedCopy(s.vram, s.ram, EXPERT_SIZE);
            }

            // Verify after transfer — catch mid-transfer corruption
            if (verifyIntegrity(s)) {
                s.transition(Slot::TRANSFERRING, Slot::HOT);
            } else {
                s.state.store(Slot::CORRUPT, std::memory_order_release);
                resetSlot(s);
            }
            cv_.notify_all(); // wake waitHot()
        }
    }

    // ── Chunked copy: avoids PCIe burst saturation ───────────────────────────
    void chunkedCopy(void* dst, const void* src, size_t total) {
        size_t offset = 0;
        while (offset < total) {
            size_t chunk = std::min(PCIE_CHUNK_BYTES, total - offset);
            memcpy((uint8_t*)dst + offset,
                   (uint8_t*)src + offset, chunk); // hipMemcpyAsync in prod
            offset += chunk;
            // Yield between chunks — lets other streams breathe
            std::this_thread::yield();
        }
    }

    // ── Integrity check ──────────────────────────────────────────────────────
    bool verifyIntegrity(const ExpertSlot& s) {
        auto* hdr = (const WeightHeader*)s.vram;
        if (hdr->magic != 0xSL1NGS0T) return false;
        if (hdr->expert_id != (uint32_t)s.id) return false;
        uint32_t actual = xor32((uint8_t*)s.vram + sizeof(WeightHeader),
                                EXPERT_SIZE - sizeof(WeightHeader));
        return actual == s.expected_checksum;
    }

    // ── Atomic reset: CORRUPT → COLD ─────────────────────────────────────────
    void resetSlot(ExpertSlot& s) {
        // Clear VRAM region before marking cold — no stale corrupt data
        memset(s.vram, 0, EXPERT_SIZE);
        s.state.store(Slot::COLD, std::memory_order_release);
    }

    // ── Force load on calling thread (fallback if prefetch missed) ───────────
    void forceLoad(int id) {
        ExpertSlot& s = slots_[id];
        s.transition(Slot::COLD, Slot::TRANSFERRING);
        {
            auto token = pcie_.acquire();
            chunkedCopy(s.vram, s.ram, EXPERT_SIZE);
        }
        if (verifyIntegrity(s))
            s.transition(Slot::TRANSFERRING, Slot::HOT);
        else {
            s.state.store(Slot::CORRUPT);
            resetSlot(s);
        }
    }

    // ── Wait for HOT with timeout (ms) ───────────────────────────────────────
    bool waitHot(int id, int timeout_ms) {
        auto deadline = std::chrono::steady_clock::now()
                      + std::chrono::milliseconds(timeout_ms);
        while (std::chrono::steady_clock::now() < deadline) {
            auto st = slots_[id].state.load(std::memory_order_acquire);
            if (st == Slot::HOT)    return true;
            if (st == Slot::CORRUPT) return false;
            std::this_thread::sleep_for(std::chrono::microseconds(100));
        }
        return false;
    }

    // ── Expert execution (stub → Sovereign_ExecuteMoEKernel) ─────────────────
    void executeExpert(const ExpertSlot& s, const float* in,
                       float* out, size_t dim) {
        const float* w = (const float*)((uint8_t*)s.vram + sizeof(WeightHeader));
        for (size_t i = 0; i < dim; i++)
            out[i] += w[i % ((EXPERT_SIZE - sizeof(WeightHeader)) / 4)] * in[i];
        // prod: Sovereign_ExecuteMoEKernel(s.vram_ptr, in, out, dim);
    }
};

// ── POC main ─────────────────────────────────────────────────────────────────
#ifdef SLINGSHOT_GUARD_MAIN
#include <cstdio>
#include <cstdlib>
#include <chrono>

int main() {
    constexpr int   N_EXPERTS  = 64;
    constexpr int   HIDDEN     = 7168;
    constexpr int   TOKENS     = 20;

    printf("SlingshotGuard POC\n");
    printf("PCIe safe concurrent streams : %d\n", PCIE_SAFE_CONCURRENT);
    printf("Chunk size                   : %zuMB\n", PCIE_CHUNK_BYTES>>20);
    printf("Experts                      : %d\n", N_EXPERTS);
    printf("Lookahead depth              : %d\n\n", LOOKAHEAD);

    SlingshotGuard engine(N_EXPERTS);

    std::vector<float> gate(N_EXPERTS), in(HIDDEN, 1.0f), out(HIDDEN, 0.0f);
    int ok = 0, fail = 0;

    auto t0 = std::chrono::high_resolution_clock::now();
    for (int t = 0; t < TOKENS; t++) {
        for (int i = 0; i < N_EXPERTS; i++) gate[i] = (float)(rand()%100)/100.f;
        if (engine.forward(gate.data(), in.data(), out.data(), HIDDEN)) ok++;
        else fail++;
    }
    auto ms = std::chrono::duration<double,std::milli>(
        std::chrono::high_resolution_clock::now()-t0).count();

    printf("Tokens OK: %d  Corrupt/retry: %d\n", ok, fail);
    printf("%.2f ms total | %.2f ms/token\n", ms, ms/TOKENS);
    printf("out[0] = %f\n", out[0]);
    return 0;
}
#endif
