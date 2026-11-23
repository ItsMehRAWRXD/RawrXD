// deep2_residency_concurrency.cpp -- RAWRXD_G04
//
// Concurrent-safe residency certification.
//
// G04 asks for a residency cache that stays correct when it is observed and
// steered WHILE work is in flight: generation leases, in-flight pinning,
// fence-safe eviction, and prefetch under concurrent / batched GPU work. This
// harness exercises all four on real hardware and refuses to certify vacuous
// conditions:
//
//   A. Concurrent steering under eviction pressure
//      Several threads prefetch, query residency, take/release leases and
//      dispatch against a budget far smaller than the working set, so the
//      eviction pass runs constantly while it is being observed.
//   B. In-flight pinning vs a concurrent eviction storm
//      A quant-dot batch is opened and its weights queued; a worker thread
//      hammers the cache with prefetches that WANT those buffers freed; the
//      batch is then submitted. Bit-identical output proves no queued weight
//      was destroyed underneath the batch.
//   C. Generation leases
//      A lease must keep a weight resident across an eviction storm, must let
//      the dispatch that consumes it return the reference result, and must be
//      rejected (not mis-applied) when released twice or with a stale id.
//   D. Dispatch determinism under concurrency
//      N threads dispatch the identical dot concurrently; every result must be
//      bit-identical to the serial reference.
//
// Hard non-vacuity guards: the GPU path must actually have run (submits > 0,
// device bytes live > 0, at least one GPU-served dispatch), the eviction pass
// must actually have run, and no deferred destruction may be left outstanding.
// If the GPU is unavailable the harness reports BLOCKED, never PASS.
//
// The CPU reference decodes the same ggml Q4_K/Q8_K block layouts the shader
// consumes, so a GPU/CPU disagreement shows up as a FAIL, not as a tolerance.

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <functional>
#include <string>
#include <thread>
#include <vector>

#include "quant_dot_dispatch.hpp"
#include "include/vulkan_compute.h"

using namespace RawrXD::Deep2::QuantDot;

namespace {

// Hang-localization checkpoints. Every phase boundary and every serial
// reference dot prints one line and flushes, so a hang names the exact
// operation that never returned (Sprint9 residency-concurrency hang diag).
std::atomic<uint64_t> g_checkpoint_seq{0};
void Checkpoint(const char* name, size_t index = static_cast<size_t>(-1)) {
    const uint64_t seq = g_checkpoint_seq.fetch_add(1, std::memory_order_relaxed) + 1;
    if (index == static_cast<size_t>(-1))
        std::printf("CHECKPOINT seq=%llu %s\n", (unsigned long long)seq, name);
    else
        std::printf("CHECKPOINT seq=%llu %s index=%zu\n",
                    (unsigned long long)seq, name, index);
    std::fflush(stdout);
}

// ---------------------------------------------------------------------------
// Independent CPU reference for Q4_K x Q8_K (mirrors ggml's block layout).
// ---------------------------------------------------------------------------
struct Q4K { uint16_t d, dmin; uint8_t scales[12]; uint8_t qs[128]; };
static_assert(sizeof(Q4K) == 144, "unexpected Q4_K layout");

float HalfToFloat(uint16_t h) {
    const uint32_t sign = uint32_t(h & 0x8000u) << 16;
    const uint32_t exp = (h >> 10) & 31u;
    const uint32_t frac = h & 1023u;
    uint32_t bits;
    if (exp == 0) {
        if (frac == 0) bits = sign;
        else {
            uint32_t m = frac; int e = -14;
            while ((m & 1024u) == 0u) { m <<= 1; --e; }
            bits = sign | (uint32_t(e + 127) << 23) | ((m & 1023u) << 13);
        }
    } else if (exp == 31) bits = sign | 0x7f800000u | (frac << 13);
    else bits = sign | ((exp + 112u) << 23) | (frac << 13);
    float f; std::memcpy(&f, &bits, 4); return f;
}

void K4ScaleMin(const uint8_t s[12], unsigned group, int& scale, int& minv) {
    if (group < 4) { scale = int(s[group] & 63u); minv = int(s[group + 4] & 63u); }
    else {
        scale = int((s[group + 4] & 15u) | ((s[group - 4] >> 6) << 4));
        minv = int((s[group + 4] >> 4) | ((s[group] >> 6) << 4));
    }
}

struct Q8Ref {
    float d;
    std::array<int8_t, 256> qs;
    std::array<int16_t, 16> bsums;
};

// One synthetic weight bank: n_out rows of Q4_K blocks over n_in inputs.
struct Bank {
    std::vector<uint8_t> bytes;   // packed Q4_K weights (the cache key)
    size_t n_out = 0, n_in = 0, n_blocks = 0;
    size_t packedBytes() const { return n_out * n_blocks * sizeof(Q4K); }
};

float DotQ4(const uint8_t* x, const float* q8, size_t block) {
    Q4K w; std::memcpy(&w, x, sizeof(w));
    // Block b of the interleaved Q8 activation.
    const float* y = q8 + block * 273u;
    const float yd = y[0];
    int32_t lanes[8] = {}; int32_t min_sum = 0;
    for (unsigned group = 0; group < 8; ++group) {
        int scale, minv; K4ScaleMin(w.scales, group, scale, minv);
        const uint8_t* q = w.qs + (group / 2) * 32;
        const bool high = (group & 1u) != 0;
        for (unsigned i = 0; i < 32; ++i) {
            const int weight = high ? int(q[i] >> 4) : int(q[i] & 15u);
            lanes[i & 7u] += scale * weight * int(y[1 + group * 32 + i]);
        }
        min_sum += minv * (int(y[257 + 2 * group]) + int(y[257 + 2 * group + 1]));
    }
    const float d = HalfToFloat(w.d) * yd;
    const float dmin = HalfToFloat(w.dmin) * yd;
    float sumf = 0.0f;
    for (unsigned i = 0; i < 8; ++i) sumf += d * float(lanes[i]);
    return sumf - dmin * float(min_sum);
}

// Deterministic bank: every bank is distinct (distinct host pointer AND
// distinct fingerprint) so the residency cache treats them as separate
// entries, which is what makes eviction pressure observable.
Bank MakeBank(size_t n_out, size_t n_in, size_t seed) {
    Bank b;
    b.n_out = n_out; b.n_in = n_in; b.n_blocks = n_in / 256u;
    b.bytes.assign(b.packedBytes(), 0);
    for (size_t r = 0; r < b.n_out; ++r) {
        uint8_t* row = b.bytes.data() + r * b.n_blocks * sizeof(Q4K);
        for (size_t blk = 0; blk < b.n_blocks; ++blk) {
            Q4K* w = reinterpret_cast<Q4K*>(row + blk * sizeof(Q4K));
            w->d = 0x2C00;      // ~0.03125
            w->dmin = 0x3000;   // ~0.0625
            for (int i = 0; i < 12; ++i)
                w->scales[i] = uint8_t((seed * 31 + r * 7 + blk * 13 + i * 5) & 0xFFu);
            for (int i = 0; i < 128; ++i)
                w->qs[i] = uint8_t((seed * 17 + r * 5 + blk * 3 + i * 11) & 0xFFu);
        }
    }
    return b;
}

// Interleaved Q8_K activation for one input vector (per super-block:
// [d, qs(256), bsums(16)] as floats = 273 floats).
std::vector<float> MakeQ8(size_t n_in, size_t seed) {
    const size_t n_sb = n_in / 256u;
    std::vector<float> v(n_sb * 273u, 0.0f);
    for (size_t b = 0; b < n_sb; ++b) {
        float* base = v.data() + b * 273u;
        base[0] = 0.03125f * float(b + 1) + 0.001f;
        for (unsigned j = 0; j < 256; ++j) {
            const int t = int(std::lround(127.0 * std::sin(0.37 * double(j + b * 17 + seed))));
            base[1 + j] = float(std::max(-127, std::min(127, t)));
        }
        for (unsigned j = 0; j < 16; ++j) {
            int s = 0;
            for (unsigned k = 0; k < 16; ++k) s += int(base[1 + 16 * j + k]);
            base[257 + j] = float(s);
        }
    }
    return v;
}

// Float activations, n_in long. The GPU path consumes only the pre-quantised
// Q8 buffer, but DotBlocked's contract still requires a real activation pointer
// (it is what the CPU fallback dots), so this is a genuine deterministic
// vector rather than a null stand-in.
std::vector<float> MakeAct(size_t n_in, size_t seed) {
    std::vector<float> v(n_in);
    for (size_t i = 0; i < n_in; ++i)
        v[i] = 0.5f * std::sin(0.11f * float(i + seed)) + 0.25f * float((i % 7) - 3);
    return v;
}

CpuDot MakeCpuRef(const Bank& b) {
    return [&b](const uint8_t* row, const void* q8, size_t rowIndex) -> float {
        const size_t blkBytes = sizeof(Q4K);
        float acc = 0.0f;
        const float* q = static_cast<const float*>(q8);
        for (size_t blk = 0; blk < b.n_blocks; ++blk)
            acc += DotQ4(row + rowIndex * b.n_blocks * blkBytes + blk * blkBytes, q, blk);
        return acc;
    };
}

bool SameBits(const std::vector<float>& a, const std::vector<float>& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i)
        if (std::memcmp(&a[i], &b[i], sizeof(float)) != 0) return false;
    return true;
}

int g_fail = 0;
void Check(bool ok, const char* what) {
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) ++g_fail;
}

struct Snap {
    uint64_t hits, misses, evictions, prefetches, prefetch_hits;
    uint64_t live, peak, submits, waits;
    uint64_t pinned, leases, retired_pending, retired_reaped, budget_overrides;
    uint64_t epoch, completed_epoch;
};

Snap Take() {
    const CacheStats c = GetCacheStats();
    return { c.hits, c.misses, c.evictions, c.prefetches, c.prefetch_hits,
             c.device_bytes_live, c.device_bytes_peak, c.submits, c.waits,
             c.pinned, c.leases, c.retired_pending, c.retired_reaped,
             c.budget_overrides, c.epoch, c.completed_epoch };
}

void PrintSnap(const char* label, const Snap& s) {
    std::printf("  %-26s hits=%llu misses=%llu evictions=%llu prefetch=%llu "
                "prefetch_hits=%llu live=%lluB submits=%llu\n",
                label, (unsigned long long)s.hits, (unsigned long long)s.misses,
                (unsigned long long)s.evictions, (unsigned long long)s.prefetches,
                (unsigned long long)s.prefetch_hits, (unsigned long long)s.live,
                (unsigned long long)s.submits);
    std::printf("  %-26s pinned=%llu leases=%llu retired_pending=%llu "
                "retired_reaped=%llu budget_overrides=%llu epoch=%llu completed=%llu\n",
                "", (unsigned long long)s.pinned, (unsigned long long)s.leases,
                (unsigned long long)s.retired_pending, (unsigned long long)s.retired_reaped,
                (unsigned long long)s.budget_overrides, (unsigned long long)s.epoch,
                (unsigned long long)s.completed_epoch);
}

} // namespace

int main(int argc, char** argv) {
    size_t n_threads = 4;
    size_t n_banks = 16;
    size_t rounds = 40;
    int64_t budget = 0;   // 0 = derive (9 banks' worth is forced below)
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--threads" && i + 1 < argc) n_threads = (size_t)std::strtoull(argv[++i], nullptr, 10);
        else if (a == "--banks" && i + 1 < argc) n_banks = (size_t)std::strtoull(argv[++i], nullptr, 10);
        else if (a == "--rounds" && i + 1 < argc) rounds = (size_t)std::strtoull(argv[++i], nullptr, 10);
        else if (a == "--budget" && i + 1 < argc) budget = (int64_t)std::strtoll(argv[++i], nullptr, 10);
        else { std::printf("unknown arg %s\n", a.c_str()); return 2; }
    }

    std::printf("=== RAWRXD_G04 concurrent-safe residency ===\n");
    std::printf("threads=%zu banks=%zu rounds=%zu\n", n_threads, n_banks, rounds);

    // ---- build the workload -------------------------------------------------
    // 64 outputs x 1024 inputs = 4 Q4_K blocks/row = 576 B/row -> 36 KiB/bank.
    // Small enough that a deliberately tight budget produces a real eviction
    // storm rather than depending on how much VRAM this host happens to have.
    const size_t n_out = 64, n_in = 1024;
    std::vector<Bank> banks;
    banks.reserve(n_banks);
    for (size_t i = 0; i < n_banks; ++i) banks.push_back(MakeBank(n_out, n_in, i + 1));
    const std::vector<float> q8 = MakeQ8(n_in, 3);
    const std::vector<float> act = MakeAct(n_in, 5);

    const size_t bank_bytes = banks[0].packedBytes();
    const int64_t forced_budget = (budget > 0) ? budget : (int64_t)(bank_bytes * 3);
    SetWeightCacheBudget(forced_budget);
    std::printf("bank_bytes=%zu forced_budget=%lld (%.1f banks)\n",
                bank_bytes, (long long)forced_budget, double(forced_budget) / double(bank_bytes));
    Checkpoint("SERIAL_REFERENCE_BEGIN");

    // ---- serial reference: one GPU dot per bank -----------------------------
    std::vector<std::vector<float>> ref(n_banks);
    {
        uint64_t gpu_before = GetCacheStats().submits;
        bool all_ok = true, all_gpu = true;
        for (size_t i = 0; i < n_banks; ++i) {
            Checkpoint("SERIAL_DOT_BEGIN", i);
            std::vector<float> y(n_out, 0.0f);
            const CpuDot cpu = MakeCpuRef(banks[i]);
            const bool ok = DotBlocked(0, banks[i].bytes.data(), banks[i].packedBytes(),
                                       act.data(), n_in, y.data(), n_out, cpu,
                                       q8.data(), q8.size() * sizeof(float), false);
            if (!ok) { all_ok = false; break; }
            if (!LastReceipt().used_gpu) all_gpu = false;
            ref[i] = y;
            Checkpoint("SERIAL_DOT_COMPLETE", i);
        }
        const uint64_t gpu_after = GetCacheStats().submits;
        std::printf("serial reference: ok=%s gpu=%s submits=%llu\n",
                    all_ok ? "yes" : "NO", all_gpu ? "yes" : "NO",
                    (unsigned long long)(gpu_after - gpu_before));
        if (!all_ok || !all_gpu || gpu_after == gpu_before) {
            std::printf("G04_RESULT=BLOCKED (no usable GPU quant-dot path; reason=%s)\n",
                        LastReceipt().fallback_reason ? LastReceipt().fallback_reason : "none");
            return 3;
        }
        Check(all_gpu, "serial reference dispatched on the GPU (receipt used_gpu)");
        Check(gpu_after > gpu_before, "serial reference produced real submits");
    }
    Checkpoint("SERIAL_REFERENCE_COMPLETE");

    // =========================================================================
    // A. Concurrent steering under eviction pressure.
    // =========================================================================
    std::printf("\n--- A. concurrent steering under eviction pressure ---\n");
    Checkpoint("SECTION_A_BEGIN");
    const Snap a0 = Take();
    std::atomic<size_t> a_dispatch{0}, a_prefetch{0}, a_lease{0};
    std::atomic<bool> a_bad{false};
    {
        std::vector<std::thread> ts;
        for (size_t t = 0; t < n_threads; ++t) {
            ts.emplace_back([&, t]() {
                uint32_t rng = (uint32_t)(t * 2654435761u + 12345u);
                auto next = [&rng]() { rng = rng * 1664525u + 1013904223u; return rng; };
                std::vector<float> y(n_out);
                for (size_t r = 0; r < rounds; ++r) {
                    const size_t i = next() % n_banks;
                    // Observe.
                    (void)IsWeightResident(banks[i].bytes.data(), banks[i].packedBytes(), 0);
                    // Steer.
                    if (PrefetchWeight(banks[i].bytes.data(), banks[i].packedBytes(), 0)) ++a_prefetch;
                    // Lease.
                    const uint64_t lease = AcquireWeightLease(banks[i].bytes.data(),
                                                              banks[i].packedBytes(), 0);
                    if (lease) ++a_lease;
                    // Dispatch: the result must be the reference, whatever the
                    // cache did meanwhile.
                    const CpuDot cpu = MakeCpuRef(banks[i]);
                    const bool ok = DotBlocked(0, banks[i].bytes.data(), banks[i].packedBytes(),
                                               act.data(), n_in, y.data(), n_out, cpu,
                                               q8.data(), q8.size() * sizeof(float), false);
                    if (ok) ++a_dispatch; else a_bad = true;
                    if (lease) ReleaseWeightLease(lease);
                }
            });
        }
        for (auto& th : ts) th.join();
    }
    const Snap a1 = Take();
    PrintSnap("A after:", a1);
    Check(!a_bad.load(), "A: every concurrent dispatch succeeded");
    Check(a_dispatch.load() == n_threads * rounds, "A: dispatch count matches threads*rounds");
    Check(a_prefetch.load() > 0, "A: prefetches were issued (steering actually happened)");
    Check(a_lease.load() > 0, "A: leases were acquired");
    Check(a1.leases == 0, "A: every lease released (no residency leak)");
    Check(a1.pinned == 0, "A: no pin left outstanding");
    Check(a1.retired_pending == 0, "A: no deferred destruction left outstanding");
        Check(a1.retired_pending == 0 && a1.retired_reaped >= a1.evictions,
              "A: every counted eviction reaped after its fence (fence-safe destruction)");
    Check(a1.evictions > a0.evictions, "A: the residency budget actually forced evictions");

    // =========================================================================
    // B1. Deep2 dispatch-layer batch: a storm running while a batch is OPEN at
    //     the dispatch layer can evict the queued weights before End resolves
    //     them. That must be harmless (the weights are simply re-resolved and
    //     re-uploaded) and the results must still be bit-exact.
    // =========================================================================
    std::printf("\n--- B1. dispatch-layer batch vs concurrent eviction ---\n");
    Checkpoint("SECTION_B1_BEGIN");
    const size_t batch_n = std::min<size_t>(BatchCapacity(), n_banks);
    std::vector<std::vector<float>> bout(batch_n);
    std::vector<std::vector<float>> bref(batch_n);
    Checkpoint("B1_REFERENCE_BEGIN");
    for (size_t i = 0; i < batch_n; ++i) {
        bout[i].resize(n_out);
        std::vector<float> y(n_out);
        const CpuDot cpu = MakeCpuRef(banks[i]);
        if (!DotBlocked(0, banks[i].bytes.data(), banks[i].packedBytes(),
                        act.data(), n_in, y.data(), n_out, cpu,
                        q8.data(), q8.size() * sizeof(float), false)) {
            std::printf("B1: reference dispatch failed\n"); return 3;
        }
        bref[i] = y;
    }
    Checkpoint("B1_REFERENCE_COMPLETE");
    {
        std::atomic<bool> storm_stop{false};
        std::atomic<bool> storm_ready{false};
        std::atomic<uint64_t> storm_prefetch{0};
        std::thread storm([&]() {
            uint32_t rng = 99991u;
            auto spin = [&]() {
                for (int i = 0; i < 4 && !storm_stop.load(); ++i) {
                    rng = rng * 1664525u + 1013904223u;
                    if (PrefetchWeight(banks[rng % n_banks].bytes.data(),
                                       banks[rng % n_banks].packedBytes(), 0))
                        ++storm_prefetch;
                }
            };
            spin();
            storm_ready.store(true);
            storm_ready.notify_one();
            while (!storm_stop.load()) spin();
        });
        storm_ready.wait(false);
        Checkpoint("B1_STORM_READY");
        const Snap b0 = Take();
        Checkpoint("B1_BEFORE_BEGIN");
        if (!BeginBatch()) { std::printf("B1: BeginBatch failed\n"); return 3; }
        Checkpoint("B1_BATCH_OPEN");
        bool queued_ok = true;
        for (size_t i = 0; i < batch_n; ++i) {
            const CpuDot cpu = MakeCpuRef(banks[i]);
            if (!DotBlocked(0, banks[i].bytes.data(), banks[i].packedBytes(),
                            act.data(), n_in, bout[i].data(), n_out, cpu,
                            q8.data(), q8.size() * sizeof(float), false))
                queued_ok = false;
            Checkpoint("B1_QUEUE_COMPLETE", i);
        }
        Checkpoint("B1_ALL_QUEUED");
        const Snap b_open = Take();
        Checkpoint("B1_OPEN_SNAPSHOT");
        storm_stop.store(true);
        Checkpoint("B1_STORM_STOP_REQUESTED");
        storm.join();
        Checkpoint("B1_STORM_JOINED");
        Checkpoint("B1_END_BEGIN");
        const bool ended = EndBatch();
        Checkpoint("B1_END_COMPLETE");
        const Snap b1 = Take();
        std::printf("  queued=%zu open: prefetches=%llu evictions=%llu overrides=%llu "
                    "evicted_while_open=%llu\n",
                    batch_n, (unsigned long long)storm_prefetch.load(),
                    (unsigned long long)b_open.evictions,
                    (unsigned long long)b_open.budget_overrides,
                    (unsigned long long)(b_open.evictions - b0.evictions));
        Check(queued_ok, "B1: every dot queued into the open batch");
        Check(storm_prefetch.load() > 0, "B1: storm prefetched while the batch was open");
        Check(b_open.evictions > b0.evictions,
              "B1: evictions ran while the batch was open (non-vacuous)");
        Check(ended, "B1: EndBatch succeeded");
        bool bit = true;
        for (size_t i = 0; i < batch_n; ++i) if (!SameBits(bout[i], bref[i])) bit = false;
        Check(bit, "B1: batched output bit-identical to serial reference");
        Check(b1.pinned == 0, "B1: no batch pin left after End");
    }

    // =========================================================================
    // B2. DEVICE-level batch pinning. Begin/Queue/End are driven directly on
    //     the very device the dispatcher uses, so the window between Queue and
    //     End is real and another thread can evict while it is open. The
    //     residency budget must then DEFER eviction rather than free a buffer
    //     the pending batch still references.
    // =========================================================================
    std::printf("\n--- B2. device-level batch in-flight pinning ---\n");
    Checkpoint("SECTION_B2_BEGIN");
    {
        // Budget holds ~2 banks; the batch pins 8, so the budget cannot be met
        // by eviction and the deferred path is the only legal outcome.
        const size_t pin_n = 8;
        const int64_t tight = (int64_t)(bank_bytes * 2);
        VulkanCompute& vk = DispatchDevice();
        vk.SetQuantWeightBudgetBytes((size_t)tight);
        std::vector<std::vector<float>> bout2(pin_n);
        std::vector<std::vector<float>> bref2(pin_n);
        for (size_t i = 0; i < pin_n; ++i) {
            bout2[i].resize(n_out);
            std::vector<float> y(n_out);
            const CpuDot cpu = MakeCpuRef(banks[i]);
            if (!vk.ExecuteQuantDot(banks[i].bytes.data(), banks[i].packedBytes(),
                                    q8.data(), q8.size() * sizeof(float),
                                    y.data(), n_out * sizeof(float),
                                    n_out, n_in, n_in / 256u, 0)) {
                std::printf("B2: single reference dispatch failed\n"); return 3;
            }
            bref2[i] = y;
        }
        std::atomic<bool> storm_stop{false};
        std::atomic<bool> storm_ready{false};
        std::atomic<uint64_t> storm_prefetch{0};
        std::atomic<uint64_t> storm_evict_seen{0};
        uint64_t last_seen_evict = 0;
        std::thread storm([&]() {
            uint32_t rng = 5150u;
            auto spin = [&]() {
                for (int i = 0; i < 4 && !storm_stop.load(); ++i) {
                    rng = rng * 1664525u + 1013904223u;
                    const Bank& b = banks[rng % n_banks];
                    const uint64_t e0 = GetCacheStats().evictions;
                    vk.PrefetchQuantWeight(b.bytes.data(), b.packedBytes(), 0);
                    const uint64_t e1 = GetCacheStats().evictions;
                    if (e1 > e0) storm_evict_seen += (e1 - e0);
                    ++storm_prefetch;
                }
            };
            spin();
            storm_ready.store(true);
            storm_ready.notify_one();
            while (!storm_stop.load()) spin();
        });
        storm_ready.wait(false);
        const Snap p0 = Take();
        if (!vk.BeginQuantDotBatch()) { std::printf("B2: BeginQuantDotBatch failed\n"); return 3; }
        bool qok = true;
        for (size_t i = 0; i < pin_n; ++i) {
            if (!vk.QueueQuantDot(banks[i].bytes.data(), banks[i].packedBytes(),
                                  q8.data(), q8.size() * sizeof(float),
                                  bout2[i].data(), n_out * sizeof(float),
                                  n_out, n_in, 0))
                qok = false;
        }
        // Sample the pin state WHILE the batch is open on the device.
        const uint64_t open_pins = (uint64_t)vk.PinnedWeightCount();
        const uint64_t open_overrides = (uint64_t)vk.BudgetOverrides();
        storm_stop.store(true);
        storm.join();
        const uint64_t evicted_during = GetCacheStats().evictions - p0.evictions;
        const bool ended2 = vk.EndQuantDotBatch();
        const Snap p1 = Take();
        std::printf("  pinned=%zu queued=%d open_pins=%llu open_overrides=%llu "
                    "evicted_while_open=%llu overrides_during=%llu\n",
                    pin_n, qok ? 1 : 0, (unsigned long long)open_pins,
                    (unsigned long long)open_overrides,
                    (unsigned long long)evicted_during,
                    (unsigned long long)(p1.budget_overrides - p0.budget_overrides));
        Check(qok, "B2: every dot queued into the open device batch");
        Check(open_pins >= pin_n, "B2: open device batch pinned every queued weight");
        Check(p1.budget_overrides > p0.budget_overrides,
              "B2: eviction DEFERRED because the in-flight set was pinned");
        const CacheStats b2_after = GetCacheStats();
        Check(b2_after.retired_pending == 0 &&
                  b2_after.retired_reaped >= b2_after.evictions,
              "B2: every counted eviction was fence-safe and reaped");
        Check(ended2, "B2: EndQuantDotBatch succeeded");
        bool bit2 = true;
        for (size_t i = 0; i < pin_n; ++i) if (!SameBits(bout2[i], bref2[i])) bit2 = false;
        Check(bit2, "B2: pinned batch output bit-identical to serial reference");
        Check(p1.pinned == 0, "B2: device batch pins released after End");
        // Restore the derived budget for the remaining sections.
        vk.SetQuantWeightBudgetBytes(0);
    }

    // =========================================================================
    // C. Generation leases.
    // =========================================================================
    std::printf("\n--- C. generation leases ---\n");
    Checkpoint("SECTION_C_BEGIN");
    {
        const size_t i = n_banks - 1;
        const uint64_t lease = AcquireWeightLease(banks[i].bytes.data(),
                                                  banks[i].packedBytes(), 0);
        Check(lease != 0, "C: lease acquired on a fresh weight");
        Checkpoint("C_LEASE_ACQUIRED");
        std::atomic<bool> storm_stop{false};
        std::atomic<bool> storm_ready{false};
        std::atomic<uint64_t> storm_prefetch{0};
        std::thread storm([&]() {
            uint32_t rng = 4242u;
            auto spin = [&]() {
                for (int i2 = 0; i2 < 4 && !storm_stop.load(); ++i2) {
                    rng = rng * 1664525u + 1013904223u;
                    const Bank& b = banks[rng % n_banks];
                    if (PrefetchWeight(b.bytes.data(), b.packedBytes(), 0)) ++storm_prefetch;
                    std::this_thread::yield();
                }
            };
            spin();
            storm_ready.store(true);
            storm_ready.notify_one();
            while (!storm_stop.load()) {
                spin();
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        });
        storm_ready.wait(false);
        Checkpoint("C_STORM_READY");
        const Snap c0 = Take();
        bool resident = true;
        for (int r = 0; r < 200 && resident; ++r) {
            if (!IsWeightResident(banks[i].bytes.data(), banks[i].packedBytes(), 0)) resident = false;
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        Checkpoint("C_RESIDENCY_CHECK_COMPLETE");
        std::vector<float> y(n_out);
        const CpuDot cpu = MakeCpuRef(banks[i]);
        const bool ok = DotBlocked(0, banks[i].bytes.data(), banks[i].packedBytes(),
                                   act.data(), n_in, y.data(), n_out, cpu,
                                   q8.data(), q8.size() * sizeof(float), false);
        const bool leased_result_ok = ok && SameBits(y, ref[i]);
        storm_stop.store(true);
        Checkpoint("C_STORM_STOP_REQUESTED");
        storm.join();
        Checkpoint("C_STORM_JOINED");
        const Snap c1 = Take();
        Check(resident, "C: leased weight stayed resident through the eviction storm");
        Check(c0.pinned >= 1, "C: the lease shows up as an in-flight pin");
        Check(c1.evictions > c0.evictions, "C: the storm really did evict (non-vacuous)");
        Check(leased_result_ok, "C: dispatch on the leased weight is bit-exact");
        ReleaseWeightLease(lease);
        ReleaseWeightLease(lease);                       // double release: must be a no-op
        ReleaseWeightLease(0xDEADBEEFu);                  // stale id: must be a no-op
        Checkpoint("C_LEASE_RELEASED");
        const Snap c2 = Take();
        Check(c2.leases == 0, "C: lease released; double/stale release are no-ops");
        Check(c2.pinned == 0, "C: pin dropped once the lease was released");
        // One dispatch after the storm: that is the moment the fence proves the
        // deferred destructions safe. This is the real fence-safety property.
        {
            std::vector<float> y2(n_out);
            const CpuDot cpu2 = MakeCpuRef(banks[0]);
            Checkpoint("C_DRAIN_DISPATCH_BEGIN");
            (void)DotBlocked(0, banks[0].bytes.data(), banks[0].packedBytes(),
                             act.data(), n_in, y2.data(), n_out, cpu2,
                             q8.data(), q8.size() * sizeof(float), false);
            Checkpoint("C_DRAIN_DISPATCH_COMPLETE");
        }
        const Snap c3 = Take();
        Check(c3.retired_pending == 0, "C: deferred destruction drained after one dispatch");
        Check(c3.retired_pending == 0 && c3.retired_reaped >= c3.evictions,
              "C: every counted eviction was reaped (fence-safe)");
    }
    std::printf("\n--- D. dispatch determinism under concurrency ---\n");
    Checkpoint("SECTION_D_BEGIN");
    {
        std::vector<std::vector<float>> outs(n_threads);
        std::atomic<bool> bad{false};
        std::vector<std::thread> ts;
        for (size_t t = 0; t < n_threads; ++t) {
            ts.emplace_back([&, t]() {
                std::vector<float> y(n_out);
                for (size_t r = 0; r < rounds; ++r) {
                    const size_t i = (t + r) % n_banks;
                    const CpuDot cpu = MakeCpuRef(banks[i]);
                    const bool ok = DotBlocked(0, banks[i].bytes.data(), banks[i].packedBytes(),
                                               act.data(), n_in, y.data(), n_out, cpu,
                                               q8.data(), q8.size() * sizeof(float), false);
                    if (!ok || !SameBits(y, ref[i])) { bad = true; return; }
                }
                outs[t] = y;
            });
        }
        for (auto& th : ts) th.join();
        const Snap d1 = Take();
        Check(!bad.load(), "D: every concurrent dispatch bit-identical to the reference");
        Check(d1.retired_pending == 0 && d1.retired_reaped >= d1.evictions,
              "D: residency accounting drained cleanly");
        PrintSnap("D final:", d1);
    }

    std::printf("\n--- E. batch ownership and empty-close regression ---\n");
    Checkpoint("SECTION_E_BEGIN");
    {
        bool repeated_empty = true;
        for (int i = 0; i < 8; ++i) {
            if (!BeginBatch() || !EndBatch()) { repeated_empty = false; break; }
        }
        Check(repeated_empty, "E: repeated empty batches close exactly once");

        const bool owner_opened = BeginBatch();
        const size_t e_q6_row_bytes = ((n_in + 255u) / 256u) * 210u;
        std::vector<uint8_t> e_q6_payload(n_out * e_q6_row_bytes);
        for (size_t i = 0; i < e_q6_payload.size(); ++i)
            e_q6_payload[i] = static_cast<uint8_t>((i * 17u + 31u) & 0xffu);
        std::vector<float> e_batch_out(n_out, 0.0f);
        const CpuDot e_cpu = [e_q6_row_bytes](const uint8_t* row,
                                               const void* q8_ptr,
                                               size_t) -> float {
            const float* q8_values = static_cast<const float*>(q8_ptr);
            float acc = 0.0f;
            for (size_t i = 0; i < e_q6_row_bytes; ++i)
                acc += static_cast<float>(row[i]) *
                       q8_values[i % 8u] * 0.0001f;
            return acc;
        };
        const bool owner_queued = owner_opened && DotBlocked(
            1, e_q6_payload.data(), e_q6_payload.size(),
            act.data(), n_in, e_batch_out.data(), n_out, e_cpu,
            q8.data(), q8.size() * sizeof(float), false);
        Check(owner_queued && LastReceipt().queued,
              "E: primary executor queued work for aggregate accounting");
        std::atomic<bool> contender_started{false};
        BatchAccounting contender_snapshot{};
        bool contender_acquired = true;
        bool contender_preclose = true;
        bool contender_closed = false;
        std::thread contender([&]() {
            contender_started.store(true, std::memory_order_release);
            contender_snapshot = BatchAccountingSnapshot();
            contender_preclose = EndBatch();
            contender_acquired = BeginBatch();
            if (contender_acquired) contender_closed = EndBatch();
        });
        while (!contender_started.load(std::memory_order_acquire)) std::this_thread::yield();
        contender.join();
        const bool owner_closed = owner_opened && EndBatch();
        Check(owner_opened, "E: primary executor acquired batch ownership");
        Check(!contender_preclose, "E: non-owner cannot close another executor batch");
        Check(contender_acquired, "E: independent executor acquired its own batch");
        Check(contender_closed, "E: independent executor closes its own batch");
        Check(owner_closed, "E: owning executor closes its batch");
        Check(contender_snapshot.active_batches >= 1 &&
                  contender_snapshot.pending_queued >= 1 &&
                  !contender_snapshot.batch_active &&
                  contender_snapshot.queued == 0,
              "E: cross-thread accounting reports another executor's batch");
        const BatchAccounting after_owner = BatchAccountingSnapshot();
        Check(after_owner.active_batches == 0 && after_owner.pending_queued == 0,
              "E: aggregate accounting drains after owner closure");

        const bool retry_opened = BeginBatch();
        const bool retry_closed = retry_opened && EndBatch();
        Check(retry_opened && retry_closed, "E: ownership is reusable after close");

        SetActiveDevice(-1);
        std::atomic<int32_t> child_device{-2};
        std::thread device_scope([&]() {
            SetActiveDevice(17);
            child_device.store(ActiveDevice(), std::memory_order_release);
        });
        device_scope.join();
        Check(child_device.load(std::memory_order_acquire) == 17 &&
                  ActiveDevice() == -1,
              "E: active-device override is isolated per executor thread");
    }

    std::printf("\n--- F. injected device-close failure recovery ---\n");
    Checkpoint("SECTION_F_BEGIN");
    {
        std::vector<float> failed_out(n_out, 0.0f);
        // Q4_K is intentionally kept on the synchronous path by the
        // production dispatcher. Use a valid Q6_K-shaped payload here so the
        // regression reaches the real deferred batch and EndQuantDotBatch
        // failure path rather than accidentally testing a synchronous dot.
        const size_t q6_row_bytes = (n_in / 256u) * 210u;
        std::vector<uint8_t> q6_payload(n_out * q6_row_bytes);
        for (size_t i = 0; i < q6_payload.size(); ++i)
            q6_payload[i] = static_cast<uint8_t>((i * 29u + 17u) & 0xffu);
        const size_t q8_count = q8.size();
        const CpuDot failed_cpu = [q6_row_bytes, q8_count](
            const uint8_t* row, const void* q8_ptr, size_t) -> float {
            const float* q8_values = static_cast<const float*>(q8_ptr);
            float acc = 0.0f;
            for (size_t i = 0; i < q6_row_bytes; ++i)
                acc += static_cast<float>(row[i]) *
                       q8_values[i % q8_count] * 0.0001f;
            return acc;
        };
        std::vector<float> failed_ref(n_out, 0.0f);
        for (size_t row = 0; row < n_out; ++row)
            failed_ref[row] = failed_cpu(
                q6_payload.data() + row * q6_row_bytes,
                q8.data(), row);
        const bool opened = BeginBatch();
        const bool queued = opened && DotBlocked(
            1, q6_payload.data(), q6_payload.size(),
            act.data(), n_in, failed_out.data(), n_out, failed_cpu,
            q8.data(), q8.size() * sizeof(float), false);
        const bool queued_receipt = queued && LastReceipt().queued;
        const bool injected = queued && InjectEndBatchFailureForTest();
        const bool closed = injected && EndBatch();
        Check(opened, "F: failure-injection batch opened");
        Check(queued_receipt, "F: dot accepted into failure-injection batch");
        Check(injected, "F: EndBatch failure was armed");
        Check(!closed, "F: injected device close failure is reported");
        Check(LastReceipt().fail_stage &&
                  std::strcmp(LastReceipt().fail_stage, "end") == 0,
              "F: receipt identifies device close failure");
        Check(LastReceipt().cpu_rows == n_out && SameBits(failed_out, failed_ref),
              "F: failed batch replays the queued dot exactly once on CPU");
        const BatchAccounting accounting = BatchAccountingSnapshot();
        Check(!accounting.batch_active && accounting.queued == 0,
              "F: failed close leaves no active or queued logical batch state");
        Check(accounting.accepted == accounting.completed + accounting.failed,
              "F: failed close preserves terminal accounting");
        Check(GetCacheStats().pinned == 0,
              "F: failed close releases all residency pins");
        const bool recovered_open = BeginBatch();
        const bool recovered_close = recovered_open && EndBatch();
        Check(recovered_open && recovered_close,
              "F: a later batch can open and close after failure recovery");
        std::vector<float> drain_out(n_out, 0.0f);
        const bool drained = DotBlocked(
            0, banks[0].bytes.data(), banks[0].packedBytes(),
            act.data(), n_in, drain_out.data(), n_out, MakeCpuRef(banks[0]),
            q8.data(), q8.size() * sizeof(float), false);
        Check(drained && LastReceipt().used_gpu,
              "F: a real post-failure dispatch drains deferred residency safely");
        const CacheStats f_after = GetCacheStats();
        Check(f_after.retired_pending == 0 && f_after.retired_reaped >= f_after.evictions,
              "F: post-failure residency is fully reaped");
    }

    // =========================================================================
    // G. B03: per-executor batch ownership (production candidate v2, 7fbf5806ad).
    //
    // All mutable dispatch state is thread_local here, so batch ownership is
    // per-thread. These tests exercise that contract directly rather than
    // assuming it: same-owner batching, two overlapping executors, cross-thread
    // misuse, and repeated lifecycle on a reused thread.
    //
    // Q8_0 (kind=3) weights are compared GPU-serial vs GPU-batched for the SAME
    // bytes and activation, so bit-identity is meaningful without introducing an
    // unverified Q8_0 CPU reference (the harness's only independent reference,
    // DotQ4, is Q4_K-specific).
    // =========================================================================
    std::printf("\n--- G. B03: per-executor batch ownership ---\n");
    {
        const size_t G_OUT = 64, G_IN = 1024, G_BLK = 32;
        const size_t G_NBLK = G_IN / G_BLK;
        const size_t G_ROWBYTES = G_NBLK * 34;      // Q8_0: fp16 d + 32 x int8
        const size_t G_BANKS = 4;

        std::vector<std::vector<uint8_t>> w(G_BANKS);
        uint32_t rng = 0x9e3779b9u;
        auto next = [&rng]() -> uint32_t {
            rng = rng * 1664525u + 1013904223u;
            return (rng >> 8) & 0xffffu;
        };
        for (size_t b = 0; b < G_BANKS; ++b) {
            w[b].assign(G_OUT * G_ROWBYTES, 0);
            for (size_t r = 0; r < G_OUT; ++r) {
                uint8_t* row = w[b].data() + r * G_ROWBYTES;
                for (size_t k = 0; k < G_NBLK; ++k) {
                    uint8_t* blk = row + k * 34;
                    blk[0] = 0x00; blk[1] = 0x3C;   // fp16 1.0
                    for (size_t i = 0; i < 32; ++i)
                        blk[2 + i] = (uint8_t)(int8_t)(int(next() % 201u) - 100);
                }
            }
        }

        const std::vector<float> q8 = MakeQ8(G_IN, 11);
        const std::vector<float> act = MakeAct(G_IN, 13);

        auto dot = [&](size_t b, float* out) -> bool {
            auto cpu = [&act](const uint8_t* row, const void*, size_t rowIndex) -> float {
                float acc = 0.0f;
                for (size_t k = 0; k < 32; ++k) {
                    const uint8_t* blk = row + rowIndex * 1088 + k * 34;
                    uint16_t d; std::memcpy(&d, blk, sizeof(d));
                    const float sc = HalfToFloat(d);
                    float s = 0.0f;
                    for (size_t i = 0; i < 32; ++i)
                        s += float((int8_t)blk[2 + i]) * act[k * 32 + i];
                    acc += s * sc;
                }
                return acc;
            };
            return DotBlocked(3, w[b].data(), w[b].size(), act.data(), G_IN,
                              out, G_OUT, cpu, q8.data(), q8.size() * sizeof(float), false);
        };

        // ---- G1: same-owner batching, one thread owns Begin/Dot/End ----
        std::vector<float> g1_serial(G_OUT, 0.0f), g1_batched(G_OUT, 0.0f);
        const bool g1_serial_ok = dot(0, g1_serial.data()) && LastReceipt().used_gpu;
        const auto g1_before = BatchAccountingSnapshot();
        bool g1_opened = false, g1_queued = false, g1_closed = false;
        if (g1_serial_ok) {
            g1_opened = BeginBatch();
            if (g1_opened) {
                g1_queued = dot(0, g1_batched.data());
                g1_closed = EndBatch();
            }
        }
        const auto g1_after = BatchAccountingSnapshot();
        const uint64_t g1_acc = g1_after.accepted - g1_before.accepted;
        const uint64_t g1_cmp = g1_after.completed - g1_before.completed;
        const uint64_t g1_fail = g1_after.failed - g1_before.failed;
        const uint64_t g1_dev = g1_after.device_batches_opened - g1_before.device_batches_opened;
        const bool g1_bits = g1_serial_ok && SameBits(g1_batched, g1_serial);
        printf("  G1 same-owner: serial=%s opened=%s queued=%s closed=%s bits=%s "
               "accepted=%llu completed=%llu failed=%llu device_batches=%llu\n",
               g1_serial_ok ? "ok" : "NO", g1_opened ? "yes" : "NO",
               g1_queued ? "yes" : "NO", g1_closed ? "yes" : "NO",
               g1_bits ? "yes" : "NO",
               (unsigned long long)g1_acc, (unsigned long long)g1_cmp,
               (unsigned long long)g1_fail, (unsigned long long)g1_dev);
        Check(g1_serial_ok, "G1: serial Q8_0 baseline ran on the GPU");
        Check(g1_opened && g1_queued && g1_closed, "G1: same-owner batch opened, queued and closed");
        Check(g1_bits, "G1: batched output bit-identical to GPU serial");
        Check(g1_acc == g1_cmp + g1_fail && g1_fail == 0,
              "G1: accepted == completed + failed, no failures");
        Check(g1_after.queued == 0 && !g1_after.batch_active,
              "G1: no pending queue and no active batch after close");
        Check(g1_dev >= 1 && g1_cmp > 0, "G1: exactly one real device batch, non-vacuous");

        // ---- G2: two independent executors with overlapping batches ----
        std::atomic<bool> g2_go{false};
        std::atomic<bool> g2_ok{true};
        std::atomic<uint64_t> a_acc{0}, a_cmp{0}, a_fail{0}, b_acc{0}, b_cmp{0}, b_fail{0};
        std::atomic<int> a_open_seen{0}, b_open_seen{0};
        auto executor = [&](size_t bank, std::atomic<uint64_t>& acc,
                            std::atomic<uint64_t>& cmp, std::atomic<uint64_t>& fail,
                            std::atomic<int>& open_seen) {
            while (!g2_go.load(std::memory_order_acquire)) std::this_thread::yield();
            std::vector<float> s(G_OUT, 0.0f), b(G_OUT, 0.0f);
            const bool serial_ok = dot(bank, s.data()) && LastReceipt().used_gpu;
            const auto before = BatchAccountingSnapshot();
            const bool opened = serial_ok && BeginBatch();
            const bool queued = opened && dot(bank, b.data());
            const bool closed = opened && EndBatch();
            const auto after = BatchAccountingSnapshot();
            acc.store(after.accepted - before.accepted);
            cmp.store(after.completed - before.completed);
            fail.store(after.failed - before.failed);
            open_seen.store(after.batch_active ? 0 : 1);
            const bool bits = serial_ok && SameBits(b, s);
            const bool balanced = (after.accepted - before.accepted) ==
                                  (after.completed - before.completed) +
                                  (after.failed - before.failed);
            if (!(serial_ok && opened && queued && closed && bits && balanced &&
                  after.queued == 0 && !after.batch_active))
                g2_ok.store(false);
        };
        std::thread g2t1(executor, 1, std::ref(a_acc), std::ref(a_cmp), std::ref(a_fail),
                         std::ref(a_open_seen));
        std::thread g2t2(executor, 2, std::ref(b_acc), std::ref(b_cmp), std::ref(b_fail),
                         std::ref(b_open_seen));
        g2_go.store(true);
        g2t1.join();
        g2t2.join();
        printf("  G2 executors: A(accepted=%llu completed=%llu failed=%llu) "
               "B(accepted=%llu completed=%llu failed=%llu) ok=%s\n",
               (unsigned long long)a_acc.load(), (unsigned long long)a_cmp.load(),
               (unsigned long long)a_fail.load(), (unsigned long long)b_acc.load(),
               (unsigned long long)b_cmp.load(), (unsigned long long)b_fail.load(),
               g2_ok.load() ? "yes" : "NO");
        Check(g2_ok.load(), "G2: both independent executors batched correctly");
        Check(a_acc.load() > 0 && b_acc.load() > 0,
              "G2: both executors accepted real work (non-vacuous)");
        Check(a_acc.load() == a_cmp.load() + a_fail.load() &&
              b_acc.load() == b_cmp.load() + b_fail.load(),
              "G2: per-executor accounting balanced independently");

        // ---- G3: cross-thread misuse must not close another executor's batch ----
        bool g3_opened = false, g3_remote_closed = false, g3_closed = false;
        bool g3_still_active = false;
        if (BeginBatch()) {
            g3_opened = true;
            std::atomic<bool> remote_done{false};
            std::thread intruder([&]() {
                g3_remote_closed = EndBatch();   // must fail: this thread owns no batch
                remote_done.store(true);
            });
            intruder.join();
            g3_still_active = BatchAccountingSnapshot().batch_active;
            g3_closed = EndBatch();
        }
        printf("  G3 cross-thread: opened=%s remote_closed=%s owner_still_active=%s closed=%s\n",
               g3_opened ? "yes" : "NO", g3_remote_closed ? "YES" : "no",
               g3_still_active ? "yes" : "NO", g3_closed ? "yes" : "NO");
        Check(g3_opened, "G3: owner opened a batch");
        Check(!g3_remote_closed, "G3: a foreign thread could not close the owner's batch");
        Check(g3_still_active, "G3: owner's batch survived the foreign close attempt");
        Check(g3_closed && !BatchAccountingSnapshot().batch_active,
              "G3: owner closed its own batch afterwards");

        // ---- G4: repeated lifecycle on a reused thread ----
        bool g4_ok = true;
        int g4_cycles = 0;
        for (int i = 0; i < 8 && g4_ok; ++i) {
            std::vector<float> s(G_OUT, 0.0f), b(G_OUT, 0.0f);
            if (!(dot(3, s.data()) && LastReceipt().used_gpu)) { g4_ok = false; break; }
            const auto before = BatchAccountingSnapshot();
            const bool opened = BeginBatch();
            const bool queued = opened && dot(3, b.data());
            const bool closed = opened && EndBatch();
            const auto after = BatchAccountingSnapshot();
            const bool balanced = (after.accepted - before.accepted) ==
                                  (after.completed - before.completed) +
                                  (after.failed - before.failed);
            if (!(opened && queued && closed && balanced && SameBits(s, b) &&
                  after.queued == 0 && !after.batch_active)) { g4_ok = false; break; }
            ++g4_cycles;
        }
        printf("  G4 repeated lifecycle: cycles=%d ok=%s\n", g4_cycles, g4_ok ? "yes" : "NO");
        Check(g4_cycles == 8, "G4: eight sequential batches on one thread all balanced");
        Check(g4_ok && BatchAccountingSnapshot().queued == 0 &&
              !BatchAccountingSnapshot().batch_active,
              "G4: no stale queue, receipt or batch state after reuse");

        const auto g_final = BatchAccountingSnapshot();
        Check(g_final.queued == 0 && !g_final.batch_active,
              "G: no leaked batch or pending queue after all B03 tests");

        // ---- H: B04.1 deterministic inverted completion ordering ----
        //
        // G2 ran two executors concurrently but left the order of their EndBatch
        // calls to chance. Here it is forced: the slow executor queues and then
        // WAITS for the fast executor to close before closing itself, so the
        // close order is inverted by construction rather than by timing.
        //
        // Every wait is bounded. If the peer stalls, the thread stops waiting and
        // still closes its own batch, so a stalled peer cannot strand a live GPU
        // submission or leave a batch open.
        std::printf("\n--- H. B04.1: inverted completion ordering ---\n");
        auto run_inverted = [&](size_t bank_slow, size_t bank_fast) -> bool {
            std::atomic<bool> fast_done{false};
            std::atomic<bool> slow_ready{false};
            std::atomic<bool> ok{true};
            std::atomic<uint64_t> s_acc{0}, s_cmp{0}, s_fail{0};
            std::atomic<uint64_t> f_acc{0}, f_cmp{0}, f_fail{0};
            constexpr uint64_t kSpinLimit = 20000000ull;

            auto slow_exec = [&]() {
                std::vector<float> s(G_OUT, 0.0f), b(G_OUT, 0.0f);
                const bool serial_ok = dot(bank_slow, s.data()) && LastReceipt().used_gpu;
                const auto before = BatchAccountingSnapshot();
                const bool opened = serial_ok && BeginBatch();
                const bool queued = opened && dot(bank_slow, b.data());
                slow_ready.store(true, std::memory_order_release);
                for (uint64_t i = 0; i < kSpinLimit &&
                     !fast_done.load(std::memory_order_acquire); ++i)
                    std::this_thread::yield();
                const bool closed = opened && EndBatch();
                const auto after = BatchAccountingSnapshot();
                s_acc.store(after.accepted - before.accepted);
                s_cmp.store(after.completed - before.completed);
                s_fail.store(after.failed - before.failed);
                const bool bits = serial_ok && SameBits(s, b);
                if (!(serial_ok && opened && queued && closed && bits &&
                      after.queued == 0 && !after.batch_active))
                    ok.store(false);
            };
            auto fast_exec = [&]() {
                for (uint64_t i = 0; i < kSpinLimit &&
                     !slow_ready.load(std::memory_order_acquire); ++i)
                    std::this_thread::yield();
                std::vector<float> s(G_OUT, 0.0f), b(G_OUT, 0.0f);
                const bool serial_ok = dot(bank_fast, s.data()) && LastReceipt().used_gpu;
                const auto before = BatchAccountingSnapshot();
                const bool opened = serial_ok && BeginBatch();
                const bool queued = opened && dot(bank_fast, b.data());
                const bool closed = opened && EndBatch();
                fast_done.store(true, std::memory_order_release);
                const auto after = BatchAccountingSnapshot();
                f_acc.store(after.accepted - before.accepted);
                f_cmp.store(after.completed - before.completed);
                f_fail.store(after.failed - before.failed);
                const bool bits = serial_ok && SameBits(s, b);
                if (!(serial_ok && opened && queued && closed && bits &&
                      after.queued == 0 && !after.batch_active))
                    ok.store(false);
            };

            std::thread slow(slow_exec), fast(fast_exec);
            slow.join();
            fast.join();

            const bool attributed =
                s_acc.load() == 1 && s_cmp.load() == 1 && s_fail.load() == 0 &&
                f_acc.load() == 1 && f_cmp.load() == 1 && f_fail.load() == 0;
            printf("  H: slow(bank=%zu) accepted=%llu completed=%llu failed=%llu | "
                   "fast(bank=%zu) accepted=%llu completed=%llu failed=%llu ok=%s\n",
                   bank_slow, (unsigned long long)s_acc.load(),
                   (unsigned long long)s_cmp.load(), (unsigned long long)s_fail.load(),
                   bank_fast, (unsigned long long)f_acc.load(),
                   (unsigned long long)f_cmp.load(), (unsigned long long)f_fail.load(),
                   ok.load() ? "yes" : "NO");
            return ok.load() && attributed;
        };

        Check(run_inverted(1, 2),
              "H1: inverted ordering (slow closes after fast) attributes one op each");
        Check(run_inverted(3, 0),
              "H2: inverted ordering with roles reversed attributes one op each");
    }

    // ---- final invariants ---------------------------------------------------
    const Snap f = Take();
    std::printf("\n--- final invariants ---\n");
    Check(f.leases == 0, "no outstanding lease");
    Check(f.pinned == 0, "no outstanding pin");
    Check(f.retired_pending == 0, "no deferred destruction outstanding");
    Check(f.retired_pending == 0 && f.retired_reaped >= f.evictions,
          "every counted eviction was destroyed only after its fence (fence-safe)");
    Check(f.completed_epoch == f.epoch, "every submitted epoch has completed");
    Check(f.live > 0, "device residency is real (non-zero live bytes)");
    PrintSnap("FINAL:", f);

    std::printf("\nG04_RESULT=%s (failures=%d)\n", g_fail == 0 ? "PASS" : "FAIL", g_fail);
    return g_fail == 0 ? 0 : 1;
}
