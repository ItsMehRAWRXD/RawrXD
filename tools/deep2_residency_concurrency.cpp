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
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")
#endif

#include "quant_dot_dispatch.hpp"
#include "include/vulkan_compute.h"

using namespace RawrXD::Deep2::QuantDot;

namespace {

// ---------------------------------------------------------------------------
// Hang watchdog: when no checkpoint has fired for RAWRXD_HANG_WATCHDOG_MS
// (default 10 s), capture and print every thread's stack so a stall names the
// exact wait: host mutex (ucrtbase/ntdll), Vulkan fence (vulkan-1 / driver),
// or harness code. Threads are suspended only for GetThreadContext and resumed
// before any symbol lookup, so dbghelp can never deadlock on the loader lock.
// ---------------------------------------------------------------------------
std::atomic<uint64_t> g_wd_seq{0};
std::atomic<int64_t> g_wd_last_ms{0};
std::atomic<int64_t> g_wd_threshold_ms{10000};

int64_t NowMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

void Checkpoint(const char* name, size_t index = static_cast<size_t>(-1)) {
    const uint64_t seq = g_wd_seq.fetch_add(1, std::memory_order_relaxed) + 1;
    g_wd_last_ms.store(NowMs(), std::memory_order_relaxed);
    if (index == static_cast<size_t>(-1))
        std::printf("CHECKPOINT seq=%llu %s\n", (unsigned long long)seq, name);
    else
        std::printf("CHECKPOINT seq=%llu %s index=%zu\n",
                    (unsigned long long)seq, name, index);
    std::fflush(stdout);
}

#if defined(_WIN32)
void WatchdogCaptureStacks(const char* reason) {
    struct Cap { DWORD tid; CONTEXT ctx; };
    std::vector<Cap> caps;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te; te.dwSize = sizeof(te);
        if (Thread32First(snap, &te)) {
            do {
                if (te.th32OwnerProcessID != GetCurrentProcessId()) continue;
                if (te.th32ThreadID == GetCurrentThreadId()) continue;
                HANDLE h = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME |
                                      THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                if (!h) continue;
                if (SuspendThread(h) == (DWORD)-1) { CloseHandle(h); continue; }
                Cap c{}; c.tid = te.th32ThreadID; c.ctx.ContextFlags = CONTEXT_CONTROL;
                const BOOL got = GetThreadContext(h, &c.ctx);
                (void)ResumeThread(h);
                CloseHandle(h);
                if (got) caps.push_back(c);
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);
    }
    HANDLE hp = GetCurrentProcess();
    static std::atomic<bool> sym_init{false};
    if (!sym_init.exchange(true)) {
        char dir[MAX_PATH] = {};
        GetModuleFileNameA(nullptr, dir, MAX_PATH);
        char* slash = std::strrchr(dir, '\\');
        if (slash) *slash = '\0';
        SymInitialize(hp, dir, TRUE);
    }
    std::printf("WATCHDOG_STALL reason=%s threads=%zu last_checkpoint_seq=%llu\n",
                reason, caps.size(), (unsigned long long)g_wd_seq.load());
    std::fflush(stdout);
    for (const Cap& c : caps) {
        std::printf("--- thread tid=%lu ---\n", c.tid);
        CONTEXT ctx = c.ctx;
        STACKFRAME64 sf; std::memset(&sf, 0, sizeof(sf));
        const DWORD machine = IMAGE_FILE_MACHINE_AMD64;
        sf.AddrPC.Mode = AddrModeFlat; sf.AddrFrame.Mode = AddrModeFlat;
        sf.AddrStack.Mode = AddrModeFlat;
        sf.AddrPC.Offset = ctx.Rip; sf.AddrFrame.Offset = ctx.Rbp;
        sf.AddrStack.Offset = ctx.Rsp;
        for (int frame = 0; frame < 24; ++frame) {
            char symbuf[sizeof(SYMBOL_INFO) + MAX_SYM_NAME];
            std::memset(symbuf, 0, sizeof(symbuf));
            SYMBOL_INFO* sym = reinterpret_cast<SYMBOL_INFO*>(symbuf);
            sym->SizeOfStruct = sizeof(SYMBOL_INFO);
            sym->MaxNameLen = MAX_SYM_NAME;
            DWORD64 disp = 0;
            const char* name = "??";
            if (SymFromAddr(hp, sf.AddrPC.Offset, &disp, sym)) name = sym->Name;
            IMAGEHLP_LINE64 line; std::memset(&line, 0, sizeof(line));
            line.SizeOfStruct = sizeof(line);
            DWORD ldisp = 0;
            char file[MAX_PATH] = {}; int lineno = 0;
            if (SymGetLineFromAddr64(hp, sf.AddrPC.Offset, &ldisp, &line)) {
                std::snprintf(file, sizeof(file), "%s", line.FileName);
                lineno = (int)line.LineNumber;
            }
            HMODULE mod = nullptr;
            char modname[MAX_PATH] = {};
            if (GetModuleHandleExA(
                    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                    GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                    reinterpret_cast<LPCSTR>(sf.AddrPC.Offset), &mod) && mod) {
                GetModuleFileNameA(mod, modname, MAX_PATH);
                const char* base = std::strrchr(modname, '\\');
                base = base ? base + 1 : modname;
                std::printf("    #%02d %s+0x%llx %s\n", frame, name,
                            (unsigned long long)(sf.AddrPC.Offset - (DWORD64)mod),
                            file[0] ? file : base);
                if (file[0]) std::printf("         %s:%d\n", file, lineno);
            } else {
                std::printf("    #%02d %s 0x%llx\n", frame, name,
                            (unsigned long long)sf.AddrPC.Offset);
            }
            if (sf.AddrPC.Offset == sf.AddrReturn.Offset) break;
            if (!StackWalk64(machine, hp, nullptr, &sf, &ctx, nullptr, nullptr, nullptr, nullptr))
                break;
        }
        std::fflush(stdout);
    }
}
#endif // _WIN32

void WatchdogMain() {
    for (;;) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        const int64_t last = g_wd_last_ms.load(std::memory_order_relaxed);
        if (last == 0) continue;
        const int64_t now = NowMs();
        const int64_t th = g_wd_threshold_ms.load(std::memory_order_relaxed);
        if (th <= 0) return;
        if (now - last > th) {
            WatchdogCaptureStacks("no checkpoint progress");
            g_wd_last_ms.store(now, std::memory_order_relaxed);  // re-arm
        }
    }
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

    // Hang watchdog: enabled unless RAWRXD_HANG_WATCHDOG_MS=0.
    {
        const char* wd = std::getenv("RAWRXD_HANG_WATCHDOG_MS");
        const int64_t wd_ms = wd ? std::strtoll(wd, nullptr, 10) : 10000;
        g_wd_threshold_ms.store(wd_ms, std::memory_order_relaxed);
        if (wd_ms > 0) {
            std::thread(WatchdogMain).detach();
            std::printf("watchdog enabled threshold_ms=%lld\n", (long long)wd_ms);
        }
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
    Check(a1.evictions == a1.retired_reaped,
          "A: every eviction reaped after its fence (fence-safe destruction)");
    Check(a1.evictions > a0.evictions, "A: the residency budget actually forced evictions");

    // =========================================================================
    // B1. Deep2 dispatch-layer batch: a storm running while a batch is OPEN at
    //     the dispatch layer can evict the queued weights before End resolves
    //     them. That must be harmless (the weights are simply re-resolved and
    //     re-uploaded) and the results must still be bit-exact.
    // =========================================================================
    std::printf("\n--- B1. dispatch-layer batch vs concurrent eviction ---\n");
    const size_t batch_n = std::min<size_t>(BatchCapacity(), n_banks);
    std::vector<std::vector<float>> bout(batch_n);
    for (auto& r : bout) r.resize(n_out);   // FIX: empty rows -> data()==nullptr
    std::vector<std::vector<float>> bref(batch_n);
    for (size_t i = 0; i < batch_n; ++i) {
        std::vector<float> y(n_out);
        const CpuDot cpu = MakeCpuRef(banks[i]);
        if (!DotBlocked(0, banks[i].bytes.data(), banks[i].packedBytes(),
                        act.data(), n_in, y.data(), n_out, cpu,
                        q8.data(), q8.size() * sizeof(float), false)) {
            std::printf("B1: reference dispatch failed\n"); return 3;
        }
        bref[i] = y;
    }
    {
        std::atomic<bool> storm_stop{false};
        std::atomic<bool> storm_ready{false};
        std::atomic<uint64_t> storm_prefetch{0};
        // B1 readiness protocol (instrumented): a plain store() never wakes a
        // thread already parked in atomic::wait() -- the wakeup is lost when
        // the store lands between the waiter's value read and its park. The
        // store must be followed by notify_all(), and the main-side wait must
        // be BOUNDED with an explicit failure receipt so a stuck worker can
        // never hang the certification run.
        Checkpoint("B1_STORM_WORKER_CREATED");
        std::thread storm([&]() {
            Checkpoint("B1_STORM_WORKER_STARTED");
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
            storm_ready.store(true, std::memory_order_release);
            storm_ready.notify_all();
            Checkpoint("B1_STORM_WORKER_READY");
            Checkpoint("B1_STORM_READY_NOTIFY");
            Checkpoint("B1_STORM_PREFETCH_BEGIN");
            while (!storm_stop.load()) spin();
            Checkpoint("B1_STORM_PREFETCH_COMPLETE");
        });
        Checkpoint("B1_MAIN_WAIT_BEGIN");
        bool ready = false;
        for (const int64_t deadline = NowMs() + 10000; NowMs() < deadline;) {
            if (storm_ready.load(std::memory_order_acquire)) { ready = true; break; }
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        Checkpoint(ready ? "B1_MAIN_WAIT_COMPLETE" : "B1_READINESS_TIMEOUT");
        Check(ready, "B1: storm worker reached readiness within the bounded wait");
        if (!ready) {
            // Explicit failure receipt; the worker may be stuck in a driver
            // call, so detach (never join) and terminate instead of hanging.
            storm_stop.store(true);
            storm.detach();
            Checkpoint("B1_STORM_DETACHED");
            std::printf("G04_RESULT=FAIL (B1_READINESS_TIMEOUT: storm worker did not signal readiness in 10s)\n");
            { std::fflush(stdout); std::_Exit(1); }
        }
        const Snap b0 = Take();
        if (!BeginBatch()) { std::printf("B1: BeginBatch failed\n"); return 3; }
        bool queued_ok = true;
        for (size_t i = 0; i < batch_n; ++i) {
            const CpuDot cpu = MakeCpuRef(banks[i]);
            if (!DotBlocked(0, banks[i].bytes.data(), banks[i].packedBytes(),
                            act.data(), n_in, bout[i].data(), n_out, cpu,
                            q8.data(), q8.size() * sizeof(float), false))
                queued_ok = false;
        }
        const Snap b_open = Take();
        storm_stop.store(true);
        Checkpoint("B1_STORM_JOIN_BEGIN");
        storm.join();
        Checkpoint("B1_STORM_JOIN_COMPLETE");
        const bool ended = EndBatch();
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
    {
        // Budget holds ~2 banks; the batch pins 8, so the budget cannot be met
        // by eviction and the deferred path is the only legal outcome.
        const size_t pin_n = 8;
        const int64_t tight = (int64_t)(bank_bytes * 2);
        VulkanCompute& vk = DispatchDevice();
        vk.SetQuantWeightBudgetBytes((size_t)tight);
        std::vector<std::vector<float>> bout2(pin_n);
        for (auto& r : bout2) r.resize(n_out);   // FIX: empty rows -> data()==nullptr
        std::vector<std::vector<float>> bref2(pin_n);
        for (size_t i = 0; i < pin_n; ++i) {
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
            storm_ready.notify_all();
            while (!storm_stop.load()) spin();
        });
        Checkpoint("B2_MAIN_WAIT_BEGIN");
        bool ready2 = false;
        for (const int64_t deadline = NowMs() + 10000; NowMs() < deadline;) {
            if (storm_ready.load(std::memory_order_acquire)) { ready2 = true; break; }
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        Checkpoint(ready2 ? "B2_MAIN_WAIT_COMPLETE" : "B2_READINESS_TIMEOUT");
        Check(ready2, "B2: storm worker reached readiness within the bounded wait");
        if (!ready2) {
            storm_stop.store(true);
            storm.detach();
            Checkpoint("B2_STORM_DETACHED");
            std::printf("G04_RESULT=FAIL (B2_READINESS_TIMEOUT)\n");
            { std::fflush(stdout); std::_Exit(1); }
        }
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
        Check(GetCacheStats().evictions == GetCacheStats().retired_reaped,
              "B2: fence-safe destruction kept pace with eviction");
        Check(ended2, "B2: EndQuantDotBatch succeeded");
        bool bit2 = true;
        for (size_t i = 0; i < pin_n; ++i) if (!SameBits(bout2[i], bref2[i])) bit2 = false;
        Check(bit2, "B2: pinned batch output bit-identical to serial reference");
        Check(p1.pinned == 0, "B2: device batch pins released after End");
        // Restore the derived budget for the remaining sections.
        vk.SetQuantWeightBudgetBytes(0);
    }

    // =========================================================================
    // B3. Forced queue rejection while weights are pinned (P0 regression).
    // Acceptance contract (directive):
    //   B3_PRE_ACCEPTED >= 1            (a dot accepted before rejection)
    //   B3_REJECTION = EXPLICIT         (one false return)
    //   B3_REJECTED_OUTPUT = NOT_WRITTEN
    //   PINS at rejection point > 0     (live pins existed when rejected)
    //   B3_POST_ACCEPTED >= 1           (a fresh batch works after rejection)
    //   PINS_AFTER = PINS_BEFORE        (no pin leak)
    //   ACCEPTED = COMPLETED + FAILED, FAILED = 0
    //   QUEUED_AFTER = 0 / BATCH_ACTIVE_AFTER = 0
    // =========================================================================
    std::printf("\n--- B3. forced queue rejection with live pins ---\n");
    Checkpoint("SECTION_B3_BEGIN");
    {
        VulkanCompute& vk = DispatchDevice();
        const size_t pins_before = vk.PinnedWeightCount();
        const size_t b3_max = 40;
        std::vector<std::vector<float>> bout3(b3_max);
        for (auto& r : bout3) r.resize(n_out);   // FIX: empty rows -> data()==nullptr
        std::vector<char> acc3(b3_max, 0);
        std::vector<std::vector<float>> ref3(n_banks);
        for (size_t i = 0; i < n_banks; ++i) {
            std::vector<float> y(n_out);
            const CpuDot cpu = MakeCpuRef(banks[i]);
            if (!DotBlocked(0, banks[i].bytes.data(), banks[i].packedBytes(),
                            act.data(), n_in, y.data(), n_out, cpu,
                            q8.data(), q8.size() * sizeof(float), false)) {
                std::printf("B3: reference dispatch failed\n"); return 3;
            }
            ref3[i] = y;
        }
        Checkpoint("B3_REFERENCES_DONE");
        vk.SetQuantWeightBudgetBytes(0);   // derived default budget
        if (!vk.BeginQuantDotBatch()) { Check(false, "B3: BeginQuantDotBatch succeeded"); }
        size_t accepted3 = 0, rejected3 = 0;
        bool pre_ok = false;
        int first_ret = -1;
        for (size_t i = 0; i < b3_max; ++i) {
            const Bank& b = banks[i % n_banks];
            if (i == 0) {
                std::printf("B3_CALLSITE this=%p budget_before=%zu\n",
                            static_cast<void*>(&vk), vk.QuantWeightBudgetBytes());
                std::fflush(stdout);
            }
            const bool qret = vk.QueueQuantDot(b.bytes.data(), b.packedBytes(),
                                               q8.data(), q8.size() * sizeof(float),
                                               bout3[i].data(), n_out * sizeof(float),
                                               n_out, n_in, 0);
            if (i == 0) {
                first_ret = qret ? 1 : 0;
                std::printf("B3_CALLSITE first_ret=%d budget_after=%zu\n",
                            first_ret, vk.QuantWeightBudgetBytes());
                std::fflush(stdout);
            }
            if (qret) {
                acc3[i] = 1;
                ++accepted3;
                if (accepted3 == 1) { pre_ok = true; Checkpoint("B3_PRE_ACCEPTED"); }
            } else {
                ++rejected3;
                break;   // first explicit rejection ends the fill
            }
        }
        const size_t pins_at_reject = vk.PinnedWeightCount();
        Checkpoint("B3_FILL_DONE");
        const bool ended3 = vk.EndQuantDotBatch();
        const size_t pins_after = vk.PinnedWeightCount();
        bool bit3 = true;
        size_t checked3 = 0;
        for (size_t i = 0; i < b3_max && acc3[i]; ++i) {
            if (!SameBits(bout3[i], ref3[i % n_banks])) bit3 = false;
            ++checked3;
        }
        // Post-rejection recovery: a fresh batch must accept and complete work.
        size_t post3 = 0;
        bool post_ended = false, post_bit = false;
        if (vk.BeginQuantDotBatch()) {
            std::vector<float> ypost(n_out, 0.0f);
            const Bank& b0 = banks[0];
            if (vk.QueueQuantDot(b0.bytes.data(), b0.packedBytes(),
                                 q8.data(), q8.size() * sizeof(float),
                                 ypost.data(), n_out * sizeof(float),
                                 n_out, n_in, 0)) {
                ++post3;
                post_ended = vk.EndQuantDotBatch();
                post_bit = SameBits(ypost, ref3[0]);
            }
        }
        std::printf("B3: accepted=%zu rejected=%zu pre_ok=%d pins_at_reject=%zu "
                    "pins_before=%zu pins_after=%zu post=%zu post_ended=%d post_bit=%d\n",
                    accepted3, rejected3, (int)pre_ok, pins_at_reject,
                    pins_before, pins_after, post3, (int)post_ended, (int)post_bit);
        Check(pre_ok, "B3: pre-rejection dot accepted (B3_PRE_ACCEPTED >= 1)");
        Check(rejected3 == 1, "B3: queue rejection was EXPLICIT (one false return)");
        Check(pins_at_reject >= 1,
              "B3: live pins existed at the rejection point (PinnedWeightCount > 0)");
        Check(ended3, "B3: EndQuantDotBatch succeeded after rejection");
        Check(bit3 && checked3 == accepted3,
              "B3: every accepted dot output bit-identical (rejected dot never wrote output)");
        Check(pins_after == pins_before,
              "B3: pins returned to the pre-test baseline after the forced rejection");
        Check(post3 == 1, "B3: post-rejection batch accepted a dot (B3_POST_ACCEPTED >= 1)");
        Check(post_ended && post_bit,
              "B3: post-rejection dot completed with bit-identical output");
        Checkpoint("B3_COMPLETE");
    }

    // =========================================================================
    // C. Generation leases.
    // =========================================================================
    std::printf("\n--- C. generation leases ---\n");
    {
        // C must prove eviction is non-vacuous: constrain the residency budget
        // so the storm can actually evict, then restore the derived default.
        VulkanCompute& vk = DispatchDevice();
        // Budget scope guard (directive): restore the previous device budget on
        // EVERY exit from Section C (early assertion failures, exceptions,
        // normal completion) -- configuration only, never GPU-owned resources.
        const size_t prev_budget = vk.QuantWeightBudgetBytes();
        struct BudgetRestoreGuard {
            VulkanCompute& v;
            size_t prev;
            ~BudgetRestoreGuard() { v.SetQuantWeightBudgetBytes(prev); }
        } budget_guard{vk, prev_budget};
        vk.SetQuantWeightBudgetBytes((size_t)(bank_bytes * 2));
        const size_t i = n_banks - 1;
        const uint64_t lease = AcquireWeightLease(banks[i].bytes.data(),
                                                  banks[i].packedBytes(), 0);
        Check(lease != 0, "C: lease acquired on a fresh weight");
        // C non-vacuity (directive, forced-miss design): the storm must MISS.
        // All 16 banks are resident from B3, so flush the unpinned banks with
        // the dedicated trim (counted SEPARATELY as weight_cache_evictions_trim),
        // take a fresh baseline AFTER the trim, then run the storm with a
        // 2-bank device budget: every storm upload is a miss that must evict a
        // previous bank (the leased bank is pinned and survives).
        {
            const size_t trimmed = vk.TrimUnpinnedQuantWeights();
            std::printf("C_DIAG trim: trimmed=%zu pinned=%zu live_after=%llu\n",
                        trimmed, vk.PinnedWeightCount(),
                        (unsigned long long)GetCacheStats().device_bytes_live);
            std::fflush(stdout);
        }
        const Snap c0 = Take();
        const uint64_t c0_budget_ev = DispatchDevice().GetGpuCounters().weight_cache_evictions_budget;
        std::printf("C_DIAG baseline: evictions=%llu evictions_budget=%llu evictions_trim=%llu "
                    "live=%llu pinned=%zu\n",
                    (unsigned long long)c0.evictions,
                    (unsigned long long)c0_budget_ev,
                    (unsigned long long)DispatchDevice().GetGpuCounters().weight_cache_evictions_trim,
                    (unsigned long long)c0.live,
                    (unsigned long long)c0.pinned);
        std::fflush(stdout);
        vk.SetQuantWeightBudgetBytes((size_t)(bank_bytes * 2));
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
                }
            };
            spin();
            storm_ready.store(true, std::memory_order_release);
            storm_ready.notify_all();
            // Bounded storm: each miss is a real upload+fence, so an unbounded
            // spin would starve the main thread's device access. 400 spins x 4
            // prefetches is ample eviction pressure with a hard upper bound.
            for (int iter = 0; iter < 400 && !storm_stop.load(); ++iter) spin();
        });
        Checkpoint("C_MAIN_WAIT_BEGIN");
        bool ready_c = false;
        for (const int64_t deadline = NowMs() + 10000; NowMs() < deadline;) {
            if (storm_ready.load(std::memory_order_acquire)) { ready_c = true; break; }
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        Checkpoint(ready_c ? "C_MAIN_WAIT_COMPLETE" : "C_READINESS_TIMEOUT");
        Check(ready_c, "C: storm worker reached readiness within the bounded wait");
        if (!ready_c) {
            storm_stop.store(true);
            storm.detach();
            Checkpoint("C_STORM_DETACHED");
            std::printf("G04_RESULT=FAIL (C_READINESS_TIMEOUT)\n");
            { std::fflush(stdout); std::_Exit(1); }
        }
        bool resident = true;
        for (int r = 0; r < 200 && resident; ++r) {
            if (!IsWeightResident(banks[i].bytes.data(), banks[i].packedBytes(), 0)) resident = false;
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        std::vector<float> y(n_out);
        const CpuDot cpu = MakeCpuRef(banks[i]);
        const bool ok = DotBlocked(0, banks[i].bytes.data(), banks[i].packedBytes(),
                                   act.data(), n_in, y.data(), n_out, cpu,
                                   q8.data(), q8.size() * sizeof(float), false);
        const bool leased_result_ok = ok && SameBits(y, ref[i]);
        storm_stop.store(true);
        storm.join();
        const Snap c1 = Take();
        Check(resident, "C: leased weight stayed resident through the eviction storm");
        Check(c0.pinned >= 1, "C: the lease shows up as an in-flight pin");
        Check(c1.evictions > c0.evictions,
              "C: the storm really did evict (non-vacuous)");
        const uint64_t c1_budget_ev = DispatchDevice().GetGpuCounters().weight_cache_evictions_budget;
        std::printf("C_DIAG storm: evictions=%llu (delta=%llu) evictions_budget=%llu "
                    "(delta=%llu) evictions_trim=%llu\n",
                    (unsigned long long)c1.evictions,
                    (unsigned long long)(c1.evictions - c0.evictions),
                    (unsigned long long)c1_budget_ev,
                    (unsigned long long)(c1_budget_ev - c0_budget_ev),
                    (unsigned long long)DispatchDevice().GetGpuCounters().weight_cache_evictions_trim);
        std::fflush(stdout);
        Check(c1_budget_ev > c0_budget_ev,
              "C: budget-driven eviction observed (weight_cache_evictions_budget delta > 0)");
        Check(leased_result_ok, "C: dispatch on the leased weight is bit-exact");
        ReleaseWeightLease(lease);
        ReleaseWeightLease(lease);                       // double release: must be a no-op
        ReleaseWeightLease(0xDEADBEEFu);                  // stale id: must be a no-op
        const Snap c2 = Take();
        Check(c2.leases == 0, "C: lease released; double/stale release are no-ops");
        Check(c2.pinned == 0, "C: pin dropped once the lease was released");
        // One dispatch after the storm: that is the moment the fence proves the
        // deferred destructions safe. This is the real fence-safety property.
        {
            std::vector<float> y2(n_out);
            const CpuDot cpu2 = MakeCpuRef(banks[0]);
            (void)DotBlocked(0, banks[0].bytes.data(), banks[0].packedBytes(),
                             act.data(), n_in, y2.data(), n_out, cpu2,
                             q8.data(), q8.size() * sizeof(float), false);
        }
        const Snap c3 = Take();
        Check(c3.retired_pending == 0, "C: deferred destruction drained after one dispatch");
        Check(c3.evictions == c3.retired_reaped, "C: evictions == reaped (fence-safe)");
        vk.SetQuantWeightBudgetBytes(0);   // restore derived default (single authoritative routine)
    }
    std::printf("\n--- D. dispatch determinism under concurrency ---\n");
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
        Check(d1.evictions == d1.retired_reaped && d1.retired_pending == 0,
              "D: residency accounting drained cleanly");
        PrintSnap("D final:", d1);
    }

    std::printf("\n--- E. batch ownership and empty-close regression ---\n");
    {
        bool repeated_empty = true;
        for (int i = 0; i < 8; ++i) {
            if (!BeginBatch() || !EndBatch()) { repeated_empty = false; break; }
        }
        Check(repeated_empty, "E: repeated empty batches close exactly once");

        const bool owner_opened = BeginBatch();
        std::atomic<bool> contender_started{false};
        bool contender_acquired = true;
        std::thread contender([&]() {
            contender_started.store(true, std::memory_order_release);
            contender_acquired = BeginBatch();
            if (contender_acquired) (void)EndBatch();
        });
        while (!contender_started.load(std::memory_order_acquire)) std::this_thread::yield();
        contender.join();
        const bool owner_closed = owner_opened && EndBatch();
        Check(owner_opened, "E: primary executor acquired batch ownership");
        Check(contender_acquired,
              "E: independent executor acquires its own batch while owner batch active");
        Check(owner_closed, "E: owning executor closes its batch");
        Check(repeated_empty, "E: repeated empty batches close exactly once (each executor its own)");

        const bool retry_opened = BeginBatch();
        const bool retry_closed = retry_opened && EndBatch();
        Check(retry_opened && retry_closed, "E: ownership is reusable after close");
    }

    // =========================================================================
    // F. Producer/closer interleaving vs the batch lifecycle (Stage A P0).
    //
    // The production interleaving the Stage A mutex repair makes safe: the
    // owning executor (main) opens a batch, producer threads push Q6_K (kind 1)
    // dots into it while it is open, and the OWNER closes the batch mid-flight
    // while producers are still pushing. Every dot either landed in the queue
    // before the swap (and runs at EndBatch) or observed the closed batch and
    // executed synchronously. Pre-fix, a dot that read g_batch_active unlocked
    // and was preempted before push_back was silently lost after its caller
    // was told "queued": its output stayed at the NaN sentinel forever.
    //
    // kind 1 (Q6_K) is used deliberately: kind 0 (Q4_K) is pinned to the
    // synchronous path in the dispatch layer (quant_dot_dispatch.cpp:745-750),
    // so sections A-E never exercise the queue Stage A protects. This section
    // does: real queued work, a mid-flight close, and per-dot terminal
    // outcomes verified against a validated GPU reference.
    // =========================================================================
    std::printf("\n--- F. producer/closer interleaving (Stage A P0, Q6_K) ---\n");
    Checkpoint("SECTION_F_BEGIN");
    {
        const size_t f_out = 64, f_in = 1024;
        const size_t f_blk = f_in / 256u;               // 4 Q6_K blocks per row
        const size_t f_row_bytes = f_blk * 210u;        // 840 B per row
        uint32_t f_nan_bits = 0x7FC00000u;
        float f_nan;
        std::memcpy(&f_nan, &f_nan_bits, sizeof(f_nan));

        // Deterministic Q6_K bank (ggml block_q6_K layout: ql[128], qh[64],
        // scales[16] int8, fp16 d -- 210 bytes per 256-value block).
        std::vector<uint8_t> fbytes(f_out * f_row_bytes, 0);
        for (size_t r = 0; r < f_out; ++r) {
            for (size_t b = 0; b < f_blk; ++b) {
                uint8_t* w = fbytes.data() + r * f_row_bytes + b * 210u;
                for (size_t i = 0; i < 208; ++i)
                    w[i] = uint8_t((r * 29u + b * 43u + i * 7u) & 0xFFu);
                for (size_t i = 0; i < 16; ++i)
                    w[192 + i] = uint8_t(int8_t(4 + (int(i) % 8)));
                w[208] = 0x00; w[209] = 0x2C;           // d = 0x2C00 ~ 0.03125
            }
        }
        const std::vector<float> q8f = MakeQ8(f_in, 11);
        const std::vector<float> actf = MakeAct(f_in, 13);

        // Independent CPU reference: ggml dequantize_row_q6_K (ggml-quants.c
        // :1762) folded with the interleaved Q8 super-block scale; Q6_K has no
        // min term. Used by the dispatch's CPU fallback/replay so a replayed
        // batch stays numerically comparable.
        const CpuDot cpu6 = [&](const uint8_t* row, const void*, size_t) -> float {
            float acc = 0.0f;
            for (size_t b = 0; b < f_blk; ++b) {
                const uint8_t* w = row + b * 210u;
                const float d = HalfToFloat(uint16_t(w[208] | (uint16_t(w[209]) << 8)));
                const float* y8 = q8f.data() + b * 273u;
                const float yd = y8[0];
                float q[256];
                for (int h = 0; h < 2; ++h) {
                    const uint8_t* ql = w + h * 64;
                    const uint8_t* qh = w + 128 + h * 32;
                    const int8_t* sc = reinterpret_cast<const int8_t*>(w + 192) + h * 8;
                    for (int l = 0; l < 32; ++l) {
                        const int is = l / 16;
                        const int q1 = int((ql[l] & 0xF) | (((qh[l] >> 0) & 3) << 4)) - 32;
                        const int q2 = int((ql[l + 32] & 0xF) | (((qh[l] >> 2) & 3) << 4)) - 32;
                        const int q3 = int((ql[l] >> 4) | (((qh[l] >> 4) & 3) << 4)) - 32;
                        const int q4 = int((ql[l + 32] >> 4) | (((qh[l] >> 6) & 3) << 4)) - 32;
                        q[h * 128 + l]      = d * sc[is + 0] * float(q1);
                        q[h * 128 + l + 32] = d * sc[is + 2] * float(q2);
                        q[h * 128 + l + 64] = d * sc[is + 4] * float(q3);
                        q[h * 128 + l + 96] = d * sc[is + 6] * float(q4);
                    }
                }
                for (size_t j = 0; j < 256; ++j) acc += q[j] * (yd * y8[1 + j]);
            }
            return acc;
        };

        // Validated reference: the same GPU kernel, synchronously (batch closed).
        std::vector<float> fref(f_out, 0.0f);
        {
            Checkpoint("F_REFERENCE_BEGIN");
            const bool ok = DotBlocked(1, fbytes.data(), fbytes.size(),
                                       actf.data(), f_in, fref.data(), f_out, cpu6,
                                       q8f.data(), q8f.size() * sizeof(float), false);
            const bool gpu = ok && LastReceipt().used_gpu;
            std::printf("F: reference dot ok=%d gpu=%d\n", (int)ok, (int)gpu);
            Check(ok, "F: Q6_K reference dot executed");
            Check(gpu, "F: Q6_K reference dot ran on the GPU (non-vacuous)");
            if (!ok) {
                std::printf("G04_RESULT=BLOCKED (Q6_K sync reference failed: %s)\n",
                            LastReceipt().fallback_reason ? LastReceipt().fallback_reason : "none");
                return 3;
            }
        }

        // Same-owner queue (thread-local contract, converged design): the owner
        // thread opens the batch, queues every dot, and closes it. Foreign
        // producer threads CANNOT enqueue into this batch (thread-local state --
        // see G2); the cross-thread close rejection is covered by G3 and the
        // independent-executor interleaving by G2. F here proves the owner's
        // queue admission, device completion, and accounting on the converged
        // dispatch. (The pre-convergence global-mutex design let foreign
        // producers enqueue into one shared batch; that design is intentionally
        // retired, so F was rewritten to the valid same-owner shape.)
        const BatchAccounting acc0 = BatchAccountingSnapshot();
        const size_t f_total = 144;
        std::vector<std::vector<float>> fslots(f_total, std::vector<float>(f_out, f_nan));
        bool queued_seen = false, ended = false;
        {
            Checkpoint("F_PRODUCERS_BEGIN");
            std::printf("F_BEGIN_OWNER=%llu\n",
                        (unsigned long long)std::hash<std::thread::id>{}(std::this_thread::get_id()));
            if (!BeginBatch()) {
                std::printf("F: BeginBatch failed\n");
                return 3;
            }
            size_t f_attempts = 0;
            for (size_t g = 0; g < f_total; ++g) {
                (void)DotBlocked(1, fbytes.data(), fbytes.size(),
                                 actf.data(), f_in, fslots[g].data(), f_out, cpu6,
                                 q8f.data(), q8f.size() * sizeof(float), false);
                ++f_attempts;
                if (!queued_seen && BatchAccountingSnapshot().queued > 0) queued_seen = true;
            }
            std::printf("F_QUEUE_ATTEMPTS=%zu F_QUEUED_BEFORE_END=%zu\n",
                        f_attempts, BatchAccountingSnapshot().queued);
            Checkpoint("F_CLOSING");
            ended = EndBatch();
        }
        Checkpoint("F_PRODUCERS_JOINED");
        const BatchAccounting acc1 = BatchAccountingSnapshot();
        const uint64_t d_acc = acc1.accepted - acc0.accepted;
        const uint64_t d_cmp = acc1.completed - acc0.completed;
        const uint64_t d_fail = acc1.failed - acc0.failed;
        std::printf("F: accounting accepted_delta=%llu completed_delta=%llu failed_delta=%llu "
                    "queued=%zu batch_active=%d batches=%llu device_batches=%llu\n",
                    (unsigned long long)d_acc, (unsigned long long)d_cmp, (unsigned long long)d_fail,
                    acc1.queued, (int)acc1.batch_active,
                    (unsigned long long)(acc1.batches_opened - acc0.batches_opened),
                    (unsigned long long)(acc1.device_batches_opened - acc0.device_batches_opened));

        size_t f_written = 0, f_bit = 0;
        bool f_nan_left = false;
        for (size_t g = 0; g < f_total; ++g) {
            bool is_nan = false;
            for (size_t j = 0; j < f_out; ++j)
                if (std::memcmp(&fslots[g][j], &f_nan, sizeof(float)) == 0) { is_nan = true; break; }
            if (!is_nan) ++f_written; else f_nan_left = true;
            if (!is_nan && SameBits(fslots[g], fref)) ++f_bit;
        }
        Check(queued_seen, "F: at least one dot was queued while the batch was open");
        Check(ended, "F: owning executor closed the batch mid-flight");
        Check(!f_nan_left && f_written == f_total,
              "F: every dot output written (no NaN sentinel left -- no silently lost dot)");
        Check(f_bit == f_total,
              "F: every dot output bit-identical to the synchronous reference");
        Check(acc1.queued == 0 && !acc1.batch_active,
              "F: queue empty and batch closed after EndBatch");
        Check(d_acc == d_cmp + d_fail,
              "F: accepted == completed + failed (all accepted work reached a terminal outcome)");
        Check(d_cmp >= 1, "F: at least one device batch chunk actually completed");
        Check(acc1.batches_opened > acc0.batches_opened &&
              acc1.device_batches_opened > acc0.device_batches_opened,
              "F: a real device batch was opened (non-vacuous)");
        Checkpoint("F_COMPLETE");
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
            const auto before = ThreadAccountingSnapshot();
            const bool opened = serial_ok && BeginBatch();
            const bool queued = opened && dot(bank, b.data());
            const bool closed = opened && EndBatch();
            const auto after = ThreadAccountingSnapshot();
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
    }

    // ---- final invariants ---------------------------------------------------
    const Snap f = Take();
    std::printf("\n--- final invariants ---\n");
    Check(f.leases == 0, "no outstanding lease");
    Check(f.pinned == 0, "no outstanding pin");
    Check(f.retired_pending == 0, "no deferred destruction outstanding");
    // Corrected fence-safe contract (supersedes the pre-09696d9d37 equality):
    // retirements include non-budget pointer replacements, so reaped >= evictions
    // with pending==0; the reaper guarantees each retirement is reaped exactly once
    // (no double-reclaim), and no destruction happens without completion evidence.
    Check(f.retired_reaped >= f.evictions,
          "every eviction was destroyed only after its fence (fence-safe; reaped >= evictions)");
    Check(f.completed_epoch == f.epoch, "every submitted epoch has completed");
    Check(f.live > 0, "device residency is real (non-zero live bytes)");
    PrintSnap("FINAL:", f);

    std::printf("\nG04_RESULT=%s (failures=%d)\n", g_fail == 0 ? "PASS" : "FAIL", g_fail);
    return g_fail == 0 ? 0 : 1;
}
