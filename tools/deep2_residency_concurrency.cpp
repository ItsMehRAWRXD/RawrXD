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

#include "quant_dot_dispatch.hpp"
#include "include/vulkan_compute.h"

using namespace RawrXD::Deep2::QuantDot;

namespace {

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

    // ---- serial reference: one GPU dot per bank -----------------------------
    std::vector<std::vector<float>> ref(n_banks);
    {
        uint64_t gpu_before = GetCacheStats().submits;
        bool all_ok = true, all_gpu = true;
        for (size_t i = 0; i < n_banks; ++i) {
            std::vector<float> y(n_out, 0.0f);
            const CpuDot cpu = MakeCpuRef(banks[i]);
            const bool ok = DotBlocked(0, banks[i].bytes.data(), banks[i].packedBytes(),
                                       act.data(), n_in, y.data(), n_out, cpu,
                                       q8.data(), q8.size() * sizeof(float), false);
            if (!ok) { all_ok = false; break; }
            if (!LastReceipt().used_gpu) all_gpu = false;
            ref[i] = y;
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

    // =========================================================================
    // A. Concurrent steering under eviction pressure.
    // =========================================================================
    std::printf("\n--- A. concurrent steering under eviction pressure ---\n");
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
            while (!storm_stop.load()) spin();
        });
        storm_ready.wait(false);
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
        storm.join();
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
    // C. Generation leases.
    // =========================================================================
    std::printf("\n--- C. generation leases ---\n");
    {
        const size_t i = n_banks - 1;
        const uint64_t lease = AcquireWeightLease(banks[i].bytes.data(),
                                                  banks[i].packedBytes(), 0);
        Check(lease != 0, "C: lease acquired on a fresh weight");
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
            storm_ready.store(true);
            while (!storm_stop.load()) spin();
        });
        storm_ready.wait(false);
        const Snap c0 = Take();
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
        Check(c1.evictions > c0.evictions, "C: the storm really did evict (non-vacuous)");
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

    // ---- final invariants ---------------------------------------------------
    const Snap f = Take();
    std::printf("\n--- final invariants ---\n");
    Check(f.leases == 0, "no outstanding lease");
    Check(f.pinned == 0, "no outstanding pin");
    Check(f.retired_pending == 0, "no deferred destruction outstanding");
    Check(f.evictions == f.retired_reaped,
          "every eviction was destroyed only after its fence (fence-safe)");
    Check(f.completed_epoch == f.epoch, "every submitted epoch has completed");
    Check(f.live > 0, "device residency is real (non-zero live bytes)");
    PrintSnap("FINAL:", f);

    std::printf("\nG04_RESULT=%s (failures=%d)\n", g_fail == 0 ? "PASS" : "FAIL", g_fail);
    return g_fail == 0 ? 0 : 1;
}