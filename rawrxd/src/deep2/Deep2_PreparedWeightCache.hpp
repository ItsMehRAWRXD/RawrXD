// RAWRXD_B70_PREPARED_CACHE_UNIT_001
//
// Shared header for the B63 prepared-weight cache.
//
// Extracted from Deep2Engine_GpuForward.cpp so that the engine and the
// RAWRXD_B70_PREPARED_CACHE_UNIT_001 unit test compile the SAME implementation.
// A test that re-declared the class would be testing its own copy, which is the
// failure mode that let B63 ship with its eviction path unverified.
//
// The cache takes a dequantizer callback rather than calling
// QuantKernelRegistry directly, so the unit test does not need to link the
// engine, initialize a registry, or provide a GGUF type. The engine passes the
// registry's GetDequant(wt.type) at Acquire time.

#pragma once

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

namespace Deep2 {

// Host-side budget for prepared F32. Deliberately independent of VRAM: this is
// system RAM, and preparing a weight here must not consume Vulkan heap capacity.
// Read once, on first use.
inline uint64_t PreparedHostBudgetBytes() {
    static const uint64_t budget = []() -> uint64_t {
        const char* s = std::getenv("RAWRXD_PREPARED_BUDGET_BYTES");
        if (s && *s) {
            char* endp = nullptr;
            const long long v = std::strtoll(s, &endp, 10);
            if (endp && *endp == '\0' && v > 0) return static_cast<uint64_t>(v);
        }
        // Default 12 GiB. Enough to hold a 3B model expanded to F32 without
        // making host F32 growth an unbounded implicit invariant.
        return 12ull * 1024ull * 1024ull * 1024ull;
    }();
    return budget;
}

// The subset of Deep2::WeightTensor the cache actually reads. Declaring it here
// keeps the cache independent of the full tensor type and of the engine.
struct PreparedWeightSource {
    std::string name;
    int         type = 0;        // GGML tensor type id
    uint32_t    rows = 0;
    uint32_t    cols = 0;
    const uint8_t* data = nullptr;
    uint64_t    sizeBytes = 0;

    // Non-owning: the source must outlive any prepared entry keyed on it.
    // Deep2Engine guarantees this by releasing the cache before the model
    // mapping is torn down (~Deep2Engine).
};

// Signature matches QuantKernelRegistry::DequantFn.
using PreparedDequantFn = void (*)(const uint8_t* src, float* dst, size_t n);

// RAWRXD_B63_GATE_COUNTERS: the gate is CPU_DEQUANT_CALLS(weight) <= 1 across
// multiple generated tokens, NOT a TPS target. These counters exist so that
// claim is checkable rather than inferred from wall time.
struct PreparedCacheStats {
    uint64_t acquireCalls = 0;
    uint64_t prepareMiss = 0;   // dequant actually performed
    uint64_t prepareHit = 0;    // served from prepared cache
    uint64_t evict = 0;
    uint64_t cpuDequantCalls = 0;
    uint64_t cpuDequantBytes = 0;
    uint64_t preparedBytesLive = 0;
    uint64_t preparedPeakBytes = 0;
    uint64_t oversizedEntries = 0;
};

struct PreparedWeightKey {
    const void* source = nullptr;
    uint64_t sourceBytes = 0;
    uint32_t ggmlType = 0;
    uint64_t elements = 0;

    // unordered_map::find/erase require key equality. Identity is the full key,
    // not just the source pointer: the same tensor may be re-prepared with a
    // different element count or after a remap, and a pointer-only match would
    // serve a stale entry.
    bool operator==(const PreparedWeightKey& o) const noexcept {
        return source == o.source &&
               sourceBytes == o.sourceBytes &&
               ggmlType == o.ggmlType &&
               elements == o.elements;
    }
};

struct PreparedWeightKeyHash {
    size_t operator()(const PreparedWeightKey& k) const noexcept {
        // Mix pointer bits with geometry so two different tensors that happen to
        // reuse a freed address do not collide into one entry.
        uint64_t h = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(k.source));
        h ^= h >> 33; h *= 0xff51afd7ed558ccdull;
        h ^= k.sourceBytes + 0x9e3779b97f4a7c15ull + (h << 6) + (h >> 2);
        h ^= k.ggmlType + 0x9e3779b97f4a7c15ull + (h << 6) + (h >> 2);
        h ^= k.elements + 0x9e3779b97f4a7c15ull + (h << 6) + (h >> 2);
        return static_cast<size_t>(h);
    }
};

struct PreparedWeight {
    std::vector<float> f32;
    uint64_t bytes = 0;
    uint64_t lastUseTick = 0;
};

// Bounded LRU prepared-weight cache. One instance per engine, referenced
// through the engine rather than a file-static, so it dies with the engine and
// cannot outlive the model whose source pointers it keys on.
class PreparedWeightCache {
public:
    // deq may be null, in which case Acquire returns nullptr (the engine passes
    // the registry's dequantizer for wt.type, which may be unregistered).
    const float* Acquire(const PreparedWeightSource& wt, PreparedDequantFn deq) {
        if (!wt.data) return nullptr;
        const size_t elems = static_cast<size_t>(wt.rows) * static_cast<size_t>(wt.cols);
        if (elems == 0) return nullptr;
        const uint64_t bytes = static_cast<uint64_t>(elems) * sizeof(float);

        ++s_.acquireCalls;
        ++tick_;

        // Hit path: a prepared representation already exists for this tensor.
        const PreparedWeightKey key{
            wt.data,
            wt.sizeBytes,
            static_cast<uint32_t>(wt.type),
            static_cast<uint64_t>(elems)};
        auto it = index_.find(key);
        if (it != index_.end()) {
            PreparedWeight& pw = it->second;
            pw.lastUseTick = tick_;
            ++s_.prepareHit;
            return pw.f32.data();
        }

        // Miss: dequantize exactly once into a persistent buffer.
        if (!deq) return nullptr;

        PreparedWeight pw;
        pw.f32.resize(elems);
        pw.bytes = bytes;
        deq(reinterpret_cast<const uint8_t*>(wt.data), pw.f32.data(), pw.f32.size());
        pw.lastUseTick = tick_;
        ++s_.prepareMiss;
        ++s_.cpuDequantCalls;
        s_.cpuDequantBytes += bytes;

        // RAWRXD_B64_TENSOR_CENSUS: record what was actually prepared. B63
        // established HOW MANY times a weight is dequantized; it did not
        // establish WHICH tensors those were. The B64 invariant is narrower
        // than "no prepared weights": it is "no Q2_K matrix weight participating
        // in product decode requires persistent F32 preparation".
        std::fprintf(stderr,
            "PREPARED_PREPARE name=%s type=%d rows=%u cols=%u elements=%llu bytes=%llu\n",
            wt.name.c_str(), wt.type,
            (unsigned)wt.rows, (unsigned)wt.cols,
            (unsigned long long)elems,
            (unsigned long long)bytes);
        std::fflush(stderr);

        const float* result = pw.f32.data();
        Commit(key, std::move(pw));
        return result;
    }

    const PreparedCacheStats& stats() const { return s_; }

    // RAWRXD_B63_RECEIPT: emit the counters the gate is written against.
    void WriteReceipt() const {
        std::fprintf(stderr,
            "PREPARED_CACHE acquire=%llu miss=%llu hit=%llu evict=%llu "
            "cpuDequantCalls=%llu cpuDequantBytes=%llu liveBytes=%llu peakBytes=%llu "
            "budgetBytes=%llu oversized=%llu\n",
            (unsigned long long)s_.acquireCalls,
            (unsigned long long)s_.prepareMiss,
            (unsigned long long)s_.prepareHit,
            (unsigned long long)s_.evict,
            (unsigned long long)s_.cpuDequantCalls,
            (unsigned long long)s_.cpuDequantBytes,
            (unsigned long long)s_.preparedBytesLive,
            (unsigned long long)s_.preparedPeakBytes,
            (unsigned long long)PreparedHostBudgetBytes(),
            (unsigned long long)s_.oversizedEntries);
        std::fflush(stderr);
    }

private:
    void Commit(const PreparedWeightKey& key, PreparedWeight&& pw) {
        const uint64_t bytes = pw.bytes;
        // A single weight larger than the whole budget cannot be cached without
        // exceeding it. Prepare it anyway and let it live unindexed: correctness
        // first, and the accounting below reports the overage rather than
        // silently thrashing.
        if (bytes > PreparedHostBudgetBytes()) {
            ++s_.oversizedEntries;
            oversized_.push_back(std::move(pw));
            std::fprintf(stderr, "PREPARED_OVERSIZE bytes=%llu budgetBytes=%llu\n",
                (unsigned long long)bytes, (unsigned long long)PreparedHostBudgetBytes());
            std::fflush(stderr);
            return;
        }
        EnforceBudget(bytes);
        s_.preparedBytesLive += bytes;
        if (s_.preparedBytesLive > s_.preparedPeakBytes)
            s_.preparedPeakBytes = s_.preparedBytesLive;
        auto ins = index_.emplace(key, std::move(pw));
        if (!ins.second) {
            // Key collided with an existing entry; do not double-count bytes.
            s_.preparedBytesLive -= bytes;
        }
    }

    void EnforceBudget(uint64_t incoming) {
        const uint64_t budget = PreparedHostBudgetBytes();
        while (s_.preparedBytesLive + incoming > budget) {
            // Evict least-recently-USED (not least-recently-prepared): the
            // caller's most recent Acquire refreshes lastUseTick, so a weight
            // still in active use is never the victim.
            auto victim = index_.end();
            for (auto i = index_.begin(); i != index_.end(); ++i) {
                if (victim == index_.end() || i->second.lastUseTick < victim->second.lastUseTick)
                    victim = i;
            }
            if (victim == index_.end()) break;
            s_.preparedBytesLive -= victim->second.bytes;
            index_.erase(victim);
            ++s_.evict;
        }
    }

    std::unordered_map<PreparedWeightKey, PreparedWeight, PreparedWeightKeyHash> index_;
    std::vector<PreparedWeight> oversized_;
    PreparedCacheStats s_;
    uint64_t tick_ = 0;
};

} // namespace Deep2