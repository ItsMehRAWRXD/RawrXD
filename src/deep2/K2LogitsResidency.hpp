// K2LogitsResidency.hpp — Q6_K packed residency witnesses (not F32 warehouse)
#pragma once
#include <atomic>
#include <cstdint>
#include <cstdio>

namespace Deep2 {

inline std::atomic<uint64_t>& LogitsPackedDotRows() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& LogitsPackedResidentHits() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& LogitsArgmaxCalls() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& LogitsFullMaterializeCalls() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& LogitsFullVocabDequantBytes() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& LogitsF32WarehouseBytes() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& LogitsShardRowReads() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& LogitsShardBytes() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& LogitsVocabUpload() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& LogitsHotAlloc() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& LogitsParityChecks() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& LogitsParityFail() {
    static std::atomic<uint64_t> v{0}; return v;
}

inline void LogitsResidency_Reset() {
    LogitsPackedDotRows().store(0);
    LogitsPackedResidentHits().store(0);
    LogitsArgmaxCalls().store(0);
    LogitsFullMaterializeCalls().store(0);
    LogitsFullVocabDequantBytes().store(0);
    LogitsF32WarehouseBytes().store(0);
    LogitsShardRowReads().store(0);
    LogitsShardBytes().store(0);
    LogitsVocabUpload().store(0);
    LogitsHotAlloc().store(0);
    LogitsParityChecks().store(0);
    LogitsParityFail().store(0);
}

inline void LogitsResidency_Emit(FILE* f) {
    if (!f) f = stdout;
    fprintf(f,
            "Q6K_VOCAB_UPLOAD_TIMED=%llu Q6K_RESIDENT_HIT=%llu\n"
            "Q6K_FULL_DEQUANT_BYTES=%llu LOGITS_FULL_F32_MATERIALIZE=%llu\n"
            "HOT_ALLOC=%llu SHARD_LOGITS_BYTES=%llu SHARD_LOGITS_ROWS=%llu\n"
            "ARGMAX_PARITY_CHECKS=%llu ARGMAX_PARITY_FAIL=%llu "
            "ARGMAX_PARITY=%d\n"
            "LOGITS_PACKED_DOT_ROWS=%llu LOGITS_ARGMAX_CALLS=%llu\n",
            (unsigned long long)LogitsVocabUpload().load(),
            (unsigned long long)LogitsPackedResidentHits().load(),
            (unsigned long long)LogitsFullVocabDequantBytes().load(),
            (unsigned long long)LogitsFullMaterializeCalls().load(),
            (unsigned long long)LogitsHotAlloc().load(),
            (unsigned long long)LogitsShardBytes().load(),
            (unsigned long long)LogitsShardRowReads().load(),
            (unsigned long long)LogitsParityChecks().load(),
            (unsigned long long)LogitsParityFail().load(),
            LogitsParityFail().load() == 0 && LogitsParityChecks().load() > 0
                ? 1
                : 0,
            (unsigned long long)LogitsPackedDotRows().load(),
            (unsigned long long)LogitsArgmaxCalls().load());
    fflush(f);
}

} // namespace Deep2
