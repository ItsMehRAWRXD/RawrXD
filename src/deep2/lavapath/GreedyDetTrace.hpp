#pragma once
/* GreedyDetTrace — FNV TRACE_HASH / EXPERT_SEQUENCE_HASH for temp=0. ≤55. */
#include "DualStickImbalance_Det.hpp"
#include <cstdint>
#include <cstdio>

namespace Deep2 {
namespace greedy_det {

inline uint64_t& TraceHash() {
    static uint64_t h = 14695981039346656037ull;
    return h;
}
inline uint64_t& ExpertSeqHash() {
    static uint64_t h = 14695981039346656037ull;
    return h;
}
inline uint32_t& ArgmaxSteps() {
    static uint32_t n = 0;
    return n;
}
inline void Reset() {
    TraceHash() = 14695981039346656037ull;
    ExpertSeqHash() = 14695981039346656037ull;
    ArgmaxSteps() = 0;
}
inline void NoteArgmax(int32_t tok) {
    uint64_t& h = TraceHash();
    h ^= (uint64_t)(uint32_t)tok;
    h *= 1099511628211ull;
    ArgmaxSteps()++;
}
inline void NoteExpert(uint32_t layer, int32_t expertId) {
    uint64_t& h = ExpertSeqHash();
    h ^= ((uint64_t)layer << 32) ^ (uint64_t)(uint32_t)expertId;
    h *= 1099511628211ull;
}
inline void Dump(FILE* f) {
    if (!f) f = stderr;
    std::fprintf(f,
                 "GREEDY_DET TRACE_HASH=%016llx EXPERT_SEQUENCE_HASH=%016llx "
                 "ARGMAX_STEPS=%u STICK_HASH_MODE=%d\n",
                 (unsigned long long)TraceHash(),
                 (unsigned long long)ExpertSeqHash(), ArgmaxSteps(),
                 ds_imb::StickHashMode());
}

} // namespace greedy_det
} // namespace Deep2
