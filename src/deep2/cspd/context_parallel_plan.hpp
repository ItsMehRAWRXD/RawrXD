// ============================================================================
// CSPD Stage 1a -- context-parallel planning.
//
// Context-Scaled Parallel Decode (CSPD) splits the KV context into logical
// chunks so attention over a long context can be evaluated as P partial
// results that are combined with a numerically stable reduction (see
// split_kv_attention.hpp).
//
// SAFEGUARD (per engineering review): the number of 4K chunks is NOT used as
// an unconditional GPU split count. A 64K context yields 16 logical chunks,
// but 16 parallel splits can be slower than 4 or 8 once the GPU is saturated
// or reduction overhead dominates. select_splits_adaptive() benchmarks the
// candidate split counts with a caller-supplied timing function and returns
// the fastest verified configuration (ties -> fewer splits).
//
// Standalone: header-only, no dependencies beyond the C++17 standard library.
// ============================================================================
#pragma once

#include <algorithm>
#include <cstddef>
#include <limits>
#include <utility>
#include <vector>

namespace rawrxd {
namespace cspd {

struct ContextParallelPlan {
    std::size_t contextTokens  = 0;
    std::size_t kvChunkTokens  = 4096;  // logical chunk size (tokens)
    std::size_t logicalChunks  = 1;     // ceil(context / chunk), min 1
    std::size_t parallelSplits = 1;     // min(logicalChunks, maxSplits), min 1
    std::size_t tailTokens     = 0;     // tokens in the final (partial) chunk

    bool singleSplitFallback() const { return parallelSplits <= 1; }
};

// Plan the context split. kvChunkTokens <= 0 is clamped to 1;
// maxParallelSplits <= 0 is clamped to 1.
inline ContextParallelPlan plan_context_parallel(std::size_t contextTokens,
                                                 std::size_t maxParallelSplits,
                                                 std::size_t kvChunkTokens = 4096) {
    ContextParallelPlan p;
    p.contextTokens = contextTokens;
    p.kvChunkTokens = kvChunkTokens == 0 ? 1u : kvChunkTokens;
    p.logicalChunks = (contextTokens + p.kvChunkTokens - 1) / p.kvChunkTokens;
    if (p.logicalChunks == 0) p.logicalChunks = 1;  // empty context -> 1 empty chunk
    const std::size_t capped = maxParallelSplits == 0 ? 1u : maxParallelSplits;
    p.parallelSplits = std::min(p.logicalChunks, capped);
    const std::size_t fullChunks = contextTokens / p.kvChunkTokens;
    p.tailTokens = (fullChunks < p.logicalChunks)
                       ? contextTokens - fullChunks * p.kvChunkTokens
                       : 0;  // exact multiple: tail reported as 0
    return p;
}

// Split [0, contextTokens) into `splits` contiguous ranges. The first
// (splits - remainder) ranges have size base; the final `remainder` ranges
// have size base + 1. `splits` is clamped to [1, contextTokens] (a context
// smaller than the split count yields contextTokens singleton-ish ranges).
inline std::vector<std::pair<std::size_t, std::size_t>>
split_ranges(std::size_t contextTokens, std::size_t splits) {
    std::vector<std::pair<std::size_t, std::size_t>> ranges;
    if (contextTokens == 0) return ranges;
    const std::size_t s = std::max<std::size_t>(1u, std::min(splits, contextTokens));
    const std::size_t base = contextTokens / s;
    const std::size_t rem  = contextTokens % s;
    std::size_t begin = 0;
    for (std::size_t i = 0; i < s; ++i) {
        const std::size_t len = base + ((i >= s - rem) ? 1u : 0u);
        ranges.emplace_back(begin, begin + len);
        begin += len;
    }
    return ranges;
}

// Adaptive split selection.
//
// bench(splits) must return the measured time (milliseconds, > 0) for one
// decode step at `contextTokens` with `splits` parallel KV chunks. The
// selector evaluates every candidate from 1..parallelSplits and returns the
// fastest; ties keep the smaller split count (less reduction overhead).
template <class Bench>
std::size_t select_splits_adaptive(std::size_t contextTokens,
                                   std::size_t maxParallelSplits,
                                   Bench&& bench,
                                   std::size_t kvChunkTokens = 4096) {
    const ContextParallelPlan plan =
        plan_context_parallel(contextTokens, maxParallelSplits, kvChunkTokens);
    std::size_t bestSplits = 1;
    double bestMs = std::numeric_limits<double>::infinity();
    for (std::size_t s = 1; s <= plan.parallelSplits; ++s) {
        const double ms = static_cast<double>(bench(s));
        if (ms < bestMs) {  // strict: ties keep fewer splits
            bestMs = ms;
            bestSplits = s;
        }
    }
    return bestSplits;
}

}  // namespace cspd
}  // namespace rawrxd