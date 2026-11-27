#pragma once
// RAWRXD REAP (Streaming track): demand-driven expert provider.
//
// Yields retained experts ONE AT A TIME by reading only that expert's byte range
// from a caller-supplied random-access source, into a bounded window. It never
// materializes the full transformed expert bank (memory = one expert + window),
// which is the functional distinction of Streaming vs Physical/Virtual. Uses the
// shared ReapExpertSlice (V02) for offsets/lengths.
#include "deep2/ReapExpertSlice.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace RawrXD {
namespace Reap {

// ReadFn: bool(uint64_t offset, uint64_t length, uint8_t* dst) — random-access read
//         of `length` bytes at `offset` into `dst` (must succeed fully).
// SinkFn: void(uint32_t expertIndex, const uint8_t* data, uint64_t length).
// maxWindowBytes: hard cap on the per-expert window (fail-closed if exceeded).
// Returns false on layout error, window overflow, or a failed source read.
template <typename ReadFn, typename SinkFn>
bool ForEachRetainedExpert(const std::vector<uint64_t>& dims,
                           uint64_t tensorBytes,
                           const std::vector<uint32_t>& retained,
                           uint64_t maxWindowBytes,
                           ReadFn&& read,
                           SinkFn&& sink,
                           std::string& error) {
    ExpertSliceLayout layout;
    if (!ComputeExpertSliceLayout(dims, tensorBytes, retained, layout, error)) return false;
    if (layout.stride > maxWindowBytes) { error = "EXPERT_WINDOW_EXCEEDS_BUDGET"; return false; }
    std::vector<uint8_t> window(static_cast<size_t>(layout.stride));
    for (size_t i = 0; i < retained.size(); ++i) {
        const ExpertSlice& s = layout.slices[i];
        if (!read(s.offset, s.length, window.data())) {
            error = "EXPERT_SOURCE_READ_FAILED";
            return false;
        }
        sink(retained[i], window.data(), s.length);
    }
    return true;
}

}  // namespace Reap
}  // namespace RawrXD