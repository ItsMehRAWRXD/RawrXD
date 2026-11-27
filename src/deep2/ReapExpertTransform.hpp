#pragma once
// RAWRXD REAP V03: reusable in-memory expert transformation.
//
// Composes V01 (Selection) + V02 (ExpertSliceLayout) into a storage-independent
// transform: source stacked-expert tensor buffer + retained experts -> transformed
// buffer (retained experts concatenated in ORIGINAL order). No file I/O. This is
// the shared algorithm Physical (writer), Virtual (ingestion) and Streaming (demand
// slices) consume without duplication.
#include "deep2/ReapExpertSlice.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace RawrXD {
namespace Reap {

// Transform one stacked expert tensor in memory.
//  - dims.back() == original physical expert count; tensorBytes == src size.
//  - retained: kept expert indices (original order); the selection contract.
//  - dst: transformed bytes (retained.size()*stride). Fail-closed on any layout
//    error (propagated from ComputeExpertSliceLayout) or null src.
inline bool TransformExpertTensor(const std::vector<uint64_t>& dims,
                                  uint64_t tensorBytes,
                                  const uint8_t* src,
                                  const std::vector<uint32_t>& retained,
                                  std::vector<uint8_t>& dst,
                                  std::string& error) {
    dst.clear();
    ExpertSliceLayout layout;
    if (!ComputeExpertSliceLayout(dims, tensorBytes, retained, layout, error)) return false;
    if (!src && tensorBytes) { error = "NULL_SOURCE"; return false; }
    dst.resize(layout.totalBytes);
    uint64_t w = 0;
    for (const ExpertSlice& s : layout.slices) {
        for (uint64_t i = 0; i < s.length; ++i) dst[w++] = src[s.offset + i];
    }
    return true;
}

}  // namespace Reap
}  // namespace RawrXD