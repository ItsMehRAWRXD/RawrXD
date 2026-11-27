#pragma once
// RAWRXD REAP V02: storage-independent quantization-aware expert slicing.
//
// Extracted from ReapMoETransformer.cpp's per-expert slice loop so Physical,
// Virtual and Streaming consume the SAME authoritative slicing algorithm without
// duplication. No file I/O: given a stacked expert tensor's geometry and the
// retained expert indices (original order), it yields the per-expert byte ranges
// and the transformed tensor size. The expert axis is dims.back() (== original
// physical expert count); stride = tensorBytes / originalExperts.
#include <cstdint>
#include <string>
#include <vector>

namespace RawrXD {
namespace Reap {

struct ExpertSlice {
    uint64_t offset = 0;  // byte offset within the source expert tensor
    uint64_t length = 0;  // bytes for one expert (== stride)
};

struct ExpertSliceLayout {
    uint64_t stride = 0;       // bytes per expert
    uint64_t totalBytes = 0;   // transformed tensor bytes (retained * stride)
    std::vector<ExpertSlice> slices;  // one per retained expert, in retained order
};

// Compute the per-expert slice layout for a stacked expert tensor.
//  - dims.back() is the physical expert count (originalExperts).
//  - retained are the kept expert indices in ORIGINAL order (selection contract).
//  - Returns false (fail-closed) on empty dims, zero expert axis, non-divisible
//    byte count, or an out-of-range retained index.
inline bool ComputeExpertSliceLayout(const std::vector<uint64_t>& dims,
                                     uint64_t tensorBytes,
                                     const std::vector<uint32_t>& retained,
                                     ExpertSliceLayout& out, std::string& error) {
    out = {};
    error.clear();
    if (dims.empty()) { error = "EMPTY_DIMS"; return false; }
    const uint64_t originalExperts = dims.back();
    if (originalExperts == 0) { error = "ZERO_EXPERT_AXIS"; return false; }
    if (tensorBytes % originalExperts != 0) { error = "BYTES_NOT_DIVISIBLE_BY_EXPERTS"; return false; }
    const uint64_t stride = tensorBytes / originalExperts;
    out.stride = stride;
    out.slices.reserve(retained.size());
    uint64_t total = 0;
    for (const uint32_t e : retained) {
        if (e >= originalExperts) { error = "RETAINED_EXPERT_OUT_OF_RANGE"; return false; }
        const uint64_t off = static_cast<uint64_t>(e) * stride;
        if (off > tensorBytes || stride > tensorBytes - off) { error = "SLICE_OFFSET_OVERFLOW"; return false; }
        out.slices.push_back(ExpertSlice{off, stride});
        total += stride;
    }
    out.totalBytes = total;
    return true;
}

}  // namespace Reap
}  // namespace RawrXD