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
#include <map>
#include <string>
#include <utility>
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

// SC01: superset compatibility layer (formerly src/reap/ReapTensorSlice.hpp).
// One authoritative slicing algorithm; the layer+selection lookup and name/layer
// error context are preserved here so existing consumers/tests are unchanged.
struct SliceTensorDesc {
    std::string name;
    std::vector<uint64_t> dims;   // logical dims; expert dim = last
    uint64_t bytes = 0;           // total tensor bytes
};

using ExpertSelection = std::map<uint32_t, std::vector<uint32_t>>;  // layer -> retained

struct SliceResult {
    bool ok = false;
    std::string error;
    uint64_t stride = 0;
    std::vector<std::pair<uint64_t, uint64_t>> ranges;  // (offset, bytes) per selected
};

inline SliceResult SliceExperts(const SliceTensorDesc& t, uint32_t layer,
                                const ExpertSelection& sel) {
    SliceResult r;
    auto it = sel.find(layer);
    if (it == sel.end() || it->second.empty()) {
        r.error = "selection missing layer " + std::to_string(layer) + " for " + t.name;
        return r;
    }
    ExpertSliceLayout layout;
    if (!ComputeExpertSliceLayout(t.dims, t.bytes, it->second, layout, r.error)) {
        if (!r.error.empty()) r.error += " for " + t.name;
        return r;
    }
    r.ok = true;
    r.stride = layout.stride;
    r.ranges.reserve(layout.slices.size());
    for (const ExpertSlice& s : layout.slices) r.ranges.push_back({s.offset, s.length});
    return r;
}

}  // namespace Reap
}  // namespace RawrXD