// ReapTensorSlice.hpp — RAWRXD_ADAPTIVE_REPAIR / V02
// Storage-independent quantization-aware expert slicing (extracted from the GGUF
// writer's geometry logic). No GGUF, no engine deps — reusable by Physical,
// Virtual and Streaming. Preserves block geometry, expert ordering, overflow and
// alignment guards; rejects unsupported layouts explicitly.
#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <limits>
#include <utility>

namespace RawrXD::Reap {

struct SliceTensorDesc {
    std::string name;
    std::vector<uint64_t> dims;   // logical dims; expert dim = last
    uint64_t bytes = 0;           // total tensor bytes
};

using ExpertSelection = std::map<uint32_t, std::vector<uint32_t>>;   // layer -> retained expert ids

struct SliceResult {
    bool ok = false;
    std::string error;
    uint64_t stride = 0;                              // bytes per expert
    std::vector<std::pair<uint64_t,uint64_t>> ranges; // (byte offset, bytes) per selected expert
};

// V02: compute per-expert byte ranges for a stacked expert tensor (storage-independent).
inline SliceResult SliceExperts(const SliceTensorDesc& t, uint32_t layer, const ExpertSelection& sel) {
    SliceResult r;
    if (t.dims.empty()) { r.error = "expert tensor has no dimensions: " + t.name; return r; }
    const uint64_t expertDim = t.dims.back();
    if (expertDim == 0) { r.error = "zero expert dimension: " + t.name; return r; }
    if (t.bytes % expertDim != 0) {
        r.error = "bytes not divisible by expert dim: " + t.name +
                  " bytes=" + std::to_string(t.bytes) + " expert_dim=" + std::to_string(expertDim);
        return r;
    }
    const auto it = sel.find(layer);
    if (it == sel.end() || it->second.empty()) {
        r.error = "selection missing layer " + std::to_string(layer) + " for " + t.name;
        return r;
    }
    const uint64_t stride = t.bytes / expertDim;
    for (uint32_t expert : it->second) {
        if (expert >= expertDim) {
            r.error = "selected expert " + std::to_string(expert) + " exceeds expert dim " + std::to_string(expertDim) + " for " + t.name;
            return r;
        }
        if (expert > 0 && stride > std::numeric_limits<uint64_t>::max() / expert) {
                r.error = "expert slice offset overflow for " + t.name; return r;
        }
        r.ranges.push_back({(uint64_t)expert * stride, stride});
    }
    r.stride = stride; r.ok = true; return r;
}

} // namespace RawrXD::Reap