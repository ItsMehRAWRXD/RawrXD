// ReapExpertGeometry.hpp — RAWRXD geometry validation (V02 extension)
// Validates expert-axis placement and quantization-block alignment for stacked
// expert tensors — storage-independent. Rejects unsupported layouts explicitly
// (does not rely solely on bytes/experts). No RNG.
#pragma once
#include "reap/ReapTensorSlice.hpp"
#include <cstdint>
#include <string>

namespace RawrXD::Reap {

struct GeometryResult {
    bool ok = false;
    std::string error;
    uint64_t stride = 0;
    uint32_t blockBytes = 0;
};

// Validate that `t` is a stacked expert tensor whose last dim is the expert axis
// and whose per-expert stride is an integer multiple of the quantization block.
inline GeometryResult ValidateExpertGeometry(const SliceTensorDesc& t, uint32_t quantBlockBytes) {
    GeometryResult r;
    if (t.dims.empty()) { r.error = "no dims: " + t.name; return r; }
    const uint64_t expertDim = t.dims.back();
    if (expertDim == 0) { r.error = "zero expert dim: " + t.name; return r; }
    if (t.bytes % expertDim != 0) {
        r.error = "bytes not divisible by expert dim: " + t.name; return r;
    }
    const uint64_t stride = t.bytes / expertDim;
    if (quantBlockBytes == 0) { r.error = "zero quant block size"; return r; }
    if (stride % quantBlockBytes != 0) {
        r.error = "expert stride " + std::to_string(stride) +
                  " not aligned to quant block " + std::to_string(quantBlockBytes) + " for " + t.name;
        return r;
    }
    r.ok = true; r.stride = stride; r.blockBytes = quantBlockBytes; return r;
}

} // namespace RawrXD::Reap