#include "PackedExpertSlicer.h"
#include <limits>

namespace rawrxd::deep2 {
namespace {

bool mulSize(size_t a, size_t b, size_t& out) noexcept {
    if (a != 0 && b > std::numeric_limits<size_t>::max() / a) return false;
    out = a * b;
    return true;
}

bool addSize(size_t a, size_t b, size_t& out) noexcept {
    if (b > std::numeric_limits<size_t>::max() - a) return false;
    out = a + b;
    return true;
}

void fail(PackedSliceReceipt& r, const char* why) noexcept {
    r.valid = false;
    r.failure = why;
}

} // namespace

bool PackedExpertSlicer::typeGeometry(GgmlStorageType type,
                                      uint32_t& blockElements,
                                      uint32_t& blockBytes) noexcept {
    switch (type) {
        case GgmlStorageType::F32:  blockElements = 1;   blockBytes = 4;   return true;
        case GgmlStorageType::F16:  blockElements = 1;   blockBytes = 2;   return true;
        case GgmlStorageType::BF16: blockElements = 1;   blockBytes = 2;   return true;
        case GgmlStorageType::Q4_0: blockElements = 32;  blockBytes = 18;  return true;
        case GgmlStorageType::Q4_1: blockElements = 32;  blockBytes = 20;  return true;
        case GgmlStorageType::Q5_0: blockElements = 32;  blockBytes = 22;  return true;
        case GgmlStorageType::Q5_1: blockElements = 32;  blockBytes = 24;  return true;
        case GgmlStorageType::Q8_0: blockElements = 32;  blockBytes = 34;  return true;
        case GgmlStorageType::Q2_K: blockElements = 256; blockBytes = 84;  return true;
        case GgmlStorageType::Q3_K: blockElements = 256; blockBytes = 110; return true;
        case GgmlStorageType::Q4_K: blockElements = 256; blockBytes = 144; return true;
        case GgmlStorageType::Q5_K: blockElements = 256; blockBytes = 176; return true;
        case GgmlStorageType::Q6_K: blockElements = 256; blockBytes = 210; return true;
        case GgmlStorageType::Q8_K: blockElements = 256; blockBytes = 292; return true;
        default: break;
    }
    blockElements = 0;
    blockBytes = 0;
    return false;
}

bool PackedExpertSlicer::slice(const PackedTensorDescriptor& d,
                               std::vector<ExpertTensorSlice>& out,
                               PackedSliceReceipt* receipt) noexcept {
    PackedSliceReceipt local{};
    out.clear();

    if (!d.data || d.bytes == 0) { fail(local, "NULL_OR_EMPTY"); if (receipt) *receipt = local; return false; }
    if (d.dims.empty() || d.expertAxis >= d.dims.size()) { fail(local, "BAD_DIMS_OR_AXIS"); if (receipt) *receipt = local; return false; }
    if (d.dims[d.expertAxis] == 0) { fail(local, "ZERO_EXPERT_AXIS"); if (receipt) *receipt = local; return false; }

    // One cached expert must be one contiguous byte span. Current production GGUF MoE
    // layouts put the expert dimension outermost. Non-outer expert axes can be strided/
    // interleaved and are rejected rather than silently uploading the wrong bytes.
    if (d.expertAxis != d.dims.size() - 1) {
        fail(local, "EXPERT_AXIS_NOT_CONTIGUOUS"); if (receipt) *receipt = local; return false;
    }

    const uint64_t declaredExperts = d.expertCount ? d.expertCount : d.dims[d.expertAxis];
    if (declaredExperts == 0 || declaredExperts > d.dims[d.expertAxis] || declaredExperts > UINT32_MAX) {
        fail(local, "BAD_EXPERT_COUNT"); if (receipt) *receipt = local; return false;
    }

    size_t expertStride = 0;
    size_t expertBytes = 0;

    if (!d.byteStrides.empty()) {
        if (d.byteStrides.size() != d.dims.size() || d.byteStrides[d.expertAxis] == 0) {
            fail(local, "BAD_STRIDES"); if (receipt) *receipt = local; return false;
        }
        local.usedExplicitStrides = true;
        if (d.byteStrides[d.expertAxis] > std::numeric_limits<size_t>::max()) {
            fail(local, "STRIDE_OVERFLOW"); if (receipt) *receipt = local; return false;
        }
        expertStride = static_cast<size_t>(d.byteStrides[d.expertAxis]);
        expertBytes = expertStride;
        if (d.expertAxis + 1 < d.dims.size() && d.byteStrides[d.expertAxis + 1] < d.byteStrides[d.expertAxis]) {
            fail(local, "NON_MONOTONIC_STRIDES"); if (receipt) *receipt = local; return false;
        }

        uint32_t be = 0, bb = 0;
        if (typeGeometry(d.type, be, bb) && !d.dims.empty() && d.dims[0] % be == 0) {
            local.quantBlockAligned = true;
            local.rowBytes = static_cast<size_t>((d.dims[0] / be) * bb);
        }
    } else {
        // Automatic derivation is intentionally restricted to the common GGUF packed layout
        // [row_width, rows_per_expert, ..., experts], where experts are the outermost axis.
        if (d.expertAxis != d.dims.size() - 1) {
            fail(local, "STRIDES_REQUIRED_FOR_NON_OUTERMOST_EXPERT_AXIS"); if (receipt) *receipt = local; return false;
        }

        uint32_t blockElements = 0, blockBytes = 0;
        if (!typeGeometry(d.type, blockElements, blockBytes)) {
            fail(local, "UNKNOWN_TYPE_REQUIRES_STRIDES"); if (receipt) *receipt = local; return false;
        }
        if (d.dims[0] == 0 || d.dims[0] % blockElements != 0) {
            fail(local, "QUANT_BLOCK_MISALIGN"); if (receipt) *receipt = local; return false;
        }
        local.quantBlockAligned = true;
        local.rowBytes = static_cast<size_t>((d.dims[0] / blockElements) * blockBytes);

        size_t bytes = local.rowBytes;
        for (size_t axis = 1; axis < d.expertAxis; ++axis) {
            if (d.dims[axis] == 0 || d.dims[axis] > std::numeric_limits<size_t>::max()) {
                fail(local, "DIM_OVERFLOW"); if (receipt) *receipt = local; return false;
            }
            if (!mulSize(bytes, static_cast<size_t>(d.dims[axis]), bytes)) {
                fail(local, "SIZE_OVERFLOW"); if (receipt) *receipt = local; return false;
            }
        }
        expertStride = bytes;
        expertBytes = bytes;
    }

    if (expertStride == 0 || expertBytes == 0) { fail(local, "ZERO_EXPERT_STRIDE"); if (receipt) *receipt = local; return false; }

    size_t covered = 0;
    if (!mulSize(expertStride, static_cast<size_t>(declaredExperts - 1), covered) ||
        !addSize(covered, expertBytes, covered) || covered > d.bytes) {
        fail(local, "OUT_OF_BOUNDS"); if (receipt) *receipt = local; return false;
    }

    out.reserve(static_cast<size_t>(declaredExperts));
    const auto* base = static_cast<const uint8_t*>(d.data);
    for (uint32_t e = 0; e < static_cast<uint32_t>(declaredExperts); ++e) {
        size_t off = 0;
        if (!mulSize(expertStride, static_cast<size_t>(e), off)) {
            out.clear(); fail(local, "OFFSET_OVERFLOW"); if (receipt) *receipt = local; return false;
        }
        out.push_back(ExpertTensorSlice{d.layer, e, base + off, expertBytes,
                                        d.fileOffset + static_cast<uint64_t>(off), off});
    }

    local.valid = true;
    local.failure = nullptr;
    local.experts = static_cast<uint32_t>(declaredExperts);
    local.expertStrideBytes = expertStride;
    local.coveredBytes = covered;
    if (receipt) *receipt = local;
    return true;
}

} // namespace rawrxd::deep2
