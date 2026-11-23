#pragma once
// Native REAP tensor inventory. No external dependencies or silent size guesses.
// An unknown quantized layout is an explicit unsupported result, never zero bytes.
#include "GGUFLoader.hpp"
#include <algorithm>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

namespace RawrXD { namespace REAP {
struct TensorRecord {
    std::string name;
    uint32_t ggml_type = 0;
    std::vector<uint64_t> dimensions;
    uint64_t element_count = 0;
    uint64_t storage_bytes = 0;
    uint64_t data_offset = 0;
    bool prunable = false; // Conservative until an architecture adapter certifies it.
};
struct Inventory {
    std::vector<TensorRecord> tensors;
    uint64_t logical_bytes = 0;
    uint64_t physical_bytes = 0;
    uint64_t alignment = 32;
};
enum class InventoryError { None, InvalidDimensions, Overflow, UnsupportedType,
                            TruncatedTensor, InvalidAlignment, OverlappingTensors };

inline bool CheckedMultiply(uint64_t a, uint64_t b, uint64_t& out) {
    if (b && a > std::numeric_limits<uint64_t>::max() / b) return false;
    out = a * b;
    return true;
}
inline bool StorageLayout(uint32_t type, uint64_t& block, uint64_t& bytes) {
    switch (type) {
        case 0: block=1; bytes=4; return true;  // F32
        case 1: block=1; bytes=2; return true;  // F16
        case 28: block=1; bytes=8; return true; // GGML_TYPE_F64
        case 2: block=32; bytes=18; return true; // Q4_0
        case 3: block=32; bytes=20; return true; // Q4_1
        case 6: block=32; bytes=22; return true; // Q5_0
        case 7: block=32; bytes=24; return true; // Q5_1
        case 8: block=32; bytes=34; return true; // Q8_0
        case 9: block=32; bytes=36; return true; // Q8_1: fp16 d, fp16 s, 32 int8
        case 10: block=256; bytes=84; return true; // Q2_K
        case 11: block=256; bytes=110; return true; // Q3_K
        case 12: block=256; bytes=144; return true; // Q4_K
        case 13: block=256; bytes=176; return true; // Q5_K
        case 14: block=256; bytes=210; return true; // Q6_K
        case 15: block=256; bytes=292; return true; // Q8_K
        default: return false;
    }
}
// Inventory construction is transactional: out remains unchanged on failure.
// Offsets refer to the GGUF tensor data section, not the file header.
inline InventoryError BuildInventory(const EngineContext& ctx, Inventory& out) {
    Inventory next;
    next.alignment = ctx.cfg.ggufAlignment;
    if (!next.alignment || (next.alignment & (next.alignment - 1)))
        return InventoryError::InvalidAlignment;
    next.physical_bytes = static_cast<uint64_t>(ctx.tensorWeightsPool.size());
    for (const auto& kv : ctx.tensors) {
        const auto& meta = kv.second;
        TensorRecord r;
        r.name = kv.first;
        r.ggml_type = meta.type;
        r.dimensions = meta.dims;
        r.data_offset = meta.offset;
        if (r.dimensions.empty()) return InventoryError::InvalidDimensions;
        r.element_count = 1;
        for (uint64_t dim : r.dimensions) {
            if (!dim) return InventoryError::InvalidDimensions;
            if (!CheckedMultiply(r.element_count,dim,r.element_count))
                return InventoryError::Overflow;
        }
        uint64_t block=0, bytes=0;
        if (!StorageLayout(r.ggml_type,block,bytes))
            return InventoryError::UnsupportedType;
        if (r.dimensions.front() % block) return InventoryError::InvalidDimensions;
        if (!CheckedMultiply(r.element_count / block,bytes,r.storage_bytes))
            return InventoryError::Overflow;
        if (r.data_offset % next.alignment ||
            r.data_offset > next.physical_bytes ||
            r.storage_bytes > next.physical_bytes-r.data_offset)
            return InventoryError::TruncatedTensor;
        if (next.logical_bytes > std::numeric_limits<uint64_t>::max()-r.storage_bytes)
            return InventoryError::Overflow;
        next.logical_bytes += r.storage_bytes;
        next.tensors.push_back(std::move(r));
    }
    std::sort(next.tensors.begin(),next.tensors.end(),
              [](const TensorRecord& a,const TensorRecord& b){return a.name<b.name;});
    // A portable GGUF cannot have intersecting tensor storage extents.
    // Gaps for alignment are allowed; overlapping tensors are not.
    std::vector<const TensorRecord*> by_offset;
    by_offset.reserve(next.tensors.size());
    for (const auto& record : next.tensors) by_offset.push_back(&record);
    std::sort(by_offset.begin(), by_offset.end(),
              [](const TensorRecord* a, const TensorRecord* b) {
                  return a->data_offset < b->data_offset;
              });
    uint64_t previous_end = 0;
    for (const auto* record : by_offset) {
        if (record->data_offset < previous_end)
            return InventoryError::OverlappingTensors;
        previous_end = record->data_offset + record->storage_bytes;
    }
    out = std::move(next);
    return InventoryError::None;
}
}} // namespace RawrXD::REAP
