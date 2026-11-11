// GgufStaticResidency.hpp — static weight residency solver from tensor directory
#pragma once
#include "GgufDynamicGeometry.hpp"
#include <cstdint>

namespace Deep2 {

// Residency policy for M_min
enum class ResidencyPolicy : uint8_t {
    PIN_EMBED_AND_HEAD = 0,   // standard: embed + head (tied or untied) pinned
    PIN_EMBED_ONLY = 1,       // only embedding pinned, head streamable
    FULLY_STREAMABLE = 2,     // theoretical floor: nothing pinned
};

// Integrity verdict codes
enum class IntegrityVerdict : uint8_t {
    UNVERIFIED = 0,
    COMPLETE = 1,
    TRUNCATED = 2,
    OVERSIZE = 3,
    UNKNOWN_TYPES_WEAKENED = 4,
};

// Compute static residency frontier from a GGUF tensor directory.
// This is a header-only pass; never reads weight payload.
// Returns true on success, false on parse/integrity failure.
bool GgufComputeStaticResidency(const char* path, GgufDynamicGeometry* out);

// Integrity gate: validates every tensor extent fits within the file
// BEFORE any weight payload is read.
// Returns true iff ALL_TENSOR_EXTENTS_PROVEN=1.
bool GgufVerifyRomIntegrity(const char* path, GgufDynamicGeometry* out);

// Helper: GGML type → (block_elems, bytes_per_block)
// Returns false if type is unknown.
bool GgufDecodeTypeInfo(uint32_t ggml_type, uint64_t& block_elems, uint64_t& bytes_per_block);

} // namespace Deep2