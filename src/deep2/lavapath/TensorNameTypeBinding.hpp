#pragma once
/* TENSOR_NAME_TYPE_BINDING — per-tensor role bind (fail-closed). ≤99. */
#include "LocalModelAuthority.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace rawr::olma {

struct TensorBinding {
    const char* logical_role = "";
    std::string gguf_name;
    uint32_t ggml_type = 0;
    std::vector<uint64_t> dimensions;
    uint64_t data_offset = 0; /* relative to tensor data section */
    uint64_t byte_span = 0;
    std::string owning_shard;
};

struct SchemaSeal {
    int PASS = 0;
    int EVERY_LAYER_PRESENT = 0;
    int EVERY_BINDING_ONE_TO_ONE = 0;
    int QUANT_FROM_TENSOR = 1;
    int OFFSETS_BOUNDS_CHECKED = 0;
    int SHARD_OWNER_RESOLVED = 0;
    int GEOMETRY_UNCHANGED = 0;
    int ONE_LOCAL_MODEL_AUTHORITY = 1;
    int OUTPUT_WEIGHT_EXPLICIT = 0;
    int OUTPUT_WEIGHT_TIED_TO_TOKEN_EMBD = 0;
    std::string OUTPUT_WEIGHT_AUTHORITY;
    uint32_t TENSOR_SCHEMA_REQUIRED = 0;
    uint32_t TENSOR_SCHEMA_BOUND = 0;
    uint32_t TENSOR_SCHEMA_MISSING = 0;
    uint32_t TENSOR_SCHEMA_DUPLICATE = 0;
    uint32_t TENSOR_SCHEMA_AMBIGUOUS = 0;
    uint32_t TENSOR_SCHEMA_BAD_TYPE = 0;
    uint32_t TENSOR_SCHEMA_BAD_SHAPE = 0;
    uint32_t TENSOR_SCHEMA_OOB = 0;
    uint32_t VOCAB = 0;
    std::string BLOCKED_AT, EXPECTED, OBSERVED, REASON, FIRST_DELTA;
    std::vector<TensorBinding> bindings;
    GeomSeal geom{};
};

inline void SBlock(SchemaSeal& s, const char* at, const std::string& exp, const std::string& obs,
                   const char* reason, const char* delta) {
    s.PASS = 0;
    s.BLOCKED_AT = at;
    s.EXPECTED = exp;
    s.OBSERVED = obs;
    s.REASON = reason;
    s.FIRST_DELTA = delta;
}

bool BindLlamaSchema(const Deep2::GGUFLoadResult& r, const GeomSeal& geom, const char* shardPath,
                     SchemaSeal& s);
void EmitSchema(FILE* f, const SchemaSeal& s);

} // namespace rawr::olma
