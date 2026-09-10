#pragma once
/* Emit TENSOR_NAME_TYPE_BINDING_001 receipt. ≤99. */
#include "TensorNameTypeBinding.hpp"
#include <cstdio>

namespace rawr::olma {

inline void EmitSchema(FILE* f, const SchemaSeal& s) {
    if (!f) f = stdout;
    if (!s.PASS) {
        std::fprintf(f, "TENSOR_NAME_TYPE_BINDING_001=BLOCKED\n");
        std::fprintf(f, "BLOCKED_AT=%s\nBLOCKED_OWNER=TENSOR_SCHEMA\n", s.BLOCKED_AT.c_str());
        std::fprintf(f, "EXPECTED=%s\nOBSERVED=%s\n", s.EXPECTED.c_str(), s.OBSERVED.c_str());
        std::fprintf(f, "REASON=%s\nFIRST_DELTA=%s\n", s.REASON.c_str(), s.FIRST_DELTA.c_str());
        return;
    }
    std::fprintf(f, "TENSOR_SCHEMA_REQUIRED=%u\nTENSOR_SCHEMA_BOUND=%u\n",
                 s.TENSOR_SCHEMA_REQUIRED, s.TENSOR_SCHEMA_BOUND);
    std::fprintf(f, "TENSOR_SCHEMA_MISSING=%u\nTENSOR_SCHEMA_DUPLICATE=%u\n",
                 s.TENSOR_SCHEMA_MISSING, s.TENSOR_SCHEMA_DUPLICATE);
    std::fprintf(f, "TENSOR_SCHEMA_AMBIGUOUS=%u\nTENSOR_SCHEMA_BAD_TYPE=%u\n",
                 s.TENSOR_SCHEMA_AMBIGUOUS, s.TENSOR_SCHEMA_BAD_TYPE);
    std::fprintf(f, "TENSOR_SCHEMA_BAD_SHAPE=%u\nTENSOR_SCHEMA_OOB=%u\n",
                 s.TENSOR_SCHEMA_BAD_SHAPE, s.TENSOR_SCHEMA_OOB);
    std::fprintf(f, "EVERY_LAYER_PRESENT=%d\nEVERY_BINDING_ONE_TO_ONE=%d\n",
                 s.EVERY_LAYER_PRESENT, s.EVERY_BINDING_ONE_TO_ONE);
    std::fprintf(f, "QUANT_FROM_TENSOR=%d\nOFFSETS_BOUNDS_CHECKED=%d\n", s.QUANT_FROM_TENSOR,
                 s.OFFSETS_BOUNDS_CHECKED);
    std::fprintf(f, "SHARD_OWNER_RESOLVED=%d\nGEOMETRY_UNCHANGED=%d\n", s.SHARD_OWNER_RESOLVED,
                 s.GEOMETRY_UNCHANGED);
    std::fprintf(f, "ONE_LOCAL_MODEL_AUTHORITY=%d\n", s.ONE_LOCAL_MODEL_AUTHORITY);
    std::fprintf(f, "OUTPUT_WEIGHT_EXPLICIT=%d\nOUTPUT_WEIGHT_TIED_TO_TOKEN_EMBD=%d\n",
                 s.OUTPUT_WEIGHT_EXPLICIT, s.OUTPUT_WEIGHT_TIED_TO_TOKEN_EMBD);
    std::fprintf(f, "OUTPUT_WEIGHT_AUTHORITY=%s\nVOCAB=%u\n", s.OUTPUT_WEIGHT_AUTHORITY.c_str(),
                 s.VOCAB);
    std::fprintf(f, "TENSOR_NAME_TYPE_BINDING_001=PASS\nFIRST_DELTA=QUANT_DISPATCH\n");
}

} // namespace rawr::olma
