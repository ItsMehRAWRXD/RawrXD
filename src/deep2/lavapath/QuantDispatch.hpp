#pragma once
/* QUANT_DISPATCH — per-binding ggml_type dispatch seal (fail-closed). ≤99. */
#include "TensorNameTypeBinding.hpp"
#include "../QuantTypeTable.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace rawr::olma {

struct QuantDispatchEntry {
    const char* logical_role = "";
    std::string gguf_name;
    uint32_t ggml_type = 0;
    const char* type_name = "";
    int kernel_ready = 0;
    int dequant_slot = 0; /* ggml_type is dispatch key; 0=absent */
    int gemv_required = 0;
    uint64_t elems = 0;
    uint64_t expected_bytes = 0;
};

struct QuantDispatchSeal {
    int PASS = 0;
    int QUANT_FROM_TENSOR = 1;
    int NO_SILENT_F32_FALLBACK = 1;
    int NO_ZERO_FALLBACK = 1;
    int DISPATCH_TABLE_COMPLETE = 0;
    int BYTE_SPAN_MATCHES_TYPE = 0;
    int GEOMETRY_UNCHANGED = 0;
    int ONE_LOCAL_MODEL_AUTHORITY = 1;
    uint32_t BINDINGS_CHECKED = 0;
    uint32_t BINDINGS_DISPATCHABLE = 0;
    uint32_t UNSUPPORTED_TYPE = 0;
    uint32_t SPAN_MISMATCH = 0;
    uint32_t TYPE_F32 = 0, TYPE_Q4_K = 0, TYPE_Q6_K = 0, TYPE_OTHER = 0;
    std::string BLOCKED_AT, EXPECTED, OBSERVED, REASON, FIRST_DELTA;
    std::vector<QuantDispatchEntry> entries;
    GeomSeal geom{};
};

inline void QBlock(QuantDispatchSeal& q, const char* at, const std::string& exp,
                   const std::string& obs, const char* reason, const char* delta) {
    q.PASS = 0;
    q.BLOCKED_AT = at;
    q.EXPECTED = exp;
    q.OBSERVED = obs;
    q.REASON = reason;
    q.FIRST_DELTA = delta;
}

bool SealQuantDispatch(const SchemaSeal& schema, QuantDispatchSeal& q);
void EmitQuantDispatch(FILE* f, const QuantDispatchSeal& q);

} // namespace rawr::olma
