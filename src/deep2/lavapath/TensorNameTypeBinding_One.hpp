#pragma once
/* BindOne helper for tensor schema. ≤99. */
#include "TensorNameTypeBinding.hpp"
#include "../QuantTypeTable.hpp"
#include <cstring>
#include <string>

namespace rawr::olma {
namespace detail {

inline int CountName(const Deep2::GGUFLoadResult& r, const std::string& name) {
    int n = 0;
    for (const auto& t : r.tensors)
        if (t.name == name) ++n;
    return n;
}

inline const Deep2::TensorInfo* Get1(const Deep2::GGUFLoadResult& r, const std::string& name) {
    const Deep2::TensorInfo* f = nullptr;
    for (const auto& t : r.tensors)
        if (t.name == name) {
            if (f) return nullptr;
            f = &t;
        }
    return f;
}

inline bool DimsEq(const Deep2::TensorInfo& t, const uint64_t* e, size_t n) {
    if (t.dimensions.size() != n) return false;
    for (size_t i = 0; i < n; ++i)
        if (t.dimensions[i] != e[i]) return false;
    return true;
}

/* GGUF ne[] order varies; accept exact or 2D transpose for linears. */
inline bool DimsEqOrSwap2(const Deep2::TensorInfo& t, const uint64_t* e) {
    if (DimsEq(t, e, 2)) return true;
    if (t.dimensions.size() != 2) return false;
    return t.dimensions[0] == e[1] && t.dimensions[1] == e[0];
}

inline bool BindOne(SchemaSeal& s, const Deep2::GGUFLoadResult& r, const char* role,
                    const std::string& name, const uint64_t* exp, size_t nExp, const char* shard,
                    uint64_t fileSize) {
    const int n = CountName(r, name);
    if (n != 1) {
        if (n > 1) {
            ++s.TENSOR_SCHEMA_DUPLICATE;
            SBlock(s, role, name, "duplicate", "duplicate", "TENSOR_SCHEMA");
        } else {
            ++s.TENSOR_SCHEMA_MISSING;
            SBlock(s, role, name, "absent", "missing", "TENSOR_SCHEMA");
        }
        return false;
    }
    const Deep2::TensorInfo* t = Get1(r, name);
    if (!t || Deep2::QuantTypeBlockBytes((uint32_t)t->type) == 0) {
        ++s.TENSOR_SCHEMA_BAD_TYPE;
        SBlock(s, role, "known ggml_type", t ? std::to_string((unsigned)t->type) : "null", "type",
               "TENSOR_SCHEMA");
        return false;
    }
    const bool okDims = [&]() -> bool {
        if (nExp == 2 && DimsEqOrSwap2(*t, exp)) return true;
        if (nExp != 2) return DimsEq(*t, exp, nExp);
        // Phi-3 style: gate fused into ffn_up → intermediate = 2*FFN.
        if (role && (std::strcmp(role, "ffn_up") == 0 || std::strcmp(role, "ffn_gate") == 0)) {
            const uint64_t alt[2] = {exp[0], exp[1] * 2ull};
            if (DimsEqOrSwap2(*t, alt)) return true;
        }
        return false;
    }();
    if (!okDims) {
        ++s.TENSOR_SCHEMA_BAD_SHAPE;
        std::string obs;
        for (size_t i = 0; i < t->dimensions.size(); ++i) {
            if (i) obs += ",";
            obs += std::to_string(t->dimensions[i]);
        }
        SBlock(s, role, name, obs, "shape", "TENSOR_SCHEMA");
        return false;
    }
    const uint64_t absOff = r.dataOffset + t->offset;
    if (!t->size || absOff + t->size < absOff || absOff + t->size > fileSize) {
        ++s.TENSOR_SCHEMA_OOB;
        SBlock(s, role, "in-file span", name, "offset", "TENSOR_SCHEMA");
        return false;
    }
    TensorBinding b;
    b.logical_role = role;
    b.gguf_name = name;
    b.ggml_type = (uint32_t)t->type;
    b.dimensions = t->dimensions;
    b.data_offset = t->offset;
    b.byte_span = t->size;
    b.owning_shard = shard;
    s.bindings.push_back(std::move(b));
    ++s.TENSOR_SCHEMA_BOUND;
    return true;
}

} // namespace detail
} // namespace rawr::olma
