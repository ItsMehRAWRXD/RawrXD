#pragma once
// Stub: GGUF loader
#include <string>
#include <vector>
#include <cstdint>
#include <cstdio>

enum class GGMLType : int {
    GGML_TYPE_F32  = 0,
    GGML_TYPE_F16  = 1,
    GGML_TYPE_Q4_0 = 2,
    GGML_TYPE_Q5_0 = 6,
    GGML_TYPE_Q8_0 = 8,
    GGML_TYPE_Q2_K = 10,
    GGML_TYPE_Q3_K = 11,
    GGML_TYPE_Q4_K = 12,
    GGML_TYPE_Q5_K = 13,
    GGML_TYPE_Q6_K = 14,
    GGML_TYPE_Q8_K = 15,
};

struct GGUFLoadResult {
    bool ok = false;
    int mmapBound = 0;
};

inline bool load_gguf(const std::string& path, void* out) { return false; }
