#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <cstddef>

// GGUF magic: "GGUF" = 0x46554747
#define GGUF_MAGIC 0x46554747

// Local TensorInfo definition
struct TensorInfo {
    std::string name;
    uint32_t type = 0;
    std::vector<uint64_t> dims;
    size_t fileOffset = 0;
    size_t dataLength = 0;
    void* data = nullptr;
};

enum class GGMLType : uint32_t {
    F32  = 0,
    F16  = 1,
    Q4_0 = 2,
    Q4_1 = 3,
    Q5_0 = 6,
    Q5_1 = 7,
    Q8_0 = 8,
    Q2_K = 14,
    Q3_K = 15,
    Q4_K = 16,
    Q5_K = 17,
    Q6_K = 18,
};

// Quantized block structures
struct block_q4_0 {
    uint16_t d;
    uint8_t qs[16];
};

struct block_q4_1 {
    uint16_t d;
    uint16_t m;
    uint8_t qs[16];
};

struct block_q8_0 {
    uint16_t d;
    int8_t qs[32];
};
