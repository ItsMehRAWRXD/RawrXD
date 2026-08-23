// ============================================================================
// test_gguf_tensor_bounds.cpp
// B34 — GGUF Tensor/Offset Bounds Gate
// Production parser API: GGUFTensorLoader::ParseHeader(data, len)
// ============================================================================
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <string>
#include <vector>
#include <algorithm>
#include <fstream>
#include <filesystem>

#include "runtime/gguf_tensor_loader.hpp"

namespace {

using u8  = uint8_t;
using u32 = uint32_t;
using u64 = uint64_t;

constexpr u32 GGUF_MAGIC   = 0x46554747u;
constexpr u32 GGUF_VERSION = 3u;

// GGUF value types
constexpr u32 GGUF_TYPE_UINT32 = 4u;
constexpr u32 GGUF_TYPE_STRING = 8u;

// GGML tensor types
constexpr u32 GGML_TYPE_F32  = 0u;
constexpr u32 GGML_TYPE_Q4_0 = 2u;
constexpr u32 GGML_TYPE_Q8_0 = 8u;

struct Buffer {
    std::vector<u8> data;

    template <typename T>
    void put(T value) {
        const u8* p = reinterpret_cast<const u8*>(&value);
        data.insert(data.end(), p, p + sizeof(T));
    }

    void bytes(const void* ptr, size_t n) {
        const u8* p = static_cast<const u8*>(ptr);
        data.insert(data.end(), p, p + n);
    }

    void zeros(size_t n) { data.insert(data.end(), n, 0); }
};

static void put_string(Buffer& b, const std::string& s) {
    b.put<u64>(static_cast<u64>(s.size()));
    if (!s.empty()) b.bytes(s.data(), s.size());
}

static void put_header(Buffer& b, u64 tensor_count, u64 metadata_count) {
    b.put<u32>(GGUF_MAGIC);
    b.put<u32>(GGUF_VERSION);
    b.put<u64>(tensor_count);
    b.put<u64>(metadata_count);
}

static void put_metadata_uint32(Buffer& b, const std::string& key, u32 value) {
    put_string(b, key);
    b.put<u32>(GGUF_TYPE_UINT32);
    b.put<u32>(value);
}

static void put_tensor(Buffer& b,
                       const std::string& name,
                       u32 n_dims,
                       const std::vector<u64>& dims,
                       u32 type,
                       u64 offset)
{
    put_string(b, name);
    b.put<u32>(n_dims);
    for (u32 i = 0; i < n_dims; ++i) {
        b.put<u64>(i < dims.size() ? dims[i] : 1);
    }
    b.put<u32>(type);
    b.put<u64>(offset);
}

static bool checked_add(u64 a, u64 b, u64& out) {
    if (b > std::numeric_limits<u64>::max() - a) return false;
    out = a + b;
    return true;
}

static bool checked_mul(u64 a, u64 b, u64& out) {
    if (a != 0 && b > std::numeric_limits<u64>::max() / a) return false;
    out = a * b;
    return true;
}

// ── Fixture builders ───────────────────────────────────────────────────────

static Buffer make_minimal_valid() {
    Buffer b;
    put_header(b, 0, 0);
    b.zeros(64);
    return b;
}

static Buffer make_one_tensor_valid() {
    Buffer b;
    put_header(b, 1, 0);
    put_tensor(b, "tensor", 2, {4, 4}, GGML_TYPE_F32, 0);
    b.zeros(64);
    return b;
}

static Buffer make_two_tensors_valid() {
    Buffer b;
    put_header(b, 2, 0);
    put_tensor(b, "a", 2, {4, 4}, GGML_TYPE_F32, 0);
    put_tensor(b, "b", 2, {4, 4}, GGML_TYPE_F32, 64);
    b.zeros(128);
    return b;
}

static Buffer make_metadata_and_tensor() {
    Buffer b;
    put_header(b, 1, 1);
    put_metadata_uint32(b, "general.alignment", 32);
    put_tensor(b, "weight", 2, {8, 8}, GGML_TYPE_F32, 0);
    b.zeros(256);
    return b;
}

static Buffer make_string_metadata_tensor() {
    Buffer b;
    put_header(b, 1, 1);
    put_string(b, "general.name");
    b.put<u32>(GGUF_TYPE_STRING);
    put_string(b, "RawrXD");
    put_tensor(b, "weight", 2, {8, 8}, GGML_TYPE_F32, 0);
    b.zeros(256);
    return b;
}

static Buffer make_q4_tensor_valid() {
    Buffer b;
    put_header(b, 1, 0);
    put_tensor(b, "q4", 2, {32, 32}, GGML_TYPE_Q4_0, 0);
    b.zeros(512);
    return b;
}

static Buffer make_tensor_count_truncated(u64 count) {
    Buffer b;
    put_header(b, count, 0);
    b.zeros(16);
    return b;
}

static Buffer make_name_length_max() {
    Buffer b;
    put_header(b, 1, 0);
    b.put<u64>(std::numeric_limits<u64>::max());
    return b;
}

static Buffer make_name_truncated() {
    Buffer b;
    put_header(b, 1, 0);
    b.put<u64>(1024);
    b.zeros(8);
    return b;
}

static Buffer make_dims_64() {
    Buffer b;
    put_header(b, 1, 0);
    put_string(b, "x");
    b.put<u32>(64);
    b.zeros(16);
    return b;
}

static Buffer make_dim_max() {
    Buffer b;
    put_header(b, 1, 0);
    put_string(b, "x");
    b.put<u32>(1);
    b.put<u64>(std::numeric_limits<u64>::max());
    return b;
}

static Buffer make_offset_oob() {
    Buffer b;
    put_header(b, 1, 0);
    put_tensor(b, "x", 1, {32}, GGML_TYPE_F32, 0x100000000ULL);
    b.zeros(64);
    return b;
}

static Buffer make_offset_max() {
    Buffer b;
    put_header(b, 1, 0);
    put_tensor(b, "x", 1, {32}, GGML_TYPE_F32, std::numeric_limits<u64>::max());
    b.zeros(64);
    return b;
}

static Buffer make_offset_plus_size_overflow() {
    Buffer b;
    put_header(b, 1, 0);
    put_tensor(b, "x", 2,
               {std::numeric_limits<u64>::max(), 2},
               GGML_TYPE_F32,
               std::numeric_limits<u64>::max() - 16);
    b.zeros(64);
    return b;
}

static Buffer make_invalid_type() {
    Buffer b;
    put_header(b, 1, 0);
    put_tensor(b, "x", 1, {32}, 0xffffffffu, 0);
    b.zeros(64);
    return b;
}

static Buffer make_record_truncation() {
    Buffer b;
    put_header(b, 1, 0);
    put_string(b, "x");
    b.put<u32>(2);
    b.put<u64>(32);
    return b;
}

static Buffer make_offset_alignment() {
    Buffer b;
    put_header(b, 1, 0);
    put_tensor(b, "x", 1, {32}, GGML_TYPE_F32, 3);
    b.zeros(128);
    return b;
}

static Buffer make_huge_count() {
    Buffer b;
    put_header(b, std::numeric_limits<u64>::max(), 0);
    b.zeros(64);
    return b;
}

static Buffer make_count_record_overflow() {
    Buffer b;
    put_header(b, 0x8000000000000000ULL, 0);
    b.zeros(64);
    return b;
}

static Buffer make_tensor_overlap() {
    Buffer b;
    put_header(b, 2, 0);
    put_tensor(b, "a", 2, {4, 4}, GGML_TYPE_F32, 0);
    put_tensor(b, "b", 2, {4, 4}, GGML_TYPE_F32, 32); // overlaps a (0-63)
    b.zeros(128);
    return b;
}

static Buffer make_offset_past_eof() {
    Buffer b;
    put_header(b, 1, 0);
    put_tensor(b, "x", 1, {32}, GGML_TYPE_F32, 256);
    b.zeros(64);
    return b;
}

static Buffer make_zero_dim() {
    Buffer b;
    put_header(b, 1, 0);
    put_tensor(b, "x", 2, {0, 4}, GGML_TYPE_F32, 0);
    b.zeros(64);
    return b;
}

static Buffer make_type_255() {
    Buffer b;
    put_header(b, 1, 0);
    put_tensor(b, "x", 1, {32}, 255, 0);
    b.zeros(64);
    return b;
}

static Buffer make_negative_offset_wrapped() {
    Buffer b;
    put_header(b, 1, 0);
    put_tensor(b, "x", 1, {32}, GGML_TYPE_F32, 0xFFFFFFFFFFFFFFFFULL);
    b.zeros(64);
    return b;
}

static Buffer make_count_times_record_overflow() {
    Buffer b;
    put_header(b, 0x100000000ULL, 0);
    b.zeros(64);
    return b;
}

// ── Deterministic mutation fixtures ────────────────────────────────────────
static std::vector<Buffer> make_deterministic_mutations() {
    std::vector<Buffer> mutations;
    for (int i = 0; i < 17; ++i) {
        Buffer b;
        put_header(b, 1, 0);
        put_string(b, std::string("tensor_") + std::to_string(i));
        b.put<u32>(static_cast<u32>(i % 7 + 1));
        for (int d = 0; d < i % 7 + 1; ++d) {
            b.put<u64>(i == 16 ? std::numeric_limits<u64>::max() : static_cast<u64>(d + 1));
        }
        b.put<u32>(i == 15 ? 0xffffffffu : GGML_TYPE_F32);
        b.put<u64>(i >= 8 ? std::numeric_limits<u64>::max() - static_cast<u64>(i) : static_cast<u64>(i * 3));
        b.zeros(32);
        mutations.push_back(std::move(b));
    }
    return mutations;
}

// ── Case definition ──────────────────────────────────────────────────────
struct Case {
    const char* name;
    Buffer buffer;
    bool expect_valid;
};

static std::vector<Case> build_cases() {
    std::vector<Case> cases;

    // Positive controls (6)
    cases.push_back({"minimal_valid",              make_minimal_valid(),              true});
    cases.push_back({"one_tensor_valid",             make_one_tensor_valid(),           true});
    cases.push_back({"two_tensors_valid",            make_two_tensors_valid(),          true});
    cases.push_back({"metadata_tensor_valid",        make_metadata_and_tensor(),        true});
    cases.push_back({"string_metadata_tensor_valid", make_string_metadata_tensor(),     true});
    cases.push_back({"q4_tensor_valid",              make_q4_tensor_valid(),            true});

    // Tensor-count truncation (5)
    cases.push_back({"tensor_count_1_truncated",     make_tensor_count_truncated(1),        false});
    cases.push_back({"tensor_count_255_truncated",   make_tensor_count_truncated(255),      false});
    cases.push_back({"tensor_count_1024_truncated",  make_tensor_count_truncated(1024),     false});
    cases.push_back({"tensor_count_4g_truncated",    make_tensor_count_truncated(0x100000000ULL), false});
    cases.push_back({"tensor_count_max_truncated",   make_tensor_count_truncated(std::numeric_limits<u64>::max()), false});

    // Tensor-name length boundaries (2)
    cases.push_back({"tensor_name_length_max",     make_name_length_max(),            false});
    cases.push_back({"tensor_name_truncated",        make_name_truncated(),             false});

    // Tensor dimension-count boundaries (2)
    cases.push_back({"tensor_dims_64",               make_dims_64(),                    false});
    cases.push_back({"tensor_dim_max",               make_dim_max(),                    false});

    // Tensor offset boundaries (4)
    cases.push_back({"tensor_offset_oob",            make_offset_oob(),                 false});
    cases.push_back({"tensor_offset_uint64_max",     make_offset_max(),                 false});
    cases.push_back({"tensor_offset_past_eof",       make_offset_past_eof(),            false});
    cases.push_back({"tensor_offset_negative_wrap",  make_negative_offset_wrapped(),    false});

    // Tensor offset + size overflow (1)
    cases.push_back({"tensor_offset_plus_size_overflow", make_offset_plus_size_overflow(), false});

    // Tensor type boundaries (3)
    cases.push_back({"tensor_invalid_type",          make_invalid_type(),               false});
    cases.push_back({"tensor_type_255",              make_type_255(),                   false});
    cases.push_back({"tensor_record_truncated",      make_record_truncation(),          false});

    // Alignment / data-start (1)
    cases.push_back({"tensor_offset_unaligned",      make_offset_alignment(),           false});

    // Combined count × record-size overflow (2)
    cases.push_back({"tensor_count_uint64_max",      make_huge_count(),                 false});
    cases.push_back({"tensor_count_record_overflow", make_count_record_overflow(),      false});

    // Tensor overlap (1)
    cases.push_back({"tensor_overlap",               make_tensor_overlap(),             false});

    // Zero dimension (1)
    cases.push_back({"tensor_zero_dim",              make_zero_dim(),                   false});

    // Count × record overflow v2 (1)
    cases.push_back({"count_times_record_overflow",  make_count_times_record_overflow(), false});

    // Deterministic mutations (17)
    auto mutations = make_deterministic_mutations();
    for (size_t i = 0; i < mutations.size(); ++i) {
        std::string name = "tensor_deterministic_mutation_" + std::to_string(i);
        cases.push_back({name.c_str(), std::move(mutations[i]), false});
    }

    return cases;
}

} // namespace

// ============================================================================
// Main
// ============================================================================
int main() {
    const auto cases = build_cases();

    size_t pass = 0;
    size_t fail = 0;

    std::printf("B34 GGUF Tensor/Offset Bounds Gate\n");
    std::printf("Cases=%zu\n\n", cases.size());

    for (size_t i = 0; i < cases.size(); ++i) {
        const Case& c = cases[i];

        rawrxd::runtime::GGUFTensorLoader loader;
        const bool actual = loader.ParseHeader(
            c.buffer.data.data(),
            c.buffer.data.size()
        );

        const bool ok = actual == c.expect_valid;

        std::printf(
            "[%03zu] %-40s expected=%s actual=%s %s\n",
            i + 1,
            c.name,
            c.expect_valid ? "VALID" : "REJECT",
            actual ? "VALID" : "REJECT",
            ok ? "PASS" : "FAIL"
        );

        if (ok) ++pass;
        else     ++fail;
    }

    std::printf("\nB34 SUMMARY: %zu/%zu PASS, %zu failures\n",
                pass, cases.size(), fail);

    if (fail != 0) {
        std::printf("B34 RESULT: FAIL\n");
        return 1;
    }

    std::printf("B34 RESULT: PASS\nEXIT_CODE=0\n");

    // Write evidence JSON
    std::filesystem::create_directories("D:/rawrxd/evidence");
    std::ofstream json("D:/rawrxd/evidence/B34_TENSOR_OFFSET_BOUNDS.json");
    if (json) {
        json << "{\n";
        json << "  \"batch\": \"B34\",\n";
        json << "  \"gate\": \"tensor-offset-bounds\",\n";
        json << "  \"cases\": " << cases.size() << ",\n";
        json << "  \"pass\": " << pass << ",\n";
        json << "  \"fail\": " << fail << ",\n";
        json << "  \"result\": \"PASS\",\n";
        json << "  \"exit_code\": 0\n";
        json << "}\n";
    }

    return 0;
}
