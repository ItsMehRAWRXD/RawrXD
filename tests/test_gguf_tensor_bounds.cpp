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
#include <utility>

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

    Buffer() = default;
    Buffer(const Buffer& other) : data(other.data) {}
    Buffer(Buffer&& other) noexcept : data(std::move(other.data)) {}
    Buffer& operator=(const Buffer& other) { data = other.data; return *this; }
    Buffer& operator=(Buffer&& other) noexcept { data = std::move(other.data); return *this; }

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
static std::vector<Case> make_deterministic_mutations() {
    std::vector<Case> mutations;

    // 0: truncated dimensions (claim 3, provide 1)
    {
        Buffer b; put_header(b, 1, 0);
        put_string(b, "mut_truncated_dims");
        b.put<u32>(3); b.put<u64>(1); b.zeros(8);
        mutations.push_back(Case("mut_truncated_dims", std::move(b), false));
    }
    // 1: zero dimension
    {
        Buffer b; put_header(b, 1, 0);
        put_string(b, "mut_zero_dim");
        b.put<u32>(2); b.put<u64>(0); b.put<u64>(4);
        b.put<u32>(GGML_TYPE_F32); b.put<u64>(0); b.zeros(32);
        mutations.push_back(Case("mut_zero_dim", std::move(b), false));
    }
    // 2: invalid type
    {
        Buffer b; put_header(b, 1, 0);
        put_string(b, "mut_invalid_type");
        b.put<u32>(1); b.put<u64>(4);
        b.put<u32>(0xDEADBEEFu); b.put<u64>(0); b.zeros(32);
        mutations.push_back(Case("mut_invalid_type", std::move(b), false));
    }
    // 3: offset past EOF
    {
        Buffer b; put_header(b, 1, 0);
        put_string(b, "mut_offset_eof");
        b.put<u32>(1); b.put<u64>(4);
        b.put<u32>(GGML_TYPE_F32); b.put<u64>(256); b.zeros(32);
        mutations.push_back(Case("mut_offset_eof", std::move(b), false));
    }
    // 4: huge dimension causing size overflow
    {
        Buffer b; put_header(b, 1, 0);
        put_string(b, "mut_dim_overflow");
        b.put<u32>(2); b.put<u64>(0xFFFFFFFFFFFFFFFFULL); b.put<u64>(2);
        b.put<u32>(GGML_TYPE_F32); b.put<u64>(0); b.zeros(32);
        mutations.push_back(Case("mut_dim_overflow", std::move(b), false));
    }
    // 5: 65 dims (exceeds max)
    {
        Buffer b; put_header(b, 1, 0);
        put_string(b, "mut_65_dims");
        b.put<u32>(65); b.zeros(64);
        mutations.push_back(Case("mut_65_dims", std::move(b), false));
    }
    // 6: type 255
    {
        Buffer b; put_header(b, 1, 0);
        put_string(b, "mut_type_255");
        b.put<u32>(1); b.put<u64>(4);
        b.put<u32>(255); b.put<u64>(0); b.zeros(32);
        mutations.push_back(Case("mut_type_255", std::move(b), false));
    }
    // 7: unaligned offset
    {
        Buffer b; put_header(b, 1, 0);
        put_string(b, "mut_unaligned");
        b.put<u32>(1); b.put<u64>(4);
        b.put<u32>(GGML_TYPE_F32); b.put<u64>(7); b.zeros(32);
        mutations.push_back(Case("mut_unaligned", std::move(b), false));
    }
    // 8: tensor size exceeds file
    {
        Buffer b; put_header(b, 1, 0);
        put_string(b, "mut_size_eof");
        b.put<u32>(2); b.put<u64>(100); b.put<u64>(100);
        b.put<u32>(GGML_TYPE_F32); b.put<u64>(0); b.zeros(16);
        mutations.push_back(Case("mut_size_eof", std::move(b), false));
    }
    // 9: truncated at name length
    {
        Buffer b; put_header(b, 1, 0);
        b.put<u64>(1024); b.zeros(8);
        mutations.push_back(Case("mut_trunc_name", std::move(b), false));
    }
    // 10: truncated at type
    {
        Buffer b; put_header(b, 1, 0);
        put_string(b, "mut_trunc_type");
        b.put<u32>(1); b.put<u64>(4); b.zeros(4);
        mutations.push_back(Case("mut_trunc_type", std::move(b), false));
    }
    // 11: truncated at offset
    {
        Buffer b; put_header(b, 1, 0);
        put_string(b, "mut_trunc_offset");
        b.put<u32>(1); b.put<u64>(4);
        b.put<u32>(GGML_TYPE_F32); b.zeros(4);
        mutations.push_back(Case("mut_trunc_offset", std::move(b), false));
    }
    // 12: negative offset (wraps to max)
    {
        Buffer b; put_header(b, 1, 0);
        put_string(b, "mut_neg_offset");
        b.put<u32>(1); b.put<u64>(4);
        b.put<u32>(GGML_TYPE_F32); b.put<u64>(0xFFFFFFFFFFFFFFFFULL); b.zeros(32);
        mutations.push_back(Case("mut_neg_offset", std::move(b), false));
    }
    // 13: overlap with self (two tensors overlapping)
    {
        Buffer b; put_header(b, 2, 0);
        put_tensor(b, "a", 1, {4}, GGML_TYPE_F32, 0);
        put_tensor(b, "b", 1, {4}, GGML_TYPE_F32, 8);
        b.zeros(32);
        mutations.push_back(Case("mut_overlap", std::move(b), false));
    }
    // 14: huge tensor count
    {
        Buffer b; put_header(b, 0x100000000ULL, 0);
        b.zeros(64);
        mutations.push_back(Case("mut_huge_count", std::move(b), false));
    }
    // 15: Q4_0 with huge dims causing size overflow
    {
        Buffer b; put_header(b, 1, 0);
        put_string(b, "mut_q4_overflow");
        b.put<u32>(2); b.put<u64>(0xFFFFFFFFULL); b.put<u64>(0xFFFFFFFFULL);
        b.put<u32>(GGML_TYPE_Q4_0); b.put<u64>(0); b.zeros(32);
        mutations.push_back(Case("mut_q4_overflow", std::move(b), false));
    }
    // 16: metadata count too large
    {
        Buffer b; put_header(b, 0, 0xFFFFFFFFFFFFFFFFULL);
        b.zeros(64);
        mutations.push_back(Case("mut_huge_metadata", std::move(b), false));
    }

    return mutations;
}

// ── Case definition ──────────────────────────────────────────────────────
struct Case {
    std::string name;
    Buffer buffer;
    bool expect_valid;
    
    Case() = default;
    Case(const Case&) = default;
    Case(Case&&) = default;
    Case& operator=(const Case&) = default;
    Case& operator=(Case&&) = default;
    Case(std::string n, Buffer b, bool e)
        : name(std::move(n)), buffer(std::move(b)), expect_valid(e) {}
};

static std::vector<Case> build_cases() {
    std::vector<Case> cases;

    // Positive controls (6)
    cases.push_back(Case("minimal_valid",              make_minimal_valid(),              true));
    cases.push_back(Case("one_tensor_valid",             make_one_tensor_valid(),           true));
    cases.push_back(Case("two_tensors_valid",            make_two_tensors_valid(),          true));
    cases.push_back(Case("metadata_tensor_valid",        make_metadata_and_tensor(),        true));
    cases.push_back(Case("string_metadata_tensor_valid", make_string_metadata_tensor(),     true));
    cases.push_back(Case("q4_tensor_valid",              make_q4_tensor_valid(),            true));

    // Tensor-count truncation (5)
    cases.push_back(Case("tensor_count_1_truncated",     make_tensor_count_truncated(1),        false));
    cases.push_back(Case("tensor_count_255_truncated",   make_tensor_count_truncated(255),      false));
    cases.push_back(Case("tensor_count_1024_truncated",  make_tensor_count_truncated(1024),     false));
    cases.push_back(Case("tensor_count_4g_truncated",    make_tensor_count_truncated(0x100000000ULL), false));
    cases.push_back(Case("tensor_count_max_truncated",   make_tensor_count_truncated(std::numeric_limits<u64>::max()), false));

    // Tensor-name length boundaries (2)
    cases.push_back(Case("tensor_name_length_max",     make_name_length_max(),            false));
    cases.push_back(Case("tensor_name_truncated",        make_name_truncated(),             false));

    // Tensor dimension-count boundaries (2)
    cases.push_back(Case("tensor_dims_64",               make_dims_64(),                    false));
    cases.push_back(Case("tensor_dim_max",               make_dim_max(),                    false));

    // Tensor offset boundaries (4)
    cases.push_back(Case("tensor_offset_oob",            make_offset_oob(),                 false));
    cases.push_back(Case("tensor_offset_uint64_max",     make_offset_max(),                 false));
    cases.push_back(Case("tensor_offset_past_eof",       make_offset_past_eof(),            false));
    cases.push_back(Case("tensor_offset_negative_wrap",  make_negative_offset_wrapped(),    false));

    // Tensor offset + size overflow (1)
    cases.push_back(Case("tensor_offset_plus_size_overflow", make_offset_plus_size_overflow(), false));

    // Tensor type boundaries (3)
    cases.push_back(Case("tensor_invalid_type",          make_invalid_type(),               false));
    cases.push_back(Case("tensor_type_255",              make_type_255(),                   false));
    cases.push_back(Case("tensor_record_truncated",      make_record_truncation(),          false));

    // Alignment / data-start (1)
    cases.push_back(Case("tensor_offset_unaligned",      make_offset_alignment(),           false));

    // Combined count × record-size overflow (2)
    cases.push_back(Case("tensor_count_uint64_max",      make_huge_count(),                 false));
    cases.push_back(Case("tensor_count_record_overflow", make_count_record_overflow(),      false));

    // Tensor overlap (1)
    cases.push_back(Case("tensor_overlap",               make_tensor_overlap(),             false));

    // Zero dimension (1)
    cases.push_back(Case("tensor_zero_dim",              make_zero_dim(),                   false));

    // Count × record overflow v2 (1)
    cases.push_back(Case("count_times_record_overflow",  make_count_times_record_overflow(), false));

    // Deterministic mutations (17)
    auto mutations = make_deterministic_mutations();
    for (auto& m : mutations) {
        cases.push_back(std::move(m));
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
            c.name.c_str(),
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
