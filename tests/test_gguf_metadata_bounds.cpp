/**
 * @file test_gguf_metadata_bounds.cpp
 * @brief B33 — GGUF Metadata Bounds Gate
 *
 * Attacks metadata parsing specifically with boundary values.
 * Classification: VALID (parser accepts) or REJECT (parser rejects).
 * No crash/hang = automatic failure.
 *
 * Standalone — uses inline parser matching production GGUFTensorLoader::ParseHeader().
 */

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>
#include <string>
#include <limits>

namespace {

static constexpr uint32_t GGUF_MAGIC    = 0x46554747; // "GGUF"
static constexpr uint32_t GGUF_VERSION  = 3;

// GGUF metadata types.
enum : uint32_t {
    GGUF_TYPE_UINT8   = 0,
    GGUF_TYPE_INT8    = 1,
    GGUF_TYPE_UINT16  = 2,
    GGUF_TYPE_INT16   = 3,
    GGUF_TYPE_UINT32  = 4,
    GGUF_TYPE_INT32   = 5,
    GGUF_TYPE_FLOAT32 = 6,
    GGUF_TYPE_BOOL    = 7,
    GGUF_TYPE_STRING  = 8,
    GGUF_TYPE_ARRAY   = 9,
    GGUF_TYPE_UINT64  = 10,
    GGUF_TYPE_INT64   = 11,
    GGUF_TYPE_FLOAT64 = 12
};

struct Buffer {
    std::vector<uint8_t> bytes;

    void u32(uint32_t v) {
        bytes.push_back(static_cast<uint8_t>(v));
        bytes.push_back(static_cast<uint8_t>(v >> 8));
        bytes.push_back(static_cast<uint8_t>(v >> 16));
        bytes.push_back(static_cast<uint8_t>(v >> 24));
    }

    void u64(uint64_t v) {
        for (unsigned i = 0; i != 8; ++i)
            bytes.push_back(static_cast<uint8_t>(v >> (i * 8)));
    }

    void raw(const void* p, size_t n) {
        const auto* b = static_cast<const uint8_t*>(p);
        bytes.insert(bytes.end(), b, b + n);
    }

    void resize(size_t n) {
        bytes.resize(n, 0);
    }
};

static void make_header(Buffer& b,
                        uint64_t tensor_count,
                        uint64_t metadata_count) {
    b.bytes.clear();

    // "GGUF" magic (little-endian: 0x46554747)
    b.bytes.push_back('G');
    b.bytes.push_back('G');
    b.bytes.push_back('U');
    b.bytes.push_back('F');

    b.u32(GGUF_VERSION);
    b.u64(tensor_count);
    b.u64(metadata_count);
}

static void metadata_string(Buffer& b,
                            const char* key,
                            const char* value) {
    const uint64_t key_len = std::strlen(key);
    const uint64_t value_len = std::strlen(value);

    b.u64(key_len);
    b.raw(key, static_cast<size_t>(key_len));

    b.u32(GGUF_TYPE_STRING);

    b.u64(value_len);
    b.raw(value, static_cast<size_t>(value_len));
}

static void metadata_u32(Buffer& b,
                         const char* key,
                         uint32_t value) {
    const uint64_t key_len = std::strlen(key);

    b.u64(key_len);
    b.raw(key, static_cast<size_t>(key_len));

    b.u32(GGUF_TYPE_UINT32);
    b.u32(value);
}

static void metadata_bool(Buffer& b,
                          const char* key,
                          uint8_t value) {
    const uint64_t key_len = std::strlen(key);

    b.u64(key_len);
    b.raw(key, static_cast<size_t>(key_len));

    b.u32(GGUF_TYPE_BOOL);
    b.bytes.push_back(value);
}

static void metadata_bad_type(Buffer& b,
                              const char* key,
                              uint32_t type) {
    const uint64_t key_len = std::strlen(key);

    b.u64(key_len);
    b.raw(key, static_cast<size_t>(key_len));
    b.u32(type);
}

static void metadata_string_length_only(Buffer& b,
                                        const char* key,
                                        uint64_t length) {
    const uint64_t key_len = std::strlen(key);

    b.u64(key_len);
    b.raw(key, static_cast<size_t>(key_len));

    b.u32(GGUF_TYPE_STRING);
    b.u64(length);
}

static void metadata_array_length_only(Buffer& b,
                                       const char* key,
                                       uint32_t element_type,
                                       uint64_t count) {
    const uint64_t key_len = std::strlen(key);

    b.u64(key_len);
    b.raw(key, static_cast<size_t>(key_len));

    b.u32(GGUF_TYPE_ARRAY);
    b.u32(element_type);
    b.u64(count);
}

static bool parse(const Buffer& b) {
    const uint8_t* data = b.bytes.data();
    size_t len = b.bytes.size();

    if (!data || len < 64) {
        return false;
    }

    const uint8_t* ptr = data;
    const uint8_t* end = data + len;

    // Magic
    uint32_t magic;
    std::memcpy(&magic, ptr, sizeof(magic));
    ptr += sizeof(magic);
    if (magic != GGUF_MAGIC) return false;

    // Version
    uint32_t version;
    std::memcpy(&version, ptr, sizeof(version));
    ptr += sizeof(version);
    if (version != 3) return false;

    // Tensor count
    uint64_t tensor_count;
    std::memcpy(&tensor_count, ptr, sizeof(tensor_count));
    ptr += sizeof(tensor_count);

    // Metadata count
    uint64_t metadata_count;
    std::memcpy(&metadata_count, ptr, sizeof(metadata_count));
    ptr += sizeof(metadata_count);

    // Skip metadata with bounds checks (matching production parser)
    for (uint64_t i = 0; i < metadata_count && ptr < end; ++i) {
        // Key length
        if (ptr + sizeof(uint64_t) > end) return false;
        uint64_t key_len;
        std::memcpy(&key_len, ptr, sizeof(key_len));
        ptr += sizeof(key_len);
        if (key_len > static_cast<uint64_t>(end - ptr)) return false;
        ptr += key_len;

        // Value type
        if (ptr + sizeof(uint32_t) > end) return false;
        uint32_t value_type;
        std::memcpy(&value_type, ptr, sizeof(value_type));
        ptr += sizeof(value_type);

        // Skip value based on type
        switch (value_type) {
            case 0: case 1:
                if (ptr + 1 > end) return false;
                ptr += 1; break;
            case 2: case 3:
                if (ptr + 2 > end) return false;
                ptr += 2; break;
            case 4: case 5: case 6:
                if (ptr + 4 > end) return false;
                ptr += 4; break;
            case 7:
                if (ptr + 1 > end) return false;
                ptr += 1; break;
            case 8: {
                if (ptr + sizeof(uint64_t) > end) return false;
                uint64_t str_len;
                std::memcpy(&str_len, ptr, sizeof(str_len));
                ptr += sizeof(str_len);
                if (str_len > static_cast<uint64_t>(end - ptr)) return false;
                ptr += str_len;
                break;
            }
            case 9: {
                if (ptr + sizeof(uint32_t) > end) return false;
                uint32_t arr_type;
                std::memcpy(&arr_type, ptr, sizeof(arr_type));
                ptr += sizeof(arr_type);
                if (ptr + sizeof(uint64_t) > end) return false;
                uint64_t arr_len;
                std::memcpy(&arr_len, ptr, sizeof(arr_len));
                ptr += sizeof(arr_len);
                for (uint64_t j = 0; j < arr_len && ptr < end; ++j) {
                    size_t elem_size = 0;
                    switch (arr_type) {
                        case 0: case 1: elem_size = 1; break;
                        case 2: case 3: elem_size = 2; break;
                        case 4: case 5: case 6: elem_size = 4; break;
                        case 7: elem_size = 1; break;
                        case 8: {
                            if (ptr + sizeof(uint64_t) > end) return false;
                            uint64_t sl;
                            std::memcpy(&sl, ptr, sizeof(sl));
                            ptr += sizeof(sl);
                            if (sl > static_cast<uint64_t>(end - ptr)) return false;
                            ptr += sl;
                            continue;
                        }
                        case 9: elem_size = 0; break;
                        case 10: case 11: case 12: elem_size = 8; break;
                        default: elem_size = 8; break;
                    }
                    if (elem_size > 0) {
                        if (ptr + elem_size > end) return false;
                        ptr += elem_size;
                    }
                }
                break;
            }
            case 10: case 11: case 12:
                if (ptr + 8 > end) return false;
                ptr += 8; break;
            default:
                return false; // Unknown type
        }
    }

    // Parse tensor info with bounds checks
    for (uint64_t i = 0; i < tensor_count && ptr < end; ++i) {
        if (ptr + sizeof(uint64_t) > end) return false;
        uint64_t name_len;
        std::memcpy(&name_len, ptr, sizeof(name_len));
        ptr += sizeof(name_len);
        if (name_len > static_cast<uint64_t>(end - ptr)) return false;
        ptr += name_len;

        if (ptr + sizeof(uint32_t) > end) return false;
        uint32_t n_dims;
        std::memcpy(&n_dims, ptr, sizeof(n_dims));
        ptr += sizeof(n_dims);
        for (uint32_t d = 0; d < n_dims; ++d) {
            if (ptr + sizeof(uint64_t) > end) return false;
            ptr += sizeof(uint64_t);
        }

        if (ptr + sizeof(uint32_t) > end) return false;
        ptr += sizeof(uint32_t);

        if (ptr + sizeof(uint64_t) > end) return false;
        uint64_t offset;
        std::memcpy(&offset, ptr, sizeof(offset));
        ptr += sizeof(offset);
        if (offset > len) return false;
    }

    return true;
}

enum class Expected {
    Valid,
    Reject
};

struct Case {
    std::string name;
    Buffer data;
    Expected expected;
};

static Case make_case(const std::string& name,
                      Expected expected) {
    Case c{};
    c.name = name;
    c.expected = expected;
    return c;
}

} // namespace

int main() {
    std::vector<Case> cases;

    /*
     * ---------------------------------------------------------------
     * Positive controls
     * ---------------------------------------------------------------
     */

    {
        Case c = make_case("metadata_count_zero", Expected::Valid);
        make_header(c.data, 0, 0);
        c.data.resize(64);
        cases.push_back(std::move(c));
    }

    {
        Case c = make_case("metadata_count_one_uint32", Expected::Valid);
        make_header(c.data, 0, 1);
        metadata_u32(c.data, "test.key", 42);
        c.data.resize(64);
        cases.push_back(std::move(c));
    }

    {
        Case c = make_case("metadata_count_one_string", Expected::Valid);
        make_header(c.data, 0, 1);
        metadata_string(c.data, "test.key", "hello");
        c.data.resize(64);
        cases.push_back(std::move(c));
    }

    {
        Case c = make_case("metadata_count_one_bool", Expected::Valid);
        make_header(c.data, 0, 1);
        metadata_bool(c.data, "test.bool", 1);
        c.data.resize(64);
        cases.push_back(std::move(c));
    }

    /*
     * ---------------------------------------------------------------
     * Metadata count truncation
     * ---------------------------------------------------------------
     */

    {
        Case c = make_case("metadata_count_two_truncated", Expected::Reject);
        make_header(c.data, 0, 2);
        metadata_u32(c.data, "only.one", 1);
        cases.push_back(std::move(c));
    }

    {
        Case c = make_case("metadata_count_255_truncated", Expected::Reject);
        make_header(c.data, 0, 255);
        metadata_u32(c.data, "only.one", 1);
        cases.push_back(std::move(c));
    }

    {
        Case c = make_case("metadata_count_max_truncated", Expected::Reject);
        make_header(c.data, 0, std::numeric_limits<uint64_t>::max());
        cases.push_back(std::move(c));
    }

    /*
     * ---------------------------------------------------------------
     * Key-length boundaries
     * ---------------------------------------------------------------
     */

    {
        Case c = make_case("key_length_zero", Expected::Valid);
        make_header(c.data, 0, 1);
        c.data.u64(0);
        c.data.u32(GGUF_TYPE_UINT8);
        c.data.bytes.push_back(7);
        c.data.resize(64);
        cases.push_back(std::move(c));
    }

    {
        Case c = make_case("key_length_one", Expected::Valid);
        make_header(c.data, 0, 1);
        c.data.u64(1);
        c.data.bytes.push_back('x');
        c.data.u32(GGUF_TYPE_UINT8);
        c.data.bytes.push_back(7);
        c.data.resize(64);
        cases.push_back(std::move(c));
    }

    {
        Case c = make_case("key_length_truncated", Expected::Reject);
        make_header(c.data, 0, 1);
        c.data.u64(1024);
        c.data.bytes.push_back('x');
        cases.push_back(std::move(c));
    }

    {
        Case c = make_case("key_length_uint64_max", Expected::Reject);
        make_header(c.data, 0, 1);
        c.data.u64(std::numeric_limits<uint64_t>::max());
        cases.push_back(std::move(c));
    }

    /*
     * ---------------------------------------------------------------
     * String-length boundaries
     * ---------------------------------------------------------------
     */

    {
        Case c = make_case("string_length_zero", Expected::Valid);
        make_header(c.data, 0, 1);
        metadata_string_length_only(c.data, "empty", 0);
        c.data.resize(64);
        cases.push_back(std::move(c));
    }

    {
        Case c = make_case("string_length_one_truncated", Expected::Reject);
        make_header(c.data, 0, 1);
        metadata_string_length_only(c.data, "one", 1);
        cases.push_back(std::move(c));
    }

    {
        Case c = make_case("string_length_4096_truncated", Expected::Reject);
        make_header(c.data, 0, 1);
        metadata_string_length_only(c.data, "large", 4096);
        cases.push_back(std::move(c));
    }

    {
        Case c = make_case("string_length_uint64_max", Expected::Reject);
        make_header(c.data, 0, 1);
        metadata_string_length_only(c.data, "overflow", std::numeric_limits<uint64_t>::max());
        cases.push_back(std::move(c));
    }

    /*
     * ---------------------------------------------------------------
     * Array-length boundaries
     * ---------------------------------------------------------------
     */

    {
        Case c = make_case("array_length_zero", Expected::Valid);
        make_header(c.data, 0, 1);
        metadata_array_length_only(c.data, "empty.array", GGUF_TYPE_UINT8, 0);
        c.data.resize(64);
        cases.push_back(std::move(c));
    }

    {
        Case c = make_case("array_length_one_truncated", Expected::Reject);
        make_header(c.data, 0, 1);
        metadata_array_length_only(c.data, "one.array", GGUF_TYPE_UINT64, 1);
        cases.push_back(std::move(c));
    }

    {
        Case c = make_case("array_length_4096_truncated", Expected::Reject);
        make_header(c.data, 0, 1);
        metadata_array_length_only(c.data, "large.array", GGUF_TYPE_UINT32, 4096);
        cases.push_back(std::move(c));
    }

    {
        Case c = make_case("array_length_uint64_max", Expected::Reject);
        make_header(c.data, 0, 1);
        metadata_array_length_only(c.data, "overflow.array", GGUF_TYPE_UINT8, std::numeric_limits<uint64_t>::max());
        cases.push_back(std::move(c));
    }

    /*
     * ---------------------------------------------------------------
     * Metadata type validation
     * ---------------------------------------------------------------
     */

    const uint32_t invalid_types[] = {
        13,
        14,
        15,
        0x7fffffffU,
        0xffffffffU
    };

    for (uint32_t type : invalid_types) {
        char name[64];
        std::snprintf(name, sizeof(name), "invalid_metadata_type_%08x", type);

        Case c = make_case(name, Expected::Reject);
        make_header(c.data, 0, 1);
        metadata_bad_type(c.data, "bad.type", type);
        cases.push_back(std::move(c));
    }

    /*
     * ---------------------------------------------------------------
     * Header-level count overflow boundaries
     * ---------------------------------------------------------------
     */

    {
        const uint64_t counts[] = {
            2, 16, 1024, 0x100000000ULL, std::numeric_limits<uint64_t>::max()
        };

        for (uint64_t count : counts) {
            char name[80];
            std::snprintf(name, sizeof(name), "metadata_count_%llu_truncated",
                          static_cast<unsigned long long>(count));

            Case c = make_case(name, Expected::Reject);
            make_header(c.data, 0, count);
            cases.push_back(std::move(c));
        }
    }

    /*
     * ---------------------------------------------------------------
     * Execute
     * ---------------------------------------------------------------
     */

    size_t passed = 0;
    size_t failed = 0;

    std::printf("B33 GGUF Metadata Bounds Gate\n");
    std::printf("CASES=%zu\n", cases.size());

    for (size_t i = 0; i < cases.size(); ++i) {
        const Case& c = cases[i];

        bool accepted = parse(c.data);

        bool pass = false;
        if (c.expected == Expected::Valid)
            pass = accepted;
        else
            pass = !accepted;

        std::printf("CASE=%03zu NAME=%s EXPECTED=%s RESULT=%s\n",
                    i, c.name.c_str(),
                    c.expected == Expected::Valid ? "VALID" : "REJECT",
                    pass ? "PASS" : "FAIL");

        if (pass)
            ++passed;
        else
            ++failed;
    }

    std::printf("B33_RESULT=%zu/%zu PASS\n", passed, cases.size());

    if (failed != 0) {
        std::printf("B33_RESULT=FAIL\n");
        return 1;
    }

    std::printf("B33_RESULT=PASS\n");
    return 0;
}
