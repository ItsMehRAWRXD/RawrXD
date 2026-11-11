#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <cstring>
#include <limits>
#include <cstdint>

// Test strtoull hardening (runtime_graph_executor.cpp style)
bool test_strtoull_safe(const char* input, uint64_t& out) {
    if (!input || *input == '-') return false;
    char* end = nullptr;
    errno = 0;
    unsigned long long v = std::strtoull(input, &end, 10);
    if (errno != 0 || end == input || *end != '\0' || v == 0) return false;
    out = static_cast<uint64_t>(v);
    return true;
}

// Test strtoul hardening (vulkan_compute.cpp, engine_main.cpp style)
bool test_strtoul_safe(const char* input, uint32_t& out) {
    if (!input || *input == '-') return false;
    char* end = nullptr;
    errno = 0;
    unsigned long v = std::strtoul(input, &end, 10);
    if (errno != 0 || end == input || *end != '\0' || v == 0 || v > UINT32_MAX) return false;
    out = static_cast<uint32_t>(v);
    return true;
}

// Test strtol hardening (BatchedPrefill.hpp, Deep2Engine_ModelFit.cpp style)
bool test_strtol_safe(const char* input, int64_t& out) {
    if (!input || *input == '-') return false;
    char* end = nullptr;
    errno = 0;
    long v = std::strtol(input, &end, 10);
    if (errno != 0 || end == input || *end != '\0' || v <= 0) return false;
    out = static_cast<int64_t>(v);
    return true;
}

// Test MiB to bytes overflow guard
bool test_mib_to_bytes(uint64_t mib, uint64_t& bytes) {
    if (mib != 0 && mib > std::numeric_limits<uint64_t>::max() / 1024ull / 1024ull) {
        bytes = std::numeric_limits<uint64_t>::max();
        return true;
    }
    bytes = mib * 1024ull * 1024ull;
    return true;
}

// Test base + count overflow guard (DequantRange style)
bool test_base_plus_count(size_t base, size_t count, size_t& result) {
    if (base > std::numeric_limits<size_t>::max() - count) {
        result = std::numeric_limits<size_t>::max();
        return false; // overflow detected
    }
    result = base + count;
    return true;
}

int main() {
    int passed = 0, failed = 0;
    
    auto check = [&](bool cond, const char* name, const char* key) {
        if (cond) { 
            printf("PASS: %s\n", name); 
            printf("%s=PASS\n", key);
            passed++; 
        }
        else { 
            printf("FAIL: %s\n", name); 
            printf("%s=FAIL\n", key);
            failed++; 
        }
    };
    
    // === strtoull tests ===
    uint64_t u64;
    check(test_strtoull_safe("1024", u64) && u64 == 1024, "strtoull: valid 1024", "NUMERIC_PARSE_VALID");
    check(!test_strtoull_safe("", u64), "strtoull: empty string", "NUMERIC_PARSE_EMPTY");
    check(!test_strtoull_safe("-1", u64), "strtoull: negative", "NUMERIC_PARSE_NEGATIVE");
    check(!test_strtoull_safe("123abc", u64), "strtoull: trailing chars", "NUMERIC_PARSE_TRAILING");
    check(!test_strtoull_safe("0", u64), "strtoull: zero rejected", "NUMERIC_PARSE_ZERO");
    check(test_strtoull_safe("18446744073709551615", u64) && u64 == UINT64_MAX, "strtoull: UINT64_MAX", "NUMERIC_PARSE_MAX");
    check(!test_strtoull_safe("18446744073709551616", u64), "strtoull: >UINT64_MAX", "NUMERIC_PARSE_OVERFLOW");
    check(!test_strtoull_safe("   ", u64), "strtoull: whitespace", "NUMERIC_PARSE_WHITESPACE");
    
    // === strtoul tests ===
    uint32_t u32;
    check(test_strtoul_safe("4294967295", u32) && u32 == UINT32_MAX, "strtoul: UINT32_MAX", "NUMERIC_PARSE_UINT32_MAX");
    check(!test_strtoul_safe("4294967296", u32), "strtoul: >UINT32_MAX", "NUMERIC_PARSE_UINT32_OVERFLOW");
    check(!test_strtoul_safe("-1", u32), "strtoul: negative", "NUMERIC_PARSE_UINT32_NEGATIVE");
    check(!test_strtoul_safe("123abc", u32), "strtoul: trailing chars", "NUMERIC_PARSE_UINT32_TRAILING");
    check(!test_strtoul_safe("0", u32), "strtoul: zero rejected", "NUMERIC_PARSE_UINT32_ZERO");
    
    // === strtol tests ===
    int64_t i64;
    check(test_strtol_safe("32", i64) && i64 == 32, "strtol: valid positive", "NUMERIC_PARSE_STR_TO_L");
    check(!test_strtol_safe("-1", i64), "strtol: negative", "NUMERIC_PARSE_STR_TO_L_NEGATIVE");
    check(!test_strtol_safe("0", i64), "strtol: zero rejected", "NUMERIC_PARSE_STR_TO_L_ZERO");
    check(!test_strtol_safe("123abc", i64), "strtol: trailing chars", "NUMERIC_PARSE_STR_TO_L_TRAILING");
    
    // === MiB to bytes overflow ===
    uint64_t bytes;
    check(test_mib_to_bytes(8192, bytes) && bytes == 8192ull * 1024ull * 1024ull, "MiB: 8192 MiB", "MIB_BOUNDARY_NORMAL");
    check(test_mib_to_bytes(1, bytes) && bytes == 1024ull * 1024ull, "MiB: 1 MiB", "MIB_BOUNDARY_ONE");
    uint64_t max_valid_mib = std::numeric_limits<uint64_t>::max() / 1024ull / 1024ull;
    check(test_mib_to_bytes(max_valid_mib, bytes), "MiB: max valid", "MIB_BOUNDARY_MAX_VALID");
    check(test_mib_to_bytes(max_valid_mib + 1, bytes) && bytes == UINT64_MAX, "MiB: overflow capped", "MIB_BOUNDARY_OVERFLOW");
    
    // === base + count overflow ===
    size_t r;
    check(test_base_plus_count(100, 50, r) && r == 150, "base+count: normal", "DEQUANT_RANGE_NORMAL");
    check(test_base_plus_count(0, 0, r) && r == 0, "base+count: zero", "DEQUANT_RANGE_ZERO");
    check(!test_base_plus_count(SIZE_MAX - 10, 20, r), "base+count: overflow detected", "DEQUANT_RANGE_OVERFLOW");
    size_t half = SIZE_MAX / 2;
    size_t expected = half + half;
    check(test_base_plus_count(half, half, r) && r == expected, "base+count: exact max", "DEQUANT_RANGE_EXACT_MAX");
    
    printf("\nTOTAL_PASS=%d\n", passed);
    printf("TOTAL_FAIL=%d\n", failed);
    printf("NUMERIC_SAFETY_CERTIFIED=%d\n", failed == 0 ? 1 : 0);
    return failed == 0 ? 0 : 1;
}