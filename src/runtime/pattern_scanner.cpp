// ============================================================================
// pattern_scanner.cpp — SIMD Pattern Scanner with Boyer-Moore-Horspool
// ============================================================================
// High-performance pattern matching for reverse engineering tasks
// Features: SSE4.2/AVX2, BMH optimization, Rabin-Karp fallback
// ============================================================================

#include <immintrin.h>
#include <intrin.h>  // For __cpuid, __cpuidex, _BitScanForward
#include <windows.h>
#include <cstdint>
#include <cstddef>
#include <cstring>

// CPU feature detection
static bool g_scannerInitialized = false;
static bool g_hasSSE42 = false;
static bool g_hasAVX2 = false;
static bool g_hasAVX512BW = false;

static void InitScannerFeatures() {
    if (g_scannerInitialized) return;
    
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 1);
    
    // SSE4.2: bit 20 of ECX
    g_hasSSE42 = (cpuInfo[2] & (1 << 20)) != 0;
    
    // AVX2: bit 5 of EBX from leaf 7
    int cpuInfo7[4] = {0};
    __cpuidex(cpuInfo7, 7, 0);
    g_hasAVX2 = (cpuInfo7[1] & (1 << 5)) != 0;
    
    // AVX-512BW: bit 30 of EBX from leaf 7
    g_hasAVX512BW = (cpuInfo7[1] & (1 << 30)) != 0;
    
    g_scannerInitialized = true;
}

// ============================================================================
// Boyer-Moore-Horspool Preprocessing
// ============================================================================

struct BMHTable {
    size_t badCharSkip[256];
    size_t patternLen;
};

static void BuildBMHTable(BMHTable* table, const uint8_t* pattern, size_t patternLen) {
    table->patternLen = patternLen;
    
    // Initialize all skips to pattern length
    for (int i = 0; i < 256; i++) {
        table->badCharSkip[i] = patternLen;
    }
    
    // Set skips for characters in pattern (except last)
    for (size_t i = 0; i < patternLen - 1; i++) {
        table->badCharSkip[pattern[i]] = patternLen - 1 - i;
    }
}

// ============================================================================
// Scalar BMH Search
// ============================================================================

static const uint8_t* BMHSearch(const uint8_t* data, size_t dataLen,
                                const uint8_t* pattern, size_t patternLen,
                                const BMHTable* table) {
    if (patternLen == 0 || dataLen < patternLen) {
        return nullptr;
    }
    
    if (patternLen == 1) {
        // Simple byte search
        return (const uint8_t*)memchr(data, pattern[0], dataLen);
    }
    
    const uint8_t* end = data + dataLen - patternLen;
    const uint8_t* p = data;
    
    while (p <= end) {
        // Check if pattern matches at current position
        if (memcmp(p, pattern, patternLen) == 0) {
            return p;
        }
        
        // Skip based on bad character
        p += table->badCharSkip[p[patternLen - 1]];
    }
    
    return nullptr;
}

// ============================================================================
// SSE4.2 Accelerated Search
// ============================================================================

static const uint8_t* SSE42Search(const uint8_t* data, size_t dataLen,
                                  const uint8_t* pattern, size_t patternLen) {
    if (patternLen == 0 || dataLen < patternLen) {
        return nullptr;
    }
    
    if (patternLen == 1) {
        return (const uint8_t*)memchr(data, pattern[0], dataLen);
    }
    
    // For small patterns, use first/last byte filtering with SSE4.2
    if (patternLen <= 16) {
        const uint8_t firstByte = pattern[0];
        const uint8_t lastByte = pattern[patternLen - 1];
        
        __m128i firstVec = _mm_set1_epi8(firstByte);
        __m128i lastVec = _mm_set1_epi8(lastByte);
        
        const uint8_t* p = data;
        const uint8_t* end = data + dataLen - patternLen;
        
        while (p <= end) {
            // Load 16 bytes
            __m128i block = _mm_loadu_si128((const __m128i*)p);
            
            // Find first byte matches
            __m128i firstMatch = _mm_cmpeq_epi8(block, firstVec);
            int firstMask = _mm_movemask_epi8(firstMatch);
            
            // Check last byte for each potential match
            while (firstMask != 0) {
                unsigned long bit;
                _BitScanForward(&bit, firstMask);
                if (p + bit + patternLen - 1 <= end &&
                    p[bit + patternLen - 1] == lastByte) {
                    // Full pattern check
                    if (memcmp(p + bit, pattern, patternLen) == 0) {
                        return p + bit;
                    }
                }
                firstMask &= ~(1 << bit);
            }
            
            p += 16;
        }
    }
    
    return nullptr;
}

// ============================================================================
// AVX2 Accelerated Search
// ============================================================================

static const uint8_t* AVX2Search(const uint8_t* data, size_t dataLen,
                                 const uint8_t* pattern, size_t patternLen) {
    if (patternLen == 0 || dataLen < patternLen) {
        return nullptr;
    }
    
    if (patternLen == 1) {
        return (const uint8_t*)memchr(data, pattern[0], dataLen);
    }
    
    // For small patterns, use AVX2 for parallel comparison
    if (patternLen <= 32) {
        const uint8_t firstByte = pattern[0];
        const uint8_t lastByte = pattern[patternLen - 1];
        
        __m256i firstVec = _mm256_set1_epi8(firstByte);
        __m256i lastVec = _mm256_set1_epi8(lastByte);
        
        const uint8_t* p = data;
        const uint8_t* end = data + dataLen - patternLen;
        
        while (p <= end - 32) {
            // Load 32 bytes
            __m256i block = _mm256_loadu_si256((const __m256i*)p);
            
            // Find first byte matches
            __m256i firstMatch = _mm256_cmpeq_epi8(block, firstVec);
            int firstMask = _mm256_movemask_epi8(firstMatch);
            
            // Check last byte for each potential match
            while (firstMask != 0) {
                unsigned long bit;
                _BitScanForward(&bit, firstMask);
                if (p + bit + patternLen - 1 <= end &&
                    p[bit + patternLen - 1] == lastByte) {
                    // Full pattern check
                    if (memcmp(p + bit, pattern, patternLen) == 0) {
                        return p + bit;
                    }
                }
                firstMask &= ~(1 << bit);
            }
            
            p += 32;
        }
        
        // Handle remainder with scalar
        while (p <= end) {
            if (p[0] == firstByte && p[patternLen - 1] == lastByte) {
                if (memcmp(p, pattern, patternLen) == 0) {
                    return p;
                }
            }
            p++;
        }
    }
    
    return nullptr;
}

// ============================================================================
// Rabin-Karp Rolling Hash (for multiple pattern search)
// ============================================================================

static const uint32_t RK_PRIME = 16777619;  // FNV prime
static const uint32_t RK_MOD = 0xFFFFFFFF; // 2^32

static uint32_t ComputeRKHash(const uint8_t* data, size_t len) {
    uint32_t hash = 2166136261; // FNV offset basis
    for (size_t i = 0; i < len; i++) {
        hash = (hash * RK_PRIME) ^ data[i];
    }
    return hash;
}

// ============================================================================
// Public API
// ============================================================================

extern "C" {

// Find pattern in memory - main entry point
const void* find_pattern_asm(const void* data, size_t dataLen,
                             const void* pattern, size_t patternLen) {
    InitScannerFeatures();
    
    if (!data || !pattern || dataLen == 0 || patternLen == 0) {
        return nullptr;
    }
    
    if (dataLen < patternLen) {
        return nullptr;
    }
    
    const uint8_t* data8 = (const uint8_t*)data;
    const uint8_t* pattern8 = (const uint8_t*)pattern;
    
    // Choose search strategy based on pattern size and CPU features
    if (patternLen >= 32 && dataLen >= 4096) {
        // Large pattern - use BMH
        BMHTable table;
        BuildBMHTable(&table, pattern8, patternLen);
        return BMHSearch(data8, dataLen, pattern8, patternLen, &table);
    }
    
    if (g_hasAVX2 && dataLen >= 64) {
        // AVX2 path for medium patterns
        const uint8_t* result = AVX2Search(data8, dataLen, pattern8, patternLen);
        if (result) return result;
    }
    
    if (g_hasSSE42 && dataLen >= 32) {
        // SSE4.2 path for smaller data
        const uint8_t* result = SSE42Search(data8, dataLen, pattern8, patternLen);
        if (result) return result;
    }
    
    // Fallback to BMH
    BMHTable table;
    BuildBMHTable(&table, pattern8, patternLen);
    return BMHSearch(data8, dataLen, pattern8, patternLen, &table);
}

// Find pattern with mask (for wildcard patterns)
const void* find_pattern_masked_asm(const void* data, size_t dataLen,
                                      const void* pattern, const void* mask,
                                      size_t patternLen) {
    if (!data || !pattern || !mask || dataLen == 0 || patternLen == 0) {
        return nullptr;
    }
    
    if (dataLen < patternLen) {
        return nullptr;
    }
    
    const uint8_t* data8 = (const uint8_t*)data;
    const uint8_t* pattern8 = (const uint8_t*)pattern;
    const uint8_t* mask8 = (const uint8_t*)mask;
    
    const uint8_t* end = data8 + dataLen - patternLen;
    
    for (const uint8_t* p = data8; p <= end; p++) {
        bool match = true;
        for (size_t i = 0; i < patternLen; i++) {
            if ((p[i] & mask8[i]) != (pattern8[i] & mask8[i])) {
                match = false;
                break;
            }
        }
        if (match) {
            return p;
        }
    }
    
    return nullptr;
}

// Find all occurrences of a pattern
int find_all_patterns_asm(const void* data, size_t dataLen,
                          const void* pattern, size_t patternLen,
                          void** results, int maxResults) {
    if (!data || !pattern || !results || maxResults <= 0) {
        return 0;
    }
    
    int count = 0;
    const uint8_t* data8 = (const uint8_t*)data;
    const uint8_t* pattern8 = (const uint8_t*)pattern;
    
    BMHTable table;
    BuildBMHTable(&table, pattern8, patternLen);
    
    const uint8_t* p = data8;
    const uint8_t* end = data8 + dataLen;
    
    while (p < end && count < maxResults) {
        const uint8_t* match = BMHSearch(p, end - p, pattern8, patternLen, &table);
        if (!match) break;
        
        results[count++] = (void*)match;
        p = match + 1; // Continue search after this match
    }
    
    return count;
}

// Pattern scanner initialization
int pattern_scanner_init(void) {
    InitScannerFeatures();
    return 0;
}

// Get scanner capabilities
void pattern_scanner_get_caps(int* hasSSE42, int* hasAVX2, int* hasAVX512) {
    InitScannerFeatures();
    if (hasSSE42) *hasSSE42 = g_hasSSE42 ? 1 : 0;
    if (hasAVX2) *hasAVX2 = g_hasAVX2 ? 1 : 0;
    if (hasAVX512) *hasAVX512 = g_hasAVX512BW ? 1 : 0;
}

} // extern "C"
