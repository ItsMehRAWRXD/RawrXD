/**
 * @file aperture_cpu_features.cpp
 * @brief CPU Feature Detection and Kernel Dispatch
 * @version 1.0.0
 * 
 * Runtime CPU feature detection for Aperture kernels.
 * Automatically selects optimal implementation based on CPU capabilities.
 * 
 * @copyright (c) 2025 RawrXD Project
 */

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdio>

#ifdef _WIN32
#include <windows.h>
#include <intrin.h>
#else
#include <cpuid.h>
#endif

// ============================================================================
// CPU FEATURE FLAGS
// ============================================================================

// CPUID feature flags (ECX/EDX from leaf 1)
#define CPUID_FEAT_ECX_SSE3     (1 << 0)
#define CPUID_FEAT_ECX_SSSE3    (1 << 9)
#define CPUID_FEAT_ECX_SSE41    (1 << 19)
#define CPUID_FEAT_ECX_SSE42    (1 << 20)
#define CPUID_FEAT_ECX_AVX      (1 << 28)
#define CPUID_FEAT_ECX_FMA3     (1 << 12)

#define CPUID_FEAT_EDX_SSE      (1 << 25)
#define CPUID_FEAT_EDX_SSE2     (1 << 26)

// Extended feature flags (leaf 7, EBX)
#define CPUID_EXT_FEAT_EBX_AVX2     (1 << 5)
#define CPUID_EXT_FEAT_EBX_AVX512F  (1 << 16)
#define CPUID_EXT_FEAT_EBX_AVX512DQ (1 << 17)
#define CPUID_EXT_FEAT_EBX_AVX512IFMA (1 << 21)
#define CPUID_EXT_FEAT_EBX_AVX512PF (1 << 26)
#define CPUID_EXT_FEAT_EBX_AVX512ER (1 << 27)
#define CPUID_EXT_FEAT_EBX_AVX512CD (1 << 28)
#define CPUID_EXT_FEAT_EBX_AVX512BW (1 << 30)
#define CPUID_EXT_FEAT_EBX_AVX512VL (1 << 31)

// Extended feature flags (leaf 7, ECX)
#define CPUID_EXT_FEAT_ECX_AVX512VBMI  (1 << 1)
#define CPUID_EXT_FEAT_ECX_AVX512VNNI  (1 << 11)
#define CPUID_EXT_FEAT_ECX_AVX512BITALG (1 << 12)
#define CPUID_EXT_FEAT_ECX_AVX512VPOPCNTDQ (1 << 14)
#define CPUID_EXT_FEAT_ECX_AVX512BF16 (1 << 5)

// ============================================================================
// CPU INFO STRUCTURE
// ============================================================================

typedef struct {
    char vendor[13];           // CPU vendor string (12 chars + null)
    char brand[49];          // CPU brand string (48 chars + null)
    uint32_t family;
    uint32_t model;
    uint32_t stepping;
    
    // Feature flags
    uint32_t features_ecx;
    uint32_t features_edx;
    uint32_t ext_features_ebx;
    uint32_t ext_features_ecx;
    uint32_t ext_features_edx;
    
    // AVX-512 specific
    int has_avx512f;
    int has_avx512dq;
    int has_avx512ifma;
    int has_avx512pf;
    int has_avx512er;
    int has_avx512cd;
    int has_avx512bw;
    int has_avx512vl;
    int has_avx512vbmi;
    int has_avx512vnni;
    int has_avx512bitalg;
    int has_avx512vpopcntdq;
    int has_avx512bf16;
    
    // Other features
    int has_avx;
    int has_avx2;
    int has_fma;
    int has_sse41;
    int has_sse42;
    int has_bmi1;
    int has_bmi2;
    int has_lzcnt;
    int has_popcnt;
} ApertureCPUInfo;

// Global CPU info (initialized once)
static ApertureCPUInfo g_cpu_info = {0};
static int g_cpu_info_initialized = 0;

// ============================================================================
// INTERNAL FUNCTIONS
// ============================================================================

#ifdef _WIN32
static void cpuid(int info[4], int function_id) {
    __cpuid(info, function_id);
}

static void cpuidex(int info[4], int function_id, int subfunction_id) {
    __cpuidex(info, function_id, subfunction_id);
}
#else
static void cpuid(int info[4], int function_id) {
    __cpuid(function_id, info[0], info[1], info[2], info[3]);
}

static void cpuidex(int info[4], int function_id, int subfunction_id) {
    __cpuid_count(function_id, subfunction_id, info[0], info[1], info[2], info[3]);
}
#endif

static int check_xcr0_avx512() {
#ifdef _WIN32
    // Check XCR0 for AVX-512 OS support
    // Bits 5-7 must be set (ZMM_Hi256, ZMM_Lo256, ZMM_Hi128)
    uint64_t xcr0 = _xgetbv(0);
    return (xcr0 & 0xE0) == 0xE0;  // Check bits 5, 6, 7
#else
    // On Linux, check via /proc/cpuinfo or assume supported if AVX-512 present
    return 1;
#endif
}

// ============================================================================
// PUBLIC API
// ============================================================================

/**
 * @brief Initialize CPU feature detection
 * 
 * Must be called once before using any Aperture kernels.
 * Safe to call multiple times (idempotent).
 */
extern "C" void Aperture_InitCPUFeatures(void) {
    if (g_cpu_info_initialized) {
        return;  // Already initialized
    }
    
    int info[4];
    
    // Get vendor string
    cpuid(info, 0);
    int max_basic_id = info[0];
    
    // Vendor string is in EBX, EDX, ECX (in that order)
    memcpy(g_cpu_info.vendor, &info[1], 4);
    memcpy(g_cpu_info.vendor + 4, &info[3], 4);
    memcpy(g_cpu_info.vendor + 8, &info[2], 4);
    g_cpu_info.vendor[12] = '\0';
    
    // Get basic features
    if (max_basic_id >= 1) {
        cpuid(info, 1);
        g_cpu_info.features_ecx = info[2];
        g_cpu_info.features_edx = info[3];
        
        g_cpu_info.family = ((info[0] >> 8) & 0x0F) + ((info[0] >> 20) & 0xFF);
        g_cpu_info.model = ((info[0] >> 4) & 0x0F) | ((info[0] >> 12) & 0xF0);
        g_cpu_info.stepping = info[0] & 0x0F;
        
        // Check basic features
        g_cpu_info.has_sse41 = (info[2] & CPUID_FEAT_ECX_SSE41) != 0;
        g_cpu_info.has_sse42 = (info[2] & CPUID_FEAT_ECX_SSE42) != 0;
        g_cpu_info.has_avx = (info[2] & CPUID_FEAT_ECX_AVX) != 0;
        g_cpu_info.has_fma = (info[2] & CPUID_FEAT_ECX_FMA3) != 0;
    }
    
    // Get extended features (leaf 7)
    if (max_basic_id >= 7) {
        cpuidex(info, 7, 0);
        g_cpu_info.ext_features_ebx = info[1];
        g_cpu_info.ext_features_ecx = info[2];
        g_cpu_info.ext_features_edx = info[3];
        
        // Check AVX-512 features
        g_cpu_info.has_avx512f = (info[1] & CPUID_EXT_FEAT_EBX_AVX512F) != 0;
        g_cpu_info.has_avx512dq = (info[1] & CPUID_EXT_FEAT_EBX_AVX512DQ) != 0;
        g_cpu_info.has_avx512ifma = (info[1] & CPUID_EXT_FEAT_EBX_AVX512IFMA) != 0;
        g_cpu_info.has_avx512pf = (info[1] & CPUID_EXT_FEAT_EBX_AVX512PF) != 0;
        g_cpu_info.has_avx512er = (info[1] & CPUID_EXT_FEAT_EBX_AVX512ER) != 0;
        g_cpu_info.has_avx512cd = (info[1] & CPUID_EXT_FEAT_EBX_AVX512CD) != 0;
        g_cpu_info.has_avx512bw = (info[1] & CPUID_EXT_FEAT_EBX_AVX512BW) != 0;
        g_cpu_info.has_avx512vl = (info[1] & CPUID_EXT_FEAT_EBX_AVX512VL) != 0;
        
        g_cpu_info.has_avx512vbmi = (info[2] & CPUID_EXT_FEAT_ECX_AVX512VBMI) != 0;
        g_cpu_info.has_avx512vnni = (info[2] & CPUID_EXT_FEAT_ECX_AVX512VNNI) != 0;
        g_cpu_info.has_avx512bitalg = (info[2] & CPUID_EXT_FEAT_ECX_AVX512BITALG) != 0;
        g_cpu_info.has_avx512vpopcntdq = (info[2] & CPUID_EXT_FEAT_ECX_AVX512VPOPCNTDQ) != 0;
        g_cpu_info.has_avx512bf16 = (info[2] & CPUID_EXT_FEAT_ECX_AVX512BF16) != 0;
        
        // Check AVX2
        g_cpu_info.has_avx2 = (info[1] & CPUID_EXT_FEAT_EBX_AVX2) != 0;
        
        // Check BMI
        g_cpu_info.has_bmi1 = (info[1] & (1 << 3)) != 0;
        g_cpu_info.has_bmi2 = (info[1] & (1 << 8)) != 0;
    }
    
    // Check for AVX-512 OS support via XCR0
    if (g_cpu_info.has_avx512f) {
        if (!check_xcr0_avx512()) {
            // OS doesn't support AVX-512, disable it
            g_cpu_info.has_avx512f = 0;
            g_cpu_info.has_avx512dq = 0;
            g_cpu_info.has_avx512ifma = 0;
            g_cpu_info.has_avx512pf = 0;
            g_cpu_info.has_avx512er = 0;
            g_cpu_info.has_avx512cd = 0;
            g_cpu_info.has_avx512bw = 0;
            g_cpu_info.has_avx512vl = 0;
            g_cpu_info.has_avx512vbmi = 0;
            g_cpu_info.has_avx512vnni = 0;
            g_cpu_info.has_avx512bitalg = 0;
            g_cpu_info.has_avx512vpopcntdq = 0;
            g_cpu_info.has_avx512bf16 = 0;
        }
    }
    
    // Get brand string (leaves 0x80000002-0x80000004)
    cpuid(info, 0x80000000);
    if (info[0] >= 0x80000004) {
        char brand[48];
        cpuid(info, 0x80000002);
        memcpy(brand, info, 16);
        cpuid(info, 0x80000003);
        memcpy(brand + 16, info, 16);
        cpuid(info, 0x80000004);
        memcpy(brand + 32, info, 16);
        
        // Trim leading spaces
        int start = 0;
        while (start < 48 && brand[start] == ' ') start++;
        memcpy(g_cpu_info.brand, brand + start, 48 - start);
        g_cpu_info.brand[48 - start] = '\0';
    }
    
    g_cpu_info_initialized = 1;
}

/**
 * @brief Check if AVX-512 Foundation is available
 */
extern "C" int Aperture_HasAVX512F(void) {
    if (!g_cpu_info_initialized) Aperture_InitCPUFeatures();
    return g_cpu_info.has_avx512f;
}

/**
 * @brief Check if AVX-512 Byte/Word is available
 */
extern "C" int Aperture_HasAVX512BW(void) {
    if (!g_cpu_info_initialized) Aperture_InitCPUFeatures();
    return g_cpu_info.has_avx512bw;
}

/**
 * @brief Check if AVX-512 Double/Quad is available
 */
extern "C" int Aperture_HasAVX512DQ(void) {
    if (!g_cpu_info_initialized) Aperture_InitCPUFeatures();
    return g_cpu_info.has_avx512dq;
}

/**
 * @brief Check if AVX-512 Vector Length is available
 */
extern "C" int Aperture_HasAVX512VL(void) {
    if (!g_cpu_info_initialized) Aperture_InitCPUFeatures();
    return g_cpu_info.has_avx512vl;
}

/**
 * @brief Check if AVX-512 VNNI is available
 */
extern "C" int Aperture_HasAVX512VNNI(void) {
    if (!g_cpu_info_initialized) Aperture_InitCPUFeatures();
    return g_cpu_info.has_avx512vnni;
}

/**
 * @brief Check if AVX-512 BF16 is available
 */
extern "C" int Aperture_HasAVX512BF16(void) {
    if (!g_cpu_info_initialized) Aperture_InitCPUFeatures();
    return g_cpu_info.has_avx512bf16;
}

/**
 * @brief Check if AVX2 is available
 */
extern "C" int Aperture_HasAVX2(void) {
    if (!g_cpu_info_initialized) Aperture_InitCPUFeatures();
    return g_cpu_info.has_avx2;
}

/**
 * @brief Check if FMA is available
 */
extern "C" int Aperture_HasFMA(void) {
    if (!g_cpu_info_initialized) Aperture_InitCPUFeatures();
    return g_cpu_info.has_fma;
}

/**
 * @brief Get CPU brand string
 */
extern "C" const char* Aperture_GetCPUBrand(void) {
    if (!g_cpu_info_initialized) Aperture_InitCPUFeatures();
    return g_cpu_info.brand;
}

/**
 * @brief Get CPU vendor string
 */
extern "C" const char* Aperture_GetCPUVendor(void) {
    if (!g_cpu_info_initialized) Aperture_InitCPUFeatures();
    return g_cpu_info.vendor;
}

/**
 * @brief Print CPU information to stdout
 */
extern "C" void Aperture_PrintCPUInfo(void) {
    if (!g_cpu_info_initialized) Aperture_InitCPUFeatures();
    
    printf("[Aperture] CPU Information:\n");
    printf("[Aperture]   Vendor: %s\n", g_cpu_info.vendor);
    printf("[Aperture]   Brand: %s\n", g_cpu_info.brand);
    printf("[Aperture]   Family: %d, Model: %d, Stepping: %d\n",
           g_cpu_info.family, g_cpu_info.model, g_cpu_info.stepping);
    printf("[Aperture]   Features:\n");
    
    if (g_cpu_info.has_avx512f) printf("[Aperture]     - AVX-512 Foundation\n");
    if (g_cpu_info.has_avx512dq) printf("[Aperture]     - AVX-512 Double/Quad\n");
    if (g_cpu_info.has_avx512bw) printf("[Aperture]     - AVX-512 Byte/Word\n");
    if (g_cpu_info.has_avx512vl) printf("[Aperture]     - AVX-512 Vector Length\n");
    if (g_cpu_info.has_avx512vnni) printf("[Aperture]     - AVX-512 VNNI\n");
    if (g_cpu_info.has_avx512bf16) printf("[Aperture]     - AVX-512 BF16\n");
    if (g_cpu_info.has_avx2) printf("[Aperture]     - AVX2\n");
    if (g_cpu_info.has_fma) printf("[Aperture]     - FMA\n");
    if (g_cpu_info.has_sse41) printf("[Aperture]     - SSE4.1\n");
    if (g_cpu_info.has_sse42) printf("[Aperture]     - SSE4.2\n");
    if (g_cpu_info.has_bmi1) printf("[Aperture]     - BMI1\n");
    if (g_cpu_info.has_bmi2) printf("[Aperture]     - BMI2\n");
}

// ============================================================================
// KERNEL DISPATCH
// ============================================================================

// Forward declarations for kernel implementations
extern "C" {
    int Aperture_Q4_0_Dequant_Reference(const uint8_t* src, float* dst, size_t num_blocks);
    int Aperture_Q4_0_Dequant_AVX512(const uint8_t* src, float* dst, size_t num_blocks);  // MASM AVX-512 kernel
}

// Function pointer type for Q4_0 dequantization
typedef int (*Aperture_Q4_0_Dequant_Func)(const uint8_t* src, float* dst, size_t num_blocks);

// Global function pointer (initialized on first use)
static Aperture_Q4_0_Dequant_Func g_q4_0_dequant_func = nullptr;

/**
 * @brief Initialize kernel dispatch
 * 
 * Selects optimal implementation based on CPU features.
 */
static void Aperture_InitDispatch(void) {
    if (g_q4_0_dequant_func != nullptr) {
        return;  // Already initialized
    }
    
    // Initialize CPU features first
    Aperture_InitCPUFeatures();
    
    // Select optimal implementation
    if (g_cpu_info.has_avx512f && g_cpu_info.has_avx512bw) {
        printf("[Aperture] AVX-512 available, using AVX-512 kernel\n");
        g_q4_0_dequant_func = Aperture_Q4_0_Dequant_AVX512;
    } else {
        printf("[Aperture] Using reference kernel (AVX-512 not available)\n");
        g_q4_0_dequant_func = Aperture_Q4_0_Dequant_Reference;
    }
}

/**
 * @brief Dispatch Q4_0 dequantization to optimal implementation
 */
extern "C" int Aperture_Q4_0_Dequant(const uint8_t* src, float* dst, size_t num_blocks) {
    if (g_q4_0_dequant_func == nullptr) {
        Aperture_InitDispatch();
    }
    return g_q4_0_dequant_func(src, dst, num_blocks);
}

/**
 * @brief Get name of currently selected kernel
 */
extern "C" const char* Aperture_GetKernelName(void) {
    if (g_q4_0_dequant_func == nullptr) {
        Aperture_InitDispatch();
    }
    
    if (g_q4_0_dequant_func == Aperture_Q4_0_Dequant_AVX512) {
        return "AVX-512";
    }
    if (g_q4_0_dequant_func == Aperture_Q4_0_Dequant_Reference) {
        return "Reference";
    }
    return "Unknown";
}
