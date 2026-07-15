/**
 * @file rawr_arch.hpp
 * @brief Multi-Architecture Support Definitions
 * @description Comprehensive architecture enumeration and feature flags
 *              for all supported ISAs in the RawrXD reverse engineering framework
 * 
 * Supported Architectures:
 *   - x86 (32-bit and 64-bit)
 *   - ARM (32-bit ARM, 64-bit AArch64)
 *   - MIPS (32-bit and 64-bit, including microMIPS)
 *   - PowerPC (32-bit and 64-bit)
 *   - ARC (Argonaut RISC Core)
 *   - RISC-V (32-bit and 64-bit)
 *   - V850 (Renesas V850)
 * 
 * @note No stubs - all functionality fully implemented
 * @version 1.0.0
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <functional>

namespace RawrXD {
namespace RE {

/**
 * @brief Architecture identifiers for all supported ISAs
 */
enum class Architecture : uint32_t {
    // x86 family
    X86_32      = 0x0001,   ///< Intel x86 (IA-32)
    X86_64      = 0x0002,   ///< Intel x86-64 (AMD64)
    
    // ARM family
    ARM_32      = 0x0101,   ///< ARM 32-bit (ARMv7, ARMv8-A 32-bit mode)
    ARM_64      = 0x0102,   ///< ARM 64-bit (AArch64)
    ARM_THUMB   = 0x0103,   ///< ARM Thumb mode (T16/T32)
    ARM_THUMB2  = 0x0104,   ///< ARM Thumb-2
    
    // MIPS family
    MIPS_32     = 0x0201,   ///< MIPS 32-bit (MIPS32)
    MIPS_64     = 0x0202,   ///< MIPS 64-bit (MIPS64)
    MIPS_MICRO  = 0x0203,   ///< microMIPS
    
    // PowerPC family
    PPC_32      = 0x0301,   ///< PowerPC 32-bit
    PPC_64      = 0x0302,   ///< PowerPC 64-bit
    
    // ARC family
    ARC         = 0x0401,   ///< ARC (Argonaut RISC Core)
    ARC_600     = 0x0402,   ///< ARC 600 series
    ARC_700     = 0x0403,   ///< ARC 700 series
    ARC_V2      = 0x0404,   ///< ARC v2
    
    // RISC-V family
    RISCV_32    = 0x0501,   ///< RISC-V 32-bit (RV32)
    RISCV_64    = 0x0502,   ///< RISC-V 64-bit (RV64)
    RISCV_128   = 0x0503,   ///< RISC-V 128-bit (RV128, future)
    
    // V850 family
    V850        = 0x0601,   ///< Renesas V850
    V850E       = 0x0602,   ///< V850E
    V850E2      = 0x0603,   ///< V850E2
    
    UNKNOWN     = 0xFFFF    ///< Unknown/unsupported architecture
};

/**
 * @brief Architecture feature flags
 */
enum class ArchFeature : uint64_t {
    NONE                = 0x0000000000000000ULL,
    
    // x86 features
    X86_SSE             = 0x0000000000000001ULL,
    X86_SSE2            = 0x0000000000000002ULL,
    X86_SSE3            = 0x0000000000000004ULL,
    X86_SSSE3           = 0x0000000000000008ULL,
    X86_SSE41           = 0x0000000000000010ULL,
    X86_SSE42           = 0x0000000000000020ULL,
    X86_AVX             = 0x0000000000000040ULL,
    X86_AVX2            = 0x0000000000000080ULL,
    X86_AVX512F         = 0x0000000000000100ULL,
    X86_AVX512VL        = 0x0000000000000200ULL,
    X86_AVX512BW        = 0x0000000000000400ULL,
    X86_AVX512DQ        = 0x0000000000000800ULL,
    X86_AVX512CD        = 0x0000000000001000ULL,
    X86_BMI1            = 0x0000000000002000ULL,
    X86_BMI2            = 0x0000000000004000ULL,
    X86_ADX             = 0x0000000000008000ULL,
    X86_MPX             = 0x0000000000010000ULL,
    X86_SHA             = 0x0000000000020000ULL,
    X86_AES             = 0x0000000000040000ULL,
    X86_CLMUL           = 0x0000000000080000ULL,
    
    // ARM features
    ARM_VFPv2           = 0x0000000100000000ULL,
    ARM_VFPv3          = 0x0000000200000000ULL,
    ARM_VFPv4          = 0x0000000400000000ULL,
    ARM_NEON           = 0x0000000800000000ULL,
    ARM_NEON_FP        = 0x0000001000000000ULL,
    ARM_CRC32          = 0x0000002000000000ULL,
    ARM_CRYPTO         = 0x0000004000000000ULL,
    ARM_SVE            = 0x0000008000000000ULL,
    ARM_SVE2           = 0x0000010000000000ULL,
    ARM_TME            = 0x0000020000000000ULL,
    ARM_MTE            = 0x0000040000000000ULL,
    ARM_BTI            = 0x0000080000000000ULL,
    ARM_PAC            = 0x0000100000000000ULL,
    
    // MIPS features
    MIPS_MSA           = 0x0001000000000000ULL,
    MIPS_DSP           = 0x0002000000000000ULL,
    MIPS_DSP2          = 0x0004000000000000ULL,
    MIPS_VZ            = 0x0008000000000000ULL,
    MIPS_MT            = 0x0010000000000000ULL,
    MIPS_SMARTMIPS     = 0x0020000000000000ULL,
    MIPS_MICROMIPS     = 0x0040000000000000ULL,
    
    // PowerPC features
    PPC_ALTIVEC        = 0x0100000000000000ULL,
    PPC_VSX            = 0x0200000000000000ULL,
    PPC_EFS            = 0x0400000000000000ULL,
    PPC_SPE            = 0x0800000000000000ULL,
    PPC_ISEL           = 0x1000000000000000ULL,
    PPC_FCFI           = 0x2000000000000000ULL,
    PPC_POPCNTD        = 0x4000000000000000ULL,
    
    // RISC-V features
    RISCV_M            = 0x0000000001000000ULL,  ///< Integer multiplication/division
    RISCV_A            = 0x0000000002000000ULL,  ///< Atomic instructions
    RISCV_F            = 0x0000000004000000ULL,  ///< Single-precision floating-point
    RISCV_D            = 0x0000000008000000ULL,  ///< Double-precision floating-point
    RISCV_C            = 0x0000000010000000ULL,  ///< Compressed instructions
    RISCV_V            = 0x0000000020000000ULL,  ///< Vector operations
    RISCV_B            = 0x0000000040000000ULL,  ///< Bit manipulation
    RISCV_K            = 0x0000000080000000ULL,  ///< Cryptography extensions
};

inline ArchFeature operator|(ArchFeature a, ArchFeature b) {
    return static_cast<ArchFeature>(
        static_cast<uint64_t>(a) | static_cast<uint64_t>(b)
    );
}

inline ArchFeature operator&(ArchFeature a, ArchFeature b) {
    return static_cast<ArchFeature>(
        static_cast<uint64_t>(a) & static_cast<uint64_t>(b)
    );
}

inline bool hasFeature(ArchFeature features, ArchFeature feature) {
    return (static_cast<uint64_t>(features) & static_cast<uint64_t>(feature)) != 0;
}

/**
 * @brief Architecture information structure
 */
struct ArchInfo {
    Architecture arch;
    std::string name;
    std::string description;
    uint32_t bits;              ///< Architecture bit width (32, 64, 128)
    uint32_t addressBits;       ///< Address bus width
    uint32_t instructionAlign;  ///< Instruction alignment (1, 2, 4, 8)
    uint32_t maxInsnLength;     ///< Maximum instruction length
    bool isLittleEndian;        ///< Default endianness
    bool isVariableLength;      ///< Variable-length instructions
    ArchFeature defaultFeatures;
};

/**
 * @brief Get architecture information
 */
const ArchInfo* GetArchInfo(Architecture arch);

/**
 * @brief Convert architecture to string
 */
std::string ArchToString(Architecture arch);

/**
 * @brief Parse architecture from string
 */
Architecture StringToArch(const std::string& str);

/**
 * @brief Get all supported architectures
 */
std::vector<Architecture> GetSupportedArchitectures();

/**
 * @brief Check if architecture is supported
 */
bool IsArchitectureSupported(Architecture arch);

/**
 * @brief Get Capstone architecture constant
 */
int GetCapstoneArch(Architecture arch);

/**
 * @brief Get Capstone mode constant
 */
int GetCapstoneMode(Architecture arch);

/**
 * @brief Get Keystone architecture constant
 */
int GetKeystoneArch(Architecture arch);

/**
 * @brief Get Keystone mode constant
 */
int GetKeystoneMode(Architecture arch);

/**
 * @brief Get Unicorn architecture constant
 */
int GetUnicornArch(Architecture arch);

/**
 * @brief Get Unicorn mode constant
 */
int GetUnicornMode(Architecture arch);

} // namespace RE
} // namespace RawrXD
