#ifndef VAL064_HOST_FINGERPRINT_HPP
#define VAL064_HOST_FINGERPRINT_HPP

#include "execution_types.hpp"
#include <cstdint>
#include <cstring>
#include <intrin.h>
#include <xmmintrin.h>
#include <windows.h>

namespace val063 {

// VAL-064: Cross-Environment Replay
// Host fingerprint capture for deterministic replay across different machines

struct HostFingerprint {
    Hash256  cpu_features;     // SHA-256 of CPUID leaves (1, 7, 80000001h)
    uint32_t mxcsr_default;      // MXCSR status/control flags (FTZ, DAZ, Rounding)
    uint32_t os_build;           // NT OS Build Number
    Hash256  compiler_id;        // Build toolchain version fingerprint
    uint64_t tsc_frequency;      // Hardware timer frequency (Hz)
    bool     avx512_present;
    bool     fma_present;
    bool     bmi2_present;
    
    // Canonical serialization for hashing
    std::array<uint8_t, 128> to_bytes() const {
        std::array<uint8_t, 128> result{};
        std::copy(cpu_features.bytes.begin(), cpu_features.bytes.end(), result.begin());
        *reinterpret_cast<uint32_t*>(&result[32]) = mxcsr_default;
        *reinterpret_cast<uint32_t*>(&result[36]) = os_build;
        std::copy(compiler_id.bytes.begin(), compiler_id.bytes.end(), result.begin() + 40);
        *reinterpret_cast<uint64_t*>(&result[72]) = tsc_frequency;
        result[80] = avx512_present ? 1 : 0;
        result[81] = fma_present ? 1 : 0;
        result[82] = bmi2_present ? 1 : 0;
        return result;
    }
    
    // Combined hash of entire fingerprint
    Hash256 combined_hash() const {
        auto bytes = to_bytes();
        HashProvider provider;
        provider.update(bytes.data(), bytes.size());
        return provider.finalize();
    }
};

enum class EnvironmentVerificationResult : uint32_t {
    Compatible                  = 0,
    CpuFeatureMismatch          = 1,
    FpEnvironmentDivergence     = 2,
    CompilerVersionMismatch     = 3,
    OsBuildDriftWarning         = 4,
    TscFrequencyMismatch        = 5
};

class FingerprintCollector {
public:
    // Captures exact execution host state via CPUID and MSVC intrinsics
    static HostFingerprint capture() {
        HostFingerprint fp{};

        // 1. Capture MXCSR (Floating-point Control/Status Register)
        // Bit 15: FTZ (Flush to Zero), Bit 6: DAZ (Denormals are Zero)
        fp.mxcsr_default = _mm_getcsr();

        // 2. Query CPUID Leaves
        int cpuInfo[4] = {0};

        // Leaf 1: Standard Features (ECX Bit 12 = FMA, ECX Bit 28 = AVX)
        __cpuid(cpuInfo, 1);
        uint32_t leaf1_ecx = static_cast<uint32_t>(cpuInfo[2]);
        uint32_t leaf1_edx = static_cast<uint32_t>(cpuInfo[3]);
        fp.fma_present = (leaf1_ecx & (1 << 12)) != 0;

        // Leaf 7 (Sub-leaf 0): Extended Features (EBX Bit 8 = BMI2, EBX Bit 16 = AVX512F)
        __cpuidex(cpuInfo, 7, 0);
        uint32_t leaf7_ebx = static_cast<uint32_t>(cpuInfo[1]);
        uint32_t leaf7_ecx = static_cast<uint32_t>(cpuInfo[2]);
        fp.bmi2_present   = (leaf7_ebx & (1 << 8))  != 0;
        fp.avx512_present = (leaf7_ebx & (1 << 16)) != 0;

        // Package raw CPU feature words into static buffer for digest hashing
        struct {
            uint32_t ecx1, edx1;
            uint32_t ebx7, ecx7;
        } rawFeatures{ leaf1_ecx, leaf1_edx, leaf7_ebx, leaf7_ecx };

        fp.cpu_features = hash::of_bytes(
            reinterpret_cast<const uint8_t*>(&rawFeatures), 
            sizeof(rawFeatures)
        );

        // 3. Query true OS Build Number via ntdll.dll (bypassing Win32 API compatibility shims)
        typedef LONG(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
        HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
        if (hNtDll) {
            auto pRtlGetVersion = reinterpret_cast<RtlGetVersionPtr>(
                GetProcAddress(hNtDll, "RtlGetVersion"));
            if (pRtlGetVersion) {
                RTL_OSVERSIONINFOW rovi = { sizeof(rovi) };
                if (pRtlGetVersion(&rovi) == 0) {
                    fp.os_build = rovi.dwBuildNumber;
                }
            }
        }

        // 4. Capture Timer Counter Frequency (QPC)
        LARGE_INTEGER qpcFreq;
        QueryPerformanceFrequency(&qpcFreq);
        fp.tsc_frequency = static_cast<uint64_t>(qpcFreq.QuadPart);

        // 5. Compiler Toolchain Fingerprint
#if defined(_MSC_FULL_VER)
        uint32_t msvcVer = _MSC_FULL_VER;
        fp.compiler_id = hash::of_bytes(
            reinterpret_cast<const uint8_t*>(&msvcVer), 
            sizeof(msvcVer)
        );
#endif

        return fp;
    }

    // Gate D Verification logic: Compares target system against original execution
    static EnvironmentVerificationResult verify(const HostFingerprint& required, 
                                                const HostFingerprint& current) {
        // Hard Gate 1: CPU Feature Digest Match
        if (required.cpu_features != current.cpu_features) {
            return EnvironmentVerificationResult::CpuFeatureMismatch;
        }

        // Hard Gate 2: Floating-point Environment (MXCSR FTZ/DAZ/Rounding flags)
        // Mask out non-essential status flags (bits 0-5) to compare control state (bits 6-15)
        constexpr uint32_t MXCSR_CONTROL_MASK = 0xFFC0;
        if ((required.mxcsr_default & MXCSR_CONTROL_MASK) != 
            (current.mxcsr_default & MXCSR_CONTROL_MASK)) {
            return EnvironmentVerificationResult::FpEnvironmentDivergence;
        }

        // Hard Gate 3: Compiler Version Equivalence
        if (required.compiler_id != current.compiler_id) {
            return EnvironmentVerificationResult::CompilerVersionMismatch;
        }

        // Hard Gate 4: TSC Frequency (for timing-sensitive operations)
        // Allow 1% variance for different motherboards
        uint64_t tsc_diff = (required.tsc_frequency > current.tsc_frequency) ?
            (required.tsc_frequency - current.tsc_frequency) :
            (current.tsc_frequency - required.tsc_frequency);
        if (tsc_diff > (required.tsc_frequency / 100)) {
            return EnvironmentVerificationResult::TscFrequencyMismatch;
        }

        // Soft Gate: OS Build Drift Notification
        if (required.os_build != current.os_build) {
            return EnvironmentVerificationResult::OsBuildDriftWarning;
        }

        return EnvironmentVerificationResult::Compatible;
    }
    
    // Convert result to string for logging
    static std::string result_to_string(EnvironmentVerificationResult result) {
        switch (result) {
            case EnvironmentVerificationResult::Compatible:
                return "Compatible";
            case EnvironmentVerificationResult::CpuFeatureMismatch:
                return "CpuFeatureMismatch";
            case EnvironmentVerificationResult::FpEnvironmentDivergence:
                return "FpEnvironmentDivergence";
            case EnvironmentVerificationResult::CompilerVersionMismatch:
                return "CompilerVersionMismatch";
            case EnvironmentVerificationResult::OsBuildDriftWarning:
                return "OsBuildDriftWarning";
            case EnvironmentVerificationResult::TscFrequencyMismatch:
                return "TscFrequencyMismatch";
            default:
                return "Unknown";
        }
    }
};

// VAL-064 Evidence structure
struct VAL064Evidence {
    std::string gate{"VAL-064"};
    std::string name{"Cross-Environment Replay"};
    std::string status{"PENDING"};
    
    HostFingerprint source_fingerprint;
    HostFingerprint target_fingerprint;
    EnvironmentVerificationResult verification_result;
    
    bool cross_environment_compatible{false};
    bool cpu_verified{false};
    bool fp_verified{false};
    bool compiler_verified{false};
    bool tsc_verified{false};
    bool os_compatible{false};
    
    Timestamp captured_at;
    
    std::string to_json() const {
        std::ostringstream oss;
        oss << "{\n";
        oss << "  \"gate\": \"" << gate << "\",\n";
        oss << "  \"name\": \"" << name << "\",\n";
        oss << "  \"status\": \"" << status << "\",\n";
        oss << "  \"verification_result\": \"" 
            << FingerprintCollector::result_to_string(verification_result) << "\",\n";
        oss << "  \"cross_environment_compatible\": " 
            << (cross_environment_compatible ? "true" : "false") << ",\n";
        oss << "  \"checks\": {\n";
        oss << "    \"cpu_verified\": " << (cpu_verified ? "true" : "false") << ",\n";
        oss << "    \"fp_verified\": " << (fp_verified ? "true" : "false") << ",\n";
        oss << "    \"compiler_verified\": " << (compiler_verified ? "true" : "false") << ",\n";
        oss << "    \"tsc_verified\": " << (tsc_verified ? "true" : "false") << ",\n";
        oss << "    \"os_compatible\": " << (os_compatible ? "true" : "false") << "\n";
        oss << "  },\n";
        oss << "  \"source_fingerprint\": {\n";
        oss << "    \"cpu_features\": \"" << source_fingerprint.cpu_features.hex() << "\",\n";
        oss << "    \"mxcsr_default\": \"0x" << std::hex << source_fingerprint.mxcsr_default << "\",\n";
        oss << "    \"os_build\": " << std::dec << source_fingerprint.os_build << ",\n";
        oss << "    \"tsc_frequency\": " << source_fingerprint.tsc_frequency << ",\n";
        oss << "    \"compiler_id\": \"" << source_fingerprint.compiler_id.hex() << "\"\n";
        oss << "  },\n";
        oss << "  \"captured_at\": \"" << captured_at.iso8601() << "\"\n";
        oss << "}";
        return oss.str();
    }
    
    bool all_passed() const {
        return cross_environment_compatible && 
               cpu_verified && 
               fp_verified && 
               compiler_verified && 
               tsc_verified;
    }
};

} // namespace val063

#endif // VAL064_HOST_FINGERPRINT_HPP
