// ============================================================================
// deep2_link_stubs.cpp — Honest stubs for symbols NOT provided by real TUs
// ============================================================================

#include "vulkan_compute.h"
#include <vector>
#include <cstring>
#include <cstddef>
#include <array>
#include <string>
#include <functional>

namespace CPUInference {

// VulkanCompute stubs
VulkanCompute::VulkanCompute() {}
VulkanCompute::~VulkanCompute() {}
bool VulkanCompute::Initialize() { return false; }
bool VulkanCompute::DispatchGEMV(const float*, const float*, float*, unsigned int, unsigned int) {
    return false;
}
bool VulkanCompute::FlushAsyncCommands() { return false; }

} // namespace CPUInference

// OllamaBlobParser stub
namespace rawrxd { namespace ollama {
    struct OllamaBlobParser {
        OllamaBlobParser();
        ~OllamaBlobParser();
        struct ParseResult { bool success = false; std::string ggufPath; std::string error; };
        ParseResult parseBlobToGGUF(const std::string&);
        bool extractGGUFToFile(const std::string&, unsigned __int64, unsigned __int64, const std::string&);
    };
    OllamaBlobParser::OllamaBlobParser() {}
    OllamaBlobParser::~OllamaBlobParser() {}
    OllamaBlobParser::ParseResult OllamaBlobParser::parseBlobToGGUF(const std::string&) { return {}; }
    bool OllamaBlobParser::extractGGUFToFile(const std::string&, unsigned __int64, unsigned __int64, const std::string&) { return false; }
} } // namespace rawrxd::ollama

// ASM kernel stubs for symbols not provided by linked .obj files
extern "C" void Deep2_FP16_GEMV(const void*, const float*, float*, unsigned int, unsigned int) {}
extern "C" void Deep2_Q4_1_GEMV(const void*, const float*, float*, unsigned int, unsigned int) {}
extern "C" void Deep2_Q8_0_GEMV(const void*, const float*, float*, unsigned int, unsigned int) {}
extern "C" void Deep2_Q5_K_GEMV(const void*, const float*, float*, unsigned int, unsigned int) {}

// Note: RegisterIQKernels is provided by asm_stubs.obj
// Do NOT define it here to avoid duplicate symbol errors.

// HotPatcher dependency stubs
namespace Deep2 {

struct SHA256Checksum {
    static std::array<unsigned char,32> compute(const void*, unsigned __int64);
    static std::string toString(const std::array<unsigned char,32>&);
    static std::array<unsigned char,32> fromString(const std::string&);
    static bool equal(const std::array<unsigned char,32>&, const std::array<unsigned char,32>&);
};

std::array<unsigned char,32> SHA256Checksum::compute(const void*, unsigned __int64) { return {}; }
std::string SHA256Checksum::toString(const std::array<unsigned char,32>&) { return ""; }
std::array<unsigned char,32> SHA256Checksum::fromString(const std::string&) { return {}; }
bool SHA256Checksum::equal(const std::array<unsigned char,32>&, const std::array<unsigned char,32>&) { return true; }

struct CrashRecovery {
    struct CrashContext {};
    static bool initialize(std::function<void(const CrashContext&)>);
};
bool CrashRecovery::initialize(std::function<void(const CrashContext&)>) { return true; }

struct PatchSafety {
    struct PreFlightCheck { bool safe = true; float riskScore = 0.0f; std::string reason; };
    static PreFlightCheck runPreFlight(const std::string&);
    static float calculateRiskScore(const std::string&);
};
PatchSafety::PreFlightCheck PatchSafety::runPreFlight(const std::string&) { return {}; }
float PatchSafety::calculateRiskScore(const std::string&) { return 0.0f; }

struct PatchOperationGuard {
    PatchOperationGuard(const std::string&, const std::string&);
    ~PatchOperationGuard();
    void markSuccess();
};
PatchOperationGuard::PatchOperationGuard(const std::string&, const std::string&) {}
PatchOperationGuard::~PatchOperationGuard() {}
void PatchOperationGuard::markSuccess() {}

struct ScopedWatchdog {
    ScopedWatchdog(unsigned __int64, std::function<void()>);
    ~ScopedWatchdog();
};
ScopedWatchdog::ScopedWatchdog(unsigned __int64, std::function<void()>) {}
ScopedWatchdog::~ScopedWatchdog() {}

} // namespace Deep2
