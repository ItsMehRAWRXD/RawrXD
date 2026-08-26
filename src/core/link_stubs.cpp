// ============================================================================
// link_stubs.cpp — Stub implementations for missing dependencies
// ============================================================================
// Temporary stubs to allow VAL-051.2.B build to complete.
// These should be replaced with real implementations.
// ============================================================================

#include <vector>
#include <string>
#include <map>
#include <cstdint>

// Stub ModelSlice to avoid missing swarm_scheduler.hpp
namespace RawrXD {
    struct ModelSlice {
        std::string model_path;
        int32_t start_layer = 0;
        int32_t end_layer = 0;
        bool is_loaded = false;
    };
}

namespace codec {

// Production fallback: deflate/inflate are not implemented.
// Callers MUST check the success flag. If false, the data is NOT compressed/decompressed.
// This prevents silent data corruption from passing through raw compressed bytes.

std::vector<unsigned char> deflate(const std::vector<unsigned char>& input, bool* success) {
    if (success) *success = false;
    // Return empty to force caller to handle failure explicitly
    return {};
}

std::vector<unsigned char> inflate(const std::vector<unsigned char>& input, bool* success) {
    if (success) *success = false;
    // Return empty to force caller to handle failure explicitly
    return {};
}

} // namespace codec

namespace brutal {

// Stub for compress
std::vector<unsigned char> compress(const std::vector<unsigned char>& input) {
    return input; // Return uncompressed
}

} // namespace brutal

// Logging is now provided by src/logging/Logger.cpp - no stubs needed

// ============================================================================
// Enterprise License ASM Stubs (DISABLED — real MASM implementations linked)
// ============================================================================
// These stubs caused LNK2005 duplicates with RawrXD_EnterpriseLicense.asm,
// RawrXD_Telemetry_Kernel.asm, and swarm_tensor_stream.asm.
// Real implementations are now linked via CMake MASM custom commands.
// If building a pure-CLI target without MASM, re-enable these stubs.
// ============================================================================
#if 0  // Stubs disabled — real ASM linked
extern "C" {
    int Enterprise_InitLicenseSystem() { return 1; }
    int Enterprise_ValidateLicense() { return 1; }
    int Enterprise_CheckFeature(int) { return 1; }
    int Enterprise_Unlock800BDualEngine() { return 1; }
    int Enterprise_InstallLicense(const char*) { return 1; }
    int Enterprise_GetLicenseStatus() { return 2; } // 2 = valid
    const char* Enterprise_GetFeatureString() { return "CLI-MODE"; }
    const char* Enterprise_GenerateHardwareHash() { return "cli-stub-hash"; }
}

// Global flag for 800B dual engine unlock
extern "C" int g_800B_Unlocked = 1;

// Additional enterprise stubs for CLI builds
extern "C" {
    void Enterprise_Shutdown() {}
    int Streaming_CheckEnterpriseBudget(uint64_t) { return 1; }
    uint64_t g_EnterpriseFeatures = 0x1FF; // All features enabled for CLI
}

// Telemetry counter stubs (MASM kernel not linked in CLI)
extern "C" {
    uint64_t g_Counter_AgentLoop = 0;
    uint64_t UTC_IncrementCounter(volatile uint64_t* counterAddr) {
        if (counterAddr) {
            return ++(*counterAddr);
        }
        return 0;
    }
}

// Swarm ASM stubs (swarm_tensor_stream.asm not linked in CLI)
extern "C" {
    int64_t swarm_stream_layer(uint64_t, void*, uint64_t, uint32_t) { return 0; }
    int swarm_receive_header(uint64_t, void*) { return 0; }
    uint32_t swarm_compute_layer_crc32(const void*, uint64_t) { return 0; }
    uint64_t swarm_compress_chunk_rle(const void*, uint64_t, void*, uint64_t) { return 0; }
    uint32_t swarm_build_discovery_packet(void*, uint32_t, uint64_t, uint64_t, uint32_t, uint32_t) { return 0; }
}
#endif
