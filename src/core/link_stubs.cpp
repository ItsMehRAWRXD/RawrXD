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

// codec::deflate/inflate are implemented in src/codec/compression.cpp
// Do NOT add stubs here - they cause ODR violations with the real implementations

// brutal::compress/decompress are implemented in src/codec/brutal_gzip.cpp
// Do NOT add stubs here - they cause ODR violations with the real implementations

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
