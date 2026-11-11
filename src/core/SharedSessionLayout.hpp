#pragma once
#include <cstdint>
#include <cstddef>
#include <windows.h>

#pragma pack(push, 8) // Force strict 8-byte boundary alignment

struct SharedEventFrame {
    volatile uint64_t sequence;   // Monotonically increasing sequence ID
    uint32_t eventType;           // Hashed event category (FNV-1a)
    uint32_t payloadLength;       // Length of active data in payload
    uint8_t  payload[256];        // Fixed-size inline data frame to avoid external pointers
};

struct UnifiedSessionStateArena {
    // --- VERSION HEADER ---
    // Protocol version for compatibility checking
    alignas(8) uint32_t protocolVersion;
    alignas(8) uint32_t reservedVersion; // Padding and future use
    
    // --- ATOMIC CONTROL REGISTERS ---
    // Using volatile long to guarantee compatibility with Win32 Interlocked* intrinsics
    alignas(64) volatile long headIndex; // Writer head cursor
    alignas(64) volatile long tailIndex; // Reader tail cursor
    
    // --- ACTIVE IDE GLOBAL STATE ---
    alignas(8)  wchar_t currentWorkingDirectory[MAX_PATH];
    alignas(8)  wchar_t activeFilePath[MAX_PATH];
    
    // Model execution telemetry
    char     activeModelHash[65]; // SHA-256 hex signature + null terminator
    uint32_t activeModelVRAMUsageBytes;
    uint32_t currentExecutionMode; // 1 = GUI, 2 = CLI, 3 = Headless
    
    // --- VERSION SYNC ---
    // Runtime version info for cross-process compatibility
    alignas(8) uint32_t runtimeVersionPacked;
    alignas(8) char runtimeVersionString[32]; // "1.1.0-alpha"
    
    // --- MPMC RING BUFFER ---
    // 512-slot ring buffer for lightning-fast cross-process event streaming
    static constexpr size_t SLOT_COUNT = 512;
    alignas(64) SharedEventFrame eventRing[SLOT_COUNT];
};

#pragma pack(pop)

// Static assertions to ensure layout compatibility
static_assert(sizeof(SharedEventFrame) == 272, "SharedEventFrame size must be 272 bytes");
// Size check - arena must be under 2MB
static_assert(sizeof(UnifiedSessionStateArena) < (2 * 1024 * 1024), 
              "UnifiedSessionStateArena must fit in 2MB shared memory section");
static_assert(alignof(UnifiedSessionStateArena) >= 8, "Arena must be at least 8-byte aligned");
