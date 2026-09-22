/**
 * @file quickjs_sandbox.h
 * @brief Minimal QuickJS Plugin Sandbox declarations.
 */

#pragma once

#ifndef QUICKJS_SANDBOX_H
#define QUICKJS_SANDBOX_H

#include <cstdint.h>
#include <cstddef.h>
#include <string.h>
#include <Windows.h>
#include <mutex>
#include <atomic>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
} // extern "C"
#endif

// ============================================================================
// Constants
// ============================================================================
constexpr uint32_t SANDBOX_MAX_EXTENSIONS    = 256;
constexpr uint32_t SANDBOX_MAX_NATIVE_FUNCS  = 128;
constexpr uint32_t SANDBOX_MAX_ALLOWED_PATHS = 32;
constexpr uint32_t SANDBOX_MAX_ALLOWED_HOSTS = 32;

// ============================================================================
// Enums
// ============================================================================
enum class SecurityTier : uint8_t {
    Untrusted = 0,
    Sandboxed = 1,
    Trusted   = 2,
    Privileged = 3,
};

enum class ViolationType : uint8_t {
    None                = 0,
    NativeFunctionBlocked = 1,
    FileAccessDenied    = 2,
    NetworkAccessDenied = 3,
    ModuleImportBlocked = 4,
    MemoryLimitExceeded = 5,
    CPUTimeLimitExceeded = 6,
};

// ============================================================================
// Forward-declared structures
// ============================================================================
struct SandboxConfig;
struct SandboxStats;
struct SandboxViolation;

// ============================================================================
// Violation callback
// ============================================================================
typedef void (*ViolationCallback)(const SandboxViolation* violation, void* userData);

// ============================================================================
// SandboxResult
// ============================================================================
struct SandboxResult {
    bool success;
    const char* detail;
    int errorCode;

    static SandboxResult ok(const char* msg) {
        SandboxResult r; r.success = true; r.detail = msg; r.errorCode = 0; return r;
    }
    static SandboxResult error(const char* msg, int code = -1) {
        SandboxResult r; r.success = false; r.detail = msg; r.errorCode = code; return r;
    }
};

// ============================================================================
// Allowed entry sub-structs
// ============================================================================
struct AllowedPath {
    wchar_t path[260];
    bool    readOnly;
};

struct AllowedHost {
    char hostname[256];
    uint16_t port;
};

struct AllowedNativeFunc {
    char name[128];
};

// ============================================================================
// SandboxConfig
// ============================================================================
struct SandboxConfig {
    SecurityTier tier;
    uint64_t maxMemoryBytes;
    uint64_t maxStackBytes;
    uint32_t maxCpuMs;
    uint32_t maxTotalCpuMs;
    uint32_t allowedPathCount;
    uint32_t allowedHostCount;
    uint32_t allowedNativeFuncCount;
    bool     killOnViolation;
    bool     logViolations;
    uint32_t maxViolationsBeforeKill;

    AllowedPath       allowedPaths[SANDBOX_MAX_ALLOWED_PATHS];
    AllowedHost       allowedHosts[SANDBOX_MAX_ALLOWED_HOSTS];
    AllowedNativeFunc allowedNativeFuncs[SANDBOX_MAX_NATIVE_FUNCS];
};

// ============================================================================
// SandboxViolation
// ============================================================================
struct SandboxViolation {
    ViolationType type;
    char extensionId[128];
    char detail[512];
    uint64_t timestampUs;

    static SandboxViolation create(ViolationType t, const char* extId, const char* det) {
        SandboxViolation v{};
        v.type = t;
        strncpy_s(v.extensionId, extId, _TRUNCATE);
        strncpy_s(v.detail, det, _TRUNCATE);
        return v;
    }
};

// ============================================================================
// SandboxStats
// ============================================================================
struct SandboxStats {
    uint64_t totalExtensionsLoaded = 0;
    uint64_t totalViolations       = 0;
    uint64_t extensionsKilled      = 0;
    uint64_t nativeCallsAllowed    = 0;
    uint64_t nativeCallsBlocked    = 0;
    uint64_t fsAccessAllowed       = 0;
    uint64_t fsAccessBlocked       = 0;
    uint64_t netAccessAllowed      = 0;
    uint64_t netAccessBlocked      = 0;
    uint64_t memoryLimitHits       = 0;
    uint64_t cpuLimitHits          = 0;
};

// ============================================================================
// ExtensionSlot
// ============================================================================
struct ExtensionSlot {
    char     id[128];
    bool     active;
    SandboxConfig config;
    uint64_t memoryUsed;
    uint32_t cpuTimeMs;
    uint32_t violationCount;
    uint32_t violationHead;
    SandboxViolation violations[32];
};

// ============================================================================
// PluginSandbox
// ============================================================================
namespace RawrXD {
namespace Sandbox {

class PluginSandbox {
public:
    static PluginSandbox& instance();

    SandboxResult initialize();
    void shutdown();

    SandboxConfig createDefaultConfig(SecurityTier tier);
    void addStandardAPIWhitelist(SandboxConfig& config);

    int  findExtension(const char* extensionId) const;
    SandboxResult registerExtension(const char* extensionId, SecurityTier tier);
    SandboxResult registerExtensionWithConfig(const char* extensionId, const SandboxConfig& config);
    void unregisterExtension(const char* extensionId);
    const SandboxConfig* getConfig(const char* extensionId) const;

    bool isNativeFuncAllowed(const char* extensionId, const char* funcName);
    bool isFileAccessAllowed(const char* extensionId, const wchar_t* filePath, bool isWrite);
    bool isNetworkAccessAllowed(const char* extensionId, const char* hostname, uint16_t port);
    bool isModuleImportAllowed(const char* extensionId, const char* moduleName);
    bool checkMemoryAllocation(const char* extensionId, uint64_t allocationSize);
    bool checkCPUTime(const char* extensionId, uint32_t elapsedMs);

    void setViolationCallback(ViolationCallback callback, void* userData);
    void recordViolation(const char* extensionId, ViolationType type, const char* detail);
    uint32_t getViolations(const char* extensionId, SandboxViolation* outViolations, uint32_t maxCount) const;
    uint32_t getViolationCount(const char* extensionId) const;

    SandboxStats getStats() const;
    void resetStats();
    void dumpState() const;

private:
    PluginSandbox();
    ~PluginSandbox();

    bool m_initialized;
    uint32_t m_extensionCount;
    mutable std::mutex m_mutex;
    ExtensionSlot m_extensions[SANDBOX_MAX_EXTENSIONS];
    SandboxStats m_stats;
    ViolationCallback m_violationCallback;
    void* m_violationUserData;
};

} // namespace Sandbox
} // namespace RawrXD

#endif // QUICKJS_SANDBOX_H
