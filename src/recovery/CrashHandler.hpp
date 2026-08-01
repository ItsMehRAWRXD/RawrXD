// ============================================================================
// CrashHandler.hpp — Native Crash Handler
// SEH, minidumps, rollback
// ============================================================================

#ifndef CRASH_HANDLER_HPP
#define CRASH_HANDLER_HPP

#include <cstdint>
#include <cstddef>
#include <string>
#include <functional>
#include <optional>

#ifdef _WIN32
#include <windows.h>
#endif

namespace rawr {

// ============================================================================
// Crash Info
// ============================================================================
struct CrashInfo {
    uint64_t timestamp;
    uint32_t code;
    std::string description;
    std::string module;
    uint64_t address;
};

// ============================================================================
// Crash Callback
// ============================================================================
using CrashCallback = std::function<void(const CrashInfo& info)>;

// ============================================================================
// CrashHandler — Structured exception handling and recovery
// ============================================================================
class CrashHandler {
public:
    static CrashHandler& Get();

    void Initialize();
    void Shutdown();

    void SetOnCrash(CrashCallback cb) { m_onCrash = std::move(cb); }

    // Generate minidump
    bool WriteMinidump(const char* path = nullptr);

    // Get last crash info
    const CrashInfo* GetLastCrash() const { return m_lastCrash ? &m_lastCrash.value() : nullptr; }
    uint32_t GetCrashCount() const { return m_crashCount; }

    // Reset crash state
    void Reset();

private:
    CrashHandler() = default;
    ~CrashHandler() = default;
    CrashHandler(const CrashHandler&) = delete;
    CrashHandler& operator=(const CrashHandler&) = delete;

    static LONG WINAPI VectoredHandler(EXCEPTION_POINTERS* ep);

    uint32_t m_crashCount = 0;
    void* m_vectoredHandle = nullptr;
    CrashCallback m_onCrash;
    std::optional<CrashInfo> m_lastCrash;
};

} // namespace rawr

#endif // CRASH_HANDLER_HPP
