// ============================================================================
// headless_sovereign_bridge.cpp — Minimal C++ bridge to Sovereign MASM runtime
// ============================================================================
// Wires XR_Input_Register_Devices, XR_Time_Initialize, and XR_Diagnostic_Raise_Assert
// into the headless execution loop with lifecycle safety and source-location tracking.
//
// Build: linked via RawrEngine (Lane B) alongside src/headless/*.asm objects.
// ============================================================================

#include "rawrxd/sovereign_headless_exports.h"
#include <atomic>
#include <cstdint>
#include <mutex>

namespace {
    static std::once_flag s_timeInitFlag;
    static std::atomic<bool> s_timeReady{false};

    void DoTimeInit()
    {
        uint64_t ok = XR_Time_Initialize();
        s_timeReady.store(ok != 0, std::memory_order_release);
    }
}

// ----------------------------------------------------------------------------
// Lifecycle
// ----------------------------------------------------------------------------

extern "C" bool HeadlessSovereign_InitTime()
{
    std::call_once(s_timeInitFlag, DoTimeInit);
    return s_timeReady.load(std::memory_order_acquire);
}

extern "C" bool HeadlessSovereign_InitInput(void* hwnd)
{
    if (!hwnd)
        return false;
    uint64_t ok = XR_Input_Register_Devices(hwnd);
    return ok != 0;
}

// ----------------------------------------------------------------------------
// Per-frame tick: input polling + time delta
// ----------------------------------------------------------------------------

extern "C" uint64_t HeadlessSovereign_Tick(void* rawInputHandle)
{
    // Time delta is always queried first; zero if timer never initialized.
    uint64_t us = 0;
    if (s_timeReady.load(std::memory_order_acquire))
        us = XR_Time_Query_Interval();

    // Input is optional: rawInputHandle may be null when no WM_INPUT arrived.
    if (rawInputHandle)
        XR_Input_Parse_Message(rawInputHandle);

    return us;
}

// ----------------------------------------------------------------------------
// Diagnostic assert with C++ source location forwarding
// ----------------------------------------------------------------------------

extern "C" void HeadlessSovereign_RaiseAssert(uint64_t condition, uint32_t tag)
{
    XR_Diagnostic_Raise_Assert(condition, tag);
}

extern "C" void HeadlessSovereign_CaptureRegisters(void* dest)
{
    if (dest)
        XR_Diagnostic_Capture_Register_Dump(dest);
}

// ----------------------------------------------------------------------------
// C++ convenience macro helpers (compile-time source location)
// ----------------------------------------------------------------------------

// These are defined as inline wrappers so the call site can pass __FILE__/__LINE__
// without requiring a macro in every translation unit.

extern "C" void HeadlessSovereign_AssertWithLocation(
    uint64_t condition,
    const char* file,
    int line)
{
    // Pack file/line into a 32-bit tag for the MASM trap handler.
    // Tag = (line & 0xFFFF) | ((simple_hash(file) & 0xFFFF) << 16)
    uint32_t linePart = static_cast<uint32_t>(line) & 0xFFFFu;
    uint32_t hashPart = 0u;
    if (file)
    {
        uint32_t h = 0x811c9dc5u;
        for (const char* p = file; *p; ++p)
        {
            h ^= static_cast<uint32_t>(static_cast<unsigned char>(*p));
            h *= 0x01000193u;
        }
        hashPart = (h & 0xFFFFu) << 16;
    }
    uint32_t tag = linePart | hashPart;
    XR_Diagnostic_Raise_Assert(condition, tag);
}
