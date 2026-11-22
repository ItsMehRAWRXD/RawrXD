// native_debuggee.cpp — deterministic Win32 debuggee for RawrXD G50/G53.
//
// A real Windows process with symbols, deterministic stdout, debugger
// notifications, a breakpoint, mutable state and a known exit code.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>

volatile LONG g_debugValue = 0;

extern "C" __declspec(noinline) int NativeDebugTarget(int value) {
    InterlockedExchange(&g_debugValue, value * 2);
    return static_cast<int>(g_debugValue);
}

int main() {
    std::printf("DEBUGGEE_READY pid=%lu\n", static_cast<unsigned long>(GetCurrentProcessId()));
    std::fflush(stdout);
    OutputDebugStringA("RAWRXD_DEBUG_CONSOLE_READY");
    if (IsDebuggerPresent()) DebugBreak();
    const int first = NativeDebugTarget(21);
    std::printf("DEBUGGEE_VALUE=%d\n", first);
    std::fflush(stdout);
    OutputDebugStringA("RAWRXD_DEBUG_CONSOLE_VALUE_42");
    if (first != 42) return 1;
    std::printf("DEBUGGEE_EXIT=42\n");
    std::fflush(stdout);
    return 42;
}