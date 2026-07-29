// ============================================================================
// watchdog_stubs.cpp - Stub implementations for watchdog functions
// ============================================================================

#include <windows.h>
#include <cstdint>
#include <cstddef>

extern "C" {

void asm_watchdog_init() {
    OutputDebugStringA("[Watchdog] asm_watchdog_init stub called\n");
}

bool asm_watchdog_verify() {
    OutputDebugStringA("[Watchdog] asm_watchdog_verify stub called\n");
    return true;
}

void* asm_watchdog_get_baseline() {
    OutputDebugStringA("[Watchdog] asm_watchdog_get_baseline stub called\n");
    return nullptr;
}

int asm_watchdog_get_status() {
    OutputDebugStringA("[Watchdog] asm_watchdog_get_status stub called\n");
    return 0;
}

void asm_watchdog_shutdown() {
    OutputDebugStringA("[Watchdog] asm_watchdog_shutdown stub called\n");
}

} // extern "C"
