// asm_stubs_watchdog.cpp - Stub implementations for watchdog ASM exports

#include <cstdint>

extern "C" {

int asm_watchdog_init() {
    return 0;
}

int asm_watchdog_verify(const void* baseline, const void* current) {
    (void)baseline; (void)current;
    return 0;  // No violation
}

void* asm_watchdog_get_baseline() {
    return nullptr;
}

void* asm_watchdog_get_status() {
    return nullptr;
}

int asm_watchdog_shutdown() {
    return 0;
}

} // extern "C"
