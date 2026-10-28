// quad_registry.hpp — shared QuadState for init (013/ASM) ↔ shutdown (batch_001)
// Owner of storage: unlinked_symbols_batch_001.cpp
// PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0
#pragma once

#include <cstdint>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
using HWND = void*;
#endif

extern "C" {

// Bind HWND/geometry into the sole QuadState (batch_001).
// Call from asm_quadbuf_init providers (batch_013 C path / tests).
int quad_registry_bind(HWND hwnd, uint32_t width, uint32_t height, uint32_t flags);

// Clear bind + scratch (asm_quadbuf_shutdown in batch_001).
void quad_registry_clear(void);

// Render-thread tick counter (batch_013 render_thread path).
uint32_t quad_registry_render_tick(void);

uint32_t quad_registry_width(void);
uint32_t quad_registry_height(void);
uint32_t quad_registry_flags(void);
HWND     quad_registry_hwnd(void);

} // extern "C"
