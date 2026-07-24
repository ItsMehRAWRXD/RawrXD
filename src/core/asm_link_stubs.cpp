// ============================================================================
// asm_link_stubs.cpp — Stub implementations for missing ASM symbols
// ============================================================================
// These are minimal stub implementations for ASM functions that are referenced
// but not yet available in the MASM source files.
// ============================================================================

#include <windows.h>
#include <cstddef>

extern "C" {

// GGUF loader close stub
void asm_gguf_loader_close(void* /*ctx*/) {
    OutputDebugStringA("[asm_link_stubs] asm_gguf_loader_close stub called\n");
}

// LSP bridge shutdown stub
void asm_lsp_bridge_shutdown(void) {
    OutputDebugStringA("[asm_link_stubs] asm_lsp_bridge_shutdown stub called\n");
}

} // extern "C"
