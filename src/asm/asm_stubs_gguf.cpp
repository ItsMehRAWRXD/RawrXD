// asm_stubs_gguf.cpp - Stub implementations for GGUF loader ASM exports

#include <cstdint>

extern "C" {

int asm_gguf_loader_close(void* handle) {
    (void)handle;
    return 0;
}

} // extern "C"
