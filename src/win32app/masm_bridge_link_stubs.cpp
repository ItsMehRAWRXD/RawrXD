// MASM Bridge Link Stubs
// Purpose: Provide fallback symbols for MASM functions that are referenced but not implemented
// These stubs satisfy the linker when the actual ASM implementations are not available

#include <cstdint>
#include <cstddef>

extern "C"
{
    // GGUF Loader stubs
    void* asm_gguf_loader_open(const char* path) { (void)path; return nullptr; }
    void asm_gguf_loader_close(void* ctx) { (void)ctx; }
    int asm_gguf_loader_load(void* ctx, const char* path) { (void)ctx; (void)path; return -1; }
    
    // LSP Bridge stubs
    void asm_lsp_bridge_init(void) {}
    void asm_lsp_bridge_shutdown(void) {}
    int asm_lsp_bridge_send(const char* msg, size_t len) { (void)msg; (void)len; return -1; }
    int asm_lsp_bridge_recv(char* buf, size_t maxLen) { (void)buf; (void)maxLen; return -1; }
    
    // QuadBuffer stubs
    void* asm_quadbuf_init(size_t size) { (void)size; return nullptr; }
    void asm_quadbuf_shutdown(void) {}
    void asm_quadbuf_push(const void* data, size_t len) { (void)data; (void)len; }
    size_t asm_quadbuf_pull(void* buf, size_t maxLen) { (void)buf; (void)maxLen; return 0; }
    
    // Orchestrator stubs
    void asm_orchestrator_init(void) {}
    void asm_orchestrator_shutdown(void) {}
    int asm_orchestrator_submit_task(void* task) { (void)task; return -1; }
    void* asm_orchestrator_get_result(void) { return nullptr; }
    
    // Self-Patch Engine stubs
    void asm_spengine_init(void) {}
    void asm_spengine_shutdown(void) {}
    int asm_spengine_apply_patch(const void* patch, size_t len) { (void)patch; (void)len; return -1; }
    int asm_spengine_verify_integrity(void) { return 0; }
    
    // Additional stubs for other ASM symbols
    void asm_streaming_init(void) {}
    void asm_streaming_shutdown(void) {}
    void asm_inference_init(void) {}
    void asm_inference_shutdown(void) {}
    void asm_quant_init(void) {}
    void asm_quant_shutdown(void) {}
    
} // extern "C"
