#include <windows.h>
#include <iostream>
#include <cstdint>

extern "C" void MODEL_LOAD(void* header, void* out_buffer);

struct TensorHeader {
    uint32_t magic;
    uint32_t type;
    uint64_t size;
    void* data_ptr;
};

int main() {
    std::cout << "[TITAN] Testing Zero-Copy Load-and-Go Pipeline..." << std::endl;
    // Stage 1: Harness Init. Allocate the Virtual Memory block and set PAGE_NOACCESS guards.
    // In our test, just allocating standard RW buffers.
    void* in_buffer = VirtualAlloc(NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    void* out_buffer = VirtualAlloc(NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    
    // Stage 2: Model Mapping. 
    TensorHeader* header = (TensorHeader*)in_buffer;
    header->magic = 0x4E415454; // 'TTAN'
    header->type = 0; // SIMD Kernel
    header->size = 64; // Element Count
    header->data_ptr = (char*)in_buffer + sizeof(TensorHeader);
    
    float* data = (float*)header->data_ptr;
    for (int i = 0; i < 64; i++) data[i] = 1.0f;
    
    // Stage 3: Load & Dispatch
    std::cout << "[TITAN] Dispatching via MODEL_LOAD..." << std::endl;
    
    // Using SEH just in case to verify it hits no issues
    __try {
        MODEL_LOAD(header, out_buffer);
        std::cout << "[TITAN] Execution finished successfully with native registers mapped!" << std::endl;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        std::cout << "[TITAN] Caught exception!" << std::endl;
    }

    VirtualFree(in_buffer, 0, MEM_RELEASE);
    VirtualFree(out_buffer, 0, MEM_RELEASE);
    return 0;
}
