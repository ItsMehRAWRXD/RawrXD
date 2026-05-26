#include <windows.h>
#include <iostream>
#include <cstdint>
#include <vector>

struct TitanMemoryLayout {
    void* buffer_start; 
    size_t buffer_size;
};

class TensorMemoryManager {
public:
    static TitanMemoryLayout AllocateTensorBuffer(size_t size) {
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        size_t pageSize = si.dwPageSize;
        size_t aligned_size = (size + pageSize - 1) & ~(pageSize - 1);
        size_t total_size = aligned_size + (2 * pageSize);
        
        void* raw_ptr = VirtualAlloc(NULL, total_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!raw_ptr) exit(1);

        DWORD oldProtect;
        VirtualProtect(raw_ptr, pageSize, PAGE_NOACCESS, &oldProtect);
        VirtualProtect((char*)raw_ptr + pageSize + aligned_size, pageSize, PAGE_NOACCESS, &oldProtect);

        return { (char*)raw_ptr + pageSize, aligned_size };
    }

    static void FreeTensorBuffer(TitanMemoryLayout layout) {
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        size_t pageSize = si.dwPageSize;
        void* original_base = (char*)layout.buffer_start - pageSize;
        VirtualFree(original_base, 0, MEM_RELEASE);
    }
};

extern "C" uint64_t LOAD_MODEL(void* base_addr, size_t file_size, size_t tensor_offset);
extern "C" void GET_TENSOR_PTR(void** p1, void** p2, void* base_addr, size_t tensor_idx, size_t tensor_offset); 
// Note: standard ABI returns multiple values awkwardly. For simplicity, we just test LOAD_MODEL here.

int main() {
    std::cout << "[TITAN LOADER] Testing Loader Component..." << std::endl;
    TitanMemoryLayout model_blob = TensorMemoryManager::AllocateTensorBuffer(4096);
    
    // Mocking an in-memory mapped file blob
    // HEADER: [4] Magic = 'TNNN' (0x4E4E4E54)
    //         [4] Version = 1
    //         [8] TensorCount = 2
    uint32_t* header = (uint32_t*)model_blob.buffer_start;
    header[0] = 0x4E4E4E54; 
    header[1] = 1;
    uint64_t* count = (uint64_t*)&header[2]; // Using offset 8 for count
    *count = 2;
    
    // Tensor Table Offset = 16
    size_t tensor_offset = 16;
    uint64_t* table = (uint64_t*)((char*)model_blob.buffer_start + tensor_offset);
    
    // Tensor 0: Valid mapping
    table[0] = 128; // Offset
    table[1] = 256; // Size
    
    // Tensor 1: Valid mapping
    table[2] = 512; // Offset
    table[3] = 1024; // Size
    
    uint64_t result = LOAD_MODEL(model_blob.buffer_start, model_blob.buffer_size, tensor_offset);
    if (result == 0) {
        std::cout << "[TITAN LOADER] Success: Valid model loaded normally!" << std::endl;
    } else {
        std::cout << "[TITAN LOADER] Failed: Normal load failed!" << std::endl;
    }

    // Now corrupt it: Tensor 1 out of bounds
    table[2] = 4000;
    table[3] = 1000; // 4000 + 1000 = 5000 > 4096!
    
    result = LOAD_MODEL(model_blob.buffer_start, model_blob.buffer_size, tensor_offset);
    if (result == 1) {
        std::cout << "[TITAN LOADER] Success: Caught OOB bounds!" << std::endl;
    } else {
        std::cout << "[TITAN LOADER] Failed: Did not catch OOB!" << std::endl;
    }
    
    TensorMemoryManager::FreeTensorBuffer(model_blob);
    return 0;
}
