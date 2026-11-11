// Simple test for GGUF adapter
#include <cstdio>
#include <cstdint>

// C linkage from MASM
extern "C" {
    int64_t GGUF_Init(const char* filename);
    void GGUF_Cleanup(void);
    int64_t GGUF_NextTensor(void);
    uint64_t GGUF_GetTensorCount(void);
    const char* GGUF_GetCurrentTensorName(void);
    uint32_t GGUF_GetCurrentTensorType(void);
    const char* GGUF_GetTypeName(uint32_t type);
}

int main(int argc, char* argv[]) {
    printf("GGUF Adapter Test\n");
    printf("=================\n\n");
    
    if (argc < 2) {
        printf("Usage: %s <gguf_file>\n", argv[0]);
        return 1;
    }
    
    printf("Testing with: %s\n", argv[1]);
    
    // Test init
    int64_t result = GGUF_Init(argv[1]);
    printf("GGUF_Init returned: %lld\n", result);
    
    if (result == 0) {
        printf("Tensor count: %llu\n", (unsigned long long)GGUF_GetTensorCount());
        
        // Test iteration
        int count = 0;
        while (GGUF_NextTensor() == 0) {
            const char* name = GGUF_GetCurrentTensorName();
            uint32_t type = GGUF_GetCurrentTensorType();
            const char* typeName = GGUF_GetTypeName(type);
            
            printf("  [%d] %s: %s\n", count, name ? name : "(null)", typeName ? typeName : "?");
            
            if (++count >= 5) {
                printf("  ... (more tensors)\n");
                break;
            }
        }
        
        GGUF_Cleanup();
        printf("\nCleanup complete.\n");
    }
    
    return 0;
}
