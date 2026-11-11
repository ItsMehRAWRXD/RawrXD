// ============================================================================
// Test Program for GGUF Adapter
// ============================================================================

#include "gguf_adapter_bridge.hpp"
#include <cstdio>
#include <cstdlib>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <gguf_file>\n", argv[0]);
        return 1;
    }

    printf("================================================================================\n");
    printf("GGUF Adapter Test - Sovereign Fabricator\n");
    printf("================================================================================\n\n");

    try {
        sovereign::GGUFLoader loader;
        
        printf("Opening: %s\n", argv[1]);
        loader.open(argv[1]);
        
        printf("Tensor count: %llu\n\n", (unsigned long long)loader.tensorCount());
        
        printf("%-40s %-10s %-20s %-12s\n", "Name", "Type", "Shape", "Data Size");
        printf("%-40s %-10s %-20s %-12s\n", "----", "----", "-----", "---------");
        
        int count = 0;
        while (true) {
            int64_t result = loader.nextTensor();
            if (result == 1) break;  // End of stream
            if (result < 0) {
                printf("Error reading tensor: %lld\n", result);
                break;
            }
            
            auto info = loader.getTensorInfo();
            
            // Format shape
            char shapeStr[64] = {0};
            if (info.shape.empty()) {
                snprintf(shapeStr, sizeof(shapeStr), "scalar");
            } else {
                char temp[16];
                for (size_t i = 0; i < info.shape.size(); i++) {
                    if (i > 0) strcat(shapeStr, "x");
                    snprintf(temp, sizeof(temp), "%llu", (unsigned long long)info.shape[i]);
                    strcat(shapeStr, temp);
                }
            }
            
            printf("%-40s %-10s %-20s %-12llu\n",
                   info.name.c_str(),
                   info.typeName().c_str(),
                   shapeStr,
                   (unsigned long long)info.dataSize);
            
            if (++count >= 10) {
                printf("... (%llu more tensors)\n", 
                       (unsigned long long)(loader.tensorCount() - 10));
                break;
            }
        }
        
        printf("\n================================================================================\n");
        printf("Test completed successfully!\n");
        printf("================================================================================\n");
        
    } catch (const std::exception& e) {
        printf("ERROR: %s\n", e.what());
        return 1;
    }
    
    return 0;
}
