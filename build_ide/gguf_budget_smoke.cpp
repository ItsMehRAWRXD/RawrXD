#include "../src/streaming_gguf_loader.h"
#include <iostream>

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    StreamingGGUFLoader loader;
    if (!loader.Open(argv[1])) {
        std::cout << "OPEN=FAIL\n";
        return 3;
    }
    const bool zone = loader.LoadZone("embedding", 512);
    std::vector<uint8_t> slice;
    const bool bounded = loader.LoadTensorSlice("token_embd.weight", 0, 4096, slice);
    std::cout << "OPEN=PASS\nEMBED_ZONE=" << (zone ? "PASS" : "REJECTED_BUDGET")
              << "\nEMBED_SLICE=" << (bounded && slice.size() == 4096 ? "PASS" : "FAIL") << "\n";
    loader.Close();
    return (bounded && slice.size() == 4096) ? 0 : 4;
}
