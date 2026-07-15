// ============================================================================
// Streaming GGUF Loader Test - Tight Integration Demo
// ============================================================================

#include "gguf_adapter_bridge_v2.hpp"
#include <cstdio>
#include <chrono>

using namespace sovereign;

void printHeader() {
    printf("================================================================================\n");
    printf("Streaming GGUF Loader Test - Tight Integration\n");
    printf("================================================================================\n\n");
}

void printUsage(const char* prog) {
    printf("Usage: %s <gguf_file> [command]\n\n", prog);
    printf("Commands:\n");
    printf("  list       - List all tensors (default)\n");
    printf("  weights    - Load all weight tensors\n");
    printf("  find <name> - Find specific tensor\n");
    printf("  bench      - Benchmark iteration speed\n");
    printf("  info       - Show file info\n");
}

int cmdList(const std::string& filename) {
    printf("Opening: %s\n\n", filename.c_str());
    
    StreamingGGUFLoader loader(filename);
    if (!loader.isOpen()) {
        printf("ERROR: Failed to open file\n");
        return 1;
    }
    
    printf("Total tensors: %llu\n\n", (unsigned long long)loader.tensorCount());
    
    printf("%-50s %-10s %-20s %12s\n", "Name", "Type", "Shape", "Size");
    printf("%-50s %-10s %-20s %12s\n", "----", "----", "-----", "----");
    
    int count = 0;
    loader.forEachTensor([&](const TensorView& view) {
        PrintTensorInfo(view.info());
        if (++count >= 20 && count < (int)loader.tensorCount()) {
            printf("... (%llu more tensors)\n", 
                   (unsigned long long)(loader.tensorCount() - 20));
            return;  // Can't break from forEach, but we can skip printing
        }
    });
    
    printf("\nTotal: %d tensors listed\n", count);
    return 0;
}

int cmdWeights(const std::string& filename) {
    printf("Loading weights from: %s\n\n", filename.c_str());
    
    StreamingGGUFLoader loader(filename);
    if (!loader.isOpen()) {
        printf("ERROR: Failed to open file\n");
        return 1;
    }
    
    auto start = std::chrono::high_resolution_clock::now();
    auto weights = loader.loadWeights();
    auto end = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    printf("Loaded %zu weight tensors in %lld ms\n\n", weights.size(), (long long)duration.count());
    
    size_t totalBytes = 0;
    for (const auto& [info, data] : weights) {
        printf("%-50s %-10s %10zu bytes\n", 
               info.name.c_str(), info.typeName().c_str(), data.size());
        totalBytes += data.size();
    }
    
    printf("\nTotal weight data: %.2f MB\n", totalBytes / (1024.0 * 1024.0));
    return 0;
}

int cmdFind(const std::string& filename, const std::string& tensorName) {
    printf("Finding tensor '%s' in: %s\n\n", tensorName.c_str(), filename.c_str());
    
    StreamingGGUFLoader loader(filename);
    if (!loader.isOpen()) {
        printf("ERROR: Failed to open file\n");
        return 1;
    }
    
    auto info = loader.findTensor(tensorName);
    if (!info) {
        printf("Tensor not found: %s\n", tensorName.c_str());
        return 1;
    }
    
    printf("Found tensor:\n");
    printf("  Name:   %s\n", info->name.c_str());
    printf("  Type:   %s (%d)\n", info->typeName().c_str(), (int)info->type);
    printf("  Shape:  %s\n", info->shapeStr().c_str());
    printf("  Elements: %llu\n", (unsigned long long)info->numElements());
    printf("  Data size: %llu bytes\n", (unsigned long long)info->dataSize);
    printf("  Offset: %llu\n", (unsigned long long)info->offset);
    printf("  Is weight: %s\n", info->isWeight() ? "yes" : "no");
    printf("  Is quantized: %s\n", info->isQuantized() ? "yes" : "no");
    
    // Try to load it
    printf("\nLoading tensor data...\n");
    auto data = loader.loadTensor(tensorName);
    if (data) {
        printf("Successfully loaded %zu bytes\n", data->size());
    } else {
        printf("Failed to load tensor data\n");
    }
    
    return 0;
}

int cmdBench(const std::string& filename) {
    printf("Benchmarking: %s\n\n", filename.c_str());
    
    StreamingGGUFLoader loader(filename);
    if (!loader.isOpen()) {
        printf("ERROR: Failed to open file\n");
        return 1;
    }
    
    const int iterations = 10;
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; i++) {
        int count = 0;
        loader.forEachTensor([&](const TensorView&) { count++; });
        (void)count;  // Suppress unused warning
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    double avgUs = duration.count() / (double)iterations;
    double tensorsPerSec = loader.tensorCount() * 1000000.0 / avgUs;
    
    printf("Results (%d iterations):\n", iterations);
    printf("  Average time: %.2f us\n", avgUs);
    printf("  Tensors/sec: %.2f million\n", tensorsPerSec / 1000000.0);
    printf("  Per tensor: %.2f ns\n", avgUs * 1000.0 / loader.tensorCount());
    
    return 0;
}

int cmdInfo(const std::string& filename) {
    printf("File info: %s\n\n", filename.c_str());
    
    GGUFAdapter adapter;
    if (!adapter.init(filename)) {
        printf("ERROR: Failed to open file\n");
        return 1;
    }
    
    printf("File size:      %llu bytes (%.2f MB)\n", 
           (unsigned long long)adapter.fileSize(),
           adapter.fileSize() / (1024.0 * 1024.0));
    printf("Tensor count:   %llu\n", (unsigned long long)adapter.tensorCount());
    printf("Data section:   offset %llu\n", (unsigned long long)adapter.dataSectionOffset());
    
    return 0;
}

int main(int argc, char* argv[]) {
    printHeader();
    
    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }
    
    std::string filename = argv[1];
    std::string command = (argc >= 3) ? argv[2] : "list";
    
    if (command == "list") {
        return cmdList(filename);
    } else if (command == "weights") {
        return cmdWeights(filename);
    } else if (command == "find") {
        if (argc < 4) {
            printf("Usage: %s <file> find <tensor_name>\n", argv[0]);
            return 1;
        }
        return cmdFind(filename, argv[3]);
    } else if (command == "bench") {
        return cmdBench(filename);
    } else if (command == "info") {
        return cmdInfo(filename);
    } else {
        printf("Unknown command: %s\n", command.c_str());
        printUsage(argv[0]);
        return 1;
    }
}
