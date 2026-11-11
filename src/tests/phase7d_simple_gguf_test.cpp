// ============================================================================
// RawrXD Phase 7D: Simple GGUF Header Test
// ============================================================================
// Tests GGUF header parsing and checkpoint hooks without loading full tensors
// ============================================================================

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include "../integration/gguf_checkpoint_hooks.hpp"

using namespace RawrXD;

// GGUF magic number
static const uint32_t GGUF_MAGIC = 0x46554747;  // "GGUF" in little-endian

// Simple GGUF header structure
struct GGUFHeader {
    uint32_t magic;
    uint32_t version;
    uint64_t tensor_count;
    uint64_t kv_count;
};

// Simple tensor info
struct SimpleTensorInfo {
    std::string name;
    uint32_t n_dims;
    std::vector<uint64_t> dimensions;
    uint32_t type;
    uint64_t offset;
};

// Read a value from file
template<typename T>
bool ReadValue(FILE* f, T& value) {
    return fread(&value, sizeof(T), 1, f) == 1;
}

// Read a string from file
bool ReadString(FILE* f, std::string& str) {
    uint64_t len = 0;
    if (!ReadValue(f, len)) return false;
    
    // Sanity check - prevent huge allocations
    if (len > 1000000) {
        fprintf(stderr, "ERROR: String length too large: %llu\n", (unsigned long long)len);
        return false;
    }
    
    str.resize(len);
    if (len > 0) {
        if (fread(&str[0], 1, len, f) != len) return false;
    }
    return true;
}

// Simple SHA256 computation for model verification
std::string ComputeFileSHA256(const char* filepath) {
    FILE* f = fopen(filepath, "rb");
    if (!f) return "";
    
    // Simple hash - in production use proper SHA256
    uint64_t hash = 0x9E3779B97F4A7C15ULL;
    uint8_t buffer[4096];
    size_t read;
    
    while ((read = fread(buffer, 1, sizeof(buffer), f)) > 0) {
        for (size_t i = 0; i < read; i++) {
            hash = hash * 31 + buffer[i];
        }
    }
    
    fclose(f);
    
    char result[32];
    snprintf(result, sizeof(result), "%016llX", hash);
    return std::string(result);
}

int main(int argc, char* argv[]) {
    printf("=====================================================================\n");
    printf("RawrXD Phase 7D: Simple GGUF Header Test with Checkpoints\n");
    printf("=====================================================================\n\n");
    
    // Parse arguments
    const char* model_path = (argc > 1) ? argv[1] : "models/tinyllama.gguf";
    
    printf("Configuration:\n");
    printf("  Model: %s\n\n", model_path);
    
    // Check model file exists
    FILE* f = fopen(model_path, "rb");
    if (!f) {
        fprintf(stderr, "ERROR: Model file not found: %s\n", model_path);
        fprintf(stderr, "Please provide a valid GGUF model file path.\n");
        fprintf(stderr, "\nUsage: %s <model.gguf>\n", argv[0]);
        return 1;
    }
    
    // Get file size
    fseek(f, 0, SEEK_END);
    size_t file_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    printf("File size: %zu bytes\n\n", file_size);
    
    // Compute model hash
    printf("Step 1: Computing model hash...\n");
    std::string model_hash = ComputeFileSHA256(model_path);
    printf("  Model hash: %s\n\n", model_hash.c_str());
    
    // Initialize checkpoint context
    printf("Step 2: Initializing checkpoint context...\n");
    Integration::GGUFCheckpointContext* ctx = new Integration::GGUFCheckpointContext();
    
    if (!Integration::GGUFCheckpoint_Init(ctx, model_path, "phase7d-simple-test", "tiered_memory")) {
        fprintf(stderr, "ERROR: Failed to initialize checkpoint context\n");
        return 1;
    }
    
    printf("  Checkpoint context initialized\n");
    printf("  Model hash: 0x%016llX\n", ctx->model_hash);
    printf("  Enabled: %s\n\n", ctx->enabled ? "YES" : "NO");
    
    // Read GGUF header
    printf("Step 3: Reading GGUF header...\n");
    
    GGUFHeader header;
    if (!ReadValue(f, header.magic)) {
        fprintf(stderr, "ERROR: Failed to read magic\n");
        fclose(f);
        return 1;
    }
    
    if (header.magic != GGUF_MAGIC) {
        fprintf(stderr, "ERROR: Invalid GGUF magic: 0x%08X (expected 0x%08X)\n", 
                header.magic, GGUF_MAGIC);
        fclose(f);
        return 1;
    }
    
    if (!ReadValue(f, header.version)) {
        fprintf(stderr, "ERROR: Failed to read version\n");
        fclose(f);
        return 1;
    }
    
    if (!ReadValue(f, header.tensor_count)) {
        fprintf(stderr, "ERROR: Failed to read tensor count\n");
        fclose(f);
        return 1;
    }
    
    if (!ReadValue(f, header.kv_count)) {
        fprintf(stderr, "ERROR: Failed to read KV count\n");
        fclose(f);
        return 1;
    }
    
    printf("  GGUF header valid\n");
    printf("  Version: %u\n", header.version);
    printf("  Tensors: %llu\n", (unsigned long long)header.tensor_count);
    printf("  KV pairs: %llu\n\n", (unsigned long long)header.kv_count);
    
    // Skip KV pairs
    printf("Step 4: Skipping KV pairs...\n");
    for (uint64_t i = 0; i < header.kv_count; i++) {
        std::string key;
        if (!ReadString(f, key)) {
            fprintf(stderr, "ERROR: Failed to read KV key %llu\n", (unsigned long long)i);
            fclose(f);
            return 1;
        }
        
        // Read value type
        uint32_t value_type = 0;
        if (!ReadValue(f, value_type)) {
            fprintf(stderr, "ERROR: Failed to read KV value type\n");
            fclose(f);
            return 1;
        }
        
        // Skip value based on type
        // For simplicity, just skip 8 bytes for now
        // In a full implementation, we'd parse based on value_type
        fseek(f, 8, SEEK_CUR);
    }
    printf("  Skipped %llu KV pairs\n\n", (unsigned long long)header.kv_count);
    
    // Read tensor info
    printf("Step 5: Reading tensor info...\n");
    std::vector<SimpleTensorInfo> tensors;
    tensors.reserve(header.tensor_count);
    
    for (uint64_t i = 0; i < header.tensor_count; i++) {
        SimpleTensorInfo info;
        
        // Read tensor name
        if (!ReadString(f, info.name)) {
            fprintf(stderr, "ERROR: Failed to read tensor name %llu\n", (unsigned long long)i);
            fclose(f);
            return 1;
        }
        
        // Read dimensions
        if (!ReadValue(f, info.n_dims)) {
            fprintf(stderr, "ERROR: Failed to read tensor dimensions\n");
            fclose(f);
            return 1;
        }
        
        // Sanity check
        if (info.n_dims > 10) {
            fprintf(stderr, "ERROR: Too many dimensions: %u\n", info.n_dims);
            fclose(f);
            return 1;
        }
        
        info.dimensions.resize(info.n_dims);
        for (uint32_t d = 0; d < info.n_dims; d++) {
            if (!ReadValue(f, info.dimensions[d])) {
                fprintf(stderr, "ERROR: Failed to read dimension %u\n", d);
                fclose(f);
                return 1;
            }
        }
        
        // Read type
        if (!ReadValue(f, info.type)) {
            fprintf(stderr, "ERROR: Failed to read tensor type\n");
            fclose(f);
            return 1;
        }
        
        // Read offset
        if (!ReadValue(f, info.offset)) {
            fprintf(stderr, "ERROR: Failed to read tensor offset\n");
            fclose(f);
            return 1;
        }
        
        tensors.push_back(std::move(info));
    }
    
    printf("  Read %zu tensor info entries\n\n", tensors.size());
    
    // Print tensor info
    printf("Step 6: Tensor information:\n");
    size_t tensors_to_show = (tensors.size() < 10) ? tensors.size() : 10;
    for (size_t i = 0; i < tensors_to_show; i++) {
        const auto& tensor = tensors[i];
        printf("  [%zu] %s: [", i, tensor.name.c_str());
        for (size_t d = 0; d < tensor.dimensions.size(); d++) {
            if (d > 0) printf(", ");
            printf("%llu", (unsigned long long)tensor.dimensions[d]);
        }
        printf("] type=%u, offset=%llu\n", 
               tensor.type, (unsigned long long)tensor.offset);
    }
    if (tensors.size() > tensors_to_show) {
        printf("  ... and %zu more tensors\n", tensors.size() - tensors_to_show);
    }
    printf("\n");
    
    // Hash some dummy tensor data
    printf("Step 7: Testing tensor hashing...\n");
    for (size_t i = 0; i < tensors_to_show; i++) {
        const auto& tensor = tensors[i];
        
        // Create dummy data based on tensor name
        std::vector<uint8_t> dummy_data;
        dummy_data.reserve(tensor.name.size() + 16);
        for (char c : tensor.name) {
            dummy_data.push_back(static_cast<uint8_t>(c));
        }
        // Add dimension info
        for (size_t d = 0; d < tensor.dimensions.size(); d++) {
            uint64_t dim = tensor.dimensions[d];
            dummy_data.push_back(static_cast<uint8_t>(dim & 0xFF));
            dummy_data.push_back(static_cast<uint8_t>((dim >> 8) & 0xFF));
        }
        
        uint64_t tensor_hash = Integration::GGUFCheckpoint_HashTensor(
            dummy_data.data(), dummy_data.size(), 
            tensor.type, static_cast<uint32_t>(i));
        printf("  [%zu] %s hash: 0x%016llX\n", i, tensor.name.c_str(), tensor_hash);
    }
    printf("\n");
    
    // Export proof
    printf("Step 8: Exporting proof...\n");
    std::string proof_path = "phase7d_simple_" + model_hash + ".rawrproof";
    
    if (Integration::GGUFCheckpoint_ExportProof(ctx, proof_path.c_str())) {
        printf("  Proof exported to: %s\n", proof_path.c_str());
        
        // Get file size
        FILE* pf = fopen(proof_path.c_str(), "rb");
        if (pf) {
            fseek(pf, 0, SEEK_END);
            size_t size = ftell(pf);
            fclose(pf);
            printf("  Proof size: %zu bytes\n", size);
        }
    } else {
        printf("  WARNING: Failed to export proof\n");
    }
    
    // Get checkpoint stats
    uint32_t tensors_hashed = 0;
    uint64_t bytes = 0;
    double hash_time = 0.0;
    Integration::GGUFCheckpoint_GetStats(ctx, &tensors_hashed, &bytes, &hash_time);
    
    printf("\nCheckpoint statistics:\n");
    printf("  Tensors hashed: %u\n", tensors_hashed);
    printf("  Bytes hashed: %llu\n", bytes);
    printf("  Hash time: %.2f ms\n", hash_time);
    
    // Cleanup
    fclose(f);
    delete ctx;
    
    printf("\n=====================================================================\n");
    printf("Simple GGUF Test Complete\n");
    printf("=====================================================================\n");
    printf("\nNext steps:\n");
    printf("  1. Run determinism test: scripts\\test_determinism.bat\n");
    printf("  2. Compare with llama.cpp: scripts\\compare_llamacpp_rawrxd.ps1\n");
    printf("  3. Full audit: scripts\\audit_run_realmodel.bat\n");
    
    return 0;
}
