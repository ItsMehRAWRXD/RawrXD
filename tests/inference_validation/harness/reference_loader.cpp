/**
 * RawrXD Reference Data Loader
 * 
 * Loads golden reference data from llama.cpp for validation comparison.
 */

#include "reference_loader.hpp"
#include <cstdio>
#include <cstring>

namespace rawrxd {
namespace validation {

bool ReferenceLoader::load(const char* filename) {
    FILE* fp = fopen(filename, "rb");
    if (!fp) {
        fprintf(stderr, "Failed to open reference file: %s\n", filename);
        return false;
    }
    
    // Read header
    uint32_t magic, version;
    if (fread(&magic, sizeof(magic), 1, fp) != 1 ||
        fread(&version, sizeof(version), 1, fp) != 1) {
        fprintf(stderr, "Failed to read header\n");
        fclose(fp);
        return false;
    }
    
    if (magic != 0x52414452) { // "RADR"
        fprintf(stderr, "Invalid magic: 0x%08X\n", magic);
        fclose(fp);
        return false;
    }
    
    printf("Loading reference data (version %d)...\n", version);
    
    // Read records
    while (!feof(fp)) {
        TensorRecord record;
        
        // Layer index
        if (fread(&record.layer_idx, sizeof(record.layer_idx), 1, fp) != 1) break;
        
        // Name
        uint16_t name_len;
        if (fread(&name_len, sizeof(name_len), 1, fp) != 1) break;
        record.name.resize(name_len);
        if (fread(record.name.data(), 1, name_len, fp) != name_len) break;
        
        // Shape
        int n_dims;
        if (fread(&n_dims, sizeof(n_dims), 1, fp) != 1) break;
        record.shape.resize(n_dims);
        if (fread(record.shape.data(), sizeof(int), n_dims, fp) != (size_t)n_dims) break;
        
        // Data
        size_t n_elements;
        if (fread(&n_elements, sizeof(n_elements), 1, fp) != 1) break;
        record.data.resize(n_elements);
        if (fread(record.data.data(), sizeof(float), n_elements, fp) != n_elements) break;
        
        records_.push_back(std::move(record));
    }
    
    fclose(fp);
    
    printf("Loaded %zu tensor records\n", records_.size());
    return true;
}

const TensorRecord* ReferenceLoader::findTensor(const char* name, int layer_idx) const {
    for (const auto& record : records_) {
        if (record.layer_idx == layer_idx && record.name == name) {
            return &record;
        }
    }
    return nullptr;
}

std::vector<const TensorRecord*> ReferenceLoader::getLayerTensors(int layer_idx) const {
    std::vector<const TensorRecord*> result;
    for (const auto& record : records_) {
        if (record.layer_idx == layer_idx) {
            result.push_back(&record);
        }
    }
    return result;
}

void ReferenceLoader::printSummary() const {
    printf("\n=== Reference Data Summary ===\n");
    printf("Total records: %zu\n\n", records_.size());
    
    int current_layer = -1;
    for (const auto& record : records_) {
        if (record.layer_idx != current_layer) {
            current_layer = record.layer_idx;
            printf("\nLayer %d:\n", current_layer);
        }
        
        printf("  %s: [", record.name.c_str());
        for (size_t i = 0; i < record.shape.size(); i++) {
            if (i > 0) printf("x");
            printf("%d", record.shape[i]);
        }
        printf("] = %zu elements\n", record.data.size());
        
        // Print first few values
        printf("    Values: ");
        for (size_t i = 0; i < std::min(size_t(5), record.data.size()); i++) {
            printf("%.6f ", record.data[i]);
        }
        if (record.data.size() > 5) printf("...");
        printf("\n");
    }
}

} // namespace validation
} // namespace rawrxd
