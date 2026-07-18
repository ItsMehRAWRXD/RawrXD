// tensor_manifest.h
// VAL-020.1 Tensor Manifest System
// Captures SHA256, shape, dtype, provenance for every tensor

#ifndef TENSOR_MANIFEST_H
#define TENSOR_MANIFEST_H

#include <string>
#include <vector>
#include <cstdint>
#include <map>

namespace val020 {

// Tensor layout information
struct TensorLayout {
    std::vector<size_t> shape;
    std::vector<size_t> strides;
    std::string dtype;           // "float32", "float16", "int32", etc.
    std::string memory_format;   // "contiguous", "channels_last", etc.
    
    size_t num_elements() const;
    size_t num_bytes() const;
    bool is_contiguous() const;
};

// Provenance tracking
struct TensorProvenance {
    std::string source_run;
    std::string kernel_id;
    std::string kernel_name;
    std::string kernel_version;
    std::string timestamp;
    std::vector<std::string> input_tensors;
};

// Complete tensor manifest
struct TensorManifest {
    std::string tensor_id;
    std::string producer_kernel;
    std::vector<std::string> consumer_kernels;
    
    TensorLayout layout;
    std::string sha256_hash;
    
    TensorProvenance provenance;
    
    // Serialization
    std::string to_json() const;
    static TensorManifest from_json(const std::string& json);
};

// Manifest registry - tracks all tensors in execution
class ManifestRegistry {
public:
    void register_tensor(const TensorManifest& manifest);
    TensorManifest* get_tensor(const std::string& tensor_id);
    std::vector<TensorManifest> get_producer_outputs(const std::string& kernel_id);
    std::vector<TensorManifest> get_consumer_inputs(const std::string& kernel_id);
    
    // Integrity verification
    bool verify_all_hashes() const;
    std::map<std::string, bool> get_verification_report() const;
    
    // Serialization
    std::string to_json() const;
    void save_to_file(const std::string& path) const;
    static ManifestRegistry load_from_file(const std::string& path);
    
private:
    std::map<std::string, TensorManifest> tensors_;
};

// Hash computation for tensor data
std::string compute_tensor_hash(const void* data, size_t num_bytes);

} // namespace val020

#endif // TENSOR_MANIFEST_H
