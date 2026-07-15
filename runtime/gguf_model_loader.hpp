// ============================================================================
// gguf_model_loader.hpp - Load Real GGUF Files into TensorRegistry
// ============================================================================
// Bridges the gap between file I/O and the inference runtime.
// Reads actual GGUF files, populates TensorRegistry with TensorData,
// enables real quantized inference via TensorView.
// ============================================================================

#pragma once

#include "tensor_view.hpp"
#include <string>
#include <vector>
#include <memory>

namespace RawrXD {
namespace Runtime {

// Forward declaration
struct GGUFContext;

// ============================================================================
// GGUF Model Loader
// ============================================================================
class GGUFModelLoader {
public:
    GGUFModelLoader();
    ~GGUFModelLoader();
    
    // Load GGUF file into tensor registry
    // Returns true if at least tensors were loaded
    bool LoadFromFile(const std::string& filePath, TensorRegistry& registry);
    
    // Get last error message
    const std::string& GetLastError() const { return m_lastError; }
    
    // Get metadata values
    std::string GetMetadataString(const std::string& key) const;
    int64_t GetMetadataInt(const std::string& key, int64_t defaultVal = 0) const;
    float GetMetadataFloat(const std::string& key, float defaultVal = 0.0f) const;
    
    // Architecture detection
    std::string DetectArchitecture() const;
    std::string GetModelName() const;
    
    // Statistics
    uint32_t GetTensorCount() const { return m_tensorCount; }
    uint32_t GetMetadataCount() const { return m_metadataCount; }
    
    // Validation
    bool IsValid() const { return m_valid; }
    
    // Get loaded tensor names
    std::vector<std::string> GetTensorNames() const;
    
private:
    std::unique_ptr<GGUFContext> m_context;
    std::string m_lastError;
    bool m_valid = false;
    uint32_t m_tensorCount = 0;
    uint32_t m_metadataCount = 0;
    
    // Internal loading
    bool ParseFile(const std::string& filePath);
    bool PopulateRegistry(TensorRegistry& registry);
    
    // Tensor conversion
    TensorData ConvertTensor(const std::string& name, const void* data, 
                             size_t byteOffset, size_t bytes,
                             const std::vector<size_t>& shape,
                             GGMLType type);
    
    // Dequantization helpers
    std::vector<float> DequantizeQ4_K(const uint8_t* data, size_t numElements);
    std::vector<float> DequantizeQ2_K(const uint8_t* data, size_t numElements);
    std::vector<float> DequantizeQ6_K(const uint8_t* data, size_t numElements);
    std::vector<float> DequantizeQ8_0(const uint8_t* data, size_t numElements);
};

// ============================================================================
// Convenience Function
// ============================================================================
// Load a GGUF model file and populate registry in one call
bool LoadGGUFModel(const std::string& filePath, TensorRegistry& registry,
                   std::string& outError);

} // namespace Runtime
} // namespace RawrXD
