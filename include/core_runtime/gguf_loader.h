// =============================================================================
// RawrXD-CoreRuntime Public API: GGUF Loader
// =============================================================================
// PURPOSE: Headless GGUF model loading without UI dependencies
// =============================================================================

#ifndef RAWRXD_CORE_GGUF_LOADER_H
#define RAWRXD_CORE_GGUF_LOADER_H

#include "core_export.h"
#include <memory>
#include <cstddef>
#include <cstdint>

namespace RawrXD {
namespace Core {

class RAWRXD_CORE_EXPORT GGUFLoader {
public:
    GGUFLoader();
    ~GGUFLoader();

    // Non-copyable
    GGUFLoader(const GGUFLoader&) = delete;
    GGUFLoader& operator=(const GGUFLoader&) = delete;

    // Movable
    GGUFLoader(GGUFLoader&&) noexcept;
    GGUFLoader& operator=(GGUFLoader&&) noexcept;

    // Load model from GGUF file
    bool Load(const char* path);

    // Check if model is loaded
    bool IsLoaded() const;

    // Get loaded model path
    const char* GetModelPath() const;

    // Unload model
    void Unload();
    
    // ---- Model Information ----
    
    // Get number of tensors in the model
    size_t GetTensorCount() const;
    
    // Get number of transformer layers
    uint32_t GetLayerCount() const;
    
    // Get vocabulary size
    uint32_t GetVocabSize() const;
    
    // Get embedding dimension
    uint32_t GetEmbeddingDim() const;
    
    // Get model architecture (e.g., "llama", "qwen2", "phi3")
    const char* GetArchitecture() const;

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

} // namespace Core
} // namespace RawrXD

#endif // RAWRXD_CORE_GGUF_LOADER_H
