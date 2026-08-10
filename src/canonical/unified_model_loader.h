#pragma once
#ifndef RAWRXD_UNIFIED_MODEL_LOADER_H
#define RAWRXD_UNIFIED_MODEL_LOADER_H

#include "canonical_model_contract.h"
#include <memory>
#include <filesystem>

namespace RawrXD::Canonical {

// ============================================================================
// Unified Model Loader
// Selects the appropriate IModelAdapter based on magic-based format detection.
// Owns the adapter lifetime; provides a single entry point for model loading.
// ============================================================================
class UnifiedModelLoader {
public:
    UnifiedModelLoader();
    ~UnifiedModelLoader();

    // Load a model from path. Returns true if a supported adapter was selected
    // and successfully opened.
    bool Load(const std::filesystem::path& path);

    // Access the underlying adapter (null if Load failed)
    IModelAdapter* Adapter() const;

    // Convenience accessors
    bool IsLoaded() const;
    const ModelMetadata& Metadata() const;
    DetectedFormat Format() const;
    const char* FormatName() const;
    std::string GetLastError() const;

    // Tensor helpers
    bool FindTensor(std::string_view name, TensorDescriptor& out) const;
    bool ReadTensor(const TensorDescriptor& tensor, void* destination, size_t bytes);

    // Reset state
    void Unload();

private:
    std::unique_ptr<IModelAdapter> adapter_;
    DetectedFormat detected_format_ = DetectedFormat::Unknown;
    std::string last_error_;
};

} // namespace RawrXD::Canonical

#endif // RAWRXD_UNIFIED_MODEL_LOADER_H
