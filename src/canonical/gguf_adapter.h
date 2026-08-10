#pragma once
#ifndef RAWRXD_GGUF_ADAPTER_H
#define RAWRXD_GGUF_ADAPTER_H

#include "canonical_model_contract.h"
#include <string>
#include <vector>
#include <map>
#include <fstream>

namespace RawrXD::Canonical {

// ============================================================================
// GGUF Adapter — canonical IModelAdapter implementation for GGUF files
// Wraps existing GGUF loader; does not duplicate parsing logic.
// ============================================================================
class GGUFAdapter : public IModelAdapter {
public:
    GGUFAdapter();
    ~GGUFAdapter() override;

    // IModelAdapter
    bool Open(const std::filesystem::path& path) override;
    void Close() override;
    bool IsOpen() const override;

    bool Validate() const override;
    std::string GetValidationError() const override;

    const ModelMetadata& Metadata() const override;

    bool FindTensor(std::string_view name, TensorDescriptor& out) const override;
    bool ReadTensor(const TensorDescriptor& tensor, void* destination, size_t bytes) override;

    size_t TensorCount() const override;
    bool GetTensorIndex(size_t index, TensorDescriptor& out) const override;

    const char* FormatName() const override { return "GGUF"; }

    // GGUF-specific: raw file handle for zero-copy mmap scenarios
    std::ifstream& FileStream() { return file_; }
    uint64_t DataOffset() const { return data_offset_; }

private:
    bool ParseHeader();
    bool ParseMetadata();
    bool ParseTensorIndex();
    bool ResolveMetadata();

    std::ifstream file_;
    std::filesystem::path path_;
    bool is_open_ = false;
    std::string validation_error_;

    // Header
    uint32_t magic_ = 0;
    uint32_t version_ = 0;
    uint64_t tensor_count_ = 0;
    uint64_t metadata_kv_count_ = 0;
    uint64_t data_offset_ = 0;

    // Metadata
    ModelMetadata metadata_;
    std::map<std::string, std::string> metadata_strings_;
    std::map<std::string, uint64_t> metadata_uints_;

    // Tensors
    std::vector<TensorDescriptor> tensors_;
    std::map<std::string, size_t> tensor_name_to_index_;

    // Helpers
    static TensorDType MapGGUFType(uint32_t gguf_type);
    static ModelArchitecture ResolveArchitecture(const std::string& arch_name);
};

} // namespace RawrXD::Canonical

#endif // RAWRXD_GGUF_ADAPTER_H
