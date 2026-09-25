#pragma once
#include <string>
#include <vector>
#include <memory>
#include <optional>
#include <span>
#include <functional>
#include <future>
#include "GGUFAdapter.hpp"

namespace rawrxd::canonical {

// ───────────────────────────────────────────────────────────────
// Supported model format types
// ───────────────────────────────────────────────────────────────
enum class ModelFormat {
    GGUF,       // llama.cpp / upstream GGUF
    Safetensors, // Hugging Face safetensors
    PyTorch,    // torch .bin / .pt (via conversion)
    ONNX,       // ONNX runtime
    Unknown
};

// ───────────────────────────────────────────────────────────────
// Model source descriptor
// ───────────────────────────────────────────────────────────────
struct ModelSource {
    std::string path;
    std::string cache_key;
    ModelFormat format = ModelFormat::Unknown;
    std::vector<std::string> auxiliary_files; // vocab, tokenizer, config.json, etc.
    bool allow_mmap = true;
    bool verify_checksum = true;
    std::string expected_sha256;
};

// ───────────────────────────────────────────────────────────────
// Tensor payload abstraction (owned or memory-mapped)
// ───────────────────────────────────────────────────────────────
struct TensorPayload {
    std::string name;
    GGMLQuantType quant_type = GGMLQuantType::F32;
    std::vector<uint64_t> shape;
    std::vector<uint8_t> owned_data;
    std::span<const uint8_t> mmap_view;
    bool is_mmap = false;
    size_t byte_size() const { return is_mmap ? mmap_view.size() : owned_data.size(); }
    const uint8_t* data() const { return is_mmap ? mmap_view.data() : owned_data.data(); }
};

// ───────────────────────────────────────────────────────────────
// Loading progress event
// ───────────────────────────────────────────────────────────────
struct LoadProgress {
    enum class Phase {
        DetectFormat,
        ParseMetadata,
        ValidateChecksum,
        LoadTensors,
        BuildIndex,
        Complete
    };
    Phase phase = Phase::DetectFormat;
    size_t current_bytes = 0;
    size_t total_bytes = 0;
    size_t current_tensor = 0;
    size_t total_tensors = 0;
    std::string current_tensor_name;
    float percent() const { return total_bytes > 0 ? (current_bytes * 100.0f / total_bytes) : 0.0f; }
};

// ───────────────────────────────────────────────────────────────
// Model index — fast tensor lookup by name/prefix
// ───────────────────────────────────────────────────────────────
class ModelIndex {
public:
    void Reserve(size_t n);
    void AddTensor(std::string name, size_t payload_index);
    size_t Find(const std::string& name) const;
    std::vector<size_t> FindByPrefix(const std::string& prefix) const;
    std::vector<size_t> FindByLayer(uint32_t layer_idx) const;
    size_t Count() const { return name_to_idx_.size(); }
private:
    std::unordered_map<std::string, size_t> name_to_idx_;
};

// ───────────────────────────────────────────────────────────────
// UnifiedModelLoader — single entry point for all model formats
// ───────────────────────────────────────────────────────────────
class UnifiedModelLoader {
public:
    UnifiedModelLoader();
    ~UnifiedModelLoader();

    // Configuration
    void SetMMapEnabled(bool enabled) { mmap_enabled_ = enabled; }
    void SetProgressCallback(std::function<void(const LoadProgress&)> cb) { progress_cb_ = std::move(cb); }
    void SetThreadCount(uint32_t threads) { thread_count_ = threads; }
    void SetTensorFilter(std::function<bool(const std::string& name)> filter) { tensor_filter_ = std::move(filter); }
    void SetMaxMemoryBytes(uint64_t max_bytes) { max_memory_bytes_ = max_bytes; }

    // Main API: load from path
    bool Load(const std::string& path);
    bool Load(const ModelSource& source);

    // Async load (returns future)
    std::future<bool> LoadAsync(const std::string& path);

    // Accessors
    const GGUFAdapter* GGUF() const { return gguf_adapter_.get(); }
    const ModelMetadata& Metadata() const;
    const ModelIndex& Index() const { return index_; }
    const std::vector<TensorPayload>& Tensors() const { return tensors_; }
    std::span<const uint8_t> GetTensorData(const std::string& name) const;
    bool HasTensor(const std::string& name) const;

    // Validation
    bool ValidateAllTensorData() const;
    bool VerifySHA256(const std::string& expected) const;

    // Cache management
    bool ExportToCache(const std::string& cache_dir) const;
    bool ImportFromCache(const std::string& cache_key, const std::string& cache_dir);
    void InvalidateCache(const std::string& cache_key, const std::string& cache_dir);

    // Format detection (static)
    static ModelFormat DetectFormat(const std::string& path);
    static std::string FormatToString(ModelFormat f);

private:
    bool LoadGGUF(const ModelSource& source);
    bool LoadSafetensors(const ModelSource& source);
    bool LoadONNX(const ModelSource& source);

    void ReportProgress(LoadProgress::Phase phase, size_t current = 0, size_t total = 0);

    std::unique_ptr<GGUFAdapter> gguf_adapter_;
    std::vector<TensorPayload> tensors_;
    ModelIndex index_;
    ModelSource current_source_;
    bool mmap_enabled_ = true;
    uint32_t thread_count_ = 1;
    uint64_t max_memory_bytes_ = 0; // 0 = unlimited
    std::function<void(const LoadProgress&)> progress_cb_;
    std::function<bool(const std::string&)> tensor_filter_;
};

} // namespace rawrxd::canonical
