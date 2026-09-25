#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <optional>
#include <functional>
#include "gguf_adapter.hpp"

namespace rawrxd::canonical {

enum class ModelFormat {
    Unknown = 0,
    GGUF = 1,
    PyTorch = 2,
    SafeTensors = 3,
    ONNX = 4,
    TensorFlow = 5,
    RawBinary = 6
};

enum class LoadStatus {
    Idle = 0,
    Reading = 1,
    Parsing = 2,
    Adapting = 3,
    Quantizing = 4,
    Validating = 5,
    Complete = 6,
    Error = 7,
    Cancelled = 8
};

struct LoadProgress {
    LoadStatus status = LoadStatus::Idle;
    float percent_complete = 0.0f;
    std::string current_phase;
    std::string error_message;
    uint64_t bytes_loaded = 0;
    uint64_t total_bytes = 0;
    size_t tensors_loaded = 0;
    size_t total_tensors = 0;
};

struct ModelLoadConfig {
    bool verify_checksum = false;
    bool allow_quantized = true;
    bool load_tensors = true;
    bool mmap_tensors = true;
    size_t max_tensor_memory = 0;
    std::string preferred_device = "auto";
    std::vector<TensorLayout> allowed_quantizations;
    std::function<bool(const LoadProgress&)> on_progress;
    std::function<bool()> is_cancelled;
};

struct UnifiedModel {
    CanonicalModelDescriptor descriptor;
    std::vector<CanonicalTensor> tensors;
    std::map<std::string, std::vector<uint8_t>> raw_plans;
    std::vector<uint8_t> original_buffer;
    ModelFormat source_format = ModelFormat::Unknown;
    bool tensors_memory_mapped = false;
};

class ModelLoadResult {
public:
    bool success = false;
    UnifiedModel model;
    LoadProgress final_progress;
    std::string error_message;
    std::vector<std::string> warnings;
};

class UnifiedModelLoader {
public:
    UnifiedModelLoader();
    ~UnifiedModelLoader();

    ModelLoadResult Load(const std::string& path,
                         const ModelLoadConfig& config = ModelLoadConfig{});
    ModelLoadResult LoadFromMemory(const std::vector<uint8_t>& buffer,
                                   ModelFormat format_hint,
                                   const ModelLoadConfig& config = ModelLoadConfig{});

    bool IsLoading() const;
    LoadProgress GetProgress() const;
    void Cancel();

    static ModelFormat DetectFormat(const std::string& path);
    static ModelFormat DetectFormatFromBytes(const std::vector<uint8_t>& header);
    static bool SupportsFormat(ModelFormat format);

    static std::string FormatToString(ModelFormat format);
    static std::string StatusToString(LoadStatus status);

    void SetDefaultConfig(const ModelLoadConfig& config);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace rawrxd::canonical