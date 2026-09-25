#include "unified_model_loader.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <stdexcept>
#include <chrono>
#include <filesystem>

namespace rawrxd::canonical {

namespace fs = std::filesystem;

class UnifiedModelLoader::Impl {
public:
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    LoadProgress progress_;
    ModelLoadConfig default_config_;
    bool loading_ = false;
    bool cancelled_ = false;
    UnifiedModel loaded_model_;

    bool IsCancelled() {
        std::lock_guard<std::mutex> lock(mutex_);
        return cancelled_;
    }

    void UpdateStatus(LoadStatus status, const std::string& phase) {
        std::lock_guard<std::mutex> lock(mutex_);
        progress_.status = status;
        progress_.current_phase = phase;
    }

    void UpdateProgress(float pct, uint64_t bytes, uint64_t total, size_t tensors, size_t total_tensors) {
        std::lock_guard<std::mutex> lock(mutex_);
        progress_.percent_complete = pct;
        progress_.bytes_loaded = bytes;
        progress_.total_bytes = total;
        progress_.tensors_loaded = tensors;
        progress_.total_tensors = total_tensors;
    }

    void ReportError(const std::string& msg) {
        std::lock_guard<std::mutex> lock(mutex_);
        progress_.status = LoadStatus::Error;
        progress_.error_message = msg;
    }

    ModelLoadResult LoadSync(const std::string& path, const ModelLoadConfig& config) {
        ModelLoadResult result;
        UpdateStatus(LoadStatus::Reading, "Opening file...");

        if (!fs::exists(path)) {
            ReportError("File not found: " + path);
            result.success = false;
            result.error_message = progress_.error_message;
            return result;
        }

        uint64_t file_size = fs::file_size(path);
        UpdateProgress(0.0f, 0, file_size, 0, 0);

        auto format = DetectFormat(path);
        if (format == ModelFormat::Unknown) {
            ReportError("Unknown model format for: " + path);
            result.success = false;
            result.error_message = progress_.error_message;
            return result;
        }

        UpdateStatus(LoadStatus::Parsing, "Parsing model format...");
        if (format == ModelFormat::GGUF) {
            GGUFAdapter adapter;
            if (!adapter.AdaptFromFile(path)) {
                ReportError("Failed to parse GGUF file: " + path);
                result.success = false;
                result.error_message = progress_.error_message;
                return result;
            }
            UpdateStatus(LoadStatus::Adapting, "Building unified representation...");
            auto desc = adapter.GetDescriptor();
            if (desc) loaded_model_.descriptor = *desc;
            auto names = adapter.ListTensorNames();
            loaded_model_.source_format = ModelFormat::GGUF;
            UpdateProgress(50.0f, file_size / 2, file_size, 0, names.size());

            if (config.load_tensors) {
                UpdateStatus(LoadStatus::Quantizing, "Loading tensors...");
                for (size_t i = 0; i < names.size(); ++i) {
                    if (config.is_cancelled && config.is_cancelled()) {
                        UpdateStatus(LoadStatus::Cancelled, "Cancelled by user");
                        result.success = false;
                        return result;
                    }
                    auto tv = adapter.GetTensor(names[i]);
                    if (tv) {
                        CanonicalTensor ct;
                        ct.name = tv->Name();
                        ct.layout = tv->Layout();
                        ct.shape = tv->Shape();
                        ct.byte_size = tv->ByteSize();
                        loaded_model_.tensors.push_back(std::move(ct));
                    }
                    float pct = 50.0f + (50.0f * (i + 1.0f) / names.size());
                    UpdateProgress(pct, file_size / 2 + (file_size / 2) * (i + 1) / names.size(), file_size, i + 1, names.size());
                    if (config.on_progress) {
                        if (!config.on_progress(progress_)) {
                            UpdateStatus(LoadStatus::Cancelled, "Cancelled by callback");
                            result.success = false;
                            return result;
                        }
                    }
                }
            }
        }

        UpdateStatus(LoadStatus::Validating, "Validating model...");
        if (!ValidateModel(loaded_model_)) {
            ReportError("Model validation failed");
            result.success = false;
            result.error_message = progress_.error_message;
            return result;
        }

        UpdateStatus(LoadStatus::Complete, "Model loaded successfully");
        UpdateProgress(100.0f, file_size, file_size, loaded_model_.tensors.size(), loaded_model_.tensors.size());
        result.success = true;
        result.model = loaded_model_;
        result.final_progress = progress_;
        return result;
    }

    bool ValidateModel(const UnifiedModel& model) const {
        if (model.descriptor.architecture == ModelArchitecture::Unknown) {
            return false;
        }
        if (model.descriptor.hparams.hidden_size == 0) {
            return false;
        }
        if (model.descriptor.hparams.num_hidden_layers == 0) {
            return false;
        }
        return true;
    }
};

UnifiedModelLoader::UnifiedModelLoader() : impl_(std::make_unique<Impl>()) {}
UnifiedModelLoader::~UnifiedModelLoader() = default;

ModelLoadResult UnifiedModelLoader::Load(const std::string& path,
                                         const ModelLoadConfig& config) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->progress_ = LoadProgress{};
    impl_->loading_ = true;
    impl_->cancelled_ = false;
    impl_->loaded_model_ = UnifiedModel{};

    auto merged_config = config;
    if (merged_config.on_progress == nullptr) merged_config.on_progress = impl_->default_config_.on_progress;
    if (merged_config.is_cancelled == nullptr) merged_config.is_cancelled = impl_->default_config_.is_cancelled;

    auto result = impl_->LoadSync(path, merged_config);
    impl_->loading_ = false;
    return result;
}

ModelLoadResult UnifiedModelLoader::LoadFromMemory(const std::vector<uint8_t>& buffer,
                                                 ModelFormat format_hint,
                                                 const ModelLoadConfig& config) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->progress_ = LoadProgress{};
    impl_->loading_ = true;
    impl_->cancelled_ = false;
    impl_->loaded_model_ = UnifiedModel{};

    ModelLoadResult result;
    if (format_hint == ModelFormat::GGUF) {
        GGUFAdapter adapter;
        if (!adapter.AdaptFromMemory(buffer)) {
            impl_->ReportError("Failed to parse GGUF from memory");
            result.success = false;
            result.error_message = impl_->progress_.error_message;
            impl_->loading_ = false;
            return result;
        }
        auto desc = adapter.GetDescriptor();
        if (desc) impl_->loaded_model_.descriptor = *desc;
        impl_->loaded_model_.source_format = ModelFormat::GGUF;
        impl_->UpdateStatus(LoadStatus::Complete, "Loaded from memory");
        result.success = true;
        result.model = impl_->loaded_model_;
    } else {
        impl_->ReportError("Memory loading only supported for GGUF");
        result.success = false;
        result.error_message = impl_->progress_.error_message;
    }
    impl_->loading_ = false;
    return result;
}

bool UnifiedModelLoader::IsLoading() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->loading_;
}

LoadProgress UnifiedModelLoader::GetProgress() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->progress_;
}

void UnifiedModelLoader::Cancel() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->cancelled_ = true;
}

ModelFormat UnifiedModelLoader::DetectFormat(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return ModelFormat::Unknown;
    std::vector<uint8_t> header(8);
    file.read(reinterpret_cast<char*>(header.data()), 8);
    return DetectFormatFromBytes(header);
}

ModelFormat UnifiedModelLoader::DetectFormatFromBytes(const std::vector<uint8_t>& header) {
    if (header.size() >= 4) {
        if (header[0] == 'G' && header[1] == 'G' && header[2] == 'U' && header[3] == 'F') {
            return ModelFormat::GGUF;
        }
        if (header[0] == 'P' && header[1] == 'K') {
            return ModelFormat::SafeTensors;
        }
        if (header[0] == 0x08 && header[1] == 0x00) {
            return ModelFormat::PyTorch;
        }
    }
    if (header.size() >= 7) {
        if (std::memcmp(header.data(), "ONNX\x00\x00", 6) == 0) {
            return ModelFormat::ONNX;
        }
    }
    return ModelFormat::Unknown;
}

bool UnifiedModelLoader::SupportsFormat(ModelFormat format) {
    switch (format) {
        case ModelFormat::GGUF:
        case ModelFormat::SafeTensors:
        case ModelFormat::PyTorch:
        case ModelFormat::ONNX:
            return true;
        default:
            return false;
    }
}

std::string UnifiedModelLoader::FormatToString(ModelFormat format) {
    switch (format) {
        case ModelFormat::GGUF: return "GGUF";
        case ModelFormat::PyTorch: return "PyTorch";
        case ModelFormat::SafeTensors: return "SafeTensors";
        case ModelFormat::ONNX: return "ONNX";
        case ModelFormat::TensorFlow: return "TensorFlow";
        case ModelFormat::RawBinary: return "RawBinary";
        default: return "Unknown";
    }
}

std::string UnifiedModelLoader::StatusToString(LoadStatus status) {
    switch (status) {
        case LoadStatus::Idle: return "Idle";
        case LoadStatus::Reading: return "Reading";
        case LoadStatus::Parsing: return "Parsing";
        case LoadStatus::Adapting: return "Adapting";
        case LoadStatus::Quantizing: return "Quantizing";
        case LoadStatus::Validating: return "Validating";
        case LoadStatus::Complete: return "Complete";
        case LoadStatus::Error: return "Error";
        case LoadStatus::Cancelled: return "Cancelled";
        default: return "Unknown";
    }
}

void UnifiedModelLoader::SetDefaultConfig(const ModelLoadConfig& config) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->default_config_ = config;
}

} // namespace rawrxd::canonical
