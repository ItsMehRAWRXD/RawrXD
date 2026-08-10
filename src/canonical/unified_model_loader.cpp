// ============================================================================
// unified_model_loader.cpp — B005 Unified Model Loader
// ============================================================================
#include "unified_model_loader.h"
#include "gguf_adapter.h"
#include <cstdio>

namespace RawrXD::Canonical {

UnifiedModelLoader::UnifiedModelLoader() = default;
UnifiedModelLoader::~UnifiedModelLoader() = default;

bool UnifiedModelLoader::Load(const std::filesystem::path& path) {
    Unload();

    if (!std::filesystem::exists(path)) {
        last_error_ = "path does not exist: " + path.string();
        return false;
    }

    detected_format_ = DetectFormat(path);
    if (detected_format_ == DetectedFormat::Unknown) {
        last_error_ = "unsupported or unrecognized model format: " + path.string();
        return false;
    }

    switch (detected_format_) {
        case DetectedFormat::GGUF:
            adapter_ = std::make_unique<GGUFAdapter>();
            break;
        case DetectedFormat::SafeTensors:
            // Stub: SafeTensors adapter not yet implemented in B005
            last_error_ = "SafeTensors adapter not yet implemented (B005 stub)";
            return false;
        case DetectedFormat::RawBlob:
            last_error_ = "Raw blob adapter not yet implemented (B005 stub)";
            return false;
        default:
            last_error_ = "no adapter available for detected format";
            return false;
    }

    if (!adapter_->Open(path)) {
        last_error_ = std::string("adapter open failed: ") + adapter_->GetValidationError();
        adapter_.reset();
        return false;
    }

    if (!adapter_->Validate()) {
        last_error_ = std::string("adapter validation failed: ") + adapter_->GetValidationError();
        adapter_.reset();
        return false;
    }

    return true;
}

IModelAdapter* UnifiedModelLoader::Adapter() const {
    return adapter_.get();
}

bool UnifiedModelLoader::IsLoaded() const {
    return adapter_ != nullptr && adapter_->IsOpen() && adapter_->Validate();
}

const ModelMetadata& UnifiedModelLoader::Metadata() const {
    static const ModelMetadata empty{};
    if (!adapter_) return empty;
    return adapter_->Metadata();
}

DetectedFormat UnifiedModelLoader::Format() const {
    return detected_format_;
}

const char* UnifiedModelLoader::FormatName() const {
    return DetectedFormatName(detected_format_);
}

std::string UnifiedModelLoader::GetLastError() const {
    return last_error_;
}

bool UnifiedModelLoader::FindTensor(std::string_view name, TensorDescriptor& out) const {
    if (!adapter_) return false;
    return adapter_->FindTensor(name, out);
}

bool UnifiedModelLoader::ReadTensor(const TensorDescriptor& tensor, void* destination, size_t bytes) {
    if (!adapter_) return false;
    return adapter_->ReadTensor(tensor, destination, bytes);
}

void UnifiedModelLoader::Unload() {
    adapter_.reset();
    detected_format_ = DetectedFormat::Unknown;
    last_error_.clear();
}

} // namespace RawrXD::Canonical
