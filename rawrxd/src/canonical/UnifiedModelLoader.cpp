#include "UnifiedModelLoader.hpp"
#include <cstdio>
#include <fstream>
#include <iostream>
#include <algorithm>
#include <filesystem>
#include <thread>
#include <future>
#include "sha256.h"  // or fallback if not available

namespace rawrxd::canonical {

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Static helpers
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
static bool FileExists(const std::string& path) {
    return std::filesystem::exists(path);
}

static uint64_t FileSize(const std::string& path) {
    return std::filesystem::file_size(path);
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// ModelIndex
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
void ModelIndex::Reserve(size_t n) {
    name_to_idx_.reserve(n * 2);
}

void ModelIndex::AddTensor(std::string name, size_t payload_index) {
    name_to_idx_[std::move(name)] = payload_index;
}

size_t ModelIndex::Find(const std::string& name) const {
    auto it = name_to_idx_.find(name);
    return (it != name_to_idx_.end()) ? it->second : static_cast<size_t>(-1);
}

std::vector<size_t> ModelIndex::FindByPrefix(const std::string& prefix) const {
    std::vector<size_t> out;
    for (const auto& [name, idx] : name_to_idx_) {
        if (name.rfind(prefix, 0) == 0) out.push_back(idx);
    }
    return out;
}

std::vector<size_t> ModelIndex::FindByLayer(uint32_t layer_idx) const {
    std::string prefix = "blk." + std::to_string(layer_idx) + ".";
    return FindByPrefix(prefix);
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// UnifiedModelLoader
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
UnifiedModelLoader::UnifiedModelLoader() = default;
UnifiedModelLoader::~UnifiedModelLoader() = default;

bool UnifiedModelLoader::Load(const std::string& path) {
    ModelSource src;
    src.path = path;
    src.format = DetectFormat(path);
    src.cache_key = std::filesystem::path(path).stem().string();
    return Load(src);
}

bool UnifiedModelLoader::Load(const ModelSource& source) {
    current_source_ = source;
    ReportProgress(LoadProgress::Phase::DetectFormat);

    switch (source.format) {
        case ModelFormat::GGUF:
            return LoadGGUF(source);
        case ModelFormat::Safetensors:
            return LoadSafetensors(source);
        case ModelFormat::ONNX:
            return LoadONNX(source);
        default:
            return false;
    }
}

std::future<bool> UnifiedModelLoader::LoadAsync(const std::string& path) {
    return std::async(std::launch::async, [this, path]() { return Load(path); });
}

const ModelMetadata& UnifiedModelLoader::Metadata() const {
    if (gguf_adapter_) return gguf_adapter_->Metadata();
    static ModelMetadata empty;
    return empty;
}

std::span<const uint8_t> UnifiedModelLoader::GetTensorData(const std::string& name) const {
    size_t idx = index_.Find(name);
    if (idx == static_cast<size_t>(-1)) return {};
    if (idx >= tensors_.size()) return {};
    const auto& tp = tensors_[idx];
    return { tp.data(), tp.byte_size() };
}

bool UnifiedModelLoader::HasTensor(const std::string& name) const {
    return index_.Find(name) != static_cast<size_t>(-1);
}

bool UnifiedModelLoader::ValidateAllTensorData() const {
    if (!gguf_adapter_) return false;
    for (const auto& t : tensors_) {
        if (t.byte_size() == 0) return false;
        // Additional: verify checksums if mmap'd
    }
    return true;
}

bool UnifiedModelLoader::VerifySHA256(const std::string& expected) const {
    // RAWRXD_UNSIMULATE_001
    // Was: `return true; // placeholder` with "SHA256 computation omitted".
    //
    // This is a model INTEGRITY check. Returning true from it asserted that a
    // model file's bytes hash to a requested value without reading the file,
    // which is the one claim every other certification in this tree is pinned
    // to: receipts are bound to a model by hash. A verifier that always passes
    // makes every hash-bound receipt unfalsifiable.
    //
    // It now computes the digest. sha256.h did not exist when this function was
    // written -- the include has been in this file since before the tree was
    // assembled, which is why this translation unit never compiled and why the
    // placeholder survived.
    //
    // Every failure mode returns false with a stated reason. In particular an
    // empty expectation is NOT a pass: "no hash was asked for" is not the same
    // claim as "the hash matched", and conflating them is the same defect one
    // level up.
    if (expected.empty()) {
        std::fprintf(stderr,
            "[UnifiedModelLoader] VerifySHA256 REFUSED: no expected digest was "
            "supplied. An absent expectation is not a passing integrity check. "
            "RAWRXD_UNSIMULATE_001\n");
        std::fflush(stderr);
        return false;
    }
    if (current_source_.path.empty()) {
        std::fprintf(stderr,
            "[UnifiedModelLoader] VerifySHA256 REFUSED: no model path is loaded; "
            "there is nothing to hash.\n");
        std::fflush(stderr);
        return false;
    }
    const std::string actual = rawrxd::sha256::HexOfFile(current_source_.path);
    if (actual.empty()) {
        std::fprintf(stderr,
            "[UnifiedModelLoader] VerifySHA256 REFUSED: could not read or hash "
            "the model file (path=\"%s\"). A read failure is not a match.\n",
            current_source_.path.c_str());
        std::fflush(stderr);
        return false;
    }
    if (!rawrxd::sha256::EqualDigest(actual, expected)) {
        std::fprintf(stderr,
            "[UnifiedModelLoader] VerifySHA256 FAILED: expected %s, got %s "
            "(path=\"%s\")\n",
            expected.c_str(), actual.c_str(), current_source_.path.c_str());
        std::fflush(stderr);
        return false;
    }
    return true;
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// GGUF Load Path
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
bool UnifiedModelLoader::LoadGGUF(const ModelSource& source) {
    gguf_adapter_ = std::make_unique<GGUFAdapter>();
    gguf_adapter_->SetProgressCallback(
        [this](size_t cur, size_t tot) { ReportProgress(LoadProgress::Phase::ParseMetadata, cur, tot); });

    if (source.allow_mmap && mmap_enabled_) {
        if (!gguf_adapter_->Open(source.path)) return false;
        if (!gguf_adapter_->EnableMMap(source.path)) {
            // Fallback to non-mmap
        }
    } else {
        if (!gguf_adapter_->Open(source.path)) return false;
    }

    ReportProgress(LoadProgress::Phase::LoadTensors, 0, gguf_adapter_->Tensors().size());

    const auto& tensor_infos = gguf_adapter_->Tensors();
    tensors_.reserve(tensor_infos.size());
    index_.Reserve(tensor_infos.size());

    uint64_t loaded_bytes = 0;
    uint64_t total_bytes = 0;
    for (const auto& ti : tensor_infos) total_bytes += ti.size_bytes;

    for (size_t i = 0; i < tensor_infos.size(); ++i) {
        const auto& ti = tensor_infos[i];
        if (tensor_filter_ && !tensor_filter_(ti.name)) {
            continue;
        }

        TensorPayload payload;
        payload.name = ti.name;
        payload.quant_type = ti.quant_type;
        payload.shape = ti.shape;

        // Try mmap first
        if (source.allow_mmap && mmap_enabled_ && gguf_adapter_) {
            auto view = gguf_adapter_->MMapTensorView(ti);
            if (!view.empty()) {
                payload.mmap_view = view;
                payload.is_mmap = true;
            }
        }

        // Fallback to owned read
        if (!payload.is_mmap) {
            payload.owned_data = gguf_adapter_->ReadTensorData(ti);
            if (payload.owned_data.empty() && ti.size_bytes > 0) {
                return false; // failed to read
            }
        }

        // Memory limit check
        if (max_memory_bytes_ > 0) {
            uint64_t current_mem = 0;
            for (const auto& t : tensors_) current_mem += t.byte_size();
            if (current_mem + payload.byte_size() > max_memory_bytes_) {
                // Evict oldest tensors to stay under limit (LRU)
                // For simplicity: drop first half
                size_t drop_target = tensors_.size() / 2;
                tensors_.erase(tensors_.begin(), tensors_.begin() + drop_target);
            }
        }

        size_t payload_idx = tensors_.size();
        tensors_.push_back(std::move(payload));
        index_.AddTensor(ti.name, payload_idx);

        loaded_bytes += ti.size_bytes;
        ReportProgress(LoadProgress::Phase::LoadTensors, i + 1, tensor_infos.size());
    }

    // Validation
    auto missing = gguf_adapter_->DetectMissingArchitectureTensors();
    if (!missing.empty()) {
        // Log warnings but don't fail â€” some architectures have optional tensors
    }

    ReportProgress(LoadProgress::Phase::Complete);
    return true;
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Safetensors Load Path (placeholder)
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
bool UnifiedModelLoader::LoadSafetensors(const ModelSource& source) {
    // Safetensors format: JSON header + tensor blobs
    // Implementation: parse JSON header, read tensor offsets, mmap or copy
    (void)source;
    return false; // TODO: implement safetensors support
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// ONNX Load Path (placeholder)
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
bool UnifiedModelLoader::LoadONNX(const ModelSource& source) {
    // ONNX support via ONNX Runtime or custom minimal parser
    (void)source;
    return false; // TODO: implement ONNX support
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Cache management
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
bool UnifiedModelLoader::ExportToCache(const std::string& cache_dir) const {
    if (!gguf_adapter_) return false;
    std::filesystem::path dir(cache_dir);
    std::filesystem::create_directories(dir);
    std::string cache_file = (dir / (current_source_.cache_key + ".cache")).string();
    // Serialize tensor index + metadata
    std::ofstream ofs(cache_file, std::ios::binary);
    if (!ofs) return false;
    // Write version, metadata blob, tensor count, index
    uint32_t version = 1;
    ofs.write(reinterpret_cast<const char*>(&version), sizeof(version));
    // ... additional serialization
    return ofs.good();
}

bool UnifiedModelLoader::ImportFromCache(const std::string& cache_key, const std::string& cache_dir) {
    std::filesystem::path cache_file = std::filesystem::path(cache_dir) / (cache_key + ".cache");
    if (!std::filesystem::exists(cache_file)) return false;
    std::ifstream ifs(cache_file.string(), std::ios::binary);
    if (!ifs) return false;
    uint32_t version = 0;
    ifs.read(reinterpret_cast<char*>(&version), sizeof(version));
    if (version != 1) return false;
    // ... deserialization
    return true;
}

void UnifiedModelLoader::InvalidateCache(const std::string& cache_key, const std::string& cache_dir) {
    std::filesystem::path cache_file = std::filesystem::path(cache_dir) / (cache_key + ".cache");
    if (std::filesystem::exists(cache_file)) {
        std::filesystem::remove(cache_file);
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Format detection
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
ModelFormat UnifiedModelLoader::DetectFormat(const std::string& path) {
    std::ifstream fs(path, std::ios::binary);
    if (!fs) return ModelFormat::Unknown;
    char magic[8] = {};
    if (!fs.read(magic, 4)) return ModelFormat::Unknown;
    if (std::memcmp(magic, "GGUF", 4) == 0) return ModelFormat::GGUF;
    if (std::memcmp(magic, "\x89PNG", 4) == 0) return ModelFormat::Unknown; // not supported
    if (std::memcmp(magic, "PK\x03\x04", 4) == 0) {
        // ZIP-like: could be safetensors or PyTorch
        std::string ext = std::filesystem::path(path).extension().string();
        if (ext == ".safetensors" || ext == ".st") return ModelFormat::Safetensors;
        if (ext == ".onnx") return ModelFormat::ONNX;
        return ModelFormat::Unknown;
    }
    std::string ext = std::filesystem::path(path).extension().string();
    if (ext == ".gguf" || ext == ".ggufv2") return ModelFormat::GGUF;
    if (ext == ".safetensors" || ext == ".st") return ModelFormat::Safetensors;
    if (ext == ".onnx") return ModelFormat::ONNX;
    if (ext == ".bin" || ext == ".pt" || ext == ".pth") return ModelFormat::PyTorch;
    return ModelFormat::Unknown;
}

std::string UnifiedModelLoader::FormatToString(ModelFormat f) {
    switch (f) {
        case ModelFormat::GGUF: return "GGUF";
        case ModelFormat::Safetensors: return "Safetensors";
        case ModelFormat::PyTorch: return "PyTorch";
        case ModelFormat::ONNX: return "ONNX";
        default: return "Unknown";
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Progress reporting
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
void UnifiedModelLoader::ReportProgress(LoadProgress::Phase phase, size_t current, size_t total) {
    if (!progress_cb_) return;
    LoadProgress lp;
    lp.phase = phase;
    lp.current_bytes = current;
    lp.total_bytes = total;
    progress_cb_(lp);
}

} // namespace rawrxd::canonical
