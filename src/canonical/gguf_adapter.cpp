// ============================================================================
// gguf_adapter.cpp — Canonical GGUF adapter implementation
// B005: wraps existing GGUF parsing in the IModelAdapter contract.
// ============================================================================
#include "gguf_adapter.h"
#include <algorithm>
#include <charconv>
#include <limits>

namespace RawrXD::Canonical {

// ============================================================================
// Helpers
// ============================================================================
static std::string ToLowerAscii(std::string s) {
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return s;
}

static bool EndsWith(const std::string& s, const std::string& suffix) {
    return s.size() >= suffix.size() &&
           s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

// ============================================================================
// GGUFAdapter
// ============================================================================
GGUFAdapter::GGUFAdapter() = default;
GGUFAdapter::~GGUFAdapter() { Close(); }

bool GGUFAdapter::Open(const std::filesystem::path& path) {
    Close();
    path_ = path;
    file_.open(path, std::ios::binary);
    if (!file_.is_open()) {
        validation_error_ = "failed to open file: " + path.string();
        return false;
    }
    is_open_ = true;

    if (!ParseHeader()) {
        Close();
        return false;
    }
    if (!ParseMetadata()) {
        Close();
        return false;
    }
    if (!ParseTensorIndex()) {
        Close();
        return false;
    }
    if (!ResolveMetadata()) {
        Close();
        return false;
    }
    return true;
}

void GGUFAdapter::Close() {
    if (file_.is_open()) file_.close();
    is_open_ = false;
    magic_ = 0;
    version_ = 0;
    tensor_count_ = 0;
    metadata_kv_count_ = 0;
    data_offset_ = 0;
    tensors_.clear();
    tensor_name_to_index_.clear();
    metadata_strings_.clear();
    metadata_uints_.clear();
    metadata_ = ModelMetadata{};
    validation_error_.clear();
}

bool GGUFAdapter::IsOpen() const { return is_open_; }

// ============================================================================
// Validation — magic-based, not extension-based
// ============================================================================
bool GGUFAdapter::Validate() const {
    if (!is_open_) {
        return false;
    }
    if (magic_ != 0x46554747u) {
        return false;
    }
    if (version_ != 3) {
        return false;
    }
    if (tensor_count_ == 0 || tensor_count_ > 10000000ULL) {
        return false;
    }
    if (metadata_.architecture == ModelArchitecture::Unknown &&
        metadata_.architecture_name.empty()) {
        // Non-fatal: some GGUFs lack explicit architecture metadata
    }
    return true;
}

std::string GGUFAdapter::GetValidationError() const { return validation_error_; }

const ModelMetadata& GGUFAdapter::Metadata() const { return metadata_; }

// ============================================================================
// Tensor access
// ============================================================================
bool GGUFAdapter::FindTensor(std::string_view name, TensorDescriptor& out) const {
    auto it = tensor_name_to_index_.find(std::string(name));
    if (it == tensor_name_to_index_.end()) return false;
    if (it->second >= tensors_.size()) return false;
    out = tensors_[it->second];
    return true;
}

bool GGUFAdapter::ReadTensor(const TensorDescriptor& tensor, void* destination, size_t bytes) {
    if (!file_.is_open() || !destination) return false;
    if (bytes > tensor.byte_size) bytes = static_cast<size_t>(tensor.byte_size);
    file_.seekg(static_cast<std::streamoff>(tensor.byte_offset), std::ios::beg);
    if (!file_.good()) return false;
    file_.read(static_cast<char*>(destination), static_cast<std::streamsize>(bytes));
    return file_.good() && static_cast<size_t>(file_.gcount()) == bytes;
}

size_t GGUFAdapter::TensorCount() const { return tensors_.size(); }

bool GGUFAdapter::GetTensorIndex(size_t index, TensorDescriptor& out) const {
    if (index >= tensors_.size()) return false;
    out = tensors_[index];
    return true;
}

// ============================================================================
// Parsing
// ============================================================================
bool GGUFAdapter::ParseHeader() {
    if (!file_.is_open()) return false;
    file_.seekg(0, std::ios::beg);

    auto ReadU32 = [&](uint32_t& out) -> bool {
        file_.read(reinterpret_cast<char*>(&out), sizeof(out));
        return file_.good();
    };
    auto ReadU64 = [&](uint64_t& out) -> bool {
        file_.read(reinterpret_cast<char*>(&out), sizeof(out));
        return file_.good();
    };

    if (!ReadU32(magic_)) {
        validation_error_ = "failed to read GGUF magic";
        return false;
    }
    if (magic_ != 0x46554747u) {
        validation_error_ = "invalid GGUF magic: 0x" + std::to_string(magic_);
        return false;
    }
    if (!ReadU32(version_)) {
        validation_error_ = "failed to read GGUF version";
        return false;
    }
    if (!ReadU64(tensor_count_)) {
        validation_error_ = "failed to read tensor count";
        return false;
    }
    if (!ReadU64(metadata_kv_count_)) {
        validation_error_ = "failed to read metadata KV count";
        return false;
    }
    return true;
}

bool GGUFAdapter::ParseMetadata() {
    // Minimal metadata parsing: read KV pairs and extract known fields.
    // For B005, we only need the fields that map to ModelMetadata.
    auto ReadU64 = [&](uint64_t& out) -> bool {
        file_.read(reinterpret_cast<char*>(&out), sizeof(out));
        return file_.good();
    };
    auto ReadU32 = [&](uint32_t& out) -> bool {
        file_.read(reinterpret_cast<char*>(&out), sizeof(out));
        return file_.good();
    };
    auto ReadString = [&](std::string& out) -> bool {
        uint64_t len = 0;
        if (!ReadU64(len)) return false;
        if (len > 65536) return false; // sanity limit
        out.resize(static_cast<size_t>(len));
        if (len > 0) {
            file_.read(out.data(), static_cast<std::streamsize>(len));
            return file_.good();
        }
        return true;
    };

    for (uint64_t i = 0; i < metadata_kv_count_; ++i) {
        std::string key;
        if (!ReadString(key)) {
            validation_error_ = "failed to read metadata key " + std::to_string(i);
            return false;
        }
        uint32_t type = 0;
        if (!ReadU32(type)) {
            validation_error_ = "failed to read metadata type for key: " + key;
            return false;
        }

        // Skip value based on type
        switch (type) {
            case 0: { // uint8
                uint8_t v; file_.read(reinterpret_cast<char*>(&v), sizeof(v)); break;
            }
            case 1: { // int8
                int8_t v; file_.read(reinterpret_cast<char*>(&v), sizeof(v)); break;
            }
            case 2: { // uint16
                uint16_t v; file_.read(reinterpret_cast<char*>(&v), sizeof(v)); break;
            }
            case 3: { // int16
                int16_t v; file_.read(reinterpret_cast<char*>(&v), sizeof(v)); break;
            }
            case 4: { // uint32
                uint32_t v;
                file_.read(reinterpret_cast<char*>(&v), sizeof(v));
                metadata_uints_[key] = v;
                break;
            }
            case 5: { // int32
                int32_t v; file_.read(reinterpret_cast<char*>(&v), sizeof(v)); break;
            }
            case 6: { // float32
                float v; file_.read(reinterpret_cast<char*>(&v), sizeof(v)); break;
            }
            case 7: { // bool
                uint8_t v; file_.read(reinterpret_cast<char*>(&v), sizeof(v)); break;
            }
            case 8: { // string
                std::string v;
                if (!ReadString(v)) return false;
                metadata_strings_[key] = std::move(v);
                break;
            }
            case 9: { // array
                uint32_t arr_type = 0;
                if (!ReadU32(arr_type)) return false;
                uint64_t arr_len = 0;
                if (!ReadU64(arr_len)) return false;
                if (arr_len > 10000000) return false;
                // Skip array bytes
                for (uint64_t j = 0; j < arr_len; ++j) {
                    switch (arr_type) {
                        case 4: { uint32_t v; file_.read(reinterpret_cast<char*>(&v), sizeof(v)); break; }
                        case 5: { int32_t v; file_.read(reinterpret_cast<char*>(&v), sizeof(v)); break; }
                        case 6: { float v; file_.read(reinterpret_cast<char*>(&v), sizeof(v)); break; }
                        case 7: { uint8_t v; file_.read(reinterpret_cast<char*>(&v), sizeof(v)); break; }
                        case 8: { std::string v; if (!ReadString(v)) return false; break; }
                        default: {
                            // Unknown array element type: skip 4 bytes as fallback
                            uint32_t dummy; file_.read(reinterpret_cast<char*>(&dummy), sizeof(dummy));
                            break;
                        }
                    }
                }
                break;
            }
            case 10: { // uint64
                uint64_t v;
                file_.read(reinterpret_cast<char*>(&v), sizeof(v));
                metadata_uints_[key] = v;
                break;
            }
            case 11: { // int64
                int64_t v; file_.read(reinterpret_cast<char*>(&v), sizeof(v)); break;
            }
            case 12: { // float64
                double v; file_.read(reinterpret_cast<char*>(&v), sizeof(v)); break;
            }
            default: {
                validation_error_ = "unknown metadata value type " + std::to_string(type) + " for key " + key;
                return false;
            }
        }
        if (!file_.good()) {
            validation_error_ = "failed reading metadata value for key: " + key;
            return false;
        }
    }
    return true;
}

// Forward declaration for element size helper used in ParseTensorIndex
static uint64_t ElementSizeBytes(TensorDType dtype);

bool GGUFAdapter::ParseTensorIndex() {
    auto ReadU64 = [&](uint64_t& out) -> bool {
        file_.read(reinterpret_cast<char*>(&out), sizeof(out));
        return file_.good();
    };
    auto ReadU32 = [&](uint32_t& out) -> bool {
        file_.read(reinterpret_cast<char*>(&out), sizeof(out));
        return file_.good();
    };
    auto ReadString = [&](std::string& out) -> bool {
        uint64_t len = 0;
        if (!ReadU64(len)) return false;
        if (len > 65536) return false;
        out.resize(static_cast<size_t>(len));
        if (len > 0) {
            file_.read(out.data(), static_cast<std::streamsize>(len));
            return file_.good();
        }
        return true;
    };

    data_offset_ = static_cast<uint64_t>(file_.tellg());
    // Align to 32 bytes
    const uint64_t alignment = 32;
    if (data_offset_ % alignment != 0) {
        data_offset_ += alignment - (data_offset_ % alignment);
    }

    tensors_.reserve(static_cast<size_t>(tensor_count_));
    for (uint64_t i = 0; i < tensor_count_; ++i) {
        TensorDescriptor td;
        if (!ReadString(td.name)) {
            validation_error_ = "failed to read tensor name " + std::to_string(i);
            return false;
        }
        uint32_t n_dims = 0;
        if (!ReadU32(n_dims)) {
            validation_error_ = "failed to read tensor dims count for " + td.name;
            return false;
        }
        if (n_dims > 16) {
            validation_error_ = "too many dimensions for tensor " + td.name;
            return false;
        }
        td.shape.resize(n_dims);
        for (uint32_t d = 0; d < n_dims; ++d) {
            uint64_t dim = 0;
            if (!ReadU64(dim)) {
                validation_error_ = "failed to read tensor dimension for " + td.name;
                return false;
            }
            td.shape[d] = dim;
        }
        if (!ReadU32(td.gguf_type)) {
            validation_error_ = "failed to read tensor type for " + td.name;
            return false;
        }
        td.dtype = MapGGUFType(td.gguf_type);

        uint64_t offset = 0;
        if (!ReadU64(offset)) {
            validation_error_ = "failed to read tensor offset for " + td.name;
            return false;
        }
        td.byte_offset = data_offset_ + offset;

        // Compute byte_size from shape and dtype
        uint64_t elem_count = 1;
        for (uint64_t dim : td.shape) elem_count *= dim;
        td.byte_size = elem_count * ElementSizeBytes(td.dtype);

        tensor_name_to_index_[td.name] = tensors_.size();
        tensors_.push_back(std::move(td));
    }
    return true;
}

bool GGUFAdapter::ResolveMetadata() {
    // Map known GGUF metadata keys to ModelMetadata fields
    auto GetUint = [&](const std::string& key, uint32_t fallback) -> uint32_t {
        auto it = metadata_uints_.find(key);
        if (it != metadata_uints_.end()) {
            if (it->second <= static_cast<uint64_t>(std::numeric_limits<uint32_t>::max()))
                return static_cast<uint32_t>(it->second);
        }
        return fallback;
    };

    metadata_.vocab_size     = GetUint("general.vocab_size", 0);
    if (metadata_.vocab_size == 0) {
        metadata_.vocab_size = GetUint("llama.vocab_size", 0);
    }
    metadata_.hidden_size    = GetUint("llama.embedding_length", 0);
    metadata_.layer_count    = GetUint("llama.block_count", 0);
    metadata_.head_count     = GetUint("llama.attention.head_count", 0);
    metadata_.kv_head_count  = GetUint("llama.attention.head_count_kv", 0);
    metadata_.context_length = GetUint("llama.context_length", 0);
    metadata_.ffn_dim        = GetUint("llama.feed_forward_length", 0);
    metadata_.expert_count   = GetUint("llama.expert_count", 0);
    metadata_.expert_used_count = GetUint("llama.expert_used_count", 0);
    metadata_.file_type      = GetUint("general.file_type", 0xFFFFFFFFu);

    auto it_arch = metadata_strings_.find("general.architecture");
    if (it_arch != metadata_strings_.end()) {
        metadata_.architecture_name = it_arch->second;
        metadata_.architecture = ResolveArchitecture(it_arch->second);
    }

    auto it_tok = metadata_strings_.find("tokenizer.ggml.model");
    if (it_tok != metadata_strings_.end()) {
        metadata_.tokenizer_model = it_tok->second;
    }

    // Fallback: if hidden_size is 0, try alternate keys
    if (metadata_.hidden_size == 0) {
        metadata_.hidden_size = GetUint("general.hidden_size", 0);
    }
    if (metadata_.layer_count == 0) {
        metadata_.layer_count = GetUint("general.layer_count", 0);
    }
    if (metadata_.head_count == 0) {
        metadata_.head_count = GetUint("general.head_count", 0);
    }

    return true;
}

// ============================================================================
// Type mapping
// ============================================================================
TensorDType GGUFAdapter::MapGGUFType(uint32_t gguf_type) {
    switch (gguf_type) {
        case 0:  return TensorDType::F32;
        case 1:  return TensorDType::F16;
        case 2:  return TensorDType::Q4_0;
        case 3:  return TensorDType::Q4_1;
        case 6:  return TensorDType::Q5_0;
        case 7:  return TensorDType::Q5_1;
        case 8:  return TensorDType::Q8_0;
        case 9:  return TensorDType::Q8_1;
        case 10: return TensorDType::Q2_K;
        case 11: return TensorDType::Q3_K_S;
        case 12: return TensorDType::Q3_K_M;
        case 13: return TensorDType::Q4_K_S;
        case 14: return TensorDType::Q4_K_M;
        case 15: return TensorDType::Q5_K_S;
        case 16: return TensorDType::Q5_K_M;
        case 17: return TensorDType::Q6_K;
        case 18: return TensorDType::IQ2_XXS;
        case 19: return TensorDType::IQ2_XS;
        case 20: return TensorDType::IQ3_XXS;
        case 21: return TensorDType::IQ1_S;
        case 22: return TensorDType::IQ4_NL;
        case 23: return TensorDType::IQ3_S;
        case 24: return TensorDType::IQ3_M;
        case 25: return TensorDType::IQ2_S;
        case 26: return TensorDType::IQ2_M;
        case 27: return TensorDType::IQ4_XS;
        case 28: return TensorDType::I8;
        case 29: return TensorDType::I16;
        case 30: return TensorDType::I32;
        case 31: return TensorDType::I64;
        case 32: return TensorDType::F64;
        default: return TensorDType::Unknown;
    }
}

ModelArchitecture GGUFAdapter::ResolveArchitecture(const std::string& arch_name) {
    std::string lower = ToLowerAscii(arch_name);
    if (lower == "llama" || lower == "llama2" || lower == "llama-2") return ModelArchitecture::Llama;
    if (lower == "mistral") return ModelArchitecture::Mistral;
    if (lower == "mixtral") return ModelArchitecture::Mixtral;
    if (lower == "phi" || lower == "phi3" || lower == "phi-3") return ModelArchitecture::Phi;
    if (lower == "qwen" || lower == "qwen2" || lower == "qwen-2") return ModelArchitecture::Qwen;
    if (lower == "gemma") return ModelArchitecture::Gemma;
    if (lower == "gptneox" || lower == "gpt-neox") return ModelArchitecture::GPTNeoX;
    if (lower == "falcon") return ModelArchitecture::Falcon;
    if (lower == "gpt2" || lower == "gpt-2") return ModelArchitecture::GPT2;
    if (lower == "tinyllama") return ModelArchitecture::TinyLlama;
    return ModelArchitecture::Unknown;
}

// ============================================================================
// Element size helper (definition)
// ============================================================================
static uint64_t ElementSizeBytes(TensorDType dtype) {
    switch (dtype) {
        case TensorDType::F32:    return 4;
        case TensorDType::F16:    return 2;
        case TensorDType::BF16:   return 2;
        case TensorDType::Q4_0:   return 18; // 32 elements per block, 18 bytes
        case TensorDType::Q4_1:   return 20;
        case TensorDType::Q5_0:   return 22;
        case TensorDType::Q5_1:   return 24;
        case TensorDType::Q8_0:   return 34;
        case TensorDType::Q8_1:   return 36;
        case TensorDType::Q2_K:   return 84;  // 256 elements per block
        case TensorDType::Q3_K_S: return 110; // approximate
        case TensorDType::Q3_K_M: return 122;
        case TensorDType::Q4_K_S: return 99;
        case TensorDType::Q4_K_M: return 110;
        case TensorDType::Q5_K_S: return 128;
        case TensorDType::Q5_K_M: return 144;
        case TensorDType::Q6_K:   return 210;
        case TensorDType::I8:     return 1;
        case TensorDType::I16:    return 2;
        case TensorDType::I32:    return 4;
        case TensorDType::I64:    return 8;
        case TensorDType::F64:    return 8;
        default:                  return 1;
    }
}

// ============================================================================
// Format detection — magic-based
// ============================================================================
DetectedFormat DetectFormat(const std::filesystem::path& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) return DetectedFormat::Unknown;

    uint32_t magic = 0;
    f.read(reinterpret_cast<char*>(&magic), sizeof(magic));
    if (!f.good()) return DetectedFormat::Unknown;

    if (magic == 0x46554747u) return DetectedFormat::GGUF;          // "GGUF"
    if (magic == 0x8B1F)      return DetectedFormat::SafeTensors;    // gzip (safetensors can be gzipped)
    if (magic == 0x04034B50u) return DetectedFormat::SafeTensors;    // ZIP (safetensors uses ZIP)
    if (magic == 0x8B1F || magic == 0x1F8B) return DetectedFormat::SafeTensors; // gzip variants

    // Check for JSON header (safetensors starts with {)
    if ((magic & 0xFF) == '{') {
        // Peek more bytes to confirm JSON
        char buf[16] = {};
        f.seekg(0, std::ios::beg);
        f.read(buf, sizeof(buf));
        if (f.good() && std::string_view(buf, 16).find("__metadata__") != std::string_view::npos) {
            return DetectedFormat::SafeTensors;
        }
    }

    return DetectedFormat::Unknown;
}

const char* DetectedFormatName(DetectedFormat fmt) {
    switch (fmt) {
        case DetectedFormat::GGUF:        return "GGUF";
        case DetectedFormat::SafeTensors: return "SafeTensors";
        case DetectedFormat::RawBlob:     return "RawBlob";
        case DetectedFormat::ONNX:        return "ONNX";
        case DetectedFormat::PyTorch:     return "PyTorch";
        default:                          return "Unknown";
    }
}

} // namespace RawrXD::Canonical
