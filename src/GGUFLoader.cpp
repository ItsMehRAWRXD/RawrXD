// ============================================================================
// GGUFLoader.cpp - concrete IGGUFLoader implementation (real GGUF parser)
// ============================================================================
// Parses a real GGUF file: magic/version header, metadata key-value pairs, the
// tensor directory, and exposes tensor bytes through the file stream. Implements
// the contract declared in src/GGUFLoader.h against src/RawrXD_Interfaces.h.
// ============================================================================
#include "GGUFLoader.h"

#include <algorithm>
#include <cstring>
#include <fstream>

namespace RawrXD {
namespace {

// Raw GGUF value types (per the GGUF spec).
constexpr uint32_t GGUF_UINT8 = 0;
constexpr uint32_t GGUF_INT8 = 1;
constexpr uint32_t GGUF_UINT16 = 2;
constexpr uint32_t GGUF_INT16 = 3;
constexpr uint32_t GGUF_UINT32 = 4;
constexpr uint32_t GGUF_INT32 = 5;
constexpr uint32_t GGUF_FLOAT32 = 6;
constexpr uint32_t GGUF_BOOL = 7;
constexpr uint32_t GGUF_STRING = 8;
constexpr uint32_t GGUF_ARRAY = 9;
constexpr uint32_t GGUF_UINT64 = 10;
constexpr uint32_t GGUF_INT64 = 11;
constexpr uint32_t GGUF_FLOAT64 = 12;

size_t scalar_size(uint32_t type) {
    switch (type) {
        case GGUF_UINT8:
        case GGUF_INT8:
        case GGUF_BOOL: return 1;
        case GGUF_UINT16:
        case GGUF_INT16: return 2;
        case GGUF_UINT32:
        case GGUF_INT32:
        case GGUF_FLOAT32: return 4;
        case GGUF_UINT64:
        case GGUF_INT64:
        case GGUF_FLOAT64: return 8;
        default: return 0;
    }
}

GGMLType to_ggml_type(uint32_t t) {
    // Values match the GGMLType enum (which mirrors ggml_type).
    if (t <= static_cast<uint32_t>(GGMLType::Q6_K)) {
        return static_cast<GGMLType>(t);
    }
    return GGMLType::F32;
}

}  // namespace

GGUFLoader::GGUFLoader() = default;

GGUFLoader::~GGUFLoader() { Close(); }

bool GGUFLoader::Open(const std::string& path) {
    Close();
    if (path.empty()) return false;

    std::ifstream probe(path, std::ios::binary);
    if (!probe) return false;
    char magic[4] = {0, 0, 0, 0};
    probe.read(magic, 4);
    if (std::memcmp(magic, "GGUF", 4) != 0) return false;
    probe.close();

    filepath_ = path;
    file_.open(path, std::ios::binary);
    if (!file_) {
        filepath_.clear();
        return false;
    }
    return true;
}

bool GGUFLoader::Close() {
    if (file_.is_open()) file_.close();
    filepath_.clear();
    tensor_count_ = 0;
    metadata_kv_count_ = 0;
    metadata_kv_.clear();
    tokens_.clear();
    meta_ = GGUFMetadata{};
    tensors_.clear();
    header_ = GGUFHeader{};
    data_start_ = 0;
    index_built_ = false;
    return true;
}

bool GGUFLoader::ParseHeader() {
    if (!file_.is_open()) return false;
    file_.seekg(0, std::ios::beg);
    file_.read(reinterpret_cast<char*>(&header_.magic), sizeof(uint32_t));
    file_.read(reinterpret_cast<char*>(&header_.version), sizeof(uint32_t));
    file_.read(reinterpret_cast<char*>(&header_.tensor_count), sizeof(uint64_t));
    file_.read(reinterpret_cast<char*>(&header_.metadata_kv_count),
               sizeof(uint64_t));
    if (std::memcmp(&header_.magic, "GGUF", 4) != 0) return false;
    tensor_count_ = header_.tensor_count;
    metadata_kv_count_ = header_.metadata_kv_count;
    return true;
}

GGUFHeader GGUFLoader::GetHeader() const { return header_; }

bool GGUFLoader::ParseMetadata() {
    if (!file_.is_open() || metadata_kv_count_ == 0) {
        if (metadata_kv_count_ == 0 && tensor_count_ > 0) {
            // Header not parsed yet; parse it first.
            if (!ParseHeader()) return false;
        } else {
            return false;
        }
    }

    tokens_.clear();
    metadata_kv_.clear();
    file_.seekg(24, std::ios::beg);  // past magic/version/tensor_count/kv_count

    for (uint64_t i = 0; i < metadata_kv_count_; ++i) {
        uint64_t key_len = 0;
        if (!file_.read(reinterpret_cast<char*>(&key_len), sizeof(uint64_t)) ||
            key_len == 0 || key_len > 4096) {
            return false;
        }
        std::string key(static_cast<size_t>(key_len), '\0');
        if (!file_.read(&key[0], static_cast<std::streamsize>(key_len))) return false;

        uint32_t vtype = 0;
        if (!file_.read(reinterpret_cast<char*>(&vtype), sizeof(uint32_t))) return false;

        if (vtype == GGUF_ARRAY) {
            uint32_t elem_type = 0;
            uint64_t count = 0;
            if (!file_.read(reinterpret_cast<char*>(&elem_type), sizeof(uint32_t)) ||
                !file_.read(reinterpret_cast<char*>(&count), sizeof(uint64_t))) {
                return false;
            }
            if (elem_type == GGUF_STRING) {
                std::vector<std::string> values;
                values.reserve(static_cast<size_t>(std::min<uint64_t>(count, 1u << 20)));
                for (uint64_t j = 0; j < count; ++j) {
                    uint64_t len = 0;
                    if (!file_.read(reinterpret_cast<char*>(&len), sizeof(uint64_t)) ||
                        len == 0 || len > (1u << 20)) {
                        return false;
                    }
                    std::string v(static_cast<size_t>(len), '\0');
                    if (!file_.read(&v[0], static_cast<std::streamsize>(len))) {
                        return false;
                    }
                    values.push_back(std::move(v));
                }
                if (key == "tokenizer.ggml.tokens") tokens_ = std::move(values);
                metadata_kv_[key] = "array<string>:" + std::to_string(count);
                continue;
            }
            const size_t esz = scalar_size(elem_type);
            if (esz == 0) return false;
            file_.seekg(static_cast<std::streamoff>(count * esz), std::ios::cur);
            metadata_kv_[key] = "array:" + std::to_string(count);
            continue;
        }

        if (vtype == GGUF_STRING) {
            uint64_t len = 0;
            if (!file_.read(reinterpret_cast<char*>(&len), sizeof(uint64_t)) ||
                len > (1u << 20)) {
                return false;
            }
            std::string v(static_cast<size_t>(len), '\0');
            if (!file_.read(&v[0], static_cast<std::streamsize>(len))) return false;
            metadata_kv_[key] = v;
            continue;
        }

        const size_t sz = scalar_size(vtype);
        if (sz == 0) return false;
        std::vector<char> buf(sz);
        if (!file_.read(buf.data(), static_cast<std::streamsize>(sz))) return false;
        switch (vtype) {
            case GGUF_UINT32:
                metadata_kv_[key] =
                    std::to_string(*reinterpret_cast<const uint32_t*>(buf.data()));
                break;
            case GGUF_INT32:
                metadata_kv_[key] =
                    std::to_string(*reinterpret_cast<const int32_t*>(buf.data()));
                break;
            case GGUF_FLOAT32:
                metadata_kv_[key] =
                    std::to_string(*reinterpret_cast<const float*>(buf.data()));
                break;
            case GGUF_UINT64:
                metadata_kv_[key] =
                    std::to_string(*reinterpret_cast<const uint64_t*>(buf.data()));
                break;
            case GGUF_INT64:
                metadata_kv_[key] =
                    std::to_string(*reinterpret_cast<const int64_t*>(buf.data()));
                break;
            case GGUF_FLOAT64:
                metadata_kv_[key] =
                    std::to_string(*reinterpret_cast<const double*>(buf.data()));
                break;
            case GGUF_BOOL:
                metadata_kv_[key] = buf[0] ? "true" : "false";
                break;
            default:
                metadata_kv_[key] = std::to_string(static_cast<int>(buf[0]));
                break;
        }
    }

    // Publish the standard fields through GGUFMetadata.
    meta_ = GGUFMetadata{};
    auto it = metadata_kv_.find("general.architecture");
    if (it != metadata_kv_.end()) meta_.architecture = it->second;
    it = metadata_kv_.find("general.name");
    if (it != metadata_kv_.end()) meta_.name = it->second;
    meta_.tokens = tokens_;
    meta_.vocabSize = static_cast<uint32_t>(tokens_.size());
    meta_.kv_pairs = metadata_kv_;
    return true;
}

GGUFMetadata GGUFLoader::GetMetadata() const { return meta_; }

bool GGUFLoader::BuildTensorIndex() {
    if (!file_.is_open()) return false;
    if (metadata_kv_count_ == 0 && !ParseHeader()) return false;

    tensors_.clear();
    tensors_.reserve(static_cast<size_t>(std::min<uint64_t>(tensor_count_, 1u << 20)));

    // The tensor directory directly follows the metadata section.
    file_.seekg(24, std::ios::beg);
    for (uint64_t i = 0; i < metadata_kv_count_; ++i) {
        uint64_t key_len = 0;
        if (!file_.read(reinterpret_cast<char*>(&key_len), sizeof(uint64_t))) return false;
        file_.seekg(static_cast<std::streamsize>(key_len), std::ios::cur);
        uint32_t vtype = 0;
        if (!file_.read(reinterpret_cast<char*>(&vtype), sizeof(uint32_t))) return false;
        if (!skip_value(vtype)) return false;
    }

    for (uint64_t i = 0; i < tensor_count_; ++i) {
        uint64_t name_len = 0;
        if (!file_.read(reinterpret_cast<char*>(&name_len), sizeof(uint64_t))) return false;
        std::string name(static_cast<size_t>(name_len), '\0');
        if (!file_.read(&name[0], static_cast<std::streamsize>(name_len))) return false;

        uint32_t ndims = 0;
        if (!file_.read(reinterpret_cast<char*>(&ndims), sizeof(uint32_t))) return false;
        if (ndims > 8) return false;
        TensorInfo info;
        info.name = name;
        info.shape.resize(ndims);
        for (uint32_t d = 0; d < ndims; ++d) {
            uint64_t dim = 0;
            if (!file_.read(reinterpret_cast<char*>(&dim), sizeof(uint64_t))) return false;
            info.shape[d] = dim;
        }
        uint32_t ttype = 0;
        uint64_t rel_off = 0;
        if (!file_.read(reinterpret_cast<char*>(&ttype), sizeof(uint32_t))) return false;
        if (!file_.read(reinterpret_cast<char*>(&rel_off), sizeof(uint64_t))) return false;
        info.type = to_ggml_type(ttype);
        info.offset = rel_off;
        info.size = GetTensorByteSize(info);
        info.size_bytes = info.size;
        tensors_.push_back(std::move(info));
    }

    // Tensor data begins at the 32-byte-aligned directory end.
    data_start_ = (static_cast<size_t>(file_.tellg()) + 31u) & ~static_cast<size_t>(31u);
    index_built_ = true;
    return true;
}

bool GGUFLoader::skip_value(uint32_t type) {
    if (type == GGUF_STRING) {
        uint64_t len = 0;
        if (!file_.read(reinterpret_cast<char*>(&len), sizeof(uint64_t))) return false;
        file_.seekg(static_cast<std::streamsize>(len), std::ios::cur);
        return true;
    }
    if (type == GGUF_ARRAY) {
        uint32_t elem_type = 0;
        uint64_t count = 0;
        if (!file_.read(reinterpret_cast<char*>(&elem_type), sizeof(uint32_t)) ||
            !file_.read(reinterpret_cast<char*>(&count), sizeof(uint64_t))) {
            return false;
        }
        if (elem_type == GGUF_STRING) {
            for (uint64_t j = 0; j < count; ++j) {
                if (!skip_value(GGUF_STRING)) return false;
            }
            return true;
        }
        const size_t esz = scalar_size(elem_type);
        if (esz == 0) return false;
        file_.seekg(static_cast<std::streamoff>(count * esz), std::ios::cur);
        return true;
    }
    const size_t sz = scalar_size(type);
    if (sz == 0) return false;
    file_.seekg(static_cast<std::streamoff>(sz), std::ios::cur);
    return true;
}

std::vector<TensorInfo> GGUFLoader::GetTensorInfo() const { return tensors_; }

std::vector<TensorInfo> GGUFLoader::GetAllTensorInfo() const { return tensors_; }

const std::vector<std::string>& GGUFLoader::GetVocabulary() const { return tokens_; }

size_t GGUFLoader::GetTensorByteSize(const TensorInfo& tensor) const {
    uint64_t elements = 1;
    for (uint64_t d : tensor.shape) elements *= d ? d : 1;
    switch (tensor.type) {
        case GGMLType::F32: return static_cast<size_t>(elements * 4);
        case GGMLType::F16: return static_cast<size_t>(elements * 2);
        case GGMLType::Q4_0:
        case GGMLType::Q4_1: return static_cast<size_t>(elements / 32 * 18);
        case GGMLType::Q5_0:
        case GGMLType::Q5_1: return static_cast<size_t>(elements / 32 * 22);
        case GGMLType::Q8_0:
        case GGMLType::Q8_1: return static_cast<size_t>(elements / 32 * 34);
        default: return static_cast<size_t>(elements);
    }
}

std::string GGUFLoader::GetTypeString(GGMLType type) const {
    switch (type) {
        case GGMLType::F32: return "F32";
        case GGMLType::F16: return "F16";
        case GGMLType::Q4_0: return "Q4_0";
        case GGMLType::Q4_1: return "Q4_1";
        case GGMLType::Q5_0: return "Q5_0";
        case GGMLType::Q5_1: return "Q5_1";
        case GGMLType::Q8_0: return "Q8_0";
        case GGMLType::Q8_1: return "Q8_1";
        case GGMLType::Q2_K: return "Q2_K";
        case GGMLType::Q3_K: return "Q3_K";
        case GGMLType::Q4_K: return "Q4_K";
        case GGMLType::Q5_K: return "Q5_K";
        case GGMLType::Q6_K: return "Q6_K";
        default: return "F32";
    }
}

bool GGUFLoader::LoadTensorRange(size_t start_idx, size_t count,
                                 std::vector<uint8_t>& data) {
    if (start_idx >= tensors_.size()) return false;
    const size_t end = std::min(tensors_.size(), start_idx + count);
    uint64_t total = 0;
    for (size_t i = start_idx; i < end; ++i) total += tensors_[i].size;
    data.clear();
    data.reserve(static_cast<size_t>(total));
    for (size_t i = start_idx; i < end; ++i) {
        std::vector<uint8_t> chunk;
        if (!LoadTensorZone(tensors_[i].name, chunk)) return false;
        data.insert(data.end(), chunk.begin(), chunk.end());
    }
    return true;
}

bool GGUFLoader::LoadZone(const std::string&, uint64_t) { return file_.is_open(); }

bool GGUFLoader::UnloadZone(const std::string&) { return true; }

bool GGUFLoader::LoadTensorZone(const std::string& tensor_name,
                                std::vector<uint8_t>& data) {
    if (!file_.is_open()) return false;
    for (const auto& t : tensors_) {
        if (t.name != tensor_name) continue;
        if (t.size == 0) {
            data.clear();
            return true;
        }
        data.resize(static_cast<size_t>(t.size));
        file_.seekg(static_cast<std::streamoff>(data_start_ + t.offset),
                    std::ios::beg);
        if (!file_.read(reinterpret_cast<char*>(data.data()),
                        static_cast<std::streamsize>(t.size))) {
            data.clear();
            return false;
        }
        return true;
    }
    return false;
}

uint64_t GGUFLoader::GetFileSize() const {
    if (!file_.is_open()) return 0;
    const auto cur = file_.tellg();
    file_.seekg(0, std::ios::end);
    const auto size = static_cast<uint64_t>(file_.tellg());
    file_.seekg(cur, std::ios::beg);
    return size;
}

uint64_t GGUFLoader::GetCurrentMemoryUsage() const { return 0; }

std::vector<std::string> GGUFLoader::GetLoadedZones() const {
    if (file_.is_open()) return {"model"};
    return {};
}

std::vector<std::string> GGUFLoader::GetAllZones() const { return {"model"}; }

}  // namespace RawrXD
