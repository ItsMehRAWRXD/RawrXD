#include "gguf_loader.hpp"
#include <fstream>
#include <string>
#include <algorithm>
#include <stdexcept>
#include <mutex>
#include <limits>

namespace rawrxd {

namespace {
    uint16_t ReadU16LE(const uint8_t* p) {
        return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
    }
    uint32_t ReadU32LE(const uint8_t* p) {
        return static_cast<uint32_t>(ReadU16LE(p)) | (static_cast<uint32_t>(ReadU16LE(p + 2)) << 16);
    }
    uint64_t ReadU64LE(const uint8_t* p) {
        return static_cast<uint64_t>(ReadU32LE(p)) | (static_cast<uint64_t>(ReadU32LE(p + 4)) << 32);
    }
    float ReadF32LE(const uint8_t* p) {
        float v; std::memcpy(&v, p, sizeof(v)); return v;
    }
    double ReadF64LE(const uint8_t* p) {
        double v; std::memcpy(&v, p, sizeof(v)); return v;
    }
}

GGUFTensorView::GGUFTensorView(const uint8_t* data, const GGUFTensorInfo& info)
    : data_(data), info_(info) {}

size_t GGUFTensorView::count() const {
    size_t n = 1;
    for (auto d : info_.shape) n *= d;
    return n;
}

GGUFType GGUFTensorView::type() const { return info_.type; }
const std::vector<uint64_t>& GGUFTensorView::shape() const { return info_.shape; }
std::string GGUFTensorView::name() const { return info_.name; }

class GGUFLoader::Impl {
public:
    GGUFModel model_;
    mutable std::mutex mutex_;

    template<typename T>
    T ReadVal(const uint8_t*& p) {
        T v; std::memcpy(&v, p, sizeof(T)); p += sizeof(T); return v;
    }

    std::string ReadStr(const uint8_t*& p) {
        uint64_t len = ReadU64LE(p); p += 8;
        std::string s(reinterpret_cast<const char*>(p), len);
        p += len;
        return s;
    }

    GGUFMetadataValue ReadMetaValue(const uint8_t*& p) {
        GGUFMetadataValue mv;
        uint32_t raw_type = ReadU32LE(p); p += 4;
        mv.type = static_cast<GGUFType>(raw_type);
        switch (mv.type) {
            case GGUFType::Uint8: mv.value = static_cast<uint8_t>(*p++); break;
            case GGUFType::Int8: mv.value = static_cast<int8_t>(*p++); break;
            case GGUFType::Uint16: { uint16_t v = ReadU16LE(p); p += 2; mv.value = v; } break;
            case GGUFType::Int16: { int16_t v = static_cast<int16_t>(ReadU16LE(p)); p += 2; mv.value = v; } break;
            case GGUFType::Uint32: { uint32_t v = ReadU32LE(p); p += 4; mv.value = v; } break;
            case GGUFType::Int32: { int32_t v = static_cast<int32_t>(ReadU32LE(p)); p += 4; mv.value = v; } break;
            case GGUFType::Float32: { float v = ReadF32LE(p); p += 4; mv.value = v; } break;
            case GGUFType::Uint64: { uint64_t v = ReadU64LE(p); p += 8; mv.value = v; } break;
            case GGUFType::Int64: { int64_t v = static_cast<int64_t>(ReadU64LE(p)); p += 8; mv.value = v; } break;
            case GGUFType::Float64: { double v = ReadF64LE(p); p += 8; mv.value = v; } break;
            case GGUFType::Bool: mv.value = (*p++ != 0); break;
            case GGUFType::String: mv.value = ReadStr(p); break;
            case GGUFType::Array: {
                uint32_t arr_type = ReadU32LE(p); p += 4;
                uint64_t arr_len = ReadU64LE(p); p += 8;
                switch (static_cast<GGUFType>(arr_type)) {
                    case GGUFType::Uint32: {
                        std::vector<uint32_t> vec;
                        vec.reserve(arr_len);
                        for (uint64_t i = 0; i < arr_len; ++i) { vec.push_back(ReadU32LE(p)); p += 4; }
                        mv.value = vec;
                    } break;
                    case GGUFType::Int32: {
                        std::vector<int32_t> vec;
                        vec.reserve(arr_len);
                        for (uint64_t i = 0; i < arr_len; ++i) { vec.push_back(static_cast<int32_t>(ReadU32LE(p))); p += 4; }
                        mv.value = vec;
                    } break;
                    case GGUFType::Float32: {
                        std::vector<float> vec;
                        vec.reserve(arr_len);
                        for (uint64_t i = 0; i < arr_len; ++i) { vec.push_back(ReadF32LE(p)); p += 4; }
                        mv.value = vec;
                    } break;
                    case GGUFType::Uint64: {
                        std::vector<uint64_t> vec;
                        vec.reserve(arr_len);
                        for (uint64_t i = 0; i < arr_len; ++i) { vec.push_back(ReadU64LE(p)); p += 8; }
                        mv.value = vec;
                    } break;
                    case GGUFType::Int64: {
                        std::vector<int64_t> vec;
                        vec.reserve(arr_len);
                        for (uint64_t i = 0; i < arr_len; ++i) { vec.push_back(static_cast<int64_t>(ReadU64LE(p))); p += 8; }
                        mv.value = vec;
                    } break;
                    case GGUFType::Float64: {
                        std::vector<double> vec;
                        vec.reserve(arr_len);
                        for (uint64_t i = 0; i < arr_len; ++i) { vec.push_back(ReadF64LE(p)); p += 8; }
                        mv.value = vec;
                    } break;
                    case GGUFType::Bool: {
                        std::vector<bool> vec;
                        vec.reserve(arr_len);
                        for (uint64_t i = 0; i < arr_len; ++i) { vec.push_back(*p++ != 0); }
                        mv.value = vec;
                    } break;
                    case GGUFType::String: {
                        std::vector<std::string> vec;
                        vec.reserve(arr_len);
                        for (uint64_t i = 0; i < arr_len; ++i) { vec.push_back(ReadStr(p)); }
                        mv.value = vec;
                    } break;
                    default: break;
                }
            } break;
            default: break;
        }
        return mv;
    }

    bool ParseHeader(const std::vector<uint8_t>& buf, size_t& offset) {
        if (buf.size() < 24) return false;
        auto& h = model_.header;
        std::memcpy(h.magic, buf.data(), 4);
        if (h.magic[0] != 'G' || h.magic[1] != 'G' || h.magic[2] != 'U' || h.magic[3] != 'F') return false;
        h.version = ReadU32LE(buf.data() + 4);
        if (h.version != 2 && h.version != 3) return false;
        h.tensor_count = ReadU64LE(buf.data() + 8);
        h.metadata_kv_count = ReadU64LE(buf.data() + 16);
        h.valid = true;
        offset = 24;
        return true;
    }

    bool ParseMetadata(const std::vector<uint8_t>& buf, size_t& offset) {
        const uint8_t* p = buf.data() + offset;
        for (uint64_t i = 0; i < model_.header.metadata_kv_count; ++i) {
            uint64_t key_len = ReadU64LE(p); p += 8;
            std::string key(reinterpret_cast<const char*>(p), key_len); p += key_len;
            model_.metadata[key] = ReadMetaValue(p);
        }
        offset = static_cast<size_t>(p - buf.data());
        return true;
    }

    bool ParseTensors(const std::vector<uint8_t>& buf, size_t& offset) {
        const uint8_t* p = buf.data() + offset;
        for (uint64_t i = 0; i < model_.header.tensor_count; ++i) {
            GGUFTensorInfo info;
            uint64_t name_len = ReadU64LE(p); p += 8;
            info.name = std::string(reinterpret_cast<const char*>(p), name_len); p += name_len;
            uint32_t ndims = ReadU32LE(p); p += 4;
            info.shape.resize(ndims);
            for (uint32_t d = 0; d < ndims; ++d) {
                info.shape[d] = ReadU64LE(p); p += 8;
            }
            uint32_t type_raw = ReadU32LE(p); p += 4;
            info.type = static_cast<GGUFType>(type_raw);
            info.offset = ReadU64LE(p); p += 8;
            size_t elem_size = 4;
            switch (info.type) {
                case GGUFType::Uint8: case GGUFType::Int8: elem_size = 1; break;
                case GGUFType::Uint16: case GGUFType::Int16: elem_size = 2; break;
                case GGUFType::Uint32: case GGUFType::Int32: case GGUFType::Float32: elem_size = 4; break;
                case GGUFType::Uint64: case GGUFType::Int64: case GGUFType::Float64: elem_size = 8; break;
                default: elem_size = 4; break;
            }
            info.element_size = elem_size;
            size_t total = elem_size;
            for (auto dim : info.shape) total *= dim;
            info.byte_size = total;
            model_.tensors.push_back(info);
        }
        offset = static_cast<size_t>(p - buf.data());
        return true;
    }
};

GGUFLoader::GGUFLoader() : impl_(std::make_unique<Impl>()) {}
GGUFLoader::~GGUFLoader() = default;

bool GGUFLoader::LoadFromFile(const std::string& path) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) return false;
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) return false;
    return LoadFromMemory(buffer);
}

bool GGUFLoader::LoadFromMemory(const std::vector<uint8_t>& buffer) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->model_ = GGUFModel{};
    size_t offset = 0;
    if (!impl_->ParseHeader(buffer, offset)) return false;
    if (!impl_->ParseMetadata(buffer, offset)) return false;
    if (!impl_->ParseTensors(buffer, offset)) return false;
    size_t alignment = 32;
    auto it = impl_->model_.metadata.find("general.alignment");
    if (it != impl_->model_.metadata.end() && std::holds_alternative<uint32_t>(it->second.value))
        alignment = std::get<uint32_t>(it->second.value);
    size_t pad = (alignment - (offset % alignment)) % alignment;
    offset += pad;
    impl_->model_.data_offset = offset;
    impl_->model_.raw_data = buffer;
    return true;
}

bool GGUFLoader::IsLoaded() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->model_.header.valid;
}

const GGUFModel* GGUFLoader::GetModel() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return &impl_->model_;
}

std::optional<GGUFMetadataValue> GGUFLoader::GetMetadata(const std::string& key) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    auto it = impl_->model_.metadata.find(key);
    if (it != impl_->model_.metadata.end()) return it->second;
    return std::nullopt;
}

std::optional<GGUFTensorView> GGUFLoader::GetTensor(const std::string& name) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    for (const auto& t : impl_->model_.tensors) {
        if (t.name == name) {
            if (impl_->model_.raw_data.size() >= t.offset + t.byte_size + impl_->model_.data_offset) {
                return GGUFTensorView(impl_->model_.raw_data.data() + impl_->model_.data_offset + t.offset, t);
            }
        }
    }
    return std::nullopt;
}

std::vector<std::string> GGUFLoader::ListTensors() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::vector<std::string> names;
    for (const auto& t : impl_->model_.tensors) names.push_back(t.name);
    return names;
}

std::vector<std::string> GGUFLoader::ListMetadataKeys() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::vector<std::string> keys;
    for (const auto& kv : impl_->model_.metadata) keys.push_back(kv.first);
    return keys;
}

std::optional<uint32_t> GGUFLoader::GetUint32Metadata(const std::string& key) const {
    auto mv = GetMetadata(key);
    if (!mv) return std::nullopt;
    if (std::holds_alternative<uint32_t>(mv->value)) return std::get<uint32_t>(mv->value);
    if (std::holds_alternative<uint64_t>(mv->value)) return static_cast<uint32_t>(std::get<uint64_t>(mv->value));
    if (std::holds_alternative<int32_t>(mv->value)) return static_cast<uint32_t>(std::get<int32_t>(mv->value));
    return std::nullopt;
}

std::optional<std::string> GGUFLoader::GetStringMetadata(const std::string& key) const {
    auto mv = GetMetadata(key);
    if (!mv) return std::nullopt;
    if (std::holds_alternative<std::string>(mv->value)) return std::get<std::string>(mv->value);
    return std::nullopt;
}

std::optional<uint64_t> GGUFLoader::GetUint64Metadata(const std::string& key) const {
    auto mv = GetMetadata(key);
    if (!mv) return std::nullopt;
    if (std::holds_alternative<uint64_t>(mv->value)) return std::get<uint64_t>(mv->value);
    if (std::holds_alternative<uint32_t>(mv->value)) return std::get<uint32_t>(mv->value);
    return std::nullopt;
}

void GGUFLoader::Unload() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->model_ = GGUFModel{};
}

bool GGUFLoader::ValidateMagic(const std::vector<uint8_t>& header_bytes) {
    return header_bytes.size() >= 4 &&
           header_bytes[0] == 'G' && header_bytes[1] == 'G' &&
           header_bytes[2] == 'U' && header_bytes[3] == 'F';
}

std::string GGUFLoader::TypeToString(GGUFType type) {
    switch (type) {
        case GGUFType::Uint8: return "uint8"; case GGUFType::Int8: return "int8";
        case GGUFType::Uint16: return "uint16"; case GGUFType::Int16: return "int16";
        case GGUFType::Uint32: return "uint32"; case GGUFType::Int32: return "int32";
        case GGUFType::Float32: return "float32"; case GGUFType::Uint64: return "uint64";
        case GGUFType::Int64: return "int64"; case GGUFType::Float64: return "float64";
        case GGUFType::Bool: return "bool"; case GGUFType::String: return "string";
        case GGUFType::Array: return "array"; default: return "unknown";
    }
}

void GGUFTensorWriter::AddTensor(const std::string& name, GGUFType type,
                               const std::vector<uint64_t>& shape,
                               const std::vector<uint8_t>& data) {
    GGUFTensorInfo info;
    info.name = name;
    info.type = type;
    info.shape = shape;
    info.byte_size = data.size();
    info.element_size = 1;
    tensors_.push_back(info);
    tensor_data_.push_back(data);
}

bool GGUFTensorWriter::WriteToFile(const std::string& path,
                                 const std::map<std::string, GGUFMetadataValue>& metadata) {
    std::ofstream ofs(path, std::ios::binary);
    if (!ofs) return false;
    uint8_t header[24];
    header[0] = 'G'; header[1] = 'G'; header[2] = 'U'; header[3] = 'F';
    uint32_t version = 3;
    std::memcpy(header + 4, &version, 4);
    uint64_t tensor_count = tensors_.size();
    uint64_t meta_count = metadata.size();
    std::memcpy(header + 8, &tensor_count, 8);
    std::memcpy(header + 16, &meta_count, 8);
    ofs.write(reinterpret_cast<const char*>(header), 24);
    // Metadata omitted for brevity; extend as needed
    uint32_t alignment = 32;
    size_t offset = 0;
    for (size_t i = 0; i < tensors_.size(); ++i) {
        size_t pad = (alignment - (offset % alignment)) % alignment;
        offset += pad;
        ofs.seekp(static_cast<std::streamoff>(offset + 24));
        ofs.write(reinterpret_cast<const char*>(tensor_data_[i].data()),
                  static_cast<std::streamsize>(tensor_data_[i].size()));
        offset += tensor_data_[i].size();
    }
    return ofs.good();
}

} // namespace rawrxd
