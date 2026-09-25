#include "GGUFCore.hpp"
#include <fstream>
#include <string>
#include <vector>
#include <mutex>
#include <algorithm>

namespace rawrxd::engine {

// ───────────────────────────────────────────────────────────────
// GGUF v3 constants
// ───────────────────────────────────────────────────────────────
static constexpr uint32_t GGUF_MAGIC = 0x46554747; // "GGUF"
static constexpr uint32_t GGUF_VERSION = 3;

class GGUFCore::Impl {
public:
    mutable std::mutex mutex_;
    GGUFModel model_;
    bool parsed_ = false;
    std::vector<std::string> validation_errors_;

    template<typename T>
    T ReadLE(const uint8_t*& ptr) {
        T val = 0;
        for (size_t i = 0; i < sizeof(T); ++i) {
            val |= static_cast<T>(ptr[i]) << (i * 8);
        }
        ptr += sizeof(T);
        return val;
    }

    std::string ReadString(const uint8_t*& ptr) {
        uint64_t len = ReadLE<uint64_t>(ptr);
        std::string s(reinterpret_cast<const char*>(ptr), len);
        ptr += len;
        return s;
    }

    bool ParseHeader(const uint8_t*& ptr, const uint8_t* end) {
        if (end - ptr < 24) return false;
        model_.header.magic = ReadLE<uint32_t>(ptr);
        model_.header.version = ReadLE<uint32_t>(ptr);
        model_.header.tensor_count = ReadLE<uint64_t>(ptr);
        model_.header.metadata_kv_count = ReadLE<uint64_t>(ptr);
        if (model_.header.magic != GGUF_MAGIC) return false;
        if (model_.header.version != 2 && model_.header.version != 3) return false;
        return true;
    }

    bool ParseMetadata(const uint8_t*& ptr, const uint8_t* end) {
        for (uint64_t i = 0; i < model_.header.metadata_kv_count; ++i) {
            GGUFMetadataEntry entry;
            entry.key = ReadString(ptr);
            entry.type = static_cast<GGUFMetadataEntry::Type>(ReadLE<uint32_t>(ptr));
            // Read value based on type
            switch (entry.type) {
                case GGUFMetadataEntry::UINT8:
                case GGUFMetadataEntry::INT8:
                    entry.raw_value.assign(ptr, ptr + 1); ptr += 1; break;
                case GGUFMetadataEntry::UINT16:
                case GGUFMetadataEntry::INT16:
                    entry.raw_value.assign(ptr, ptr + 2); ptr += 2; break;
                case GGUFMetadataEntry::UINT32:
                case GGUFMetadataEntry::INT32:
                case GGUFMetadataEntry::FLOAT32:
                case GGUFMetadataEntry::BOOL:
                    entry.raw_value.assign(ptr, ptr + 4); ptr += 4; break;
                case GGUFMetadataEntry::UINT64:
                case GGUFMetadataEntry::INT64:
                case GGUFMetadataEntry::FLOAT64:
                    entry.raw_value.assign(ptr, ptr + 8); ptr += 8; break;
                case GGUFMetadataEntry::STRING:
                    {
                        uint64_t len = ReadLE<uint64_t>(ptr);
                        entry.raw_value.assign(ptr, ptr + len);
                        ptr += len;
                    }
                    break;
                case GGUFMetadataEntry::ARRAY:
                    {
                        uint32_t arr_type = ReadLE<uint32_t>(ptr);
                        uint64_t arr_len = ReadLE<uint64_t>(ptr);
                        // Store raw array for simplicity
                        for (uint64_t j = 0; j < arr_len; ++j) {
                            switch (arr_type) {
                                case 4: entry.raw_value.insert(entry.raw_value.end(), ptr, ptr + 4); ptr += 4; break;
                                case 5: entry.raw_value.insert(entry.raw_value.end(), ptr, ptr + 4); ptr += 4; break;
                                case 10: entry.raw_value.insert(entry.raw_value.end(), ptr, ptr + 8); ptr += 8; break;
                                default: break;
                            }
                        }
                    }
                    break;
                default:
                    validation_errors_.push_back("Unknown metadata type " + std::to_string(entry.type));
                    break;
            }
            model_.metadata.push_back(std::move(entry));
        }
        return true;
    }

    bool ParseTensorInfo(const uint8_t*& ptr, const uint8_t* end) {
        for (uint64_t i = 0; i < model_.header.tensor_count; ++i) {
            GGUFTensorInfo info;
            info.name = ReadString(ptr);
            info.n_dims = ReadLE<uint32_t>(ptr);
            for (uint32_t d = 0; d < info.n_dims; ++d) {
                info.dims.push_back(ReadLE<uint64_t>(ptr));
            }
            info.type = ReadLE<uint32_t>(ptr);
            info.offset = ReadLE<uint64_t>(ptr);
            model_.tensors.push_back(std::move(info));
        }
        return true;
    }
};

GGUFCore::GGUFCore() : impl_(std::make_unique<Impl>()) {}
GGUFCore::~GGUFCore() = default;

bool GGUFCore::ParseFromBuffer(std::span<const uint8_t> data) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->model_ = {};
    impl_->parsed_ = false;
    impl_->validation_errors_.clear();
    const uint8_t* ptr = data.data();
    const uint8_t* end = ptr + data.size();
    if (!impl_->ParseHeader(ptr, end)) return false;
    if (!impl_->ParseMetadata(ptr, end)) return false;
    if (!impl_->ParseTensorInfo(ptr, end)) return false;
    // Align to 32 bytes for tensor data
    size_t offset = ptr - data.data();
    size_t aligned = (offset + 31) & ~31ULL;
    if (aligned > offset && aligned <= data.size()) ptr += (aligned - offset);
    impl_->model_.tensor_data_offset = ptr - data.data();
    impl_->model_.tensor_data.assign(ptr, data.end());
    impl_->parsed_ = true;
    return true;
}

bool GGUFCore::ParseFromFile(const std::string& path) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return false;
    ifs.seekg(0, std::ios::end);
    size_t size = ifs.tellg();
    ifs.seekg(0, std::ios::beg);
    std::vector<uint8_t> buf(size);
    ifs.read(reinterpret_cast<char*>(buf.data()), size);
    return ParseFromBuffer(buf);
}

const GGUFModel& GGUFCore::GetModel() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->model_;
}

bool GGUFCore::IsParsed() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->parsed_;
}

std::optional<std::string> GGUFCore::GetMetadataString(const std::string& key) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    for (const auto& e : impl_->model_.metadata) {
        if (e.key == key && e.type == GGUFMetadataEntry::STRING) {
            return std::string(reinterpret_cast<const char*>(e.raw_value.data()), e.raw_value.size());
        }
    }
    return std::nullopt;
}

std::optional<uint32_t> GGUFCore::GetMetadataUint32(const std::string& key) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    for (const auto& e : impl_->model_.metadata) {
        if (e.key == key && e.type == GGUFMetadataEntry::UINT32 && e.raw_value.size() == 4) {
            uint32_t v = 0;
            for (size_t i = 0; i < 4; ++i) v |= static_cast<uint32_t>(e.raw_value[i]) << (i * 8);
            return v;
        }
    }
    return std::nullopt;
}

std::optional<uint64_t> GGUFCore::GetMetadataUint64(const std::string& key) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    for (const auto& e : impl_->model_.metadata) {
        if (e.key == key && e.type == GGUFMetadataEntry::UINT64 && e.raw_value.size() == 8) {
            uint64_t v = 0;
            for (size_t i = 0; i < 8; ++i) v |= static_cast<uint64_t>(e.raw_value[i]) << (i * 8);
            return v;
        }
    }
    return std::nullopt;
}

std::optional<float> GGUFCore::GetMetadataFloat32(const std::string& key) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    for (const auto& e : impl_->model_.metadata) {
        if (e.key == key && e.type == GGUFMetadataEntry::FLOAT32 && e.raw_value.size() == 4) {
            uint32_t v = 0;
            for (size_t i = 0; i < 4; ++i) v |= static_cast<uint32_t>(e.raw_value[i]) << (i * 8);
            float f;
            std::memcpy(&f, &v, sizeof(f));
            return f;
        }
    }
    return std::nullopt;
}

std::optional<std::vector<float>> GGUFCore::GetMetadataFloatArray(const std::string& key) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    for (const auto& e : impl_->model_.metadata) {
        if (e.key == key && e.type == GGUFMetadataEntry::ARRAY) {
            std::vector<float> out;
            for (size_t i = 0; i + 3 < e.raw_value.size(); i += 4) {
                uint32_t v = 0;
                for (size_t j = 0; j < 4; ++j) v |= static_cast<uint32_t>(e.raw_value[i + j]) << (j * 8);
                float f;
                std::memcpy(&f, &v, sizeof(f));
                out.push_back(f);
            }
            return out;
        }
    }
    return std::nullopt;
}

std::vector<std::string> GGUFCore::ListMetadataKeys() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::vector<std::string> keys;
    for (const auto& e : impl_->model_.metadata) keys.push_back(e.key);
    return keys;
}

bool GGUFCore::HasTensor(const std::string& name) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    for (const auto& t : impl_->model_.tensors) {
        if (t.name == name) return true;
    }
    return false;
}

std::optional<std::span<const uint8_t>> GGUFCore::GetTensorData(const std::string& name) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    for (const auto& t : impl_->model_.tensors) {
        if (t.name == name) {
            size_t type_size = 4; // default fp32
            size_t num_elems = 1;
            for (auto d : t.dims) num_elems *= d;
            size_t byte_size = num_elems * type_size;
            if (t.offset + byte_size <= impl_->model_.tensor_data.size()) {
                return std::span<const uint8_t>(
                    impl_->model_.tensor_data.data() + t.offset, byte_size);
            }
        }
    }
    return std::nullopt;
}

const GGUFTensorInfo* GGUFCore::GetTensorInfo(const std::string& name) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    for (const auto& t : impl_->model_.tensors) {
        if (t.name == name) return &t;
    }
    return nullptr;
}

std::vector<std::string> GGUFCore::ListTensorNames() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::vector<std::string> names;
    for (const auto& t : impl_->model_.tensors) names.push_back(t.name);
    return names;
}

size_t GGUFCore::GetTensorCount() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->model_.tensors.size();
}

std::string GGUFCore::GetArchitecture() const {
    auto arch = GetMetadataString("general.architecture");
    return arch.value_or("unknown");
}

uint32_t GGUFCore::GetBlockCount() const {
    return GetMetadataUint32(GetArchitecture() + ".block_count").value_or(0);
}

uint32_t GGUFCore::GetHeadCount() const {
    return GetMetadataUint32(GetArchitecture() + ".attention.head_count").value_or(0);
}

uint32_t GGUFCore::GetEmbeddingLength() const {
    return GetMetadataUint32(GetArchitecture() + ".embedding_length").value_or(0);
}

uint32_t GGUFCore::GetContextLength() const {
    return GetMetadataUint32(GetArchitecture() + ".context_length").value_or(0);
}

bool GGUFCore::ValidateAlignment() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return (impl_->model_.tensor_data_offset % 32) == 0;
}

bool GGUFCore::ValidateTensorOffsets() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    for (const auto& t : impl_->model_.tensors) {
        size_t type_size = 4; // fp32 default
        size_t num_elems = 1;
        for (auto d : t.dims) num_elems *= d;
        size_t byte_size = num_elems * type_size;
        if (t.offset + byte_size > impl_->model_.tensor_data.size()) return false;
    }
    return true;
}

std::vector<std::string> GGUFCore::GetValidationErrors() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->validation_errors_;
}

bool GGUFCore::WriteToFile(const std::string& /*path*/) const {
    // TODO: implement serialization
    return false;
}

std::vector<uint8_t> GGUFCore::SerializeToBuffer() const {
    // TODO: implement serialization
    return {};
}

} // namespace rawrxd::engine
