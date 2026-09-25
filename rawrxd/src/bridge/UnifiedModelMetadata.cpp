#include "UnifiedModelMetadata.hpp"
#include <fstream>
#include <mutex>
#include <map>
#include <algorithm>

namespace rawrxd::bridge {

class UnifiedModelMetadataRegistry::Impl {
public:
    mutable std::mutex mutex_;
    std::map<std::string, UnifiedModelMetadata> models_;
};

UnifiedModelMetadataRegistry::UnifiedModelMetadataRegistry() : impl_(std::make_unique<Impl>()) {}
UnifiedModelMetadataRegistry::~UnifiedModelMetadataRegistry() = default;

bool UnifiedModelMetadataRegistry::RegisterModel(const UnifiedModelMetadata& meta) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    if (meta.model_id.empty()) return false;
    impl_->models_[meta.model_id] = meta;
    return true;
}

bool UnifiedModelMetadataRegistry::UnregisterModel(const std::string& model_id) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    auto it = impl_->models_.find(model_id);
    if (it == impl_->models_.end()) return false;
    impl_->models_.erase(it);
    return true;
}

bool UnifiedModelMetadataRegistry::UpdateModel(const std::string& model_id, const UnifiedModelMetadata& meta) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    auto it = impl_->models_.find(model_id);
    if (it == impl_->models_.end()) return false;
    it->second = meta;
    it->second.model_id = model_id; // ensure ID stays consistent
    return true;
}

std::optional<UnifiedModelMetadata> UnifiedModelMetadataRegistry::GetModel(const std::string& model_id) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    auto it = impl_->models_.find(model_id);
    if (it != impl_->models_.end()) return it->second;
    return std::nullopt;
}

std::vector<UnifiedModelMetadata> UnifiedModelMetadataRegistry::GetAllModels() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::vector<UnifiedModelMetadata> out;
    out.reserve(impl_->models_.size());
    for (const auto& [id, meta] : impl_->models_) {
        out.push_back(meta);
    }
    return out;
}

std::vector<UnifiedModelMetadata> UnifiedModelMetadataRegistry::FindByFamily(const std::string& family) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::vector<UnifiedModelMetadata> out;
    for (const auto& [id, meta] : impl_->models_) {
        if (meta.family == family) out.push_back(meta);
    }
    return out;
}

std::vector<UnifiedModelMetadata> UnifiedModelMetadataRegistry::FindByCapability(ModelCapability cap) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::vector<UnifiedModelMetadata> out;
    uint32_t flag = static_cast<uint32_t>(cap);
    for (const auto& [id, meta] : impl_->models_) {
        if (meta.capability_flags & flag) out.push_back(meta);
    }
    return out;
}

std::vector<UnifiedModelMetadata> UnifiedModelMetadataRegistry::FindByTag(const std::string& tag_key,
                                                                              const std::string& tag_value) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::vector<UnifiedModelMetadata> out;
    for (const auto& [id, meta] : impl_->models_) {
        auto it = meta.tags.find(tag_key);
        if (it != meta.tags.end() && it->second == tag_value) out.push_back(meta);
    }
    return out;
}

std::vector<UnifiedModelMetadata> UnifiedModelMetadataRegistry::FindFittableModels(
    const HardwareRequirement& available_hw) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::vector<UnifiedModelMetadata> out;
    for (const auto& [id, meta] : impl_->models_) {
        const auto& req = meta.hw_req;
        if (available_hw.min_vram_bytes >= req.min_vram_bytes &&
            available_hw.min_cpu_cores >= req.min_cpu_cores &&
            available_hw.min_system_ram_bytes >= req.min_system_ram_bytes) {
            if (!req.requires_cuda || available_hw.requires_cuda) {
                if (!req.requires_vulkan || available_hw.requires_vulkan) {
                    out.push_back(meta);
                }
            }
        }
    }
    return out;
}

bool UnifiedModelMetadataRegistry::ValidateChecksum(const std::string& model_id,
                                                       const std::string& expected_sha256) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    auto it = impl_->models_.find(model_id);
    if (it == impl_->models_.end()) return false;
    return it->second.sha256_checksum == expected_sha256;
}

bool UnifiedModelMetadataRegistry::ValidateHardwareCompatibility(const std::string& model_id,
                                                                  const HardwareRequirement& hw) const {
    auto meta = GetModel(model_id);
    if (!meta) return false;
    const auto& req = meta->hw_req;
    if (hw.min_vram_bytes < req.min_vram_bytes) return false;
    if (hw.min_cpu_cores < req.min_cpu_cores) return false;
    if (hw.min_system_ram_bytes < req.min_system_ram_bytes) return false;
    if (req.requires_cuda && !hw.requires_cuda) return false;
    if (req.requires_vulkan && !hw.requires_vulkan) return false;
    if (req.requires_avx512 && !hw.requires_avx512) return false;
    return true;
}

std::vector<uint8_t> UnifiedModelMetadataRegistry::SerializeRegistry() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::vector<uint8_t> out;
    auto append_u32 = [&](uint32_t v) {
        for (int i = 0; i < 4; ++i) { out.push_back(static_cast<uint8_t>(v & 0xFF)); v >>= 8; }
    };
    auto append_u64 = [&](uint64_t v) {
        for (int i = 0; i < 8; ++i) { out.push_back(static_cast<uint8_t>(v & 0xFF)); v >>= 8; }
    };
    auto append_str = [&](const std::string& s) {
        append_u64(s.size());
        out.insert(out.end(), s.begin(), s.end());
    };
    append_u32(static_cast<uint32_t>(impl_->models_.size()));
    for (const auto& [id, meta] : impl_->models_) {
        append_str(meta.model_id);
        append_str(meta.display_name);
        append_str(meta.family);
        append_str(meta.version_str);
        append_str(meta.source_url);
        append_str(meta.sha256_checksum);
        append_u64(meta.file_size_bytes);
        append_u64(meta.parameter_count);
        append_u32(meta.context_length);
        append_u32(meta.vocab_size);
        append_u32(meta.embedding_dim);
        append_u32(meta.num_layers);
        append_u32(meta.num_attention_heads);
        append_u32(meta.num_kv_heads);
        append_u32(static_cast<uint32_t>(meta.quantization_types.size()));
        for (const auto& qt : meta.quantization_types) append_str(qt);
        append_u32(meta.capability_flags);
        append_u64(meta.hw_req.min_vram_bytes);
        append_u64(meta.hw_req.recommended_vram_bytes);
        append_u32(meta.hw_req.min_cpu_cores);
        append_u64(meta.hw_req.min_system_ram_bytes);
        out.push_back(meta.hw_req.requires_cuda ? 1 : 0);
        out.push_back(meta.hw_req.requires_vulkan ? 1 : 0);
        out.push_back(meta.hw_req.requires_avx512 ? 1 : 0);
        append_str(meta.hw_req.cuda_compute_capability);
        append_u32(static_cast<uint32_t>(meta.tags.size()));
        for (const auto& [k, v] : meta.tags) { append_str(k); append_str(v); }
        append_u32(static_cast<uint32_t>(meta.extra_binary_fields.size()));
        for (const auto& [k, v] : meta.extra_binary_fields) {
            append_str(k);
            append_u64(v.size());
            out.insert(out.end(), v.begin(), v.end());
        }
        out.push_back(meta.is_official ? 1 : 0);
        out.push_back(meta.is_finetune ? 1 : 0);
        append_str(meta.base_model_id);
        append_u64(meta.upload_timestamp);
        append_str(meta.license_type);
    }
    return out;
}

bool UnifiedModelMetadataRegistry::DeserializeRegistry(std::span<const uint8_t> data) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    size_t off = 0;
    auto read_u32 = [&]() -> uint32_t {
        if (off + 4 > data.size()) return 0;
        uint32_t v = 0;
        for (int i = 0; i < 4; ++i) v |= static_cast<uint32_t>(data[off++]) << (i * 8);
        return v;
    };
    auto read_u64 = [&]() -> uint64_t {
        if (off + 8 > data.size()) return 0;
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(data[off++]) << (i * 8);
        return v;
    };
    auto read_str = [&]() -> std::string {
        uint64_t len = read_u64();
        if (off + len > data.size()) return "";
        std::string s(reinterpret_cast<const char*>(data.data() + off), len);
        off += len;
        return s;
    };
    uint32_t count = read_u32();
    for (uint32_t i = 0; i < count; ++i) {
        UnifiedModelMetadata meta;
        meta.model_id = read_str();
        meta.display_name = read_str();
        meta.family = read_str();
        meta.version_str = read_str();
        meta.source_url = read_str();
        meta.sha256_checksum = read_str();
        meta.file_size_bytes = read_u64();
        meta.parameter_count = read_u64();
        meta.context_length = read_u32();
        meta.vocab_size = read_u32();
        meta.embedding_dim = read_u32();
        meta.num_layers = read_u32();
        meta.num_attention_heads = read_u32();
        meta.num_kv_heads = read_u32();
        uint32_t qt_count = read_u32();
        for (uint32_t j = 0; j < qt_count; ++j) meta.quantization_types.push_back(read_str());
        meta.capability_flags = read_u32();
        meta.hw_req.min_vram_bytes = read_u64();
        meta.hw_req.recommended_vram_bytes = read_u64();
        meta.hw_req.min_cpu_cores = read_u32();
        meta.hw_req.min_system_ram_bytes = read_u64();
        meta.hw_req.requires_cuda = (off < data.size() && data[off++] != 0);
        meta.hw_req.requires_vulkan = (off < data.size() && data[off++] != 0);
        meta.hw_req.requires_avx512 = (off < data.size() && data[off++] != 0);
        meta.hw_req.cuda_compute_capability = read_str();
        uint32_t tag_count = read_u32();
        for (uint32_t j = 0; j < tag_count; ++j) {
            std::string k = read_str();
            std::string v = read_str();
            meta.tags[k] = v;
        }
        uint32_t extra_count = read_u32();
        for (uint32_t j = 0; j < extra_count; ++j) {
            std::string k = read_str();
            uint64_t vlen = read_u64();
            if (off + vlen > data.size()) return false;
            meta.extra_binary_fields[k].assign(data.begin() + off, data.begin() + off + vlen);
            off += vlen;
        }
        meta.is_official = (off < data.size() && data[off++] != 0);
        meta.is_finetune = (off < data.size() && data[off++] != 0);
        meta.base_model_id = read_str();
        meta.upload_timestamp = read_u64();
        meta.license_type = read_str();
        impl_->models_[meta.model_id] = std::move(meta);
    }
    return true;
}

bool UnifiedModelMetadataRegistry::SaveToDisk(const std::string& path) const {
    auto data = SerializeRegistry();
    std::ofstream ofs(path, std::ios::binary);
    if (!ofs) return false;
    ofs.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    return ofs.good();
}

bool UnifiedModelMetadataRegistry::LoadFromDisk(const std::string& path) {
    std::ifstream ifs(path, std::ios::binary | std::ios::ate);
    if (!ifs) return false;
    auto size = ifs.tellg();
    ifs.seekg(0, std::ios::beg);
    std::vector<uint8_t> data(static_cast<size_t>(size));
    if (!ifs.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(size))) return false;
    return DeserializeRegistry(data);
}

size_t UnifiedModelMetadataRegistry::Count() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->models_.size();
}

size_t UnifiedModelMetadataRegistry::CountByFamily(const std::string& family) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    size_t c = 0;
    for (const auto& [id, meta] : impl_->models_) {
        if (meta.family == family) ++c;
    }
    return c;
}

} // namespace rawrxd::bridge
