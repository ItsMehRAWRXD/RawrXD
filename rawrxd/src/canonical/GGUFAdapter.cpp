#include "GGUFAdapter.hpp"
#include <cstdio>
#include <cstring>
#include <fstream>
#include <algorithm>
#include <sstream>
#include <iomanip>

// Platform-specific mmap
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#endif

namespace rawrxd::canonical {

// ───────────────────────────────────────────────────────────────
// GGUF magic: 'GGUF' in little-endian
static constexpr uint32_t kGGUFMagic = 0x46554747u; // 'GGUF'

// ───────────────────────────────────────────────────────────────
// Endian helpers (assume little-endian host for x86/x64)
template <typename T>
static T ReadLE(const uint8_t* p) {
    static_assert(std::is_trivially_copyable_v<T>);
    T v;
    std::memcpy(&v, p, sizeof(T));
    return v;
}

static uint64_t ReadU64LE(const uint8_t* p) { return ReadLE<uint64_t>(p); }
static uint32_t ReadU32LE(const uint8_t* p) { return ReadLE<uint32_t>(p); }
static uint16_t ReadU16LE(const uint8_t* p) { return ReadLE<uint16_t>(p); }
static double ReadF64LE(const uint8_t* p) { return ReadLE<double>(p); }
static float ReadF32LE(const uint8_t* p) { return ReadLE<float>(p); }

// ───────────────────────────────────────────────────────────────
// KV convenience accessors
// ───────────────────────────────────────────────────────────────
int64_t GGUFKVEntry::AsInt64() const {
    if (raw_value.size() >= sizeof(int64_t)) return ReadLE<int64_t>(raw_value.data());
    if (raw_value.size() >= sizeof(int32_t)) return ReadLE<int32_t>(raw_value.data());
    if (raw_value.size() >= sizeof(int16_t)) return ReadLE<int16_t>(raw_value.data());
    if (raw_value.size() >= sizeof(int8_t))  return ReadLE<int8_t>(raw_value.data());
    return 0;
}
uint64_t GGUFKVEntry::AsUInt64() const {
    if (raw_value.size() >= sizeof(uint64_t)) return ReadLE<uint64_t>(raw_value.data());
    if (raw_value.size() >= sizeof(uint32_t)) return ReadLE<uint32_t>(raw_value.data());
    if (raw_value.size() >= sizeof(uint16_t)) return ReadLE<uint16_t>(raw_value.data());
    if (raw_value.size() >= sizeof(uint8_t))  return ReadLE<uint8_t>(raw_value.data());
    return 0;
}
double GGUFKVEntry::AsDouble() const {
    if (raw_value.size() >= sizeof(double)) return ReadLE<double>(raw_value.data());
    if (raw_value.size() >= sizeof(float))  return ReadLE<float>(raw_value.data());
    return static_cast<double>(AsInt64());
}
std::string GGUFKVEntry::AsString() const {
    if (type == GGUFKVType::String && raw_value.size() >= sizeof(uint64_t)) {
        uint64_t len = ReadU64LE(raw_value.data());
        if (raw_value.size() >= sizeof(uint64_t) + len) {
            return std::string(reinterpret_cast<const char*>(raw_value.data() + sizeof(uint64_t)), len);
        }
    }
    return "";
}
bool GGUFKVEntry::AsBool() const {
    if (raw_value.size() >= 1) return raw_value[0] != 0;
    return false;
}
std::vector<int64_t> GGUFKVEntry::AsIntArray() const {
    std::vector<int64_t> out;
    if (type != GGUFKVType::Array || raw_value.size() < sizeof(uint32_t) + sizeof(uint64_t)) return out;
    GGUFKVType elem_type = static_cast<GGUFKVType>(ReadU32LE(raw_value.data()));
    uint64_t count = ReadU64LE(raw_value.data() + sizeof(uint32_t));
    const uint8_t* p = raw_value.data() + sizeof(uint32_t) + sizeof(uint64_t);
    size_t elem_size = 0;
    switch (elem_type) {
        case GGUFKVType::I8:  elem_size = 1; break;
        case GGUFKVType::I16: elem_size = 2; break;
        case GGUFKVType::I32: elem_size = 4; break;
        case GGUFKVType::I64: elem_size = 8; break;
        default: return out;
    }
    out.reserve(count);
    for (uint64_t i = 0; i < count; ++i) {
        int64_t v = 0;
        if (elem_size == 1) v = static_cast<int64_t>(*reinterpret_cast<const int8_t*>(p));
        else if (elem_size == 2) v = static_cast<int64_t>(ReadLE<int16_t>(p));
        else if (elem_size == 4) v = static_cast<int64_t>(ReadLE<int32_t>(p));
        else if (elem_size == 8) v = ReadLE<int64_t>(p);
        out.push_back(v);
        p += elem_size;
    }
    return out;
}
std::vector<std::string> GGUFKVEntry::AsStringArray() const {
    std::vector<std::string> out;
    if (type != GGUFKVType::Array || raw_value.size() < sizeof(uint32_t) + sizeof(uint64_t)) return out;
    uint64_t count = ReadU64LE(raw_value.data() + sizeof(uint32_t));
    const uint8_t* p = raw_value.data() + sizeof(uint32_t) + sizeof(uint64_t);
    for (uint64_t i = 0; i < count; ++i) {
        uint64_t len = ReadU64LE(p);
        p += sizeof(uint64_t);
        out.emplace_back(reinterpret_cast<const char*>(p), len);
        p += len;
    }
    return out;
}

// ───────────────────────────────────────────────────────────────
// GGUFAdapter implementation
// ───────────────────────────────────────────────────────────────
GGUFAdapter::GGUFAdapter() = default;
GGUFAdapter::~GGUFAdapter() {
#ifdef _WIN32
    if (mmap_handle_) {
        auto* h = static_cast<HANDLE*>(mmap_handle_);
        UnmapViewOfFile(h);
    }
#else
    if (mmap_handle_ && mmap_size_ > 0) {
        munmap(mmap_handle_, mmap_size_);
    }
#endif
}

bool GGUFAdapter::Open(const std::string& file_path) {
    file_path_ = file_path;
    std::ifstream fs(file_path, std::ios::binary | std::ios::ate);
    if (!fs.is_open()) return false;
    auto total = fs.tellg();
    fs.seekg(0, std::ios::beg);
    file_data_.resize(static_cast<size_t>(total));
    if (!fs.read(reinterpret_cast<char*>(file_data_.data()), static_cast<std::streamsize>(total))) {
        return false;
    }
    return OpenFromMemory(file_data_);
}

bool GGUFAdapter::OpenFromMemory(std::span<const uint8_t> data) {
    if (data.size() < 24) return false;
    size_t consumed = 0;
    if (!ParseHeader(data.data(), data.size())) return false;
    consumed += 24; // header size

    // Parse KV pairs
    for (uint64_t i = 0; i < header_.n_kv; ++i) {
        size_t kv_consumed = 0;
        if (!ParseKV(data.data() + consumed, data.size() - consumed, kv_consumed)) return false;
        consumed += kv_consumed;
    }
    header_.metadata_end_offset = consumed;

    // Align to header_.alignment
    uint64_t pad = (header_.alignment - (consumed % header_.alignment)) % header_.alignment;
    consumed += pad;
    header_.tensor_data_offset = consumed;

    // Parse tensor info
    for (uint64_t i = 0; i < header_.n_tensors; ++i) {
        size_t t_consumed = 0;
        if (!ParseTensorInfo(data.data() + consumed, data.size() - consumed, t_consumed)) return false;
        consumed += t_consumed;
    }

    // Extract metadata after all KV are parsed
    if (!ExtractMetadata()) return false;

    return true;
}

bool GGUFAdapter::ParseHeader(const uint8_t* data, size_t len) {
    if (len < 24) return false;
    header_.magic    = ReadU32LE(data + 0);
    header_.version  = ReadU32LE(data + 4);
    header_.n_tensors = ReadU64LE(data + 8);
    header_.n_kv      = ReadU64LE(data + 16);
    if (header_.magic != kGGUFMagic) return false;
    if (header_.version != 2 && header_.version != 3) return false; // support v2/v3
    header_.alignment = (header_.version >= 3) ? 32 : 1;
    return true;
}

bool GGUFAdapter::ParseKV(const uint8_t* data, size_t len, size_t& consumed) {
    if (len < sizeof(uint64_t)) return false;
    uint64_t key_len = ReadU64LE(data);
    size_t off = sizeof(uint64_t);
    if (len < off + key_len + sizeof(uint32_t)) return false;
    GGUFKVEntry entry;
    entry.key = std::string(reinterpret_cast<const char*>(data + off), key_len);
    off += key_len;
    entry.type = static_cast<GGUFKVType>(ReadU32LE(data + off));
    off += sizeof(uint32_t);

    auto read_val = [&](size_t sz) -> bool {
        if (len < off + sz) return false;
        entry.raw_value.assign(data + off, data + off + sz);
        off += sz;
        return true;
    };

    switch (entry.type) {
        case GGUFKVType::U8:  case GGUFKVType::I8:  case GGUFKVType::Bool:
            if (!read_val(1)) return false; break;
        case GGUFKVType::U16: case GGUFKVType::I16:
            if (!read_val(2)) return false; break;
        case GGUFKVType::U32: case GGUFKVType::I32: case GGUFKVType::F32:
            if (!read_val(4)) return false; break;
        case GGUFKVType::U64: case GGUFKVType::I64: case GGUFKVType::F64:
            if (!read_val(8)) return false; break;
        case GGUFKVType::String: {
            if (len < off + sizeof(uint64_t)) return false;
            uint64_t slen = ReadU64LE(data + off);
            off += sizeof(uint64_t);
            if (len < off + slen) return false;
            entry.raw_value.resize(sizeof(uint64_t) + slen);
            std::memcpy(entry.raw_value.data(), data + off - sizeof(uint64_t), sizeof(uint64_t));
            std::memcpy(entry.raw_value.data() + sizeof(uint64_t), data + off, slen);
            off += slen;
            break;
        }
        case GGUFKVType::Array: {
            if (len < off + sizeof(uint32_t) + sizeof(uint64_t)) return false;
            uint32_t elem_type = ReadU32LE(data + off);
            off += sizeof(uint32_t);
            uint64_t arr_len = ReadU64LE(data + off);
            off += sizeof(uint64_t);
            size_t elem_size = 0;
            switch (static_cast<GGUFKVType>(elem_type)) {
                case GGUFKVType::U8: case GGUFKVType::I8: case GGUFKVType::Bool: elem_size = 1; break;
                case GGUFKVType::U16: case GGUFKVType::I16: elem_size = 2; break;
                case GGUFKVType::U32: case GGUFKVType::I32: case GGUFKVType::F32: elem_size = 4; break;
                case GGUFKVType::U64: case GGUFKVType::I64: case GGUFKVType::F64: elem_size = 8; break;
                case GGUFKVType::String: elem_size = sizeof(uint64_t); break; // variable, handled below
                default: return false;
            }
            size_t arr_raw_size = sizeof(uint32_t) + sizeof(uint64_t);
            if (static_cast<GGUFKVType>(elem_type) == GGUFKVType::String) {
                const uint8_t* p = data + off;
                for (uint64_t i = 0; i < arr_len; ++i) {
                    if (len < static_cast<size_t>(p - data) + sizeof(uint64_t)) return false;
                    uint64_t s_len = ReadU64LE(p);
                    p += sizeof(uint64_t) + s_len;
                }
                arr_raw_size = static_cast<size_t>(p - (data + off - sizeof(uint32_t) - sizeof(uint64_t)));
            } else {
                arr_raw_size += static_cast<size_t>(arr_len) * elem_size;
            }
            if (len < off - sizeof(uint32_t) - sizeof(uint64_t) + arr_raw_size) return false;
            entry.raw_value.assign(data + off - sizeof(uint32_t) - sizeof(uint64_t),
                                   data + off - sizeof(uint32_t) - sizeof(uint64_t) + arr_raw_size);
            off = off - sizeof(uint32_t) - sizeof(uint64_t) + arr_raw_size;
            break;
        }
        default:
            return false;
    }

    kv_map_[entry.key] = std::move(entry);
    consumed = off;
    return true;
}

bool GGUFAdapter::ParseTensorInfo(const uint8_t* data, size_t len, size_t& consumed) {
    if (len < sizeof(uint64_t)) return false;
    uint64_t name_len = ReadU64LE(data);
    size_t off = sizeof(uint64_t);
    if (len < off + name_len + sizeof(uint32_t)) return false;

    GGUFTensorInfo info;
    info.name = std::string(reinterpret_cast<const char*>(data + off), name_len);
    off += name_len;

    info.n_dims = ReadU32LE(data + off);
    off += sizeof(uint32_t);
    if (info.n_dims > 4) return false;
    if (len < off + info.n_dims * sizeof(uint64_t) + sizeof(uint32_t) + sizeof(uint64_t)) return false;

    info.shape.resize(info.n_dims);
    for (uint32_t d = 0; d < info.n_dims; ++d) {
        info.shape[d] = ReadU64LE(data + off);
        off += sizeof(uint64_t);
    }

    info.quant_type = static_cast<GGMLQuantType>(ReadU32LE(data + off));
    off += sizeof(uint32_t);
    info.offset = ReadU64LE(data + off);
    off += sizeof(uint64_t);

    info.element_size = static_cast<size_t>(QuantTypeTypeSize(info.quant_type));
    info.size_bytes = ComputeTensorSize(info);
    info.is_q4_k_m = (info.quant_type == GGMLQuantType::Q4_K);
    info.is_q5_k_m = (info.quant_type == GGMLQuantType::Q5_K);
    info.is_q8_0   = (info.quant_type == GGMLQuantType::Q8_0);

    tensors_.push_back(std::move(info));
    consumed = off;
    return true;
}

size_t GGUFAdapter::QuantTypeBlockSize(GGMLQuantType qt) {
    switch (qt) {
        case GGMLQuantType::F32:  return 1;
        case GGMLQuantType::F16:  return 1;
        case GGMLQuantType::Q4_0: return 32;
        case GGMLQuantType::Q4_1: return 32;
        case GGMLQuantType::Q5_0: return 32;
        case GGMLQuantType::Q5_1: return 32;
        case GGMLQuantType::Q8_0: return 32;
        case GGMLQuantType::Q8_1: return 32;
        case GGMLQuantType::Q2_K: return 256;
        case GGMLQuantType::Q3_K: return 256;
        case GGMLQuantType::Q4_K: return 256;
        case GGMLQuantType::Q5_K: return 256;
        case GGMLQuantType::Q6_K: return 256;
        case GGMLQuantType::Q8_K: return 256;
        case GGMLQuantType::I8:   return 1;
        case GGMLQuantType::I16:  return 1;
        case GGMLQuantType::I32:  return 1;
        default: return 1;
    }
}

size_t GGUFAdapter::QuantTypeTypeSize(GGMLQuantType qt) {
    switch (qt) {
        case GGMLQuantType::F32:  return sizeof(float);
        case GGMLQuantType::F16:  return sizeof(uint16_t);
        case GGMLQuantType::Q4_0: return sizeof(uint8_t); // half-byte per element packed
        case GGMLQuantType::Q4_1: return sizeof(uint8_t);
        case GGMLQuantType::Q5_0: return sizeof(uint8_t);
        case GGMLQuantType::Q5_1: return sizeof(uint8_t);
        case GGMLQuantType::Q8_0: return sizeof(uint8_t);
        case GGMLQuantType::Q8_1: return sizeof(uint8_t);
        case GGMLQuantType::Q2_K: return sizeof(uint8_t);
        case GGMLQuantType::Q3_K: return sizeof(uint8_t);
        case GGMLQuantType::Q4_K: return sizeof(uint8_t);
        case GGMLQuantType::Q5_K: return sizeof(uint8_t);
        case GGMLQuantType::Q6_K: return sizeof(uint8_t);
        case GGMLQuantType::Q8_K: return sizeof(uint8_t);
        case GGMLQuantType::I8:   return sizeof(int8_t);
        case GGMLQuantType::I16:  return sizeof(int16_t);
        case GGMLQuantType::I32:  return sizeof(int32_t);
        default: return 1;
    }
}

uint64_t GGUFAdapter::ComputeTensorSize(const GGUFTensorInfo& info) {
    uint64_t n_elements = 1;
    for (auto dim : info.shape) n_elements *= dim;
    size_t block_size = QuantTypeBlockSize(info.quant_type);
    size_t type_size  = QuantTypeTypeSize(info.quant_type);
    // For Q4_0: each block has 32 weights (16 bytes total = 2 bytes scale + 16 nibbles)
    // General formula: (n_elements / block_size) * block_bytes
    uint64_t n_blocks = (n_elements + block_size - 1) / block_size;
    uint64_t block_bytes = 0;
    switch (info.quant_type) {
        case GGMLQuantType::Q4_0: block_bytes = sizeof(uint16_t) + (block_size / 2); break;
        case GGMLQuantType::Q4_1: block_bytes = 2 * sizeof(uint16_t) + (block_size / 2); break;
        case GGMLQuantType::Q5_0: block_bytes = sizeof(uint16_t) + (block_size / 8) * 5; break; // approximate
        case GGMLQuantType::Q5_1: block_bytes = 2 * sizeof(uint16_t) + (block_size / 8) * 5; break;
        case GGMLQuantType::Q8_0: block_bytes = sizeof(uint16_t) + block_size; break;
        case GGMLQuantType::Q8_1: block_bytes = 3 * sizeof(uint16_t) + block_size; break;
        case GGMLQuantType::Q2_K: block_bytes = 256 / 4 + sizeof(uint16_t) + sizeof(uint8_t); break; // approximate
        case GGMLQuantType::Q3_K: block_bytes = 256 / 8 + 12; break;
        case GGMLQuantType::Q4_K: block_bytes = 2 + 2 + 256 / 2; break;
        case GGMLQuantType::Q5_K: block_bytes = 2 + 2 + 256 / 8 * 5; break;
        case GGMLQuantType::Q6_K: block_bytes = 256 / 2 + 256 / 4 + 2; break;
        case GGMLQuantType::Q8_K: block_bytes = 2 + 256; break;
        default: block_bytes = block_size * type_size; break;
    }
    return n_blocks * block_bytes;
}

bool GGUFAdapter::ExtractMetadata() {
    auto get_kv_str = [&](const std::string& k) -> std::string {
        auto it = kv_map_.find(k);
        return (it != kv_map_.end()) ? it->second.AsString() : "";
    };
    auto get_kv_u64 = [&](const std::string& k) -> uint64_t {
        auto it = kv_map_.find(k);
        return (it != kv_map_.end()) ? it->second.AsUInt64() : 0;
    };
    auto get_kv_f64 = [&](const std::string& k) -> double {
        auto it = kv_map_.find(k);
        return (it != kv_map_.end()) ? it->second.AsDouble() : 0.0;
    };

    metadata_.name = get_kv_str("general.name");
    std::string arch_str = get_kv_str("general.architecture");
    if (arch_str == "llama") metadata_.arch = GGUFArchitecture::Llama;
    else if (arch_str == "mistral") metadata_.arch = GGUFArchitecture::Mistral;
    else if (arch_str == "mixtral") metadata_.arch = GGUFArchitecture::Mixtral;
    else if (arch_str == "phi") metadata_.arch = GGUFArchitecture::Phi;
    else if (arch_str == "gemma") metadata_.arch = GGUFArchitecture::Gemma;
    else if (arch_str == "qwen") metadata_.arch = GGUFArchitecture::Qwen;
    else metadata_.arch = GGUFArchitecture::Unknown;

    metadata_.vocab_size              = static_cast<uint32_t>(get_kv_u64(arch_str + ".vocab_size"));
    metadata_.context_length          = static_cast<uint32_t>(get_kv_u64(arch_str + ".context_length"));
    metadata_.embedding_length        = static_cast<uint32_t>(get_kv_u64(arch_str + ".embedding_length"));
    metadata_.block_count             = static_cast<uint32_t>(get_kv_u64(arch_str + ".block_count"));
    metadata_.feed_forward_length     = static_cast<uint32_t>(get_kv_u64(arch_str + ".feed_forward_length"));
    metadata_.attention_head_count    = static_cast<uint32_t>(get_kv_u64(arch_str + ".attention.head_count"));
    metadata_.attention_head_count_kv = static_cast<uint32_t>(get_kv_u64(arch_str + ".attention.head_count_kv"));
    metadata_.attention_key_length    = static_cast<uint32_t>(get_kv_u64(arch_str + ".attention.key_length"));
    metadata_.attention_value_length  = static_cast<uint32_t>(get_kv_u64(arch_str + ".attention.value_length"));
    metadata_.rope_dimension_count    = static_cast<uint32_t>(get_kv_u64(arch_str + ".rope.dimension_count"));
    metadata_.rope_freq_base           = static_cast<float>(get_kv_f64(arch_str + ".rope.freq_base"));
    if (metadata_.rope_freq_base <= 0.0f) metadata_.rope_freq_base = 10000.0f;

    metadata_.layer_norm_rms_eps           = static_cast<float>(get_kv_f64(arch_str + ".attention.layer_norm_rms_epsilon"));
    if (metadata_.layer_norm_rms_eps <= 0.0f) metadata_.layer_norm_rms_eps = 1e-5f;

    metadata_.tokenizer_model = get_kv_str("tokenizer.ggml.model");
    if (metadata_.tokenizer_model.empty()) metadata_.tokenizer_model = "llama";

    metadata_.use_parallel_residual = get_kv_u64(arch_str + ".use_parallel_residual") != 0;

    // RoPE scaling (optional)
    metadata_.use_rope_scaling = kv_map_.find(arch_str + ".rope.scaling.type") != kv_map_.end();
    if (metadata_.use_rope_scaling) {
        metadata_.rope_scaling_type   = get_kv_str(arch_str + ".rope.scaling.type");
        metadata_.rope_scaling_factor   = static_cast<float>(get_kv_f64(arch_str + ".rope.scaling.factor"));
    }

    // MoE (optional)
    metadata_.has_moe = kv_map_.find(arch_str + ".moe.expert_count") != kv_map_.end();
    if (metadata_.has_moe) {
        metadata_.moe_expert_count      = static_cast<uint32_t>(get_kv_u64(arch_str + ".moe.expert_count"));
        metadata_.moe_expert_used_count = static_cast<uint32_t>(get_kv_u64(arch_str + ".moe.expert_used_count"));
    }

    // Collect unparsed KV entries
    for (const auto& [k, v] : kv_map_) {
        if (metadata_.extra_kv.find(k) == metadata_.extra_kv.end()) {
            metadata_.extra_kv[k] = v;
        }
    }

    // Architecture tensor name prefixes
    if (metadata_.arch == GGUFArchitecture::Gemma) {
        metadata_.arch_tensor_name_prefixes = {"model.embed_tokens", "model.layers", "model.norm"};
    } else if (metadata_.arch == GGUFArchitecture::Phi) {
        metadata_.arch_tensor_name_prefixes = {"model.embed_tokens", "model.layers", "model.final_layernorm"};
    } else {
        // Llama / Mistral / Mixtral / Qwen default
        metadata_.arch_tensor_name_prefixes = {"token_embd", "blk", "output_norm", "output"};
    }

    return true;
}

const GGUFTensorInfo* GGUFAdapter::FindTensor(const std::string& name) const {
    for (const auto& t : tensors_) {
        if (t.name == name) return &t;
    }
    return nullptr;
}

std::vector<const GGUFTensorInfo*> GGUFAdapter::FindTensorsByPrefix(const std::string& prefix) const {
    std::vector<const GGUFTensorInfo*> out;
    for (const auto& t : tensors_) {
        if (t.name.rfind(prefix, 0) == 0) out.push_back(&t);
    }
    return out;
}

std::vector<const GGUFTensorInfo*> GGUFAdapter::FindTensorsByLayer(uint32_t layer_idx) const {
    std::vector<const GGUFTensorInfo*> out;
    std::string prefix = "blk." + std::to_string(layer_idx) + ".";
    for (const auto& t : tensors_) {
        if (t.name.rfind(prefix, 0) == 0) out.push_back(&t);
    }
    return out;
}

std::vector<uint8_t> GGUFAdapter::ReadTensorData(const GGUFTensorInfo& info) const {
    std::vector<uint8_t> out(info.size_bytes);
    if (!ReadTensorDataInto(info, out.data(), out.size())) {
        out.clear();
    }
    return out;
}

bool GGUFAdapter::ReadTensorDataInto(const GGUFTensorInfo& info, void* dest, size_t dest_size) const {
    if (dest_size < info.size_bytes) return false;
    if (!file_data_.empty()) {
        uint64_t abs_offset = header_.tensor_data_offset + info.offset;
        if (abs_offset + info.size_bytes > file_data_.size()) return false;
        std::memcpy(dest, file_data_.data() + abs_offset, info.size_bytes);
        return true;
    }
    if (!file_path_.empty()) {
        std::ifstream fs(file_path_, std::ios::binary);
        if (!fs) return false;
        uint64_t abs_offset = header_.tensor_data_offset + info.offset;
        fs.seekg(static_cast<std::streamoff>(abs_offset));
        if (!fs.read(reinterpret_cast<char*>(dest), static_cast<std::streamsize>(info.size_bytes))) return false;
        return true;
    }
    return false;
}

bool GGUFAdapter::EnableMMap(const std::string& file_path) {
#ifdef _WIN32
    HANDLE hFile = CreateFileA(file_path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    HANDLE hMap = CreateFileMapping(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    CloseHandle(hFile);
    if (!hMap) return false;
    void* ptr = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!ptr) { CloseHandle(hMap); return false; }
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(ptr, &mbi, sizeof(mbi))) {
        mmap_size_ = mbi.RegionSize;
    }
    mmap_handle_ = ptr; // store view pointer; file mapping handle leaks intentionally for simplicity
    (void)hMap; // suppress unused warning
#else
    int fd = open(file_path.c_str(), O_RDONLY);
    if (fd < 0) return false;
    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return false; }
    mmap_size_ = static_cast<size_t>(st.st_size);
    void* ptr = mmap(nullptr, mmap_size_, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (ptr == MAP_FAILED) return false;
    mmap_handle_ = ptr;
#endif
    return true;
}

std::span<const uint8_t> GGUFAdapter::MMapTensorView(const GGUFTensorInfo& info) const {
    if (!mmap_handle_ || mmap_size_ == 0) return {};
    uint64_t abs_offset = header_.tensor_data_offset + info.offset;
    if (abs_offset + info.size_bytes > mmap_size_) return {};
    return { reinterpret_cast<const uint8_t*>(mmap_handle_) + abs_offset, info.size_bytes };
}

bool GGUFAdapter::ValidateTensorOffsets() const {
    for (const auto& t : tensors_) {
        uint64_t abs = header_.tensor_data_offset + t.offset;
        if (abs + t.size_bytes > file_data_.size() && file_data_.size() > 0) return false;
    }
    return true;
}

bool GGUFAdapter::ValidateAlignment() const {
    return (header_.tensor_data_offset % header_.alignment) == 0;
}

std::vector<std::string> GGUFAdapter::DetectMissingArchitectureTensors() const {
    std::vector<std::string> missing;
    const auto& m = metadata_;
    // Token embedding
    if (!FindTensor("token_embd.weight") && !FindTensor("model.embed_tokens.weight")) {
        missing.push_back("token_embd.weight / model.embed_tokens.weight");
    }
    // Output norm
    if (!FindTensor("output_norm.weight") && !FindTensor("model.norm.weight")) {
        missing.push_back("output_norm.weight / model.norm.weight");
    }
    // Output (LM head)
    if (!FindTensor("output.weight") && !FindTensor("lm_head.weight") && !FindTensor("model.embed_tokens.weight")) {
        missing.push_back("output.weight / lm_head.weight");
    }
    // Per-layer required tensors
    for (uint32_t i = 0; i < m.block_count; ++i) {
        auto layer_tensors = FindTensorsByLayer(i);
        bool has_attn_q = false, has_attn_k = false, has_attn_v = false, has_attn_out = false;
        bool has_ffn_gate = false, has_ffn_up = false, has_ffn_down = false;
        bool has_ln1 = false, has_ln2 = false;
        for (const auto* t : layer_tensors) {
            if (t->name.find("attn_q") != std::string::npos) has_attn_q = true;
            if (t->name.find("attn_k") != std::string::npos) has_attn_k = true;
            if (t->name.find("attn_v") != std::string::npos) has_attn_v = true;
            if (t->name.find("attn_output") != std::string::npos) has_attn_out = true;
            if (t->name.find("ffn_gate") != std::string::npos) has_ffn_gate = true;
            if (t->name.find("ffn_up") != std::string::npos) has_ffn_up = true;
            if (t->name.find("ffn_down") != std::string::npos) has_ffn_down = true;
            if (t->name.find("ln1") != std::string::npos || t->name.find("input_layernorm") != std::string::npos) has_ln1 = true;
            if (t->name.find("ln2") != std::string::npos || t->name.find("post_attention_layernorm") != std::string::npos) has_ln2 = true;
        }
        if (!has_attn_q) missing.push_back("blk." + std::to_string(i) + ".attn_q.weight");
        if (!has_attn_k) missing.push_back("blk." + std::to_string(i) + ".attn_k.weight");
        if (!has_attn_v) missing.push_back("blk." + std::to_string(i) + ".attn_v.weight");
        if (!has_attn_out) missing.push_back("blk." + std::to_string(i) + ".attn_output.weight");
        if (!has_ffn_gate) missing.push_back("blk." + std::to_string(i) + ".ffn_gate.weight");
        if (!has_ffn_up) missing.push_back("blk." + std::to_string(i) + ".ffn_up.weight");
        if (!has_ffn_down) missing.push_back("blk." + std::to_string(i) + ".ffn_down.weight");
        if (!has_ln1) missing.push_back("blk." + std::to_string(i) + ".ln1.weight");
        if (!has_ln2) missing.push_back("blk." + std::to_string(i) + ".ln2.weight");
    }
    return missing;
}

std::string GGUFAdapter::CanonicalizeTensorName(const std::string& raw_name) const {
    if (metadata_.arch == GGUFArchitecture::Gemma) {
        // Gemma: model.layers.N.
        if (raw_name.rfind("blk.", 0) == 0) {
            size_t dot = raw_name.find('.', 4);
            if (dot != std::string::npos) {
                std::string idx = raw_name.substr(4, dot - 4);
                std::string rest = raw_name.substr(dot + 1);
                // Map raw suffix -> Gemma suffix
                std::string mapped = rest;
                if (rest == "attn_q.weight") mapped = "self_attn.q_proj.weight";
                else if (rest == "attn_k.weight") mapped = "self_attn.k_proj.weight";
                else if (rest == "attn_v.weight") mapped = "self_attn.v_proj.weight";
                else if (rest == "attn_output.weight") mapped = "self_attn.o_proj.weight";
                else if (rest == "ln1.weight") mapped = "input_layernorm.weight";
                else if (rest == "ln2.weight") mapped = "post_attention_layernorm.weight";
                else if (rest == "ffn_gate.weight") mapped = "mlp.gate_proj.weight";
                else if (rest == "ffn_up.weight") mapped = "mlp.up_proj.weight";
                else if (rest == "ffn_down.weight") mapped = "mlp.down_proj.weight";
                return "model.layers." + idx + "." + mapped;
            }
        }
        if (raw_name == "token_embd.weight") return "model.embed_tokens.weight";
        if (raw_name == "output_norm.weight") return "model.norm.weight";
        if (raw_name == "output.weight") return "model.embed_tokens.weight"; // tied
    }
    if (metadata_.arch == GGUFArchitecture::Phi) {
        if (raw_name.rfind("blk.", 0) == 0) {
            size_t dot = raw_name.find('.', 4);
            if (dot != std::string::npos) {
                std::string idx = raw_name.substr(4, dot - 4);
                std::string rest = raw_name.substr(dot + 1);
                std::string mapped = rest;
                if (rest == "attn_qkv.weight") mapped = "self_attn.qkv_proj.weight";
                else if (rest == "attn_output.weight") mapped = "self_attn.dense.weight";
                else if (rest == "ln1.weight") mapped = "input_layernorm.weight";
                else if (rest == "ffn_up.weight") mapped = "mlp.fc1.weight";
                else if (rest == "ffn_down.weight") mapped = "mlp.fc2.weight";
                return "model.layers." + idx + "." + mapped;
            }
        }
    }
    // Default: return as-is (Llama naming)
    return raw_name;
}

} // namespace rawrxd::canonical
