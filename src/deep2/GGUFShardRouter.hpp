#pragma once

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

namespace RawrXD {

class GGUFShardRouter {
public:
    struct TensorLocation {
        std::string  name;
        uint32_t     shard_index;
        uint64_t     file_offset;
        uint64_t     data_offset;
        uint64_t     size_bytes;
        uint32_t     ggml_type;
        std::vector<uint64_t> dims;
    };

    // Metadata extracted from GGUF header (first shard)
    struct ModelMetadata {
        uint32_t layer_count = 0;
        uint32_t hidden_size = 0;
        uint32_t head_count = 0;
        uint32_t head_count_kv = 0;
        uint32_t context_length = 0;
        uint32_t ffn_dim = 0;
        uint32_t expert_count = 0;
        uint32_t expert_used_count = 0;
        uint32_t vocab_size = 0;
        float    rope_theta = 10000.0f;
        float    norm_eps = 1e-6f;
        std::string architecture;
        std::string model_name;
        bool     has_metadata = false;
    };

    void add_shard(std::filesystem::path p) {
        shards_.push_back({std::move(p), 0, 0});
    }

    void add_kimi_k2_shards(const std::filesystem::path& base_dir) {
        for (int i = 1; i <= 13; ++i) {
            char buf[256];
            std::snprintf(
                buf, sizeof(buf),
                "kimi-k2-instruct-0905-q4_k_m-%05d-of-00013.gguf",
                i
            );
            add_shard(base_dir / buf);
        }
    }

    void scan() {
        tensors_.clear();
        for (size_t i = 0; i < shards_.size(); ++i) {
            scan_shard(i);
        }
    }

    std::optional<TensorLocation> resolve(const std::string& tensor_name) const {
        auto it = tensors_.find(tensor_name);
        if (it == tensors_.end()) {
            return std::nullopt;
        }
        return it->second;
    }

    const TensorLocation* find(std::string_view name) const {
        auto it = tensors_.find(std::string(name));
        if (it == tensors_.end()) {
            return nullptr;
        }
        return &it->second;
    }

    const std::filesystem::path& shard_path(uint32_t idx) const {
        return shards_.at(idx).path;
    }

    const std::unordered_map<std::string, TensorLocation>& tensors() const {
        return tensors_;
    }

    size_t tensor_count() const { return tensors_.size(); }
    size_t shard_count() const { return shards_.size(); }

    // Get metadata extracted from first shard (populated after scan())
    const ModelMetadata& metadata() const { return metadata_; }

private:
    struct Shard {
        std::filesystem::path path;
        uint64_t data_start;
        uint64_t tensor_count;
    };

public:
    const std::vector<Shard>& shards() const { return shards_; }

private:

    std::vector<Shard> shards_;
    std::unordered_map<std::string, TensorLocation> tensors_;
    ModelMetadata metadata_;

    static uint32_t read_u32(std::istream& f) {
        uint32_t v = 0;
        f.read(reinterpret_cast<char*>(&v), sizeof(v));
        if (!f) throw std::runtime_error("GGUF EOF reading u32");
        return v;
    }

    static uint64_t read_u64(std::istream& f) {
        uint64_t v = 0;
        f.read(reinterpret_cast<char*>(&v), sizeof(v));
        if (!f) throw std::runtime_error("GGUF EOF reading u64");
        return v;
    }

    static std::string read_str(std::istream& f) {
        uint64_t len = read_u64(f);
        if (len > (1ull << 24)) {
            throw std::runtime_error("GGUF string too large");
        }
        std::string s(len, '\0');
        f.read(s.data(), len);
        if (!f) throw std::runtime_error("GGUF EOF reading string");
        return s;
    }

    static void skip_or_capture_value(
        std::istream& f,
        uint32_t type,
        const std::string& key,
        uint32_t& alignment,
        ModelMetadata* meta = nullptr
    ) {
        switch (type) {
            case 0: case 1: case 7:
                f.ignore(1);
                break;
            case 2: case 3:
                f.ignore(2);
                break;
            case 4: {
                uint32_t v = read_u32(f);
                if (key == "general.alignment") alignment = v;
                if (meta) {
                    // Support both llama.* and deepseek2.* prefixes
                    if (key == "llama.block_count" || key == "deepseek2.block_count")
                        meta->layer_count = v;
                    else if (key == "llama.embedding_length" || key == "deepseek2.embedding_length")
                        meta->hidden_size = v;
                    else if (key == "llama.attention.head_count" || key == "deepseek2.attention.head_count")
                        meta->head_count = v;
                    else if (key == "llama.attention.head_count_kv" || key == "deepseek2.attention.head_count_kv")
                        meta->head_count_kv = v;
                    else if (key == "llama.context_length" || key == "deepseek2.context_length")
                        meta->context_length = v;
                    else if (key == "llama.feed_forward_length" || key == "deepseek2.feed_forward_length")
                        meta->ffn_dim = v;
                    else if (key == "llama.expert_count" || key == "deepseek2.expert_count")
                        meta->expert_count = v;
                    else if (key == "llama.expert_used_count" || key == "deepseek2.expert_used_count")
                        meta->expert_used_count = v;
                    else if (key == "general.vocab_size" || key == "deepseek2.vocab_size")
                        meta->vocab_size = v;
                }
                break;
            }
            case 5:
                f.ignore(4);
                break;
            case 6: {
                // GGUF type 6 = float32
                uint32_t bits = 0;
                f.read(reinterpret_cast<char*>(&bits), sizeof(bits));
                if (meta) {
                    if (key == "llama.rope.freq_base" || key == "deepseek2.rope.freq_base") {
                        std::memcpy(&meta->rope_theta, &bits, sizeof(float));
                    } else if (key == "llama.attention.layer_norm_rms_epsilon" ||
                               key == "deepseek2.attention.layer_norm_rms_epsilon") {
                        std::memcpy(&meta->norm_eps, &bits, sizeof(float));
                    }
                }
                break;
            }
            case 8: {
                std::string s = read_str(f);
                if (meta) {
                    if (key == "general.architecture") meta->architecture = s;
                    else if (key == "general.name") meta->model_name = s;
                }
                break;
            }
            case 9: {
                uint32_t elem_type = read_u32(f);
                uint64_t n = read_u64(f);
                std::string dummy;
                for (uint64_t i = 0; i < n; ++i) {
                    skip_or_capture_value(f, elem_type, dummy, alignment, meta);
                }
                break;
            }
            case 10: case 11: case 12: {
                uint64_t v = 0;
                f.read(reinterpret_cast<char*>(&v), sizeof(v));
                if (meta) {
                    if (key == "llama.rope.freq_base") meta->rope_theta = static_cast<float>(v);
                    else if (key == "llama.attention.layer_norm_rms_epsilon") {
                        // GGUF stores as float32 (type 10), read as uint32 bits
                        uint32_t bits = static_cast<uint32_t>(v);
                        std::memcpy(&meta->norm_eps, &bits, sizeof(float));
                    }
                }
                break;
            }
            default:
                throw std::runtime_error("unknown GGUF metadata value type");
        }
    }

    static uint64_t align_up(uint64_t v, uint64_t a) {
        if (a == 0) a = 32;
        return ((v + a - 1) / a) * a;
    }

    void scan_shard(size_t idx) {
        Shard& shard = shards_[idx];

        std::ifstream f(shard.path, std::ios::binary);
        if (!f) {
            throw std::runtime_error("cannot open shard: " + shard.path.string());
        }

        char magic[4] = {};
        f.read(magic, 4);
        if (std::memcmp(magic, "GGUF", 4) != 0) {
            throw std::runtime_error("not a GGUF file: " + shard.path.string());
        }

        uint32_t version = read_u32(f);
        if (version < 2 || version > 3) {
            throw std::runtime_error("unsupported GGUF version");
        }

        uint64_t n_tensors = read_u64(f);
        uint64_t n_kv       = read_u64(f);

        uint32_t alignment = 32;

        // Only capture metadata from first shard (all shards have identical metadata)
        ModelMetadata* meta_ptr = (idx == 0) ? &metadata_ : nullptr;
        if (meta_ptr) {
            meta_ptr->has_metadata = false;  // reset before parsing
        }

        for (uint64_t i = 0; i < n_kv; ++i) {
            std::string key = read_str(f);
            uint32_t type = read_u32(f);
            skip_or_capture_value(f, type, key, alignment, meta_ptr);
        }

        if (alignment == 0) alignment = 32;
        if (meta_ptr && meta_ptr->layer_count > 0) {
            meta_ptr->has_metadata = true;
        }

        std::vector<TensorLocation> tmp;
        tmp.reserve(n_tensors);

        for (uint64_t t = 0; t < n_tensors; ++t) {
            TensorLocation loc;
            loc.shard_index = static_cast<uint32_t>(idx);
            loc.name        = read_str(f);

            uint32_t n_dims = read_u32(f);
            loc.dims.resize(n_dims);
            for (uint32_t d = 0; d < n_dims; ++d) {
                loc.dims[d] = read_u64(f);
            }

            loc.ggml_type   = read_u32(f);
            loc.data_offset = read_u64(f);

            tmp.push_back(std::move(loc));
        }

        auto pos = f.tellg();
        if (!f || pos < 0) {
            throw std::runtime_error("failed to get header end position");
        }

        uint64_t header_end = static_cast<uint64_t>(pos);
        uint64_t data_start  = align_up(header_end, alignment);

        shard.data_start   = data_start;
        shard.tensor_count = n_tensors;

        for (auto& loc : tmp) {
            loc.file_offset = data_start + loc.data_offset;
            tensors_[loc.name] = loc;
        }
    }
};

} // namespace RawrXD
