#include "streaming_gguf_loader.h"
#include "model_loader/GGUFConstants.hpp"
#include "utils/Diagnostics.hpp"
#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <iostream>
#include <limits>
#include <regex>
#include <fstream>

// Compiled at global scope; bring the RawrXD interface vocabulary in explicitly
// (the header no longer re-declares these at file scope, because it is also
// included from inside namespace RawrXD by the engine executor).
using RawrXD::GGMLType;
using RawrXD::GGUFHeader;
using RawrXD::GGUFMetadata;
using RawrXD::IGGUFLoader;
using RawrXD::TensorInfo;

StreamingGGUFLoader::StreamingGGUFLoader()
    : is_open_(false), current_file_(nullptr), current_zone_memory_(0), max_zone_memory_mb_(GGUFConstants::DEFAULT_ZONE_MEMORY_MB) {
    std::memset(&header_, 0, sizeof(GGUFHeader));
}

StreamingGGUFLoader::~StreamingGGUFLoader() {
    Close();
}

bool StreamingGGUFLoader::Open(const std::string& filepath) {
    filepath_ = filepath;
    
    // Discover all GGUF shard files matching the pattern:
    // {basename}-{NNNNN}-of-{MMMMM}.gguf
    auto shard_paths = discover_shard_files(filepath_);
    if (shard_paths.empty()) {
        std::cerr << "❌ No GGUF shard files found: " << filepath << std::endl;
        return false;
    }
    
    // Open all shard files
    for (size_t i = 0; i < shard_paths.size(); ++i) {
        auto f = std::make_unique<std::ifstream>(shard_paths[i], std::ios::binary);
        if (!f->is_open()) {
            std::cerr << "❌ Failed to open shard: " << shard_paths[i] << std::endl;
            Close();
            return false;
        }
        shard_files_[static_cast<uint32_t>(i)] = std::move(f);
    }
    
    is_open_ = true;

    // Independently validate every shard header (uint64 tensor/kv counts).
    for (const auto& kv : shard_files_) {
        if (!ParseHeaderFromShard(kv.first)) {
            std::cerr << "❌ Shard header validation failed for shard "
                      << kv.first << std::endl;
            Close();
            return false;
        }
    }
    
    // Model-level metadata (tokenizer / arch) is on shard 0.
    if (!ParseMetadataFromShard(0)) {
        Close();
        return false;
    }
    header_ = shard_headers_[0];
    metadata_ = shard_metadata_[0];
    
    // Build tensor index from ALL shards (each uses own header/dir/dataStart).
    if (!BuildTensorIndexFromAllShards()) {
        Close();
        return false;
    }
    
    // Assign tensors to zones
    AssignTensorsToZones();
    
    std::cout << "✅ GGUF Model opened in streaming mode" << std::endl;
    std::cout << "   File: " << filepath << std::endl;
    std::cout << "   Shards: " << shard_files_.size() << std::endl;
    std::cout << "   Tensors: " << tensor_index_.size() << std::endl;
    std::cout << "   Zones: " << zones_.size() << std::endl;
    std::cout << "   Memory (header+index): ~" << ((tensor_index_.size() * 100) / (1024*1024)) << " MB" << std::endl;
    std::cerr << "MULTISHARD_SHARDS_INDEXED=" << shard_files_.size() << "/"
              << shard_files_.size() << "\n"
              << "MULTISHARD_TENSORS_INDEXED=" << tensor_index_.size() << "\n"
              << "MULTISHARD_DUPLICATES=0\n";
    
    return true;
}

// ============================================================================
// IGGUFLoader INTERFACE IMPLEMENTATIONS (wrappers around shard-specific methods)
// ============================================================================

bool StreamingGGUFLoader::ParseHeader() {
    return ParseHeaderFromShard(0);
}

GGUFHeader StreamingGGUFLoader::GetHeader() const {
    return header_;
}

bool StreamingGGUFLoader::ParseMetadata() {
    return ParseMetadataFromShard(0);
}

GGUFMetadata StreamingGGUFLoader::GetMetadata() const {
    return metadata_;
}

bool StreamingGGUFLoader::BuildTensorIndex() {
    return BuildTensorIndexFromAllShards();
}

std::string StreamingGGUFLoader::GetTensorZone(const std::string& tensor_name) const {
    return GetZoneForTensor(tensor_name);
}

// ============================================================================
// MULTI-SHARD SUPPORT
// ============================================================================

// Discover all GGUF shard files matching the pattern:
// {basename}-{NNNNN}-of-{MMMMM}.gguf
std::vector<std::string> StreamingGGUFLoader::discover_shard_files(const std::string& filepath) {
    std::vector<std::string> result;
    
    // Check if the filepath itself is a shard file (ends with -NNNNN-of-MMMMM.gguf)
    static const std::regex shard_pattern(R"((.+)-(\d{5})-of-(\d{5})\.gguf$)");
    std::smatch match;
    
    std::string base_path = filepath;
    int target_shard = -1;
    int total_shards = -1;
    
    if (std::regex_match(filepath, match, shard_pattern)) {
        base_path = match[1].str();  // Everything before -NNNNN-of-MMMMM.gguf
        target_shard = std::stoi(match[2].str());
        total_shards = std::stoi(match[3].str());
    } else {
        // Not a shard pattern - check if it's a plain .gguf file
        if (filepath.size() >= 5 && filepath.substr(filepath.size() - 5) == ".gguf") {
            result.push_back(filepath);
            return result;
        }
        // Otherwise, try appending -00001-of-00001.gguf
        base_path = filepath + "-00001-of-00001";
    }
    
    if (target_shard > 0 && total_shards > 0) {
        // Build all shard paths from the pattern
        for (int i = 1; i <= total_shards; ++i) {
            char shard_name[256];
            std::snprintf(shard_name, sizeof(shard_name), "%s-%05d-of-%05d.gguf",
                         base_path.c_str(), i, total_shards);
            result.push_back(shard_name);
        }
    } else {
        // Single shard: try -00001-of-00001.gguf
        char shard_name[256];
        std::snprintf(shard_name, sizeof(shard_name), "%s-00001-of-00001.gguf", base_path.c_str());
        result.push_back(shard_name);
    }
    
    // Verify all files exist
    std::vector<std::string> valid_shards;
    for (const auto& p : result) {
        std::ifstream test(p, std::ios::binary);
        if (test.is_open()) {
            valid_shards.push_back(p);
        } else {
            std::cerr << "[GGUF] Shard not found: " << p << std::endl;
        }
    }
    
    return valid_shards;
}

bool StreamingGGUFLoader::Close() {
    // Close all shard files
    for (auto& [shard_id, f] : shard_files_) {
        if (f && f->is_open()) {
            f->close();
        }
    }
    shard_files_.clear();
    shard_data_starts_.clear();
    current_file_ = nullptr;
    is_open_ = false;
    tensor_index_.clear();
    zones_.clear();
    active_zones_.clear();
    current_zone_ = "";
    current_zone_memory_ = 0;
    data_start_ = 0;
    return true;
}

bool StreamingGGUFLoader::ParseHeaderFromShard(uint32_t shard_id) {
    auto it = shard_files_.find(shard_id);
    if (it == shard_files_.end() || !it->second->is_open()) return false;
    
    auto& f = *it->second;
    f.seekg(0);
    
    // Read magic
    RawrXD::GGUFHeader hdr;
    if (!ReadValueFromStream(f, hdr.magic)) return false;
    if (hdr.magic != GGUFConstants::GGUF_MAGIC) {
        std::cerr << "❌ Invalid GGUF magic in shard " << shard_id << ": 0x" << std::hex << hdr.magic << std::endl;
        Diagnostics::error("Invalid GGUF magic number", "StreamingGGUFLoader");
        return false;
    }
    
    // Read version
    if (!ReadValueFromStream(f, hdr.version)) return false;
    if (hdr.version != GGUFConstants::GGUF_VERSION) {
        std::cerr << "❌ Unsupported GGUF version in shard " << shard_id << ": " << hdr.version << std::endl;
        Diagnostics::error("Unsupported GGUF version", "StreamingGGUFLoader");
        return false;
    }
    
    // Read tensor count
    if (!ReadValueFromStream(f, hdr.tensor_count)) return false;
    if (hdr.tensor_count > 10'000'000ULL) {
        std::cerr << "[GGUF] tensor count exceeds safety limit in shard " << shard_id << ": "
                  << hdr.tensor_count << std::endl;
        return false;
    }
    
    // Read metadata KV count
    if (!ReadValueFromStream(f, hdr.metadata_kv_count)) return false;
    if (hdr.metadata_kv_count > 1'000'000ULL) {
        std::cerr << "[GGUF] metadata count exceeds safety limit in shard " << shard_id << ": "
                  << hdr.metadata_kv_count << std::endl;
        return false;
    }
    
    // Calculate metadata offset
    hdr.metadata_offset = static_cast<uint64_t>(f.tellg());
    
    shard_headers_[shard_id] = hdr;
    
    return true;
}

bool StreamingGGUFLoader::ParseMetadataFromShard(uint32_t shard_id) {
    auto it = shard_files_.find(shard_id);
    if (it == shard_files_.end() || !it->second->is_open()) return false;
    
    auto& f = *it->second;
    if (shard_headers_[shard_id].metadata_kv_count == 0) {
        return false;
    }
    
    for (uint64_t i = 0; i < shard_headers_[shard_id].metadata_kv_count; ++i) {
        std::streampos key_start = f.tellg();
        std::string key, value;
        
        std::cerr << "[DEBUG] Key[" << i << "] start_pos=" << key_start << std::endl;
        
        if (!ReadStringFromStream(f, key)) {
            std::cerr << "❌ Failed to read metadata key at index " << i << " pos=" << key_start << std::endl;
            return false;
        }
        
        std::cerr << "[DEBUG] Key[" << i << "]=" << key << " key_start=" << key_start
                  << " key_end=" << f.tellg() << std::endl;
        
        if (i < 5 || i == shard_headers_[shard_id].metadata_kv_count - 1 || i < 10) {
            std::cerr << "[DEBUG] Metadata key[" << i << "]=" << key << std::endl;
        }
        
        uint32_t value_type;
        if (!ReadValueFromStream(f, value_type)) {
            std::cerr << "❌ Failed to read metadata value type for key: " << key << std::endl;
            return false;
        }
        
        std::cerr << "[DEBUG] Key[" << i << "] value_type=" << value_type << " pos=" << f.tellg() << std::endl;
        
        if (value_type == GGUFConstants::GGUF_VALUE_TYPE_STRING) {
            std::streampos val_start = f.tellg();
            if (!ReadStringFromStream(f, value)) {
                std::cerr << "❌ Failed to read metadata string value for key: " << key << std::endl;
                return false;
            }
            std::cerr << "[DEBUG] Key[" << i << "] value=" << value.substr(0, 50) 
                      << " val_start=" << val_start << " val_end=" << f.tellg() << std::endl;
            shard_metadata_[shard_id].kv_pairs[key] = value;
            
            if (key == GGUFConstants::META_GENERAL_ARCHITECTURE) {
                if (value == "llama") shard_metadata_[shard_id].architecture_type = 1;
                else if (value == "qwen3") shard_metadata_[shard_id].architecture_type = 2;
            } else if (key == GGUFConstants::META_LLAMA_BLOCK_COUNT) {
                shard_metadata_[shard_id].layer_count = std::stoul(value);
            } else if (key == GGUFConstants::META_LLAMA_CONTEXT_LENGTH) {
                shard_metadata_[shard_id].context_length = std::stoul(value);
            } else if (key == GGUFConstants::META_LLAMA_EMBEDDING_LENGTH) {
                shard_metadata_[shard_id].embedding_dim = std::stoul(value);
            } else if (key == GGUFConstants::META_LLAMA_VOCAB_SIZE) {
                shard_metadata_[shard_id].vocab_size = std::stoul(value);
            }
        } else if (value_type == GGUFConstants::GGUF_VALUE_TYPE_UINT32) {
            uint32_t v; if (!ReadValueFromStream(f, v)) return false;
            shard_metadata_[shard_id].kv_pairs[key] = std::to_string(v);
            if (key == "llama.block_count" || key == "qwen3.block_count") shard_metadata_[shard_id].layer_count = v;
            if (key == "llama.context_length" || key == "qwen3.context_length") shard_metadata_[shard_id].context_length = v;
            if (key == "llama.embedding_length" || key == "qwen3.embedding_length") shard_metadata_[shard_id].embedding_dim = v;
            if (key == "llama.vocab_size" || key == "qwen3.vocab_size") shard_metadata_[shard_id].vocab_size = v;
            if (key == "llama.head_count" || key == "qwen3.head_count") shard_metadata_[shard_id].head_count = v;
            if (key == "llama.head_count_kv" || key == "qwen3.head_count_kv") shard_metadata_[shard_id].head_count_kv = v;
            if (key == "llama.feed_forward_length" || key == "qwen3.feed_forward_length") shard_metadata_[shard_id].feed_forward_length = v;
        } else if (value_type == GGUFConstants::GGUF_VALUE_TYPE_INT32) {
            int32_t v; if (!ReadValueFromStream(f, v)) return false;
            shard_metadata_[shard_id].kv_pairs[key] = std::to_string(v);
        } else if (value_type == GGUFConstants::GGUF_VALUE_TYPE_FLOAT32) {
            float v; if (!ReadValueFromStream(f, v)) return false;
            shard_metadata_[shard_id].kv_pairs[key] = std::to_string(v);
        } else if (value_type == GGUFConstants::GGUF_VALUE_TYPE_ARRAY) {
            uint32_t elem_type;
            uint64_t count;
            if (!ReadValueFromStream(f, elem_type) || !ReadValueFromStream(f, count) || count > 10'000'000ULL) return false;
            if (key == "tokenizer.ggml.tokens" && elem_type == GGUFConstants::GGUF_VALUE_TYPE_STRING) {
                shard_metadata_[shard_id].tokens.clear();
                shard_metadata_[shard_id].tokens.reserve(static_cast<size_t>(count));
                for (uint64_t j = 0; j < count; ++j) {
                    std::string token;
                    if (!ReadStringFromStream(f, token)) return false;
                    shard_metadata_[shard_id].tokens.push_back(std::move(token));
                }
            } else if (key == "tokenizer.ggml.scores" && elem_type == GGUFConstants::GGUF_VALUE_TYPE_FLOAT32) {
                shard_metadata_[shard_id].token_scores.clear();
                shard_metadata_[shard_id].token_scores.reserve(static_cast<size_t>(count));
                for (uint64_t j = 0; j < count; ++j) {
                    float score; if (!ReadValueFromStream(f, score)) return false;
                    shard_metadata_[shard_id].token_scores.push_back(score);
                }
            } else {
                for (uint64_t j = 0; j < count; ++j) {
                    if (!SkipMetadataValueFromStream(f, elem_type)) return false;
                }
            }
        } else if (!SkipMetadataValueFromStream(f, value_type)) {
            std::cerr << "[GGUF] unsupported metadata value type " << value_type
                      << " for key " << key << std::endl;
            return false;
        }
    }
    
    return true;
}

bool StreamingGGUFLoader::BuildTensorIndexFromAllShards() {
    tensor_index_.clear();
    shard_data_starts_.clear();
    
    for (const auto& [shard_id, f] : shard_files_) {
        (void)f;
        if (!BuildTensorIndexFromShard(shard_id)) {
            return false;
        }
    }
    
    return true;
}

bool StreamingGGUFLoader::BuildTensorIndexFromShard(uint32_t shard_id) {
    // INVARIANT: AbsoluteTensorOffset = ShardDataStart + ShardLocalTensorOffset
    // Never mix this shard's stream with another shard's header/kv/tensor counts.
    auto it = shard_files_.find(shard_id);
    if (it == shard_files_.end() || !it->second->is_open()) return false;
    auto& f = *it->second;

    // Use this shard's own validated header (uint64 tensor_count + kv_count).
    if (!ParseHeaderFromShard(shard_id)) return false;
    const auto hit = shard_headers_.find(shard_id);
    if (hit == shard_headers_.end()) return false;
    const GGUFHeader& hdr = hit->second;
    const uint64_t shard_tensor_count = hdr.tensor_count;
    const uint64_t shard_metadata_kv_count = hdr.metadata_kv_count;

    // Stream is at metadata start after ParseHeaderFromShard.
    // Skip THIS shard's metadata only (capture alignment if present).
    uint64_t alignment = 32;
    for (uint64_t i = 0; i < shard_metadata_kv_count; ++i) {
        std::string key;
        if (!ReadStringFromStream(f, key)) {
            std::cerr << "[GGUF] shard " << shard_id
                      << " metadata key read failed at i=" << i << std::endl;
            return false;
        }
        uint32_t value_type = 0;
        if (!ReadValueFromStream(f, value_type)) return false;

        if (value_type == GGUFConstants::GGUF_VALUE_TYPE_UINT32 &&
            key == "general.alignment") {
            uint32_t v = 0;
            if (!ReadValueFromStream(f, v)) return false;
            if (v != 0 && (v & (v - 1)) == 0) alignment = v;
            shard_metadata_[shard_id].kv_pairs[key] = std::to_string(v);
            continue;
        }
        if (value_type == GGUFConstants::GGUF_VALUE_TYPE_UINT64 &&
            key == "general.alignment") {
            uint64_t v = 0;
            if (!ReadValueFromStream(f, v)) return false;
            if (v != 0 && (v & (v - 1)) == 0) alignment = v;
            shard_metadata_[shard_id].kv_pairs[key] = std::to_string(v);
            continue;
        }
        if (value_type == GGUFConstants::GGUF_VALUE_TYPE_ARRAY) {
            uint32_t elem_type = 0;
            uint64_t count = 0;
            if (!ReadValueFromStream(f, elem_type) ||
                !ReadValueFromStream(f, count) || count > 10'000'000ULL) {
                return false;
            }
            for (uint64_t j = 0; j < count; ++j) {
                if (!SkipMetadataValueFromStream(f, elem_type)) return false;
            }
        } else if (!SkipMetadataValueFromStream(f, value_type)) {
            return false;
        }
    }

    // Parse THIS shard's tensor directory using THIS shard's tensor_count.
    std::vector<TensorRef> local;
    local.reserve(static_cast<size_t>(shard_tensor_count));
    for (uint64_t i = 0; i < shard_tensor_count; ++i) {
        TensorRef ref;
        ref.shard_id = shard_id;
        if (!ReadStringFromStream(f, ref.name)) {
            std::cerr << "❌ Failed to read tensor name at index " << i
                      << " in shard " << shard_id << std::endl;
            return false;
        }
        uint32_t n_dims = 0;
        if (!ReadValueFromStream(f, n_dims)) return false;
        if (n_dims == 0 || n_dims > 16) {
            std::cerr << "[GGUF] invalid tensor rank " << n_dims
                      << " for tensor " << ref.name << " in shard " << shard_id
                      << std::endl;
            return false;
        }
        ref.shape.resize(n_dims);
        for (uint32_t d = 0; d < n_dims; ++d) {
            if (!ReadValueFromStream(f, ref.shape[d])) return false;
        }
        uint32_t type_val = 0;
        if (!ReadValueFromStream(f, type_val)) return false;
        ref.type = static_cast<GGMLType>(type_val);
        // Local offset relative to this shard's data section (not absolute yet).
        if (!ReadValueFromStream(f, ref.offset)) return false;
        ref.size = CalculateTensorSize(ref.shape, ref.type);
        ref.zone_name = "";
        local.push_back(std::move(ref));
    }

    const std::streampos info_end_pos = f.tellg();
    if (info_end_pos < 0) return false;
    const uint64_t info_end = static_cast<uint64_t>(info_end_pos);
    if (alignment > 1 &&
        info_end > std::numeric_limits<uint64_t>::max() - (alignment - 1)) {
        return false;
    }
    const uint64_t shard_data_start =
        (info_end + alignment - 1) & ~(alignment - 1);
    shard_data_starts_[shard_id] = shard_data_start;

    f.seekg(0, std::ios::end);
    const uint64_t shard_file_size = static_cast<uint64_t>(f.tellg());

    for (auto& ref : local) {
        if (tensor_index_.find(ref.name) != tensor_index_.end()) {
            std::cerr << "[GGUF] DUPLICATE tensor name across shards: " << ref.name
                      << " (shard " << shard_id << " vs prior)" << std::endl;
            return false;
        }
        if (ref.offset > shard_file_size - shard_data_start ||
            ref.size > shard_file_size - shard_data_start - ref.offset) {
            std::cerr << "[GGUF] tensor exceeds file in shard " << shard_id
                      << ": " << ref.name << " local_off=" << ref.offset
                      << " size=" << ref.size
                      << " data_start=" << shard_data_start
                      << " file_size=" << shard_file_size << std::endl;
            return false;
        }
        // AbsoluteTensorOffset = ShardDataStart + ShardLocalTensorOffset
        ref.offset = shard_data_start + ref.offset;
        tensor_index_[ref.name] = std::move(ref);
    }

    std::cerr << "[GGUF] shard " << shard_id
              << " tensors=" << local.size()
              << " data_start=" << shard_data_start
              << " file_size=" << shard_file_size << std::endl;
    return true;
}

// ============================================================================
// ZONE ASSIGNMENT
// ============================================================================

std::string StreamingGGUFLoader::GetZoneForTensor(const std::string& tensor_name) const {
    auto it = tensor_index_.find(tensor_name);
    if (it != tensor_index_.end()) {
        return it->second.zone_name;
    }
    return "";
}

void StreamingGGUFLoader::AssignTensorsToZones() {
    std::cerr << "[ZONE_ASSIGN_START] tensor_index_size=" << tensor_index_.size() << '\n';
    
    for (auto& [tensor_name, tensor_ref] : tensor_index_) {
        std::string zone;
        
        if (tensor_name.find("token_embd") != std::string::npos ||
            tensor_name.find("embedding") != std::string::npos) {
            zone = "embedding";
        }
        else if (tensor_name.find("output.weight") != std::string::npos ||
                 tensor_name.find("lm_head") != std::string::npos ||
                 tensor_name.find("output_norm") != std::string::npos) {
            zone = "output_head";
        }
        else if (tensor_name.find("blk.") != std::string::npos) {
            int layer = ExtractLayerNumber(tensor_name);
            int zone_num = layer / 8;
            zone = "layers_" + std::to_string(zone_num);
        }
        else {
            zone = "misc";
        }
        
        if (zones_.find(zone) == zones_.end()) {
            zones_[zone] = {zone, {}, 0, false, {}};
        }
        zones_[zone].tensors.push_back(tensor_name);
        zones_[zone].total_bytes += tensor_ref.size;
        
        tensor_ref.zone_name = zone;
        
        if (tensor_name == "blk.0.attn_norm.weight") {
            std::cerr << "[ZONE_ASSIGN_DEBUG] blk.0.attn_norm.weight zone_name set to: '" << tensor_ref.zone_name << "'\n";
        }
    }
    
    std::cout << "\n📊 Zone Assignment Summary:" << std::endl;
    for (const auto& [zone_name, zone_info] : zones_) {
        std::cout << "   " << zone_name << ": " << zone_info.tensors.size() 
                  << " tensors, " << (zone_info.total_bytes / (1024*1024)) << " MB" << std::endl;
    }
    std::cout << std::endl;
}

int32_t StreamingGGUFLoader::ExtractLayerNumber(const std::string& tensor_name) const {
    size_t pos = tensor_name.find("blk.");
    if (pos == std::string::npos) return 0;
    
    pos += 4;
    size_t end = tensor_name.find_first_not_of("0123456789", pos);
    if (end == std::string::npos) end = tensor_name.length();
    
    try {
        return std::stoi(tensor_name.substr(pos, end - pos));
    } catch (...) {
        return 0;
    }
}

template<typename T>
bool StreamingGGUFLoader::ReadValueFromStream(std::ifstream& f, T& value) {
    f.clear();
    f.seekg(f.tellg());
    f.read(reinterpret_cast<char*>(&value), sizeof(T));
    std::cerr << "[DEBUG] ReadValueFromStream: type_size=" << sizeof(T) 
              << " pos_before=" << (f.tellg() - static_cast<std::streamoff>(sizeof(T)))
              << " pos_after=" << f.tellg() << " good=" << f.good() << std::endl;
    return f.good();
}

bool StreamingGGUFLoader::ReadStringFromStream(std::ifstream& f, std::string& value) {
    uint64_t len;
    if (!ReadValueFromStream(f, len)) return false;

    std::cerr << "[DEBUG] ReadStringFromStream: len=" << len << " pos_before=" << f.tellg() << std::endl;

    // GGUF strings are metadata, never tensor payloads.  Bound them before
    // resize() so a corrupt length cannot request an arbitrary allocation.
    constexpr uint64_t kMaxMetadataString = 64ULL * 1024ULL * 1024ULL;
    if (len > kMaxMetadataString ||
        len > static_cast<uint64_t>(std::numeric_limits<size_t>::max())) {
        std::cerr << "[GGUF] metadata string exceeds safety limit: " << len
                  << " bytes" << std::endl;
        return false;
    }

    const std::streampos payload = f.tellg();
    if (payload < 0) return false;
    f.seekg(0, std::ios::end);
    const std::streampos end = f.tellg();
    f.seekg(payload, std::ios::beg);
    if (end < payload || static_cast<uint64_t>(end - payload) < len) {
        std::cerr << "[GGUF] metadata string extends beyond file" << std::endl;
        return false;
    }

    value.resize(static_cast<size_t>(len));
    if (len != 0) {
        f.read(value.data(), static_cast<std::streamsize>(len));
    }
    std::cerr << "[DEBUG] ReadStringFromStream: read " << len << " bytes, pos_after=" << f.tellg() << ", good=" << f.good() << ", eof=" << f.eof() << std::endl;
    return f.good() || f.eof();
}

bool StreamingGGUFLoader::SkipMetadataValueFromStream(std::ifstream& f, uint32_t value_type) {
    switch (value_type) {
        case GGUFConstants::GGUF_VALUE_TYPE_UINT8:
        case GGUFConstants::GGUF_VALUE_TYPE_INT8:
        case GGUFConstants::GGUF_VALUE_TYPE_BOOL: {
            uint8_t v{}; return ReadValueFromStream(f, v);
        }
        case GGUFConstants::GGUF_VALUE_TYPE_UINT16:
        case GGUFConstants::GGUF_VALUE_TYPE_INT16: {
            uint16_t v{}; return ReadValueFromStream(f, v);
        }
        case GGUFConstants::GGUF_VALUE_TYPE_UINT32:
        case GGUFConstants::GGUF_VALUE_TYPE_INT32:
        case GGUFConstants::GGUF_VALUE_TYPE_FLOAT32: {
            uint32_t v{}; return ReadValueFromStream(f, v);
        }
        case GGUFConstants::GGUF_VALUE_TYPE_UINT64:
        case GGUFConstants::GGUF_VALUE_TYPE_INT64:
        case GGUFConstants::GGUF_VALUE_TYPE_FLOAT64: {
            uint64_t v{}; return ReadValueFromStream(f, v);
        }
        case GGUFConstants::GGUF_VALUE_TYPE_STRING: {
            std::string ignored; return ReadStringFromStream(f, ignored);
        }
        case GGUFConstants::GGUF_VALUE_TYPE_ARRAY: {
            uint32_t elem_type{}; uint64_t count{};
            if (!ReadValueFromStream(f, elem_type) || !ReadValueFromStream(f, count) || count > 10'000'000ULL) return false;
            for (uint64_t i = 0; i < count; ++i) {
                if (!SkipMetadataValueFromStream(f, elem_type)) return false;
            }
            return true;
        }
        default:
            return false;
    }
}

// ============================================================================
// ZONE-BASED LOADING
// ============================================================================

bool StreamingGGUFLoader::LoadZone(const std::string& zone_name, uint64_t max_memory_mb) {
    auto zone_it = zones_.find(zone_name);
    if (zone_it == zones_.end()) {
        std::cerr << "❌ Zone not found: " << zone_name << std::endl;
        return false;
    }
    
    TensorZoneInfo& zone = zone_it->second;
    
    // Already loaded?
    if (zone.is_loaded) {
        std::cout << "✓ Zone already loaded: " << zone_name << std::endl;
        return true;
    }
    
    // Unload previous zone if needed
    if (!current_zone_.empty() && current_zone_ != zone_name) {
        UnloadZone(current_zone_);
    }
    
    // Check if any shard file is open
    if (shard_files_.empty()) {
        std::cerr << "❌ No shard files open for streaming" << std::endl;
        return false;
    }

    // Never reserve an entire multi-gigabyte zone implicitly.
    const uint64_t maxBytes =
        max_memory_mb > (std::numeric_limits<uint64_t>::max() / (1024ULL * 1024ULL))
            ? std::numeric_limits<uint64_t>::max()
            : max_memory_mb * 1024ULL * 1024ULL;
    if (zone.total_bytes > maxBytes) {
        std::cerr << "[GGUF] zone " << zone_name << " requires "
                  << (zone.total_bytes / (1024.0 * 1024.0))
                  << " MiB, above the " << max_memory_mb
                  << " MiB streaming budget; refusing allocation" << std::endl;
        return false;
    }
    if (zone.total_bytes > static_cast<uint64_t>(std::numeric_limits<size_t>::max())) {
        std::cerr << "[GGUF] zone size exceeds addressable memory" << std::endl;
        return false;
    }
    
    // Stream from disk
    zone.data.clear();
    zone.data.reserve(zone.total_bytes);
    
    uint64_t total_loaded = 0;
    
    std::cout << "📥 Loading zone: " << zone_name << " (" << (zone.total_bytes / (1024.0*1024.0)) << " MB)..." << std::endl;
    
    for (const auto& tensor_name : zone.tensors) {
        // Get tensor metadata from index
        auto tensor_it = tensor_index_.find(tensor_name);
        if (tensor_it == tensor_index_.end()) {
            std::cerr << "❌ Tensor not in index: " << tensor_name << std::endl;
            return false;
        }
        
        const TensorRef& ref = tensor_it->second;
        
        // Switch to the correct shard file
        current_file_ = shard_files_[ref.shard_id].get();
        
        // Seek to tensor offset in the correct shard
        current_file_->seekg(static_cast<std::streamoff>(ref.offset), std::ios::beg);
        
        // Read from disk into zone buffer
        size_t old_size = zone.data.size();
        if (ref.size > static_cast<uint64_t>(std::numeric_limits<size_t>::max()) - old_size ||
            ref.size > static_cast<uint64_t>(std::numeric_limits<std::streamsize>::max())) {
            std::cerr << "[GGUF] tensor allocation/read size is not representable: "
                      << tensor_name << std::endl;
            zone.data.resize(old_size);
            return false;
        }
        zone.data.resize(old_size + static_cast<size_t>(ref.size));
        
        current_file_->read(reinterpret_cast<char*>(zone.data.data() + old_size), ref.size);
        
        if (!current_file_->good()) {
            std::cerr << "❌ Failed to read tensor: " << tensor_name << std::endl;
            zone.data.resize(old_size);
            return false;
        }
        
        total_loaded += ref.size;
    }
    
    zone.is_loaded = true;
    current_zone_ = zone_name;
    current_zone_memory_ = total_loaded;
    
    std::cout << "✅ Zone loaded: " << zone_name << " (" << (total_loaded / (1024.0*1024.0)) << " MB)" << std::endl;
    
    return true;
}

bool StreamingGGUFLoader::UnloadZone(const std::string& zone_name) {
    auto zone_it = zones_.find(zone_name);
    if (zone_it == zones_.end()) {
        return false;
    }
    
    TensorZoneInfo& zone = zone_it->second;
    
    if (zone.is_loaded) {
        zone.data.clear();
        zone.data.shrink_to_fit();
        zone.is_loaded = false;
        std::cout << "📤 Zone unloaded: " << zone_name << std::endl;
    }
    
    return true;
}

bool StreamingGGUFLoader::GetTensorData(const std::string& tensor_name, std::vector<uint8_t>& data) {
    // Find which zone this tensor belongs to
    std::string zone_name = GetTensorZone(tensor_name);
    if (zone_name.empty()) {
        std::cerr << "❌ Tensor not found: " << tensor_name << std::endl;
        return false;
    }
    
    // Large zones are intentionally not materialized. Read a single tensor
    // directly when it fits the same bounded budget; callers that need only a
    // row should use LoadTensorSlice instead.
    if (!zones_[zone_name].is_loaded) {
        const auto& zone = zones_[zone_name];
        const uint64_t budgetBytes = max_zone_memory_mb_ * 1024ULL * 1024ULL;
        auto tensor_it = tensor_index_.find(tensor_name);
        if (tensor_it != tensor_index_.end() && zone.total_bytes > budgetBytes &&
            tensor_it->second.size <= budgetBytes) {
            return LoadTensorSlice(tensor_name, 0, tensor_it->second.size, data);
        }
        if (!LoadZone(zone_name)) {
            return false;
        }
    }
    
    // Find tensor in zone
    TensorZoneInfo& zone = zones_[zone_name];
    
    auto tensor_it = tensor_index_.find(tensor_name);
    if (tensor_it == tensor_index_.end()) {
        return false;
    }
    
    const TensorRef& ref = tensor_it->second;
    
    // Find offset within zone data
    uint64_t offset_in_zone = 0;
    for (const auto& other_name : zone.tensors) {
        if (other_name == tensor_name) {
            break;
        }
        offset_in_zone += tensor_index_[other_name].size;
    }
    
    // Copy tensor data
    data.resize(ref.size);
    std::memcpy(data.data(), zone.data.data() + offset_in_zone, ref.size);
    
    return true;
}

bool StreamingGGUFLoader::LoadTensorSlice(const std::string& tensor_name,
                                           uint64_t byte_offset,
                                           uint64_t byte_count,
                                           std::vector<uint8_t>& data) {
    auto it = tensor_index_.find(tensor_name);
    if (it == tensor_index_.end()) return false;
    const TensorRef& ref = it->second;
    if (byte_offset > ref.size || byte_count > ref.size - byte_offset) {
        std::cerr << "[GGUF] tensor slice outside bounds: " << tensor_name << std::endl;
        return false;
    }
    const uint64_t budgetBytes = max_zone_memory_mb_ * 1024ULL * 1024ULL;
    if (byte_count > budgetBytes ||
        byte_count > static_cast<uint64_t>(std::numeric_limits<size_t>::max()) ||
        byte_count > static_cast<uint64_t>(std::numeric_limits<std::streamsize>::max())) {
        std::cerr << "[GGUF] tensor slice exceeds bounded residency budget: " << tensor_name << std::endl;
        return false;
    }
    if (ref.offset > std::numeric_limits<uint64_t>::max() - byte_offset ||
        ref.offset + byte_offset > std::numeric_limits<uint64_t>::max() - byte_count) {
        return false;
    }
    const uint64_t absolute = ref.offset + byte_offset;
    
    // Switch to the correct shard file
    current_file_ = shard_files_[ref.shard_id].get();
    current_file_->clear();
    current_file_->seekg(static_cast<std::streamoff>(absolute), std::ios::beg);
    if (!current_file_->good()) { data.clear(); return false; }
    if (byte_count != 0) {
        current_file_->read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(byte_count));
    }
    if (!current_file_->good() && !current_file_->eof()) { data.clear(); return false; }
    return byte_count == 0 || current_file_->gcount() == static_cast<std::streamsize>(byte_count);
}

TensorZoneInfo StreamingGGUFLoader::GetZoneInfo(const std::string& zone_name) const {
    auto it = zones_.find(zone_name);
    if (it != zones_.end()) {
        return it->second;
    }
    return {};
}

uint64_t StreamingGGUFLoader::GetTotalFileSize() const {
    uint64_t total = 0;
    for (const auto& [shard_id, f] : shard_files_) {
        if (f && f->is_open()) {
            std::streampos current = f->tellg();
            f->seekg(0, std::ios::end);
            total += static_cast<uint64_t>(f->tellg());
            f->seekg(current);
        }
    }
    return total;
}

uint64_t StreamingGGUFLoader::GetCurrentMemoryUsage() const {
    uint64_t usage = 0;
    
    // Header + metadata + index
    usage += 100 * 1024 * 1024;  // ~100 MB for overhead
    
    // Active zones
    for (const auto& [zone_name, zone_info] : zones_) {
        if (zone_info.is_loaded) {
            usage += zone_info.data.size();
        }
    }
    
    return usage;
}

std::vector<std::string> StreamingGGUFLoader::GetLoadedZones() const {
    std::vector<std::string> result;
    for (const auto& [zone_name, zone_info] : zones_) {
        if (zone_info.is_loaded) {
            result.push_back(zone_name);
        }
    }
    return result;
}

std::vector<std::string> StreamingGGUFLoader::GetAllZones() const {
    std::vector<std::string> result;
    for (const auto& [zone_name, zone_info] : zones_) {
        result.push_back(zone_name);
    }
    return result;
}

std::vector<TensorInfo> StreamingGGUFLoader::GetAllTensorInfo() const {
    std::vector<TensorInfo> result;
    for (const auto& [name, ref] : tensor_index_) {
        TensorInfo info;
        info.name = name;
        info.shape = ref.shape;
        info.type = ref.type;
        info.offset = ref.offset;
        info.size_bytes = ref.size;
        result.push_back(info);
    }
    return result;
}

std::vector<TensorInfo> StreamingGGUFLoader::GetTensorInfo() const {
    return GetAllTensorInfo();
}

const TensorInfo* StreamingGGUFLoader::GetTensorInfo(const std::string& name) const {
    auto it = tensor_index_.find(name);
    if (it != tensor_index_.end()) {
        static thread_local TensorInfo cache;
        cache = TensorInfo{};
        cache.name = it->second.name;
        cache.shape = it->second.shape;
        cache.type = it->second.type;
        cache.offset = it->second.offset;
        cache.size = it->second.size;
        cache.size_bytes = it->second.size;
        return &cache;
    }
    
    // Diagnostic: log failed lookup details
    std::cerr << "[TENSOR_LOOKUP_FAIL]"
              << " name=" << name
              << " len=" << name.size()
              << " index_size=" << tensor_index_.size()
              << " loader=" << static_cast<const void*>(this)
              << '\n';
    
    // Dump candidate keys matching "attn_norm.weight"
    for (const auto& [key, ref] : tensor_index_) {
        if (key.find("attn_norm.weight") != std::string::npos) {
            std::cerr << "[INDEX_CANDIDATE]"
                      << " name=" << key
                      << " len=" << key.size()
                      << '\n';
        }
    }
    
    // Fallback: linear scan (handles any map lookup anomaly)
    for (const auto& [key, ref] : tensor_index_) {
        if (key == name) {
            static thread_local TensorInfo cache;
            cache = TensorInfo{};
            cache.name = ref.name;
            cache.shape = ref.shape;
            cache.type = ref.type;
            cache.offset = ref.offset;
            cache.size = ref.size;
            cache.size_bytes = ref.size;
            return &cache;
        }
    }
    
    std::cerr << "[GGUF] GetTensorInfo not found: " << name << " (index size=" << tensor_index_.size() << ")\n";
    return nullptr;
}

const std::vector<std::string>& StreamingGGUFLoader::GetVocabulary() const {
    return metadata_.tokens;
}

// ============================================================================
// TYPE STRING CONVERSION
// ============================================================================

std::string StreamingGGUFLoader::GetTypeString(GGMLType type) const {
    switch (type) {
        case GGMLType::F32:   return "F32 (float32)";
        case GGMLType::F16:   return "F16 (float16)";
        case GGMLType::Q4_0:  return "Q4_0 (quantized 4-bit, zero point)";
        case GGMLType::Q4_1:  return "Q4_1 (quantized 4-bit with delta)";
        case GGMLType::Q5_0:  return "Q5_0 (quantized 5-bit)";
        case GGMLType::Q5_1:  return "Q5_1 (quantized 5-bit with delta)";
        case GGMLType::Q8_0:  return "Q8_0 (quantized 8-bit, zero point)";
        case GGMLType::Q8_1:  return "Q8_1 (quantized 8-bit)";
        case GGMLType::Q2_K:  return "Q2_K (quantized 2-bit K-quant)";
        case GGMLType::Q3_K:  return "Q3_K (quantized 3-bit K-quant)";
        case GGMLType::Q4_K:  return "Q4_K (quantized 4-bit K-quant)";
        case GGMLType::Q5_K:  return "Q5_K (quantized 5-bit K-quant)";
        case GGMLType::Q6_K:  return "Q6_K (quantized 6-bit K-quant)";
        case GGMLType::Q8_K:  return "Q8_K (quantized 8-bit K-quant)";
        case GGMLType::IQ2_XXS: return "IQ2_XXS (imatrix 2-bit)";
        case GGMLType::IQ2_XS:  return "IQ2_XS (imatrix 2-bit)";
        case GGMLType::IQ3_XXS: return "IQ3_XXS (imatrix 3-bit)";
        case GGMLType::IQ1_S:   return "IQ1_S (imatrix 1-bit)";
        case GGMLType::IQ4_NL:  return "IQ4_NL (imatrix 4-bit non-linear)";
        case GGMLType::IQ3_S:   return "IQ3_S (imatrix 3-bit)";
        case GGMLType::IQ2_S:   return "IQ2_S (imatrix 2-bit)";
        case GGMLType::IQ4_XS:  return "IQ4_XS (imatrix 4-bit)";
        case GGMLType::IQ1_M:   return "IQ1_M (imatrix 1-bit)";
        case GGMLType::I8:      return "I8 (int8)";
        case GGMLType::I16:     return "I16 (int16)";
        case GGMLType::I32:     return "I32 (int32)";
        case GGMLType::I64:     return "I64 (int64)";
        case GGMLType::F64:     return "F64 (float64)";
        default: return "Unknown";
    }
}

// ============================================================================
// PRIVATE TEMPLATE FUNCTIONS (operate on current_file_)
// ============================================================================

template<typename T>
bool StreamingGGUFLoader::ReadValue(T& value) {
    if (!current_file_) return false;
    current_file_->read(reinterpret_cast<char*>(&value), sizeof(T));
    return current_file_->good();
}

bool StreamingGGUFLoader::SkipMetadataValue(uint32_t value_type) {
    switch (value_type) {
        case GGUFConstants::GGUF_VALUE_TYPE_UINT8:
        case GGUFConstants::GGUF_VALUE_TYPE_INT8:
        case GGUFConstants::GGUF_VALUE_TYPE_BOOL: {
            uint8_t v{}; return ReadValue(v);
        }
        case GGUFConstants::GGUF_VALUE_TYPE_UINT16:
        case GGUFConstants::GGUF_VALUE_TYPE_INT16: {
            uint16_t v{}; return ReadValue(v);
        }
        case GGUFConstants::GGUF_VALUE_TYPE_UINT32:
        case GGUFConstants::GGUF_VALUE_TYPE_INT32:
        case GGUFConstants::GGUF_VALUE_TYPE_FLOAT32: {
            uint32_t v{}; return ReadValue(v);
        }
        case GGUFConstants::GGUF_VALUE_TYPE_UINT64:
        case GGUFConstants::GGUF_VALUE_TYPE_INT64:
        case GGUFConstants::GGUF_VALUE_TYPE_FLOAT64: {
            uint64_t v{}; return ReadValue(v);
        }
        case GGUFConstants::GGUF_VALUE_TYPE_STRING: {
            std::string ignored; return ReadString(ignored);
        }
        case GGUFConstants::GGUF_VALUE_TYPE_ARRAY: {
            uint32_t elem_type{}; uint64_t count{};
            if (!ReadValue(elem_type) || !ReadValue(count) || count > 10'000'000ULL) return false;
            for (uint64_t i = 0; i < count; ++i) {
                if (!SkipMetadataValueFromStream(*current_file_, elem_type)) return false;
            }
            return true;
        }
        default:
            return false;
    }
}

bool StreamingGGUFLoader::ReadString(std::string& value) {
    if (!current_file_) return false;
    uint64_t len;
    if (!ReadValue(len)) return false;

    constexpr uint64_t kMaxMetadataString = 64ULL * 1024ULL * 1024ULL;
    if (len > kMaxMetadataString ||
        len > static_cast<uint64_t>(std::numeric_limits<size_t>::max())) {
        std::cerr << "[GGUF] metadata string exceeds safety limit: " << len
                  << " bytes" << std::endl;
        return false;
    }

    const std::streampos payload = current_file_->tellg();
    if (payload < 0) return false;
    current_file_->seekg(0, std::ios::end);
    const std::streampos end = current_file_->tellg();
    current_file_->seekg(payload, std::ios::beg);
    if (end < payload || static_cast<uint64_t>(end - payload) < len) {
        std::cerr << "[GGUF] metadata string extends beyond file" << std::endl;
        return false;
    }

    value.resize(static_cast<size_t>(len));
    if (len != 0) {
        current_file_->read(value.data(), static_cast<std::streamsize>(len));
    }
    return current_file_->good() || current_file_->eof();
}

uint64_t StreamingGGUFLoader::CalculateTensorSize(const std::vector<uint64_t>& shape, GGMLType type) const {
    uint64_t num_elements = 1;
    for (uint64_t dim : shape) {
        if (dim != 0 && num_elements > std::numeric_limits<uint64_t>::max() / dim) {
            return 0;
        }
        num_elements *= dim;
    }

    auto block_aligned_size = [num_elements](uint64_t block_elements, uint64_t block_size) -> uint64_t {
        uint64_t num_blocks = (num_elements + block_elements - 1) / block_elements;
        if (num_blocks > std::numeric_limits<uint64_t>::max() / block_size) return 0;
        return num_blocks * block_size;
    };

    switch (type) {
        case GGMLType::F32:   return num_elements * 4;
        case GGMLType::F16:   return num_elements * 2;
        case GGMLType::I8:    return num_elements * 1;
        case GGMLType::I16:   return num_elements * 2;
        case GGMLType::I32:   return num_elements * 4;
        case GGMLType::I64:   return num_elements * 8;
        case GGMLType::F64:   return num_elements * 8;

        case GGMLType::Q4_0:  return block_aligned_size(32,  18);
        case GGMLType::Q4_1:  return block_aligned_size(32,  20);
        case GGMLType::Q5_0:  return block_aligned_size(32,  22);
        case GGMLType::Q5_1:  return block_aligned_size(32,  24);
        case GGMLType::Q8_0:  return block_aligned_size(32,  34);

        case GGMLType::Q2_K:  return block_aligned_size(256, 84);
        case GGMLType::Q3_K:  return block_aligned_size(256, 110);
        case GGMLType::Q4_K:  return block_aligned_size(256, 144);
        case GGMLType::Q5_K:  return block_aligned_size(256, 176);
        case GGMLType::Q6_K:  return block_aligned_size(256, 210);
        case GGMLType::Q8_K:  return block_aligned_size(256, 292);

        case GGMLType::IQ2_XXS: return block_aligned_size(256,  66);
        case GGMLType::IQ2_XS:  return block_aligned_size(256,  74);
        case GGMLType::IQ3_XXS: return block_aligned_size(256,  98);
        case GGMLType::IQ1_S:   return block_aligned_size(256,  50);
        case GGMLType::IQ4_NL:  return block_aligned_size( 32,  18);
        case GGMLType::IQ3_S:   return block_aligned_size(256, 110);
        case GGMLType::IQ2_S:   return block_aligned_size(256,  82);
        case GGMLType::IQ4_XS:  return block_aligned_size(256, 136);
        case GGMLType::IQ1_M:   return block_aligned_size(256,  56);

        default:
            std::cerr << "⚠️  StreamingGGUFLoader: No size geometry for GGMLType "
                      << static_cast<uint32_t>(type)
                      << "; assuming F32 size" << std::endl;
            return num_elements * 4;
    }
}

// ============================================================================
// INTERFACE IMPLEMENTATIONS (IGGUFLoader required methods)
// ============================================================================

bool StreamingGGUFLoader::LoadTensorZone(const std::string& tensor_name, std::vector<uint8_t>& data) {
    // Delegate to GetTensorData which handles zone loading
    return GetTensorData(tensor_name, data);
}

bool StreamingGGUFLoader::LoadTensorRange(size_t start_idx, size_t count, std::vector<uint8_t>& data) {
    // Get all tensors and load the requested range
    data.clear();
    
    std::vector<std::string> tensor_names;
    for (const auto& [name, ref] : tensor_index_) {
        tensor_names.push_back(name);
    }
    
    // Sort by offset to get consistent ordering
    std::sort(tensor_names.begin(), tensor_names.end(), [this](const std::string& a, const std::string& b) {
        return tensor_index_.at(a).offset < tensor_index_.at(b).offset;
    });
    
    if (start_idx >= tensor_names.size()) {
        return false;
    }
    
    size_t end_idx = std::min(start_idx + count, tensor_names.size());
    
    for (size_t i = start_idx; i < end_idx; ++i) {
        std::vector<uint8_t> tensor_data;
        if (!GetTensorData(tensor_names[i], tensor_data)) {
            return false;
        }
        data.insert(data.end(), tensor_data.begin(), tensor_data.end());
    }
    
    return true;
}

size_t StreamingGGUFLoader::GetTensorByteSize(const TensorInfo& tensor) const {
    return static_cast<size_t>(CalculateTensorSize(tensor.shape, tensor.type));
}

uint64_t StreamingGGUFLoader::GetFileSize() const {
    return GetTotalFileSize();
}