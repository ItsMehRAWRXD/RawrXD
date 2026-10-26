#include "streaming_gguf_loader.h"
#include "model_loader/GGUFConstants.hpp"
#include "utils/Diagnostics.hpp"
#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <iostream>
#include <limits>

// Compiled at global scope; bring the RawrXD interface vocabulary in explicitly
// (the header no longer re-declares these at file scope, because it is also
// included from inside namespace RawrXD by the engine executor).
using RawrXD::GGMLType;
using RawrXD::GGUFHeader;
using RawrXD::GGUFMetadata;
using RawrXD::IGGUFLoader;
using RawrXD::TensorInfo;

StreamingGGUFLoader::StreamingGGUFLoader()
    : is_open_(false), current_zone_memory_(0), max_zone_memory_mb_(GGUFConstants::DEFAULT_ZONE_MEMORY_MB) {
    std::memset(&header_, 0, sizeof(GGUFHeader));
}

StreamingGGUFLoader::~StreamingGGUFLoader() {
    Close();
}

bool StreamingGGUFLoader::Open(const std::string& filepath) {
    filepath_ = filepath;
    file_.open(filepath, std::ios::binary);
    if (!file_.is_open()) {
        std::cerr << "❌ Failed to open GGUF file: " << filepath << std::endl;
        return false;
    }
    
    is_open_ = true;
    
    // Parse header first
    if (!ParseHeader()) {
        Close();
        return false;
    }
    
    // Parse metadata
    if (!ParseMetadata()) {
        Close();
        return false;
    }
    
    // Build tensor index (no data loaded yet!)
    if (!BuildTensorIndex()) {
        Close();
        return false;
    }
    
    // Assign tensors to zones
    AssignTensorsToZones();
    
    std::cout << "✅ GGUF Model opened in streaming mode" << std::endl;
    std::cout << "   File: " << filepath << std::endl;
    std::cout << "   Tensors: " << tensor_index_.size() << std::endl;
    std::cout << "   Zones: " << zones_.size() << std::endl;
    std::cout << "   Memory (header+index): ~" << ((tensor_index_.size() * 100) / (1024*1024)) << " MB" << std::endl;
    
    return true;
}

bool StreamingGGUFLoader::Close() {
    if (file_.is_open()) {
        file_.close();
    }
    is_open_ = false;
    tensor_index_.clear();
    zones_.clear();
    active_zones_.clear();
    current_zone_ = "";
    return true;
}

bool StreamingGGUFLoader::ParseHeader() {
    if (!file_.is_open()) return false;
    
    file_.seekg(0);
    
    // Read magic
    if (!ReadValue(header_.magic)) return false;
    if (header_.magic != GGUFConstants::GGUF_MAGIC) {
        std::cerr << "❌ Invalid GGUF magic: 0x" << std::hex << header_.magic << std::endl;
        Diagnostics::error("Invalid GGUF magic number", "StreamingGGUFLoader");
        return false;
    }
    
    // Read version
    if (!ReadValue(header_.version)) return false;
    if (header_.version != GGUFConstants::GGUF_VERSION) {
        std::cerr << "❌ Unsupported GGUF version: " << header_.version << std::endl;
        Diagnostics::error("Unsupported GGUF version: " + std::to_string(header_.version), "StreamingGGUFLoader");
        return false;
    }
    
    // Read tensor count
    if (!ReadValue(header_.tensor_count)) return false;
    // Refuse absurd counts before any vector/map allocation.  A corrupted
    // header must fail closed rather than turning into std::bad_alloc.
    if (header_.tensor_count > 10'000'000ULL) {
        std::cerr << "[GGUF] tensor count exceeds safety limit: "
                  << header_.tensor_count << std::endl;
        return false;
    }
    
    // Read metadata KV count
    if (!ReadValue(header_.metadata_kv_count)) return false;
    if (header_.metadata_kv_count > 1'000'000ULL) {
        std::cerr << "[GGUF] metadata count exceeds safety limit: "
                  << header_.metadata_kv_count << std::endl;
        return false;
    }
    
    // Calculate metadata offset
    header_.metadata_offset = file_.tellg();
    
    return true;
}

GGUFHeader StreamingGGUFLoader::GetHeader() const {
    return header_;
}

bool StreamingGGUFLoader::ParseMetadata() {
    if (!file_.is_open() || header_.metadata_kv_count == 0) {
        return false;
    }
    
    file_.seekg(header_.metadata_offset);
    
    for (uint64_t i = 0; i < header_.metadata_kv_count; ++i) {
        std::string key, value;
        
        if (!ReadString(key)) {
            std::cerr << "❌ Failed to read metadata key at index " << i << std::endl;
            return false;
        }
        
        uint32_t value_type;
        if (!ReadValue(value_type)) {
            std::cerr << "❌ Failed to read metadata value type for key: " << key << std::endl;
            return false;
        }
        
        // GGUF v3 uses the standard metadata enum (STRING == 8).  Parse the
        // scalar forms we expose and consume every other valid form so the
        // next key remains aligned.
        if (value_type == GGUFConstants::GGUF_VALUE_TYPE_STRING) {
            if (!ReadString(value)) {
                std::cerr << "❌ Failed to read metadata string value for key: " << key << std::endl;
                return false;
            }
            metadata_.kv_pairs[key] = value;
            
            // Parse important metadata
            if (key == GGUFConstants::META_GENERAL_ARCHITECTURE) {
                if (value == "llama") metadata_.architecture_type = 1;
            } else if (key == GGUFConstants::META_LLAMA_BLOCK_COUNT) {
                metadata_.layer_count = std::stoul(value);
            } else if (key == GGUFConstants::META_LLAMA_CONTEXT_LENGTH) {
                metadata_.context_length = std::stoul(value);
            } else if (key == GGUFConstants::META_LLAMA_EMBEDDING_LENGTH) {
                metadata_.embedding_dim = std::stoul(value);
            } else if (key == GGUFConstants::META_LLAMA_VOCAB_SIZE) {
                metadata_.vocab_size = std::stoul(value);
            }
        } else if (value_type == GGUFConstants::GGUF_VALUE_TYPE_UINT32) {
            uint32_t v; if (!ReadValue(v)) return false;
            metadata_.kv_pairs[key] = std::to_string(v);
            if (key == "llama.block_count" || key == "qwen3.block_count") metadata_.layer_count = v;
            if (key == "llama.context_length" || key == "qwen3.context_length") metadata_.context_length = v;
            if (key == "llama.embedding_length" || key == "qwen3.embedding_length") metadata_.embedding_dim = v;
            if (key == "llama.vocab_size" || key == "qwen3.vocab_size") metadata_.vocab_size = v;
        } else if (value_type == GGUFConstants::GGUF_VALUE_TYPE_INT32) {
            int32_t v; if (!ReadValue(v)) return false;
            metadata_.kv_pairs[key] = std::to_string(v);
        } else if (value_type == GGUFConstants::GGUF_VALUE_TYPE_FLOAT32) {
            float v; if (!ReadValue(v)) return false;
            metadata_.kv_pairs[key] = std::to_string(v);
        } else if (value_type == GGUFConstants::GGUF_VALUE_TYPE_ARRAY) {
            // Tokenizer arrays are useful to callers, so retain the two
            // common forms; all other arrays are consumed safely below.
            uint32_t elem_type;
            uint64_t count;
            if (!ReadValue(elem_type) || !ReadValue(count) || count > 10'000'000ULL) return false;
            if (key == "tokenizer.ggml.tokens" && elem_type == GGUFConstants::GGUF_VALUE_TYPE_STRING) {
                metadata_.tokens.clear();
                metadata_.tokens.reserve(static_cast<size_t>(count));
                for (uint64_t j = 0; j < count; ++j) {
                    std::string token;
                    if (!ReadString(token)) return false;
                    metadata_.tokens.push_back(std::move(token));
                }
            } else if (key == "tokenizer.ggml.scores" && elem_type == GGUFConstants::GGUF_VALUE_TYPE_FLOAT32) {
                metadata_.token_scores.clear();
                metadata_.token_scores.reserve(static_cast<size_t>(count));
                for (uint64_t j = 0; j < count; ++j) {
                    float score; if (!ReadValue(score)) return false;
                    metadata_.token_scores.push_back(score);
                }
            } else {
                // Consume each element using the same checked decoder used by
                // the tensor-index pass.  Arrays may themselves be nested.
                for (uint64_t j = 0; j < count; ++j) {
                    if (!SkipMetadataValue(elem_type)) return false;
                }
            }
        } else if (!SkipMetadataValue(value_type)) {
            std::cerr << "[GGUF] unsupported metadata value type " << value_type
                      << " for key " << key << std::endl;
            return false;
        }
    }
    
    return true;
}

GGUFMetadata StreamingGGUFLoader::GetMetadata() const {
    return metadata_;
}

bool StreamingGGUFLoader::BuildTensorIndex() {
    if (!file_.is_open()) {
        return false;
    }
    
    // Skip metadata to get to tensor info
    file_.seekg(header_.metadata_offset);
    
    // Skip metadata entries
    for (uint64_t i = 0; i < header_.metadata_kv_count; ++i) {
        std::string key, value;
        if (!ReadString(key)) return false;
        
        uint32_t value_type;
        if (!ReadValue(value_type)) return false;
        
        if (value_type == GGUFConstants::GGUF_VALUE_TYPE_ARRAY) {
            uint32_t elem_type; uint64_t count;
            if (!ReadValue(elem_type) || !ReadValue(count) || count > 10'000'000ULL) return false;
            for (uint64_t j = 0; j < count; ++j) if (!SkipMetadataValue(elem_type)) return false;
        } else if (!SkipMetadataValue(value_type)) {
            return false;
        }
    }
    
    // Now read tensor info (no data!)
    for (uint64_t i = 0; i < header_.tensor_count; ++i) {
        TensorRef ref;
        
        if (!ReadString(ref.name)) {
            std::cerr << "❌ Failed to read tensor name at index " << i << std::endl;
            return false;
        }
        
        uint32_t n_dims;
        if (!ReadValue(n_dims)) return false;
        if (n_dims == 0 || n_dims > 16) {
            std::cerr << "[GGUF] invalid tensor rank " << n_dims
                      << " for tensor " << ref.name << std::endl;
            return false;
        }
        
        ref.shape.resize(n_dims);
        for (uint32_t d = 0; d < n_dims; ++d) {
            if (!ReadValue(ref.shape[d])) return false;
        }
        
        uint32_t type_val;
        if (!ReadValue(type_val)) return false;
        ref.type = static_cast<GGMLType>(type_val);
        
        if (!ReadValue(ref.offset)) return false;
        
        ref.size = CalculateTensorSize(ref.shape, ref.type);
        ref.zone_name = "";  // Will be assigned later
        
        tensor_index_[ref.name] = ref;
    }
    
    return true;
}

std::vector<TensorRef> StreamingGGUFLoader::GetTensorIndex() const {
    std::vector<TensorRef> result;
    for (const auto& [name, ref] : tensor_index_) {
        result.push_back(ref);
    }
    return result;
}

void StreamingGGUFLoader::AssignTensorsToZones() {
    // Zone assignment strategy (like a game engine):
    // Group tensors into zones (8 layers per zone)
    
    for (auto& [tensor_name, tensor_ref] : tensor_index_) {
        std::string zone;
        
        // Pattern matching to assign zones
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
            // Extract layer number: blk.0.attn → layer 0
            int layer = ExtractLayerNumber(tensor_name);
            int zone_num = layer / 8;  // 8 layers per zone
            zone = "layers_" + std::to_string(zone_num);
        }
        else {
            zone = "misc";
        }
        
        // Add to zone
        if (zones_.find(zone) == zones_.end()) {
            zones_[zone] = {zone, {}, 0, false, {}};
        }
        zones_[zone].tensors.push_back(tensor_name);
        zones_[zone].total_bytes += tensor_ref.size;
        
        tensor_ref.zone_name = zone;
    }
    
    // Print zone info
    std::cout << "\n📊 Zone Assignment Summary:" << std::endl;
    for (const auto& [zone_name, zone_info] : zones_) {
        std::cout << "   " << zone_name << ": " << zone_info.tensors.size() 
                  << " tensors, " << (zone_info.total_bytes / (1024*1024)) << " MB" << std::endl;
    }
    std::cout << std::endl;
}

int32_t StreamingGGUFLoader::ExtractLayerNumber(const std::string& tensor_name) const {
    // Look for "blk.N" pattern
    size_t pos = tensor_name.find("blk.");
    if (pos == std::string::npos) return 0;
    
    pos += 4;  // Skip "blk."
    size_t end = tensor_name.find_first_not_of("0123456789", pos);
    if (end == std::string::npos) end = tensor_name.length();
    
    try {
        return std::stoi(tensor_name.substr(pos, end - pos));
    } catch (...) {
        return 0;
    }
}

std::string StreamingGGUFLoader::GetZoneForTensor(const std::string& tensor_name) const {
    auto it = tensor_index_.find(tensor_name);
    if (it != tensor_index_.end()) {
        return it->second.zone_name;
    }
    return "";
}

std::string StreamingGGUFLoader::GetTensorZone(const std::string& tensor_name) const {
    return GetZoneForTensor(tensor_name);
}

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
    
    // Check file is open
    if (!is_open_ || !file_.is_open()) {
        std::cerr << "❌ File not open for streaming" << std::endl;
        return false;
    }

    // Never reserve an entire multi-gigabyte zone implicitly.  The previous
    // implementation ignored max_memory_mb and called reserve(total_bytes),
    // which made selecting a large GGUF from the IDE throw std::bad_alloc.
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
        
        // Seek to tensor offset in file
        file_.seekg(ref.offset, std::ios::beg);
        
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
        
        file_.read(reinterpret_cast<char*>(zone.data.data() + old_size), ref.size);
        
        if (!file_.good()) {
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
    
    // Load zone if not already loaded
    if (!zones_[zone_name].is_loaded) {
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

TensorZoneInfo StreamingGGUFLoader::GetZoneInfo(const std::string& zone_name) const {
    auto it = zones_.find(zone_name);
    if (it != zones_.end()) {
        return it->second;
    }
    return {};
}

uint64_t StreamingGGUFLoader::GetTotalFileSize() const {
    if (!file_.is_open()) return 0;
    
    std::streampos current = file_.tellg();
    file_.seekg(0, std::ios::end);
    uint64_t size = file_.tellg();
    file_.seekg(current);
    return size;
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
    if (it == tensor_index_.end()) return nullptr;
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
// PRIVATE TEMPLATE FUNCTIONS
template<typename T>
bool StreamingGGUFLoader::ReadValue(T& value) {
    file_.read(reinterpret_cast<char*>(&value), sizeof(T));
    return file_.good();
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
                if (!SkipMetadataValue(elem_type)) return false;
            }
            return true;
        }
        default:
            return false;
    }
}

bool StreamingGGUFLoader::ReadString(std::string& value) {
    uint64_t len;
    if (!ReadValue(len)) return false;

    // GGUF strings are metadata, never tensor payloads.  Bound them before
    // resize() so a corrupt length cannot request an arbitrary allocation.
    constexpr uint64_t kMaxMetadataString = 64ULL * 1024ULL * 1024ULL;
    if (len > kMaxMetadataString ||
        len > static_cast<uint64_t>(std::numeric_limits<size_t>::max())) {
        std::cerr << "[GGUF] metadata string exceeds safety limit: " << len
                  << " bytes" << std::endl;
        return false;
    }

    const std::streampos payload = file_.tellg();
    if (payload < 0) return false;
    file_.seekg(0, std::ios::end);
    const std::streampos end = file_.tellg();
    file_.seekg(payload, std::ios::beg);
    if (end < payload || static_cast<uint64_t>(end - payload) < len) {
        std::cerr << "[GGUF] metadata string extends beyond file" << std::endl;
        return false;
    }

    value.resize(static_cast<size_t>(len));
    if (len != 0) {
        file_.read(value.data(), static_cast<std::streamsize>(len));
    }
    return file_.good() || file_.eof();
}

uint64_t StreamingGGUFLoader::CalculateTensorSize(const std::vector<uint64_t>& shape, GGMLType type) const {
    uint64_t num_elements = 1;
    for (uint64_t dim : shape) {
        if (dim != 0 && num_elements > std::numeric_limits<uint64_t>::max() / dim) {
            return 0;
        }
        num_elements *= dim;
    }

    // Helper lambda for block-aligned size calculation
    // Formula: block_size × ceil(num_elements / block_elements)
    // Block geometries match ggml.h and include/gguf_loader.h (canonical IDs).
    auto block_aligned_size = [num_elements](uint64_t block_elements, uint64_t block_size) -> uint64_t {
        uint64_t num_blocks = (num_elements + block_elements - 1) / block_elements;  // Ceiling division
        if (num_blocks > std::numeric_limits<uint64_t>::max() / block_size) return 0;
        return num_blocks * block_size;
    };

    switch (type) {
        // --- Non-block types: one stored value per element ------------------
        case GGMLType::F32:   return num_elements * 4;
        case GGMLType::F16:   return num_elements * 2;
        case GGMLType::I8:    return num_elements * 1;
        case GGMLType::I16:   return num_elements * 2;
        case GGMLType::I32:   return num_elements * 4;
        case GGMLType::I64:   return num_elements * 8;
        case GGMLType::F64:   return num_elements * 8;

        // --- Q quants (32 elements / block) ---------------------------------
        case GGMLType::Q4_0:  return block_aligned_size(32,  18);
        case GGMLType::Q4_1:  return block_aligned_size(32,  20);
        case GGMLType::Q5_0:  return block_aligned_size(32,  22);
        case GGMLType::Q5_1:  return block_aligned_size(32,  24);
        case GGMLType::Q8_0:  return block_aligned_size(32,  34);

        // --- K-quants (256 elements / super-block) --------------------------
        case GGMLType::Q2_K:  return block_aligned_size(256, 84);
        case GGMLType::Q3_K:  return block_aligned_size(256, 110);
        case GGMLType::Q4_K:  return block_aligned_size(256, 144);
        case GGMLType::Q5_K:  return block_aligned_size(256, 176);
        case GGMLType::Q6_K:  return block_aligned_size(256, 210);
        case GGMLType::Q8_K:  return block_aligned_size(256, 292);

        // --- Imatrix (IQ) quants --------------------------------------------
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

