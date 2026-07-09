// ============================================================================
// GGUF Loader Implementation
// ============================================================================

#include "gguf_loader.hpp"
#include <iostream>
#include <algorithm>
#include <cstring>

namespace rawrxd {
namespace quantization {

// ============================================================================
// GGUF Model Loader
// ============================================================================

GGUFModelLoader::GGUFModelLoader() {}

GGUFModelLoader::~GGUFModelLoader() {
    if (file_.is_open()) {
        file_.close();
    }
}

bool GGUFModelLoader::IsValidGGUF(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return false;
    
    uint32_t magic;
    file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
    return magic == 0x46554747;  // "GGUF" in little-endian
}

bool GGUFModelLoader::Load(const std::string& path) {
    path_ = path;
    
    file_.open(path, std::ios::binary);
    if (!file_) {
        std::cerr << "Failed to open: " << path << std::endl;
        return false;
    }
    
    // Read header
    file_.read(reinterpret_cast<char*>(&header_), sizeof(header_));
    
    if (header_.magic != 0x46554747) {
        std::cerr << "Invalid GGUF magic: " << std::hex << header_.magic << std::endl;
        return false;
    }
    
    std::cout << "GGUF Version: " << header_.version << std::endl;
    std::cout << "Tensors: " << header_.tensor_count << std::endl;
    std::cout << "Metadata: " << header_.metadata_kv_count << std::endl;
    
    // Parse metadata
    if (!ParseMetadata()) {
        std::cerr << "Failed to parse metadata" << std::endl;
        return false;
    }
    
    // Parse tensors
    if (!ParseTensors()) {
        std::cerr << "Failed to parse tensors" << std::endl;
        return false;
    }
    
    // Calculate data offset (where tensor data begins)
    data_offset_ = file_.tellg();
    
    // Align to 32 bytes
    uint64_t alignment = 32;
    data_offset_ = (data_offset_ + alignment - 1) & ~(alignment - 1);
    
    std::cout << "Data offset: " << data_offset_ << std::endl;
    
    return true;
}

bool GGUFModelLoader::ParseMetadata() {
    for (uint64_t i = 0; i < header_.metadata_kv_count; i++) {
        // Read key
        std::string key = ReadString();
        
        // Read value type
        uint32_t type_val;
        file_.read(reinterpret_cast<char*>(&type_val), sizeof(type_val));
        GGUFType type = static_cast<GGUFType>(type_val);
        
        // Read value based on type
        switch (type) {
            case GGUFType::UINT32: {
                uint32_t val = ReadU32();
                // Store in config
                if (key == "llama.block_count") config_.block_count = val;
                else if (key == "llama.context_length") config_.context_length = val;
                else if (key == "llama.embedding_length") config_.embedding_length = val;
                else if (key == "llama.feed_forward_length") config_.feed_forward_length = val;
                else if (key == "llama.head_count") config_.head_count = val;
                else if (key == "llama.head_count_kv") config_.head_count_kv = val;
                else if (key == "llama.vocab_size") config_.vocab_size = val;
                break;
            }
            case GGUFType::STRING: {
                std::string val = ReadString();
                if (key == "general.architecture") config_.architecture = val;
                else if (key == "tokenizer.ggml.model") config_.tokenizer_model = val;
                break;
            }
            case GGUFType::FLOAT32: {
                float val = ReadF32();
                (void)val;  // Unused for now
                break;
            }
            default: {
                // Skip unknown types
                std::cerr << "Skipping metadata key: " << key << " (type " << type_val << ")" << std::endl;
                // Need to skip the value - this is simplified
                break;
            }
        }
    }
    
    std::cout << "Architecture: " << config_.architecture << std::endl;
    std::cout << "Layers: " << config_.block_count << std::endl;
    std::cout << "Hidden size: " << config_.embedding_length << std::endl;
    std::cout << "Heads: " << config_.head_count << std::endl;
    std::cout << "Vocab: " << config_.vocab_size << std::endl;
    
    return true;
}

bool GGUFModelLoader::ParseTensors() {
    tensors_.reserve(header_.tensor_count);
    
    for (uint64_t i = 0; i < header_.tensor_count; i++) {
        TensorInfo info;
        
        // Read name
        info.name = ReadString();
        
        // Read dimensions
        uint32_t n_dims = ReadU32();
        info.dimensions.resize(n_dims);
        for (uint32_t d = 0; d < n_dims; d++) {
            info.dimensions[d] = ReadU64();
        }
        
        // Read type
        uint32_t type_val = ReadU32();
        info.type = static_cast<GGMLType>(type_val);
        
        // Calculate offset and size
        info.offset = (i == 0) ? 0 : tensors_[i-1].offset + tensors_[i-1].size;
        info.size = GetTensorSizeBytes(info);
        
        // Align to 32 bytes
        info.size = (info.size + 31) & ~31ULL;
        
        tensors_.push_back(info);
        
        // Print first few tensors for debugging
        if (i < 5) {
            std::cout << "Tensor: " << info.name << " type=" << type_val 
                      << " dims=" << n_dims;
            for (auto dim : info.dimensions) std::cout << "x" << dim;
            std::cout << " size=" << info.size << std::endl;
        }
    }
    
    return true;
}

uint64_t GGUFModelLoader::GetTensorSizeBytes(const TensorInfo& info) const {
    uint64_t num_elements = info.num_elements();
    
    switch (info.type) {
        case GGMLType::F32: return num_elements * 4;
        case GGMLType::F16: return num_elements * 2;
        case GGMLType::Q4_0: {
            uint64_t num_blocks = (num_elements + 31) / 32;
            return num_blocks * 18;  // 18 bytes per block
        }
        case GGMLType::Q8_0: {
            uint64_t num_blocks = (num_elements + 31) / 32;
            return num_blocks * 34;  // 34 bytes per block
        }
        default:
            std::cerr << "Unknown tensor type: " << static_cast<int>(info.type) << std::endl;
            return num_elements * 4;  // Assume F32
    }
}

QuantType GGUFModelLoader::ConvertGGMLType(GGMLType type) const {
    switch (type) {
        case GGMLType::Q4_0: return QuantType::Q4_0;
        case GGMLType::Q8_0: return QuantType::Q8_0;
        case GGMLType::F32: return QuantType::F32;
        default: return QuantType::F32;
    }
}

bool GGUFModelLoader::LoadQuantizedTensor(const std::string& name, 
                                            QuantizedTensor& tensor,
                                            QuantType target_type) {
    // Find tensor
    auto it = std::find_if(tensors_.begin(), tensors_.end(),
                          [&name](const TensorInfo& t) { return t.name == name; });
    
    if (it == tensors_.end()) {
        std::cerr << "Tensor not found: " << name << std::endl;
        return false;
    }
    
    const TensorInfo& info = *it;
    
    // Seek to tensor data
    uint64_t tensor_offset = data_offset_ + info.offset;
    file_.seekg(tensor_offset, std::ios::beg);
    
    // Read tensor data
    std::vector<uint8_t> data(info.size);
    file_.read(reinterpret_cast<char*>(data.data()), info.size);
    
    // Load into quantized tensor
    QuantType source_type = ConvertGGMLType(info.type);
    uint64_t num_elements = info.num_elements();
    
    // For now, just load as-is (would convert if source != target)
    tensor.LoadFromGGUF(data.data(), num_elements, source_type);
    
    // Set dimensions if 2D
    if (info.dimensions.size() == 2) {
        tensor.Initialize(source_type, info.dimensions[0], info.dimensions[1]);
    }
    
    return true;
}

bool GGUFModelLoader::LoadLayerWeights(int layer_idx, QuantizedLayerWeightsExtended& weights) {
    std::string prefix = "blk." + std::to_string(layer_idx) + ".";
    
    // Attention weights
    if (!LoadQuantizedTensor(prefix + "attn_q.weight", weights.q_proj, QuantType::Q4_0)) {
        std::cerr << "Failed to load Q projection for layer " << layer_idx << std::endl;
        return false;
    }
    if (!LoadQuantizedTensor(prefix + "attn_k.weight", weights.k_proj, QuantType::Q4_0)) {
        std::cerr << "Failed to load K projection for layer " << layer_idx << std::endl;
        return false;
    }
    if (!LoadQuantizedTensor(prefix + "attn_v.weight", weights.v_proj, QuantType::Q4_0)) {
        std::cerr << "Failed to load V projection for layer " << layer_idx << std::endl;
        return false;
    }
    if (!LoadQuantizedTensor(prefix + "attn_output.weight", weights.o_proj, QuantType::Q4_0)) {
        std::cerr << "Failed to load O projection for layer " << layer_idx << std::endl;
        return false;
    }
    
    // FFN weights
    if (!LoadQuantizedTensor(prefix + "ffn_gate.weight", weights.gate_proj, QuantType::Q4_0)) {
        // Try alternative naming
        if (!LoadQuantizedTensor(prefix + "ffn_up.weight", weights.gate_proj, QuantType::Q4_0)) {
            std::cerr << "Failed to load gate projection for layer " << layer_idx << std::endl;
            return false;
        }
    }
    if (!LoadQuantizedTensor(prefix + "ffn_up.weight", weights.up_proj, QuantType::Q4_0)) {
        std::cerr << "Failed to load up projection for layer " << layer_idx << std::endl;
        return false;
    }
    if (!LoadQuantizedTensor(prefix + "ffn_down.weight", weights.down_proj, QuantType::Q4_0)) {
        std::cerr << "Failed to load down projection for layer " << layer_idx << std::endl;
        return false;
    }
    
    // Normalization weights (F32)
    // These would be loaded separately
    weights.input_layernorm.resize(config_.embedding_length, 1.0f);
    weights.post_attention_layernorm.resize(config_.embedding_length, 1.0f);
    
    // Set dimensions
    weights.hidden_size = config_.embedding_length;
    weights.intermediate_size = config_.feed_forward_length;
    weights.num_heads = config_.head_count;
    weights.head_dim = config_.head_dim();
    
    return true;
}

// String reading helper
std::string GGUFModelLoader::ReadString() {
    uint64_t len = ReadU64();
    std::string str(len, '\0');
    file_.read(&str[0], len);
    return str;
}

uint32_t GGUFModelLoader::ReadU32() {
    uint32_t val;
    file_.read(reinterpret_cast<char*>(&val), sizeof(val));
    return val;
}

uint64_t GGUFModelLoader::ReadU64() {
    uint64_t val;
    file_.read(reinterpret_cast<char*>(&val), sizeof(val));
    return val;
}

float GGUFModelLoader::ReadF32() {
    float val;
    file_.read(reinterpret_cast<char*>(&val), sizeof(val));
    return val;
}

} // namespace quantization
} // namespace rawrxd
