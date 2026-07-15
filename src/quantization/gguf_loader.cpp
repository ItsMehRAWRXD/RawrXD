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
    
    // Read header manually to avoid struct padding issues
    file_.read(reinterpret_cast<char*>(&header_.magic), sizeof(header_.magic));
    file_.read(reinterpret_cast<char*>(&header_.version), sizeof(header_.version));
    file_.read(reinterpret_cast<char*>(&header_.tensor_count), sizeof(header_.tensor_count));
    file_.read(reinterpret_cast<char*>(&header_.metadata_kv_count), sizeof(header_.metadata_kv_count));
    
    std::cout << "  Header: magic=" << std::hex << header_.magic << " version=" << std::dec << header_.version 
              << " tensors=" << header_.tensor_count << " metadata=" << header_.metadata_kv_count << std::endl;
    
    if (header_.magic != 0x46554747) {
        std::cerr << "Invalid GGUF magic: " << std::hex << header_.magic << std::endl;
        return false;
    }
    
    // Debug output disabled for production
    // std::cout << "GGUF Version: " << header_.version << std::endl;
    // std::cout << "Tensors: " << header_.tensor_count << std::endl;
    // std::cout << "Metadata: " << header_.metadata_kv_count << std::endl;
    
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
    
    // Infer vocab_size from token_embd.weight if not set in metadata
    if (config_.vocab_size == 0) {
        InferVocabSizeFromEmbeddings();
    }
    
    // Calculate data offset (where tensor data begins)
    data_offset_ = file_.tellg();
    
    // Align to 32 bytes (GGUF spec requirement)
    uint64_t alignment = 32;
    uint64_t aligned_offset = (data_offset_ + alignment - 1) & ~(alignment - 1);
    
    // Seek to aligned position
    if (aligned_offset > data_offset_) {
        file_.seekg(static_cast<std::streamoff>(aligned_offset), std::ios::beg);
        data_offset_ = aligned_offset;
    }
    
    return true;
}

bool GGUFModelLoader::ParseMetadata() {
    std::cout << "  Parsing " << header_.metadata_kv_count << " metadata entries..." << std::endl;
    
    for (uint64_t i = 0; i < header_.metadata_kv_count; i++) {
        // Debug: show file position
        auto pos = file_.tellg();
        
        // Read key
        std::string key = ReadString();
        if (key.empty() || key.length() > 1000) {
            std::cerr << "    Warning: Invalid key length " << key.length() << " at entry " << i << " (file pos " << pos << ")" << std::endl;
            return false;
        }
        
        // Read value type
        uint32_t type_val;
        file_.read(reinterpret_cast<char*>(&type_val), sizeof(type_val));
        GGUFType type = static_cast<GGUFType>(type_val);
        
        // Debug output for first few entries and entry 12
        if (i < 20) {
            std::cout << "    Entry " << i << " (pos " << pos << "): key=\"" << key << "\" type=" << type_val << std::endl;
        }
        
        // Read value based on type
        switch (type) {
            case GGUFType::UINT32: {
                uint32_t val = ReadU32();
                // Store in config - support multiple architecture prefixes
                if (key == "llama.block_count" || key == "phi2.block_count" || key.ends_with(".block_count")) config_.block_count = val;
                else if (key == "llama.context_length" || key == "phi2.context_length" || key.ends_with(".context_length")) config_.context_length = val;
                else if (key == "llama.embedding_length" || key == "phi2.embedding_length" || key.ends_with(".embedding_length")) config_.embedding_length = val;
                else if (key == "llama.feed_forward_length" || key == "phi2.feed_forward_length" || key.ends_with(".feed_forward_length")) config_.feed_forward_length = val;
                else if (key == "llama.head_count" || key == "phi2.head_count" || key.ends_with(".head_count")) config_.head_count = val;
                else if (key == "llama.head_count_kv" || key == "phi2.head_count_kv" || key.ends_with(".head_count_kv")) config_.head_count_kv = val;
                else if (key == "llama.vocab_size" || key == "phi2.vocab_size" || key.ends_with(".vocab_size")) config_.vocab_size = val;
                break;
            }
            case GGUFType::STRING: {
                auto val_pos = file_.tellg();
                std::string val = ReadString();
                if (i == 12) {
                    std::cout << "      STRING value at pos " << val_pos << ": \"" << val << "\" (length " << val.length() << ")" << std::endl;
                }
                if (key == "general.architecture") config_.architecture = val;
                else if (key == "tokenizer.ggml.model") config_.tokenizer_model = val;
                break;
            }
            case GGUFType::FLOAT32: {
                float val = ReadF32();
                (void)val;  // Unused for now
                break;
            }
            case GGUFType::BOOL: {
                uint8_t val;
                file_.read(reinterpret_cast<char*>(&val), sizeof(val));
                (void)val;  // Unused for now
                break;
            }
            case GGUFType::UINT64: {
                uint64_t val = ReadU64();
                // Store parameter count if needed
                if (key == "general.parameter_count") {
                    // Could store this if needed for display
                }
                break;
            }
            case GGUFType::INT64: {
                int64_t val;
                file_.read(reinterpret_cast<char*>(&val), sizeof(val));
                (void)val;
                break;
            }
            case GGUFType::FLOAT64: {
                double val;
                file_.read(reinterpret_cast<char*>(&val), sizeof(val));
                (void)val;
                break;
            }
            case GGUFType::UINT8:
            case GGUFType::INT8: {
                int8_t val;
                file_.read(reinterpret_cast<char*>(&val), sizeof(val));
                (void)val;
                break;
            }
            case GGUFType::UINT16:
            case GGUFType::INT16: {
                int16_t val;
                file_.read(reinterpret_cast<char*>(&val), sizeof(val));
                (void)val;
                break;
            }
            case GGUFType::ARRAY: {
                // Read array: type (4 bytes) + count (8 bytes) + elements
                uint32_t arr_type = ReadU32();
                uint64_t arr_count = ReadU64();
                
                // Skip array elements - for tokenizer data we don't need to store it
                // Just need to advance the file position correctly
                for (uint64_t j = 0; j < arr_count; j++) {
                    if (!file_.good()) {
                        std::cerr << "    ERROR: File stream error while reading array at index " << j << std::endl;
                        return false;
                    }
                    
                    switch (static_cast<GGUFType>(arr_type)) {
                        case GGUFType::UINT32:
                        case GGUFType::INT32: 
                            ReadU32(); 
                            break;
                        case GGUFType::STRING: {
                            // Read and discard string
                            uint64_t str_len = ReadU64();
                            if (str_len > 100000) {
                                std::cerr << "    ERROR: String too long in array: " << str_len << std::endl;
                                return false;
                            }
                            if (str_len > 0) {
                                file_.seekg(static_cast<std::streamoff>(str_len), std::ios::cur);
                            }
                            break;
                        }
                        case GGUFType::FLOAT32: 
                            ReadF32(); 
                            break;
                        default: 
                            break;
                    }
                    
                    // Progress indicator for large arrays
                    if ((j + 1) % 50000 == 0) {
                        std::cout << "    Processed " << (j + 1) << "/" << arr_count << " array elements" << std::endl;
                    }
                }
                break;
            }
            default: {
                // Skip unknown types - need to handle this properly
                // For now, just skip the value based on type size
                break;
            }
        }
        
        // Progress indicator every 5 entries
        if ((i + 1) % 5 == 0 || i == header_.metadata_kv_count - 1) {
            std::cout << "    Processed " << (i + 1) << "/" << header_.metadata_kv_count << " entries" << std::endl;
        }
    }
    
    std::cout << "  Architecture: " << config_.architecture << std::endl;
    std::cout << "  Layers: " << config_.block_count << std::endl;
    std::cout << "  Hidden size: " << config_.embedding_length << std::endl;
    std::cout << "  Heads: " << config_.head_count << std::endl;
    std::cout << "  Vocab: " << config_.vocab_size << std::endl;
    
    // Note: Tensor info table starts immediately after metadata (no alignment needed)
    // The 32-byte alignment is only for tensor data, not the tensor info table
    auto end_pos = file_.tellg();
    if (end_pos > 0) {
        std::cout << "  Metadata ends at position: " << end_pos << std::endl;
    }
    
    return true;
}

void GGUFModelLoader::InferVocabSizeFromEmbeddings() {
    // Find token_embd.weight tensor to infer vocab_size
    for (const auto& tensor_info : tensors_) {
        if (tensor_info.name == "token_embd.weight" && tensor_info.dimensions.size() == 2) {
            // For transposed embeddings [hidden_size, vocab_size], vocab_size is dims[1]
            // For standard embeddings [vocab_size, hidden_size], vocab_size is dims[0]
            // We assume transposed if dims[0] < dims[1] (hidden_size < vocab_size)
            if (tensor_info.dimensions[0] < tensor_info.dimensions[1]) {
                config_.vocab_size = static_cast<uint32_t>(tensor_info.dimensions[1]);
                std::cout << "  Inferred vocab_size from token_embd.weight: " << config_.vocab_size << std::endl;
            } else {
                config_.vocab_size = static_cast<uint32_t>(tensor_info.dimensions[0]);
                std::cout << "  Inferred vocab_size from token_embd.weight: " << config_.vocab_size << std::endl;
            }
            break;
        }
    }
}

bool GGUFModelLoader::ParseTensors() {
    // Get current position (should already be aligned from ParseMetadata)
    auto current_pos = file_.tellg();
    if (current_pos < 0) {
        std::cerr << "  ERROR: Invalid file position before tensor table" << std::endl;
        return false;
    }
    
    uint64_t pos = static_cast<uint64_t>(current_pos);
    std::cout << "  Tensor table at offset: " << pos << std::endl;
    
    // Debug: Show first few bytes
    char debug_buf[16];
    file_.read(debug_buf, 16);
    std::cout << "  First 16 bytes: ";
    for (int i = 0; i < 16; i++) {
        std::cout << std::hex << (unsigned char)debug_buf[i];
    }
    std::cout << std::dec << std::endl;
    
    // Seek back to start
    file_.seekg(static_cast<std::streamoff>(pos), std::ios::beg);
    
    tensors_.reserve(header_.tensor_count);
    
    for (uint64_t i = 0; i < header_.tensor_count; i++) {
        // Check file state
        if (!file_.good()) {
            std::cerr << "  ERROR: File stream error at tensor " << i << std::endl;
            return false;
        }
        
        TensorInfo info;
        
        // Read name (length-prefixed string)
        info.name = ReadString();
        if (info.name.empty() || !file_.good()) {
            std::cerr << "  ERROR: Failed to read tensor name at index " << i << std::endl;
            return false;
        }
        
        // Read dimensions
        uint32_t n_dims = ReadU32();
        if (n_dims > 10) {  // Sanity check
            std::cerr << "  ERROR: Invalid dimension count " << n_dims << " for tensor " << info.name << std::endl;
            return false;
        }
        
        info.dimensions.resize(n_dims);
        for (uint32_t d = 0; d < n_dims; d++) {
            info.dimensions[d] = ReadU64();
        }
        
        // Read type
        uint32_t type_val = ReadU32();
        info.type = static_cast<GGMLType>(type_val);
        
        // Read offset (from GGUF spec, each tensor info has an offset field)
        info.offset = ReadU64();
        
        // Calculate size based on type
        info.size = GetTensorSizeBytes(info);
        
        tensors_.push_back(info);
        
        // Print first few tensors for debugging
        if (i < 3) {
            std::cout << "    Tensor[" << i << "]: " << info.name << " type=" << type_val 
                      << " dims=" << n_dims << " offset=" << info.offset << " size=" << info.size << std::endl;
        }
    }
    
    std::cout << "  Loaded " << tensors_.size() << " tensor infos" << std::endl;
    
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
        case GGMLType::Q4_K: {
            // Q4_K uses 256 weights per block, 144 bytes per block
            uint64_t num_blocks = (num_elements + 255) / 256;
            return num_blocks * 144;
        }
        case GGMLType::Q6_K: {
            // Q6_K uses 256 weights per block, 210 bytes per block
            uint64_t num_blocks = (num_elements + 255) / 256;
            return num_blocks * 210;
        }
        // K-quants we don't support yet - estimate size
        case GGMLType::Q2_K:
        case GGMLType::Q3_K:
        case GGMLType::Q5_K:
        case GGMLType::Q8_K:
            // Return estimated size - actual loading will fail gracefully
            return num_elements * 4;  // Assume F32 for estimation
        default:
            std::cerr << "Unknown tensor type: " << static_cast<int>(info.type) << std::endl;
            return num_elements * 4;  // Assume F32
    }
}

QuantType GGUFModelLoader::ConvertGGMLType(GGMLType type) const {
    switch (type) {
        case GGMLType::Q4_0: return QuantType::Q4_0;
        case GGMLType::Q4_1: return QuantType::Q4_1;
        case GGMLType::Q8_0: return QuantType::Q8_0;
        case GGMLType::F32: return QuantType::F32;
        case GGMLType::Q2_K: return QuantType::Q2_K;
        case GGMLType::Q4_K: return QuantType::Q4_K;
        case GGMLType::Q6_K: return QuantType::Q6_K;
        // For K-quants we don't support yet, return F32 as fallback
        case GGMLType::Q3_K:
        case GGMLType::Q5_K:
        case GGMLType::Q8_K:
            std::cerr << "Warning: K-quant type " << static_cast<int>(type) << " not fully supported, using F32 fallback" << std::endl;
            return QuantType::F32;
        default:
            std::cerr << "Warning: Unknown GGML type " << static_cast<int>(type) << ", using F32 fallback" << std::endl;
            return QuantType::F32;
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
    
    // Initialize with dimensions first if 2D
    if (info.dimensions.size() == 2) {
        tensor.Initialize(source_type, info.dimensions[0], info.dimensions[1]);
    } else if (info.dimensions.size() == 1) {
        tensor.Initialize(source_type, 1, info.dimensions[0]);
    }
    
    // Load the data
    tensor.LoadFromGGUF(data.data(), num_elements, source_type);
    
    return true;
}

bool GGUFModelLoader::LoadLayerWeights(int layer_idx, QuantizedLayerWeightsExtended& weights) {
    // Try different naming conventions
    // Vision/Multimodal: v.blk.N.* (ministral3)
    // Standard: blk.N.* (llama.cpp)
    // PyTorch: layers.N.* or model.layers.N.*
    std::vector<std::string> prefixes = {
        "v.blk." + std::to_string(layer_idx) + ".",  // Vision/multimodal (ministral3)
        "blk." + std::to_string(layer_idx) + ".",
        "layers." + std::to_string(layer_idx) + ".",
        "model.layers." + std::to_string(layer_idx) + ".",
        "model.layers." + std::to_string(layer_idx) + ".self_attn.",
        "model.layers." + std::to_string(layer_idx) + ".attention.",
        "blk." + std::to_string(layer_idx) + ".attention."
    };
    
    // Attention weights - try different naming patterns
    // Standard patterns: attn_q, attn_k, attn_v (llama.cpp)
    // PyTorch patterns: self_attn.q_proj, attention.q_proj
    // Mistral patterns: attention.wq, attention.wk, attention.wv, attention.wo
    // Vision models: mm.* prefix for multimodal
    // Mistral3 specific: blk.N.attention.wq, blk.N.attention.wk, etc.
    std::vector<std::string> q_names = {
        "attn_q.weight",           // llama.cpp standard
        "self_attn.q_proj.weight", // PyTorch transformers
        "attention.q_proj.weight", // Alternative
        "attention.wq.weight",     // Mistral/llama2
        "attn_wq.weight",          // Alternative
        "mm.attn_q.weight",        // Vision/multimodal
        "attention.wq.weight"      // Mistral3
    };
    std::vector<std::string> k_names = {
        "attn_k.weight",
        "self_attn.k_proj.weight",
        "attention.k_proj.weight",
        "attention.wk.weight",
        "attn_wk.weight",
        "mm.attn_k.weight",
        "attention.wk.weight"
    };
    std::vector<std::string> v_names = {
        "attn_v.weight",
        "self_attn.v_proj.weight",
        "attention.v_proj.weight",
        "attention.wv.weight",
        "attn_wv.weight",
        "mm.attn_v.weight",
        "attention.wv.weight"
    };
    std::vector<std::string> o_names = {
        "attn_output.weight",
        "self_attn.o_proj.weight",
        "attention.o_proj.weight",
        "attention.wo.weight",
        "attn_wo.weight",
        "mm.attn_output.weight",
        "attention.wo.weight"
    };
    
    bool q_loaded = false, k_loaded = false, v_loaded = false, o_loaded = false;
    
    // Try loading separate Q/K/V tensors (most models use this format)
    // Skip fused QKV attempt to avoid error spam
    for (const auto& prefix : prefixes) {
        if (!q_loaded) {
            for (const auto& name : q_names) {
                if (LoadQuantizedTensor(prefix + name, weights.q_proj, QuantType::Q4_0)) {
                    q_loaded = true;
                    break;
                }
            }
        }
        if (!k_loaded) {
            for (const auto& name : k_names) {
                if (LoadQuantizedTensor(prefix + name, weights.k_proj, QuantType::Q4_0)) {
                    k_loaded = true;
                    break;
                }
            }
        }
        if (!v_loaded) {
            for (const auto& name : v_names) {
                if (LoadQuantizedTensor(prefix + name, weights.v_proj, QuantType::Q4_0)) {
                    v_loaded = true;
                    break;
                }
            }
        }
        for (const auto& name : o_names) {
            if (!o_loaded && LoadQuantizedTensor(prefix + name, weights.o_proj, QuantType::Q4_0)) {
                o_loaded = true;
                break;
            }
        }
        if (q_loaded && k_loaded && v_loaded && o_loaded) break;
    }
    
    // Debug removed - tensors load correctly with v.blk prefix
    
    // FFN weights - try different naming patterns
    // Standard LLaMA-style: gate, up, down
    // Phi2-style: up (fused gate+up), down
    std::vector<std::string> gate_names = {"ffn_gate.weight", "mlp.gate_proj.weight", "feed_forward.w1.weight"};
    std::vector<std::string> up_names = {"ffn_up.weight", "mlp.up_proj.weight", "feed_forward.w3.weight"};
    std::vector<std::string> down_names = {"ffn_down.weight", "mlp.down_proj.weight", "feed_forward.w2.weight"};
    
    bool gate_loaded = false, up_loaded = false, down_loaded = false;
    
    for (const auto& prefix : prefixes) {
        // Try loading gate projection
        for (const auto& name : gate_names) {
            if (!gate_loaded && LoadQuantizedTensor(prefix + name, weights.gate_proj, QuantType::Q4_0)) {
                gate_loaded = true;
                break;
            }
        }
        // Try loading up projection
        for (const auto& name : up_names) {
            if (!up_loaded && LoadQuantizedTensor(prefix + name, weights.up_proj, QuantType::Q4_0)) {
                up_loaded = true;
                break;
            }
        }
        // Try loading down projection
        for (const auto& name : down_names) {
            if (!down_loaded && LoadQuantizedTensor(prefix + name, weights.down_proj, QuantType::Q4_0)) {
                down_loaded = true;
                break;
            }
        }
        if (gate_loaded && up_loaded && down_loaded) break;
    }
    
    // Phi2 workaround: if we have up but no gate, use up as gate (phi2 fuses them)
    if (!gate_loaded && up_loaded) {
        weights.gate_proj = weights.up_proj;  // Copy up to gate
        gate_loaded = true;
        std::cout << "  Layer " << layer_idx << ": Using up projection as gate (phi2 fused FFN)" << std::endl;
    }
    
    if (!gate_loaded) std::cerr << "Failed to load gate projection for layer " << layer_idx << std::endl;
    if (!up_loaded) std::cerr << "Failed to load up projection for layer " << layer_idx << std::endl;
    if (!down_loaded) std::cerr << "Failed to load down projection for layer " << layer_idx << std::endl;
    
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
    auto pos = file_.tellg();
    uint64_t len = ReadU64();
    // Sanity check: strings in GGUF should be reasonable length
    if (len > 10000 || len == 0) {
        std::cerr << "    Warning: Suspicious string length: " << len << " at file pos " << pos << std::endl;
        return "";
    }
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
