// ============================================================================
// GGUF Transformer Integration - Implementation
// ============================================================================

#include "gguf_transformer_integration.hpp"
#include <iostream>
#include <algorithm>
#include <cstring>
#include <cmath>
#include <limits>

namespace transformer {

// ============================================================================
// GGUFTransformerLoader Implementation
// ============================================================================
GGUFTransformerLoader::GGUFTransformerLoader() = default;
GGUFTransformerLoader::~GGUFTransformerLoader() = default;

bool GGUFTransformerLoader::LoadFromFile(const std::string& path, TransformerConfig& config) {
    loader_ = std::make_unique<sovereign::StreamingGGUFLoader>(path);
    
    if (!loader_->isOpen()) {
        std::cerr << "Failed to open GGUF file: " << path << std::endl;
        return false;
    }
    
    // Parse model configuration from GGUF metadata
    if (!ParseModelConfig()) {
        std::cerr << "Failed to parse model configuration" << std::endl;
        return false;
    }
    
    // Setup tensor name patterns based on architecture
    SetupPatterns();
    
    // Populate transformer config
    config.hidden_size = hidden_size_;
    config.num_heads = num_heads_;
    config.num_kv_heads = num_kv_heads_;
    config.head_dim = head_dim_;
    config.intermediate_size = intermediate_size_;
    config.num_layers = num_layers_;
    config.vocab_size = vocab_size_;
    config.max_seq_len = context_length_;
    
    return true;
}

bool GGUFTransformerLoader::ParseModelConfig() {
    if (!loader_) return false;
    
    // Try to get architecture from metadata
    auto arch_tensor = loader_->findTensor("general.architecture");
    if (arch_tensor) {
        // Read architecture string
        // Note: This would require reading string metadata from GGUF
        model_arch_ = "llama"; // Default
    }
    
    // Get dimensions from tensor shapes
    // Look for token embeddings to determine vocab size and hidden size
    auto embed_info = loader_->findTensor("token_embd.weight");
    if (!embed_info) embed_info = loader_->findTensor("tok_embeddings.weight");
    
    if (embed_info && embed_info->shape.size() >= 2) {
        vocab_size_ = static_cast<uint32_t>(embed_info->shape[0]);
        hidden_size_ = static_cast<uint32_t>(embed_info->shape[1]);
    } else {
        // Try to infer from other tensors
        loader_->forEachTensor([&](const sovereign::TensorView& view) {
            const auto& info = view.info();
            if (info.name.find("blk.0.attn_norm.weight") != std::string::npos) {
                hidden_size_ = static_cast<uint32_t>(info.shape[0]);
            }
        });
    }
    
    // Count layers by looking for attention norm tensors
    uint32_t max_layer = 0;
    loader_->forEachTensor([&](const sovereign::TensorView& view) {
        const auto& name = view.info().name;
        size_t blk_pos = name.find("blk.");
        if (blk_pos != std::string::npos) {
            size_t dot_pos = name.find('.', blk_pos + 4);
            if (dot_pos != std::string::npos) {
                uint32_t layer = std::stoi(name.substr(blk_pos + 4, dot_pos - blk_pos - 4));
                max_layer = std::max(max_layer, layer);
            }
        }
    });
    num_layers_ = max_layer + 1;
    
    // Infer heads from Q projection shape
    auto q_info = loader_->findTensor("blk.0.attn_q.weight");
    if (!q_info) q_info = loader_->findTensor("blk.0.attn_q.weight");
    
    if (q_info && q_info->shape.size() >= 2) {
        // Q weight shape: [hidden_size, num_heads * head_dim]
        // Or for GQA: [hidden_size, num_kv_heads * head_dim]
        uint64_t q_size = q_info->shape[1];
        
        // Try to infer head_dim (usually 64, 128, or 256)
        for (uint32_t hd : {64, 128, 256}) {
            if (hidden_size_ % hd == 0) {
                uint32_t nh = hidden_size_ / hd;
                if (q_size == nh * hd || q_size == (nh / 4) * hd) { // GQA case
                    head_dim_ = hd;
                    num_heads_ = nh;
                    num_kv_heads_ = (q_size == nh * hd) ? nh : nh / 4;
                    break;
                }
            }
        }
    }
    
    // Default head_dim if not detected
    if (head_dim_ == 0) {
        head_dim_ = 128;
        num_heads_ = hidden_size_ / head_dim_;
        num_kv_heads_ = num_heads_ / 4; // Assume GQA
    }
    
    // Infer intermediate size from gate_proj
    auto gate_info = loader_->findTensor("blk.0.ffn_gate.weight");
    if (!gate_info) gate_info = loader_->findTensor("blk.0.feed_forward.w1.weight");
    
    if (gate_info && gate_info->shape.size() >= 2) {
        intermediate_size_ = static_cast<uint32_t>(gate_info->shape[1]);
    } else {
        // Default: 2.67x hidden size (LLaMA standard)
        intermediate_size_ = hidden_size_ * 8 / 3;
    }
    
    // Context length from metadata or default
    context_length_ = 4096; // Default
    
    std::cout << "Parsed model config:" << std::endl;
    std::cout << "  Architecture: " << model_arch_ << std::endl;
    std::cout << "  Layers: " << num_layers_ << std::endl;
    std::cout << "  Hidden: " << hidden_size_ << std::endl;
    std::cout << "  Heads: " << num_heads_ << " (KV: " << num_kv_heads_ << ")" << std::endl;
    std::cout << "  Head dim: " << head_dim_ << std::endl;
    std::cout << "  Intermediate: " << intermediate_size_ << std::endl;
    std::cout << "  Vocab: " << vocab_size_ << std::endl;
    
    return num_layers_ > 0 && hidden_size_ > 0;
}

void GGUFTransformerLoader::SetupPatterns() {
    if (model_arch_ == "llama" || model_arch_ == "qwen2") {
        patterns_.input_norm = "blk.%d.attn_norm.weight";
        patterns_.post_attn_norm = "blk.%d.ffn_norm.weight";
        patterns_.q_proj = "blk.%d.attn_q.weight";
        patterns_.k_proj = "blk.%d.attn_k.weight";
        patterns_.v_proj = "blk.%d.attn_v.weight";
        patterns_.o_proj = "blk.%d.attn_output.weight";
        patterns_.gate_proj = "blk.%d.ffn_gate.weight";
        patterns_.up_proj = "blk.%d.ffn_up.weight";
        patterns_.down_proj = "blk.%d.ffn_down.weight";
    } else {
        // Default to LLaMA patterns
        patterns_.input_norm = "blk.%d.attn_norm.weight";
        patterns_.post_attn_norm = "blk.%d.ffn_norm.weight";
        patterns_.q_proj = "blk.%d.attn_q.weight";
        patterns_.k_proj = "blk.%d.attn_k.weight";
        patterns_.v_proj = "blk.%d.attn_v.weight";
        patterns_.o_proj = "blk.%d.attn_output.weight";
        patterns_.gate_proj = "blk.%d.ffn_gate.weight";
        patterns_.up_proj = "blk.%d.ffn_up.weight";
        patterns_.down_proj = "blk.%d.ffn_down.weight";
    }
}

std::string GGUFTransformerLoader::GetTensorName(const std::string& pattern, uint32_t layer) {
    char buf[256];
    snprintf(buf, sizeof(buf), pattern.c_str(), layer);
    return std::string(buf);
}

bool GGUFTransformerLoader::LoadTensorData(const std::string& name, std::vector<float>& data) {
    if (!loader_) return false;
    
    auto info = loader_->findTensor(name);
    if (!info) {
        return false;
    }
    
    // Load tensor data
    auto tensor_data = loader_->loadTensor(name);
    if (!tensor_data) {
        return false;
    }
    
    // Convert to float32 if needed
    if (info->type == sovereign::GGMLType::F32) {
        data.resize(tensor_data->size() / sizeof(float));
        std::memcpy(data.data(), tensor_data->data(), tensor_data->size());
    } else if (info->type == sovereign::GGMLType::F16) {
        // Convert F16 to F32
        const uint16_t* f16_data = reinterpret_cast<const uint16_t*>(tensor_data->data());
        size_t num_elements = tensor_data->size() / sizeof(uint16_t);
        data.resize(num_elements);
        for (size_t i = 0; i < num_elements; i++) {
            // Simple F16 to F32 conversion
            uint16_t h = f16_data[i];
            uint32_t sign = (h >> 15) & 1;
            uint32_t exp = (h >> 10) & 0x1F;
            uint32_t mant = h & 0x3FF;
            
            if (exp == 0) {
                data[i] = sign ? -0.0f : 0.0f;
            } else if (exp == 31) {
                data[i] = sign ? -std::numeric_limits<float>::infinity() : std::numeric_limits<float>::infinity();
            } else {
                float f = std::pow(2.0f, static_cast<float>(exp - 15)) * (1.0f + mant / 1024.0f);
                data[i] = sign ? -f : f;
            }
        }
    } else {
        // Quantized types - would need dequantization
        std::cerr << "Quantized tensor loading not yet implemented: " << name << std::endl;
        return false;
    }
    
    return true;
}

bool GGUFTransformerLoader::GetLayerWeights(uint32_t layer_idx, LayerWeights& weights) {
    if (!loader_ || layer_idx >= num_layers_) return false;
    
    // Load each tensor for this layer
    bool success = true;
    
    success &= LoadTensorData(GetTensorName(patterns_.input_norm, layer_idx), weights.input_layernorm);
    success &= LoadTensorData(GetTensorName(patterns_.post_attn_norm, layer_idx), weights.post_attn_layernorm);
    success &= LoadTensorData(GetTensorName(patterns_.q_proj, layer_idx), weights.q_proj);
    success &= LoadTensorData(GetTensorName(patterns_.k_proj, layer_idx), weights.k_proj);
    success &= LoadTensorData(GetTensorName(patterns_.v_proj, layer_idx), weights.v_proj);
    success &= LoadTensorData(GetTensorName(patterns_.o_proj, layer_idx), weights.o_proj);
    success &= LoadTensorData(GetTensorName(patterns_.gate_proj, layer_idx), weights.gate_proj);
    success &= LoadTensorData(GetTensorName(patterns_.up_proj, layer_idx), weights.up_proj);
    success &= LoadTensorData(GetTensorName(patterns_.down_proj, layer_idx), weights.down_proj);
    
    return success;
}

bool GGUFTransformerLoader::GetEmbeddingWeights(std::vector<float>& embeddings) {
    // Try different common names
    if (LoadTensorData("token_embd.weight", embeddings)) return true;
    if (LoadTensorData("tok_embeddings.weight", embeddings)) return true;
    if (LoadTensorData("embed_tokens.weight", embeddings)) return true;
    return false;
}

bool GGUFTransformerLoader::GetOutputWeights(std::vector<float>& weights) {
    if (LoadTensorData("output.weight", weights)) return true;
    if (LoadTensorData("lm_head.weight", weights)) return true;
    return false;
}

bool GGUFTransformerLoader::GetOutputNorm(std::vector<float>& norm) {
    if (LoadTensorData("output_norm.weight", norm)) return true;
    if (LoadTensorData("norm.weight", norm)) return true;
    return false;
}

bool GGUFTransformerLoader::GetTokenizerVocab(std::vector<std::string>& vocab) {
    // Vocab is typically stored as metadata, not tensors
    // This would require parsing GGUF metadata
    // For now, return false
    return false;
}

// ============================================================================
// CompleteModel Implementation
// ============================================================================
bool CompleteModel::Validate() const {
    if (layer_weights.empty()) return false;
    if (token_embeddings.empty()) return false;
    if (config.hidden_size == 0) return false;
    if (config.num_layers == 0) return false;
    
    // Validate each layer has required weights
    for (size_t i = 0; i < layer_weights.size(); i++) {
        const auto& w = layer_weights[i];
        if (w.q_proj.empty() || w.k_proj.empty() || w.v_proj.empty() ||
            w.o_proj.empty() || w.gate_proj.empty() || w.up_proj.empty() ||
            w.down_proj.empty()) {
            std::cerr << "Layer " << i << " missing weights" << std::endl;
            return false;
        }
    }
    
    return true;
}

void CompleteModel::PrintInfo() const {
    std::cout << "Model Information:" << std::endl;
    std::cout << "  Hidden Size: " << config.hidden_size << std::endl;
    std::cout << "  Num Heads: " << config.num_heads << std::endl;
    std::cout << "  Num KV Heads: " << config.num_kv_heads << std::endl;
    std::cout << "  Head Dim: " << config.head_dim << std::endl;
    std::cout << "  Intermediate: " << config.intermediate_size << std::endl;
    std::cout << "  Num Layers: " << config.num_layers << std::endl;
    std::cout << "  Vocab Size: " << config.vocab_size << std::endl;
    std::cout << "  Max Seq Len: " << config.max_seq_len << std::endl;
    std::cout << "  Loaded Layers: " << layer_weights.size() << std::endl;
    
    size_t total_params = 0;
    for (const auto& w : layer_weights) {
        total_params += w.q_proj.size() + w.k_proj.size() + w.v_proj.size() +
                        w.o_proj.size() + w.gate_proj.size() + w.up_proj.size() +
                        w.down_proj.size();
    }
    total_params += token_embeddings.size() + output_norm.size() + lm_head.size();
    
    std::cout << "  Total Parameters: " << (total_params / 1e6) << "M" << std::endl;
}

// ============================================================================
// LoadModelFromGGUF
// ============================================================================
CompleteModel LoadModelFromGGUF(const std::string& path) {
    CompleteModel model;
    
    GGUFTransformerLoader loader;
    if (!loader.LoadFromFile(path, model.config)) {
        std::cerr << "Failed to load model from: " << path << std::endl;
        return model;
    }
    
    // Load embeddings
    if (!loader.GetEmbeddingWeights(model.token_embeddings)) {
        std::cerr << "Warning: Failed to load token embeddings" << std::endl;
    }
    
    // Load output weights
    if (!loader.GetOutputWeights(model.lm_head)) {
        std::cerr << "Warning: Failed to load output weights" << std::endl;
    }
    
    // Load output norm
    if (!loader.GetOutputNorm(model.output_norm)) {
        std::cerr << "Warning: Failed to load output norm" << std::endl;
    }
    
    // Load layer weights
    model.layer_weights.resize(model.config.num_layers);
    for (uint32_t i = 0; i < model.config.num_layers; i++) {
        if (!loader.GetLayerWeights(i, model.layer_weights[i])) {
            std::cerr << "Warning: Failed to load layer " << i << std::endl;
        }
    }
    
    return model;
}

// ============================================================================
// GGUFTransformerRuntime Implementation
// ============================================================================
GGUFTransformerRuntime::GGUFTransformerRuntime() = default;
GGUFTransformerRuntime::~GGUFTransformerRuntime() = default;

bool GGUFTransformerRuntime::InitializeFromGGUF(const std::string& path) {
    model_ = LoadModelFromGGUF(path);
    
    if (!model_.Validate()) {
        std::cerr << "Model validation failed" << std::endl;
        return false;
    }
    
    // Initialize base TransformerRuntime
    if (!Initialize(model_.config, model_.layer_weights)) {
        std::cerr << "Failed to initialize transformer runtime" << std::endl;
        return false;
    }
    
    // Set embeddings and output weights
    token_embedding_ = model_.token_embeddings;
    output_norm_ = model_.output_norm;
    lm_head_ = model_.lm_head;
    
    return true;
}

// ============================================================================
// QuantizedTensor Implementation
// ============================================================================
std::vector<float> QuantizedTensor::Dequantize() const {
    std::vector<float> result;
    
    // Calculate total elements
    uint64_t total_elements = 1;
    for (auto dim : shape) total_elements *= dim;
    
    result.resize(total_elements);
    
    // Dequantize based on type
    switch (type) {
        case sovereign::GGMLType::Q4_0:
            // Q4_0: 4-bit quantized with block size 32
            // Each block: 2 bytes scale + 16 bytes (32 nibbles)
            // TODO: Implement dequantization
            std::cerr << "Q4_0 dequantization not yet implemented" << std::endl;
            break;
            
        case sovereign::GGMLType::Q8_0:
            // Q8_0: 8-bit quantized with block size 32
            // Each block: 4 bytes scale + 32 bytes data
            // TODO: Implement dequantization
            std::cerr << "Q8_0 dequantization not yet implemented" << std::endl;
            break;
            
        default:
            std::cerr << "Unsupported quantized type" << std::endl;
            break;
    }
    
    return result;
}

QuantizedTensor LoadQuantizedTensor(sovereign::StreamingGGUFLoader& loader, 
                                     const std::string& name) {
    QuantizedTensor result;
    
    auto info = loader.findTensor(name);
    if (!info) {
        return result;
    }
    
    result.type = info->type;
    result.shape = info->shape;
    
    auto data = loader.loadTensor(name);
    if (data) {
        result.data.resize(data->size());
        std::memcpy(result.data.data(), data->data(), data->size());
    }
    
    return result;
}

// ============================================================================
// Utility Functions
// ============================================================================
size_t GetGGMLTypeSize(sovereign::GGMLType type) {
    switch (type) {
        case sovereign::GGMLType::F32: return 4;
        case sovereign::GGMLType::F16: return 2;
        case sovereign::GGMLType::Q4_0: return 0; // Variable
        case sovereign::GGMLType::Q4_1: return 0;
        case sovereign::GGMLType::Q5_0: return 0;
        case sovereign::GGMLType::Q5_1: return 0;
        case sovereign::GGMLType::Q8_0: return 0;
        case sovereign::GGMLType::Q8_1: return 0;
        case sovereign::GGMLType::I8: return 1;
        case sovereign::GGMLType::I16: return 2;
        case sovereign::GGMLType::I32: return 4;
        case sovereign::GGMLType::I64: return 8;
        default: return 0;
    }
}

bool IsTypeSupported(sovereign::GGMLType type) {
    switch (type) {
        case sovereign::GGMLType::F32:
        case sovereign::GGMLType::F16:
        case sovereign::GGMLType::I8:
        case sovereign::GGMLType::I16:
        case sovereign::GGMLType::I32:
        case sovereign::GGMLType::I64:
            return true;
        default:
            // Quantized types require dequantization
            return false;
    }
}

std::string DetectModelArchitecture(sovereign::StreamingGGUFLoader& loader) {
    // Check for architecture-specific tensors
    if (loader.findTensor("blk.0.attn_q.weight")) {
        return "llama";
    }
    if (loader.findTensor("transformer.h.0.attn.c_attn.weight")) {
        return "gpt";
    }
    return "unknown";
}

} // namespace transformer
