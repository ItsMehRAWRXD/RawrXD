// ============================================================================
// RawrXD Model Loader - Implementation
// ============================================================================

#include "ModelLoader.hpp"
#include <cstring>
#include <cmath>
#include <algorithm>
#include <random>

namespace rawrxd {
namespace model {

// ============================================================================
// Quantized Block Structures
// ============================================================================

#pragma pack(push, 1)
struct block_q4_0 {
    uint16_t d;
    uint8_t qs[16];
};

struct block_q4_1 {
    uint16_t d;
    uint16_t m;
    uint8_t qs[16];
};

struct block_q8_0 {
    uint16_t d;
    int8_t qs[32];
};
#pragma pack(pop)

// ============================================================================
// ModelLoader Implementation
// ============================================================================

ModelLoader::ModelLoader() = default;
ModelLoader::~ModelLoader() {
    if (file_.is_open()) {
        file_.close();
    }
}

bool ModelLoader::Load(const std::string& path) {
    path_ = path;
    file_.open(path, std::ios::binary);
    if (!file_) {
        last_error_ = "Failed to open file: " + path;
        return false;
    }
    
    if (!ParseHeader()) return false;
    if (!ParseMetadata()) return false;
    if (!ParseTensorInfo()) return false;
    
    // Calculate data offset (aligned to 32 bytes)
    data_offset_ = file_.tellg();
    data_offset_ = (data_offset_ + 31) & ~31;
    
    is_loaded_ = true;
    return true;
}

bool ModelLoader::ParseHeader() {
    GGUFHeader header;
    file_.read(reinterpret_cast<char*>(&header), sizeof(header));
    
    if (header.magic != 0x46554747) { // 'GGUF' in little-endian
        last_error_ = "Invalid GGUF magic";
        return false;
    }
    
    version_ = header.version;
    return true;
}

bool ModelLoader::ParseMetadata() {
    // Read metadata count from header
    file_.seekg(0);
    GGUFHeader header;
    file_.read(reinterpret_cast<char*>(&header), sizeof(header));
    
    for (uint64_t i = 0; i < header.metadata_kv_count; i++) {
        // Read key length and key
        uint64_t key_len;
        file_.read(reinterpret_cast<char*>(&key_len), sizeof(key_len));
        std::string key(key_len, '\0');
        if (key_len > 0) {
            file_.read(&key[0], key_len);
        }
        
        // Read value type
        uint32_t val_type;
        file_.read(reinterpret_cast<char*>(&val_type), sizeof(val_type));
        
        // Parse value based on type
        switch (val_type) {
            case 4: { // UINT32
                uint32_t val;
                file_.read(reinterpret_cast<char*>(&val), sizeof(val));
                if (key == "llama.block_count") arch_.num_layers = val;
                else if (key == "llama.context_length") arch_.max_position = val;
                else if (key == "llama.embedding_length") arch_.hidden_size = val;
                else if (key == "llama.attention.head_count") arch_.num_heads = val;
                else if (key == "llama.attention.head_count_kv") arch_.num_kv_heads = val;
                else if (key == "llama.feed_forward_length") arch_.intermediate_size = val;
                break;
            }
            case 8: { // STRING
                uint64_t str_len;
                file_.read(reinterpret_cast<char*>(&str_len), sizeof(str_len));
                std::string val(str_len, '\0');
                if (str_len > 0) file_.read(&val[0], str_len);
                if (key == "general.architecture") arch_.name = val;
                break;
            }
            case 6: { // FLOAT32
                float val;
                file_.read(reinterpret_cast<char*>(&val), sizeof(val));
                if (key == "llama.rope.freq_base") arch_.rope_theta = val;
                else if (key == "llama.attention.layer_norm_rms_epsilon") arch_.rms_norm_eps = val;
                break;
            }
            default:
                // Skip unknown types
                break;
        }
    }
    
    return true;
}

bool ModelLoader::ParseTensorInfo() {
    file_.seekg(0);
    GGUFHeader header;
    file_.read(reinterpret_cast<char*>(&header), sizeof(header));
    
    // Skip metadata
    for (uint64_t i = 0; i < header.metadata_kv_count; i++) {
        uint64_t key_len;
        file_.read(reinterpret_cast<char*>(&key_len), sizeof(key_len));
        file_.seekg(key_len, std::ios::cur);
        uint32_t val_type;
        file_.read(reinterpret_cast<char*>(&val_type), sizeof(val_type));
        // Skip value based on type...
        if (val_type == 4) file_.seekg(4, std::ios::cur);
        else if (val_type == 8) {
            uint64_t str_len;
            file_.read(reinterpret_cast<char*>(&str_len), sizeof(str_len));
            file_.seekg(str_len, std::ios::cur);
        }
        else if (val_type == 6) file_.seekg(4, std::ios::cur);
    }
    
    // Read tensor info
    tensors_.reserve(header.tensor_count);
    for (uint64_t i = 0; i < header.tensor_count; i++) {
        TensorInfo info;
        
        // Read name
        uint64_t name_len;
        file_.read(reinterpret_cast<char*>(&name_len), sizeof(name_len));
        info.name.resize(name_len);
        if (name_len > 0) {
            file_.read(&info.name[0], name_len);
        }
        
        // Read dimensions
        uint32_t n_dims;
        file_.read(reinterpret_cast<char*>(&n_dims), sizeof(n_dims));
        info.dimensions.resize(n_dims);
        for (uint32_t d = 0; d < n_dims; d++) {
            file_.read(reinterpret_cast<char*>(&info.dimensions[d]), sizeof(uint64_t));
        }
        
        // Read type and offset
        uint32_t type;
        file_.read(reinterpret_cast<char*>(&type), sizeof(type));
        info.type = static_cast<GGMLType>(type);
        file_.read(reinterpret_cast<char*>(&info.offset), sizeof(info.offset));
        
        // Calculate size
        info.size = CalculateTensorSize(info);
        
        tensor_map_[info.name] = tensors_.size();
        tensors_.push_back(info);
    }
    
    return true;
}

uint64_t ModelLoader::CalculateTensorSize(const TensorInfo& info) const {
    uint64_t n = info.num_elements();
    switch (info.type) {
        case GGMLType::F32: return n * 4;
        case GGMLType::F16: return n * 2;
        case GGMLType::Q4_0: return (n / 32) * sizeof(block_q4_0);
        case GGMLType::Q4_1: return (n / 32) * sizeof(block_q4_1);
        case GGMLType::Q8_0: return (n / 32) * sizeof(block_q8_0);
        default: return n * 4;
    }
}

const TensorInfo* ModelLoader::GetTensor(const std::string& name) const {
    auto it = tensor_map_.find(name);
    if (it != tensor_map_.end()) {
        return &tensors_[it->second];
    }
    return nullptr;
}

std::vector<uint8_t> ModelLoader::LoadRawTensorData(const TensorInfo& info) {
    std::vector<uint8_t> data(info.size);
    file_.seekg(data_offset_ + info.offset);
    file_.read(reinterpret_cast<char*>(data.data()), info.size);
    return data;
}

float ModelLoader::FP16ToFP32(uint16_t h) const {
    // Simplified FP16 to FP32 conversion
    uint32_t sign = (h >> 15) & 0x1;
    uint32_t exp = (h >> 10) & 0x1F;
    uint32_t mant = h & 0x3FF;
    
    if (exp == 0) {
        return sign ? -0.0f : 0.0f;
    } else if (exp == 31) {
        return sign ? -INFINITY : INFINITY;
    }
    
    uint32_t f32 = (sign << 31) | ((exp + 112) << 23) | (mant << 13);
    return *reinterpret_cast<float*>(&f32);
}

void ModelLoader::DequantizeQ4_0(const uint8_t* src, float* dst, size_t n) {
    const block_q4_0* blocks = reinterpret_cast<const block_q4_0*>(src);
    size_t nb = n / 32;
    
    for (size_t i = 0; i < nb; i++) {
        float d = FP16ToFP32(blocks[i].d);
        for (int j = 0; j < 16; j++) {
            int x0 = (blocks[i].qs[j] & 0x0F) - 8;
            int x1 = (blocks[i].qs[j] >> 4) - 8;
            dst[i*32 + j] = x0 * d;
            dst[i*32 + 16 + j] = x1 * d;
        }
    }
}

void ModelLoader::DequantizeQ4_1(const uint8_t* src, float* dst, size_t n) {
    const block_q4_1* blocks = reinterpret_cast<const block_q4_1*>(src);
    size_t nb = n / 32;
    
    for (size_t i = 0; i < nb; i++) {
        float d = FP16ToFP32(blocks[i].d);
        float m = FP16ToFP32(blocks[i].m);
        for (int j = 0; j < 16; j++) {
            int x0 = blocks[i].qs[j] & 0x0F;
            int x1 = blocks[i].qs[j] >> 4;
            dst[i*32 + j] = x0 * d + m;
            dst[i*32 + 16 + j] = x1 * d + m;
        }
    }
}

void ModelLoader::DequantizeQ8_0(const uint8_t* src, float* dst, size_t n) {
    const block_q8_0* blocks = reinterpret_cast<const block_q8_0*>(src);
    size_t nb = n / 32;
    
    for (size_t i = 0; i < nb; i++) {
        float d = FP16ToFP32(blocks[i].d);
        for (int j = 0; j < 32; j++) {
            dst[i*32 + j] = blocks[i].qs[j] * d;
        }
    }
}

std::vector<float> ModelLoader::LoadTensorData(const std::string& name) {
    const TensorInfo* info = GetTensor(name);
    if (!info) return {};
    
    auto raw = LoadRawTensorData(*info);
    std::vector<float> result(info->num_elements());
    
    switch (info->type) {
        case GGMLType::F32:
            std::memcpy(result.data(), raw.data(), result.size() * sizeof(float));
            break;
        case GGMLType::F16:
            for (size_t i = 0; i < result.size(); i++) {
                uint16_t val;
                std::memcpy(&val, raw.data() + i*2, 2);
                result[i] = FP16ToFP32(val);
            }
            break;
        case GGMLType::Q4_0:
            DequantizeQ4_0(raw.data(), result.data(), result.size());
            break;
        case GGMLType::Q4_1:
            DequantizeQ4_1(raw.data(), result.data(), result.size());
            break;
        case GGMLType::Q8_0:
            DequantizeQ8_0(raw.data(), result.data(), result.size());
            break;
        default:
            last_error_ = "Unsupported tensor type";
            return {};
    }
    
    return result;
}

void ModelLoader::PrintInfo() const {
    std::cout << "Model: " << arch_.name << "\n";
    std::cout << "  Vocab size: " << arch_.vocab_size << "\n";
    std::cout << "  Hidden size: " << arch_.hidden_size << "\n";
    std::cout << "  Layers: " << arch_.num_layers << "\n";
    std::cout << "  Heads: " << arch_.num_heads << "\n";
    std::cout << "  KV Heads: " << arch_.num_kv_heads << "\n";
    std::cout << "  Intermediate: " << arch_.intermediate_size << "\n";
    std::cout << "  Max position: " << arch_.max_position << "\n";
    std::cout << "  Tensors: " << tensors_.size() << "\n";
}

// ============================================================================
// SimpleTokenizer Implementation
// ============================================================================

SimpleTokenizer::SimpleTokenizer() {
    // Initialize with basic vocabulary
    vocab_.push_back("<pad>");
    vocab_.push_back("</eos>");
    vocab_.push_back("<unk>");
    
    // Add basic tokens
    for (int i = 0; i < 256; i++) {
        vocab_.push_back(std::string(1, static_cast<char>(i)));
    }
    
    // Build token map
    for (size_t i = 0; i < vocab_.size(); i++) {
        token_to_id_[vocab_[i]] = static_cast<int>(i);
    }
}

bool SimpleTokenizer::LoadVocabulary(const std::string& path) {
    // TODO: Load actual vocabulary from file
    return true;
}

std::vector<int> SimpleTokenizer::Encode(const std::string& text) const {
    std::vector<int> tokens;
    for (char c : text) {
        auto it = token_to_id_.find(std::string(1, c));
        if (it != token_to_id_.end()) {
            tokens.push_back(it->second);
        } else {
            tokens.push_back(2); // <unk>
        }
    }
    return tokens;
}

std::string SimpleTokenizer::Decode(const std::vector<int>& tokens) const {
    std::string text;
    for (int token : tokens) {
        if (token >= 0 && token < static_cast<int>(vocab_.size())) {
            text += vocab_[token];
        }
    }
    return text;
}

// ============================================================================
// InferenceContext Implementation
// ============================================================================

InferenceContext::InferenceContext(ModelLoader* model) : model_(model) {}

bool InferenceContext::Initialize() {
    if (!model_ || !model_->IsLoaded()) {
        last_error_ = "Model not loaded";
        return false;
    }
    
    const auto& arch = model_->GetArchitecture();
    
    // Allocate KV cache
    size_t kv_size = static_cast<size_t>(arch.num_layers) * arch.max_position * 
                     arch.num_kv_heads * (arch.hidden_size / arch.num_heads);
    k_cache_.resize(kv_size, 0.0f);
    v_cache_.resize(kv_size, 0.0f);
    
    // Allocate working buffers
    hidden_states_.resize(arch.hidden_size);
    attention_output_.resize(arch.hidden_size);
    
    return true;
}

void InferenceContext::Softmax(std::vector<float>& values) {
    float max_val = *std::max_element(values.begin(), values.end());
    float sum = 0.0f;
    for (auto& v : values) {
        v = std::exp(v - max_val);
        sum += v;
    }
    for (auto& v : values) {
        v /= sum;
    }
}

void InferenceContext::TopKFilter(std::vector<float>& logits, int k) {
    std::vector<std::pair<float, size_t>> indexed;
    for (size_t i = 0; i < logits.size(); i++) {
        indexed.push_back({logits[i], i});
    }
    
    std::partial_sort(indexed.begin(), indexed.begin() + k, indexed.end(),
                      std::greater<std::pair<float, size_t>>());
    
    float min_keep = indexed[k-1].first;
    for (auto& logit : logits) {
        if (logit < min_keep) logit = -INFINITY;
    }
}

void InferenceContext::TopPFilter(std::vector<float>& logits, float p) {
    std::vector<std::pair<float, size_t>> indexed;
    for (size_t i = 0; i < logits.size(); i++) {
        indexed.push_back({logits[i], i});
    }
    
    std::sort(indexed.begin(), indexed.end(), 
              std::greater<std::pair<float, size_t>>());
    
    float cumsum = 0.0f;
    size_t last_idx = 0;
    for (size_t i = 0; i < indexed.size(); i++) {
        cumsum += std::exp(indexed[i].first);
        if (cumsum > p) {
            last_idx = i;
            break;
        }
    }
    
    float min_keep = indexed[last_idx].first;
    for (auto& logit : logits) {
        if (logit < min_keep) logit = -INFINITY;
    }
}

int InferenceContext::SampleToken(const std::vector<float>& logits, 
                                     float temperature, float top_p, int top_k) {
    std::vector<float> probs = logits;
    
    // Apply temperature
    for (auto& p : probs) {
        p /= temperature;
    }
    
    // Apply top-k filtering
    if (top_k > 0 && top_k < static_cast<int>(probs.size())) {
        TopKFilter(probs, top_k);
    }
    
    // Apply top-p filtering
    if (top_p < 1.0f) {
        TopPFilter(probs, top_p);
    }
    
    // Softmax
    Softmax(probs);
    
    // Sample
    std::random_device rd;
    std::mt19937 gen(rd());
    std::discrete_distribution<> dist(probs.begin(), probs.end());
    return dist(gen);
}

std::vector<int> InferenceContext::Generate(const std::vector<int>& input_tokens,
                                               const InferenceConfig& config) {
    std::vector<int> output_tokens = input_tokens;
    
    // Simple generation loop (placeholder)
    for (int i = 0; i < config.max_tokens; i++) {
        // TODO: Implement actual transformer forward pass
        // For now, just generate random tokens
        std::vector<float> logits(model_->GetArchitecture().vocab_size);
        for (auto& l : logits) {
            l = static_cast<float>(rand()) / RAND_MAX;
        }
        
        int next_token = SampleToken(logits, config.temperature, 
                                      config.top_p, config.top_k);
        output_tokens.push_back(next_token);
        
        if (next_token == 1) break; // </eos>
    }
    
    return output_tokens;
}

// ============================================================================
// Vocabulary Extraction
// ============================================================================

uint64_t ComputeVocabHash(const std::vector<std::string>& vocab) {
    // Compute hash of vocabulary for proof metadata
    // Uses FNV-1a hash combined with token hashes
    uint64_t hash = 0xcbf29ce484222325ULL; // FNV offset basis
    
    for (const auto& token : vocab) {
        // Hash each token
        for (uint8_t c : token) {
            hash ^= c;
            hash *= 0x100000001b3ULL;
        }
        // Separator between tokens
        hash ^= 0xFF;
        hash *= 0x100000001b3ULL;
    }
    
    return hash;
}

uint64_t ExtractVocabHash(const std::string& gguf_path) {
    // Extract vocabulary and compute hash
    auto vocab = ExtractVocabulary(gguf_path);
    if (vocab.empty()) return 0;
    
    return ComputeVocabHash(vocab);
}

std::vector<std::string> ExtractVocabulary(const std::string& gguf_path) {
    std::vector<std::string> vocab;
    
    // Load model to get vocab size
    ModelLoader loader;
    if (!loader.Load(gguf_path)) {
        return vocab;
    }
    
    const auto& arch = loader.GetArchitecture();
    vocab.reserve(arch.vocab_size);
    
    // Try to extract actual vocabulary from GGUF metadata
    // Look for tokenizer.ggml.tokens or similar keys
    // For now, create numbered tokens as placeholder
    // Real implementation would parse tokenizer.model section
    
    // Add special tokens first
    vocab.push_back("<unk>");
    vocab.push_back("<s>");
    vocab.push_back("</s>");
    vocab.push_back("<pad>");
    
    // Add numbered tokens
    for (uint32_t i = 4; i < arch.vocab_size; ++i) {
        vocab.push_back("token_" + std::to_string(i));
    }
    
    return vocab;
}

// Extract vocabulary with merge rules for BPE
bool ExtractVocabAndMerges(const std::string& gguf_path,
                          std::vector<std::string>& vocab,
                          std::vector<std::pair<std::string, std::string>>& merges) {
    vocab.clear();
    merges.clear();
    
    // Load model
    ModelLoader loader;
    if (!loader.Load(gguf_path)) {
        return false;
    }
    
    const auto& arch = loader.GetArchitecture();
    
    // Extract vocabulary
    vocab = ExtractVocabulary(gguf_path);
    if (vocab.empty()) return false;
    
    // Extract merge rules
    // Real implementation would parse tokenizer.ggml.merges
    // For now, return empty merges (character-level BPE)
    
    return true;
}

} // namespace model
} // namespace rawrxd
