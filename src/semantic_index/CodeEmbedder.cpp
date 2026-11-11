#include "CodeEmbedder.h"

#include <chrono>
#include <algorithm>
#include <random>
#include <cmath>

#if defined(RAWR_HAS_ONNXRUNTIME) && RAWR_HAS_ONNXRUNTIME
    #include <onnxruntime_cxx_api.h>
    #define USE_ONNX_BACKEND 1
#else
    #define USE_ONNX_BACKEND 0
#endif

namespace rawrxd {

// =============================================================================
// ONNX Runtime Implementation
// =============================================================================
#if USE_ONNX_BACKEND

struct CodeEmbedder::Impl {
    Ort::Env env;
    Ort::SessionOptions session_options;
    std::unique_ptr<Ort::Session> session;
    Ort::MemoryInfo memory_info;
    
    // Tokenizer state (simplified - production would use full WordPiece)
    std::unordered_map<std::string, int32_t> vocab;
    int32_t unk_token_id = 100;
    int32_t cls_token_id = 101;
    int32_t sep_token_id = 102;
    int32_t pad_token_id = 0;
    
    bool model_loaded = false;
    
    explicit Impl(const EmbedderConfig& config) 
        : env(ORT_LOGGING_LEVEL_WARNING, "CodeEmbedder")
        , memory_info(Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault)) {
        
        // Configure session options for performance
        session_options.SetIntraOpNumThreads(config.intra_op_threads);
        session_options.SetInterOpNumThreads(config.inter_op_threads);
        session_options.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_ALL);
        
        // Optional: Enable GPU execution
        if (config.use_gpu) {
            // OrtCUDAProviderOptions cuda_options;
            // session_options.AppendExecutionProvider_CUDA(cuda_options);
        }
    }
    
    bool LoadModel(const std::string& model_path) {
        if (model_path.empty()) return false;
        
        try {
            session = std::make_unique<Ort::Session>(env, model_path.c_str(), session_options);
            model_loaded = true;
            return true;
        } catch (const Ort::Exception& e) {
            // Log error but don't crash - will fall back to stub
            (void)e;
            return false;
        }
    }
    
    // Simple WordPiece-like tokenization (production: use huggingface tokenizer)
    std::vector<int32_t> Tokenize(std::string_view code) {
        std::vector<int32_t> tokens;
        tokens.reserve(128);
        tokens.push_back(cls_token_id);  // [CLS]
        
        // Simple whitespace/punctuation tokenization
        // Production: Full BPE/WordPiece from model vocab
        std::string token;
        for (char c : code) {
            if (std::isspace(c) || std::ispunct(c)) {
                if (!token.empty()) {
                    auto it = vocab.find(token);
                    tokens.push_back(it != vocab.end() ? it->second : unk_token_id);
                    token.clear();
                }
                // Add punctuation as separate token
                if (std::ispunct(c)) {
                    std::string punct(1, c);
                    auto it = vocab.find(punct);
                    tokens.push_back(it != vocab.end() ? it->second : unk_token_id);
                }
            } else {
                token += c;
            }
        }
        if (!token.empty()) {
            auto it = vocab.find(token);
            tokens.push_back(it != vocab.end() ? it->second : unk_token_id);
        }
        
        tokens.push_back(sep_token_id);  // [SEP]
        return tokens;
    }
    
    std::vector<float> RunInference(const std::vector<int32_t>& tokens, int embedding_dim) {
        const size_t seq_length = tokens.size();
        const size_t batch_size = 1;
        
        // Create input tensors
        std::vector<int64_t> input_shape = {static_cast<int64_t>(batch_size), static_cast<int64_t>(seq_length)};
        
        // Input IDs
        std::vector<int64_t> input_ids(seq_length);
        for (size_t i = 0; i < seq_length; ++i) {
            input_ids[i] = static_cast<int64_t>(tokens[i]);
        }
        Ort::Value input_ids_tensor = Ort::Value::CreateTensor<int64_t>(
            memory_info, input_ids.data(), input_ids.size(), input_shape.data(), input_shape.size());
        
        // Attention mask (all 1s for now - no padding)
        std::vector<int64_t> attention_mask(seq_length, 1);
        Ort::Value attention_mask_tensor = Ort::Value::CreateTensor<int64_t>(
            memory_info, attention_mask.data(), attention_mask.size(), input_shape.data(), input_shape.size());
        
        // Run inference
        const char* input_names[] = {"input_ids", "attention_mask"};
        const char* output_names[] = {"last_hidden_state"};
        std::vector<Ort::Value> input_tensors;
        input_tensors.push_back(std::move(input_ids_tensor));
        input_tensors.push_back(std::move(attention_mask_tensor));
        
        auto output_tensors = session->Run(
            Ort::RunOptions{nullptr},
            input_names, input_tensors.data(), input_tensors.size(),
            output_names, 1
        );
        
        // Extract and mean pool the output
        // Output shape: [batch_size, seq_length, hidden_size]
        Ort::Value& output = output_tensors[0];
        float* output_data = output.GetTensorMutableData<float>();
        
        // Get tensor shape
        Ort::TensorTypeAndShapeInfo shape_info = output.GetTensorTypeAndShapeInfo();
        std::vector<int64_t> output_shape = shape_info.GetShape();
        
        if (output_shape.size() < 3) {
            return std::vector<float>(embedding_dim, 0.0f);
        }
        
        const int64_t out_seq_length = output_shape[1];
        const int64_t hidden_size = output_shape[2];
        
        // Mean pooling across sequence length (excluding [CLS] and [SEP])
        std::vector<float> pooled(hidden_size, 0.0f);
        int valid_tokens = 0;
        
        for (int64_t i = 1; i < out_seq_length - 1; ++i) {  // Skip [CLS] and [SEP]
            for (int64_t j = 0; j < hidden_size; ++j) {
                pooled[j] += output_data[i * hidden_size + j];
            }
            valid_tokens++;
        }
        
        if (valid_tokens > 0) {
            for (auto& v : pooled) {
                v /= valid_tokens;
            }
        }
        
        // Project to embedding dimension if needed (hidden_size -> 384)
        std::vector<float> embedding(embedding_dim);
        if (hidden_size == embedding_dim) {
            embedding = std::move(pooled);
        } else {
            // Simple truncation/padding (production: use projection layer)
            for (int i = 0; i < embedding_dim && i < hidden_size; ++i) {
                embedding[i] = pooled[i];
            }
        }
        
        // L2 normalize
        float norm = 0.0f;
        for (float v : embedding) {
            norm += v * v;
        }
        norm = std::sqrt(norm);
        if (norm > 0.0f) {
            for (float& v : embedding) {
                v /= norm;
            }
        }
        
        return embedding;
    }
};

CodeEmbedder::CodeEmbedder(const EmbedderConfig& config) 
    : m_impl(std::make_unique<Impl>(config))
    , m_config(config) {
    // Lazy loading - model loaded on first Embed() or explicit PreloadModel()
}

CodeEmbedder::~CodeEmbedder() = default;

CodeEmbedder::CodeEmbedder(CodeEmbedder&& other) noexcept
    : m_impl(std::move(other.m_impl))
    , m_config(other.m_config)
    , m_last_latency_ms(other.m_last_latency_ms)
    , m_model_loaded(other.m_model_loaded) {
}

CodeEmbedder& CodeEmbedder::operator=(CodeEmbedder&& other) noexcept {
    if (this != &other) {
        m_impl = std::move(other.m_impl);
        m_config = other.m_config;
        m_last_latency_ms = other.m_last_latency_ms;
        m_model_loaded = other.m_model_loaded;
    }
    return *this;
}

bool CodeEmbedder::IsLoaded() const {
    return m_model_loaded && m_impl && m_impl->model_loaded;
}

float CodeEmbedder::GetLastLatencyMs() const {
    return m_last_latency_ms;
}

bool CodeEmbedder::PreloadModel() {
    if (!m_impl || m_model_loaded) return m_model_loaded;
    
    m_model_loaded = m_impl->LoadModel(m_config.model_path);
    return m_model_loaded;
}

std::vector<float> CodeEmbedder::Embed(std::string_view code) {
    auto start = std::chrono::steady_clock::now();
    
    // Lazy load model
    if (!m_model_loaded) {
        PreloadModel();
    }
    
    if (!IsLoaded()) {
        // Fallback: return zero vector
        m_last_latency_ms = 0.0f;
        return std::vector<float>(m_config.embedding_dimension, 0.0f);
    }
    
    // Tokenize
    auto tokens = m_impl->Tokenize(code);
    
    // Truncate if needed
    if (tokens.size() > static_cast<size_t>(m_config.max_sequence_length)) {
        tokens.resize(m_config.max_sequence_length - 1);
        tokens.push_back(m_impl->sep_token_id);
    }
    
    // Run inference
    auto embedding = m_impl->RunInference(tokens, m_config.embedding_dimension);
    
    auto elapsed = std::chrono::steady_clock::now() - start;
    m_last_latency_ms = std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count() / 1000.0f;
    
    return embedding;
}

#else
// =============================================================================
// Stub Implementation (ONNX Runtime not available)
// =============================================================================

struct CodeEmbedder::Impl {
    // Empty stub - no ONNX Runtime
};

CodeEmbedder::CodeEmbedder(const EmbedderConfig& config) 
    : m_impl(nullptr)
    , m_config(config) {
}

CodeEmbedder::~CodeEmbedder() = default;
CodeEmbedder::CodeEmbedder(CodeEmbedder&&) noexcept = default;
CodeEmbedder& CodeEmbedder::operator=(CodeEmbedder&&) noexcept = default;

bool CodeEmbedder::IsLoaded() const { return false; }
float CodeEmbedder::GetLastLatencyMs() const { return 0.0f; }
bool CodeEmbedder::PreloadModel() { return false; }

std::vector<float> CodeEmbedder::Embed(std::string_view code) {
    (void)code;
    // Return zero vector when ONNX is not available
    return std::vector<float>(m_config.embedding_dimension, 0.0f);
}

#endif  // USE_ONNX_BACKEND

// =============================================================================
// Stub Embedder (Deterministic fallback)
// =============================================================================

std::vector<float> StubCodeEmbedder::Embed(std::string_view code) {
    std::vector<float> vec(dimension);
    
    // Generate deterministic pseudo-embeddings based on text hash
    size_t hash = std::hash<std::string_view>{}(code);
    std::uniform_real_distribution<float> dist(-1.0f, 1.0f);
    
    for (int i = 0; i < dimension; ++i) {
        hash = hash * 31 + i;
        rng.seed(static_cast<unsigned>(hash));
        vec[i] = dist(rng);
    }
    
    // L2 normalize
    float norm = 0.0f;
    for (float v : vec) norm += v * v;
    norm = std::sqrt(norm);
    if (norm > 0) {
        for (float& v : vec) v /= norm;
    }
    
    return vec;
}

} // namespace rawrxd
