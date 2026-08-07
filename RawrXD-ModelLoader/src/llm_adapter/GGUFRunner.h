#pragma once
<<<<<<< HEAD
/**
 * GGUFRunner — C++20 only, no Qt. GGUF model loading and inference.
 */

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

// GGML tensor types
enum class GgmlType : uint32_t {
=======
#include <QHash>

#include <QObject>
#include <QString>

#include <QVector>
#include <QtGlobal>

#include <cstddef>
#include <vector>

// GGML tensor types
enum class GgmlType : quint32 {
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    F32  = 0,
    F16  = 1,
    Q4_0 = 2,
    Q4_1 = 3,
    Q5_0 = 6,
    Q5_1 = 7,
    Q8_0 = 8,
    Q8_1 = 9
};

// Q4_0 block: 32 weights in 16 bytes + 1 float16 delta
struct BlockQ4_0 {
<<<<<<< HEAD
    uint16_t d;      // delta (float16)
    uint8_t qs[16];  // 32 nibbles (2 per byte)
=======
    quint16 d;      // delta (float16)
    quint8 qs[16];  // 32 nibbles (2 per byte)
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
};

// Q8_0 block: 32 weights in 32 bytes + 1 float16 delta
struct BlockQ8_0 {
<<<<<<< HEAD
    uint16_t d;      // delta (float16)
    int8_t qs[32];   // 32 signed bytes
};

/**
 * @brief GGUFRunner manages high-performance execution of GGUF language models (C++20, no Qt).
 */
class GGUFRunner {
public:
    using TokenChunkCallback = std::function<void(const std::string&)>;
    using InferenceCompleteCallback = std::function<void(bool)>;
    using ModelLoadedCallback = std::function<void(const std::string& path, int64_t sizeBytes)>;
    using LoadingProgressCallback = std::function<void(int)>;

    GGUFRunner();
    ~GGUFRunner();

    bool runInference(const std::string& prompt, float* outputBuffer);
    bool loadModel(const std::string& filePath);

    void setMaxTokens(int max) { context_.maxTokens = max; }
    void setTemperature(float temp) { context_.temperature = (temp >= 0.0f ? temp : 0.0f); }
    void setTopP(float p) { context_.topP = (p < 0.0f ? 0.0f : (p > 1.0f ? 1.0f : p)); }
    void setRepeatPenalty(float penalty) { context_.repeatPenalty = (penalty >= 1.0f ? penalty : 1.0f); }

    std::string modelPath() const { return context_.modelPath; }
    std::string modelName() const { return context_.modelName; }
    std::string architecture() const { return context_.architecture; }
    size_t vocabularySize() const { return context_.vocabSize; }
    size_t embeddingDim() const { return context_.embedDim; }
    bool isLoaded() const { return context_.mappedData != nullptr; }

    /** Callbacks (replace Qt signals) */
    void setOnTokenChunk(TokenChunkCallback cb) { onTokenChunk_ = std::move(cb); }
    void setOnInferenceComplete(InferenceCompleteCallback cb) { onInferenceComplete_ = std::move(cb); }
    void setOnModelLoaded(ModelLoadedCallback cb) { onModelLoaded_ = std::move(cb); }
    void setOnLoadingProgress(LoadingProgressCallback cb) { onLoadingProgress_ = std::move(cb); }

    static std::vector<uint8_t> compressBrutal(const void* data, size_t len);

private:
    enum class QuantType { F32, F16, Q4_0, Q4_1, Q5_0, Q5_1, Q8_0 };

    struct ModelContext {
        bool hasAVX2{false};
        bool hasAVX512{false};
        bool hasFMA{false};
        float* mappedData{nullptr};
        bool usesMmap{false};
        size_t embedDim{0};
        size_t vocabSize{0};
        size_t nLayers{0};
        size_t nHeads{0};
        size_t nKVHeads{0};
        size_t headDim{0};
        float ropeBase{10000.0f};
        std::vector<float> invFreq;
        int64_t modelFileSize{0};
        std::vector<float> logits;
        std::vector<std::string> vocabulary;
        std::string modelPath;
        int maxTokens{64};
        int eosTokenId{-1};
        float temperature{0.8f};
        float topP{0.95f};
        float repeatPenalty{1.1f};
        QuantType quantType{QuantType::F32};
        uint32_t ggufVersion{0};
        std::string modelName;
        std::string architecture;
        std::vector<float> tok_embeddings;
        std::vector<float> output_norm_w;
        std::vector<float> output_w;
        std::vector<uint8_t> raw_q4_output;
        std::vector<int8_t> raw_q8_output;
        std::vector<float> ln_f_g;
        std::vector<float> ln_f_b;
        struct Layer {
            std::vector<float> attn_q_w, attn_k_w, attn_v_w, attn_o_w;
            std::vector<float> ln_1_g, ln_1_b, ln_2_g, ln_2_b;
            std::vector<float> mlp_up_w, mlp_gate_w, mlp_down_w;
        };
        std::vector<Layer> layers;
        std::vector<float> keyCache;
        std::vector<float> valueCache;
        size_t kvLen{0};
        struct TensorDesc { std::string name; std::vector<uint32_t> dims; GgmlType type; uint64_t offset; };
        std::unordered_map<std::string, TensorDesc> tensorTable;
    };

    TokenChunkCallback onTokenChunk_;
    InferenceCompleteCallback onInferenceComplete_;
    ModelLoadedCallback onModelLoaded_;
    LoadingProgressCallback onLoadingProgress_;

    void checkCpuFeatures();
    void loadGGUFModel(const std::string& filePath);
    void loadVocabulary(const std::string& vocabPath);
    float* getLayerWeights();
    bool prepareLLMInput(const std::string& prompt, std::vector<float>& embeddings);
=======
    quint16 d;      // delta (float16)
    qint8 qs[32];   // 32 signed bytes
};

/**
 * @brief GGUFRunner manages the high-performance execution of GGUF language models.
 */
class GGUFRunner : public QObject {
    Q_OBJECT

public:
    explicit GGUFRunner(QObject* parent = nullptr);
    ~GGUFRunner();

    /**
     * @brief Executes a full inference pass using the raw text prompt.
     * @param prompt Raw UTF-8 prompt that will be tokenized and embedded internally.
     * @param outputBuffer Buffer that will receive the logits (size must match vocab).
     */
    bool runInference(const QString& prompt, float* outputBuffer);
    
    // Model loading
    bool loadModel(const QString& filePath);
    
    // Generation parameter setters
    void setMaxTokens(int max) { context_.maxTokens = max; }
    void setTemperature(float temp) { context_.temperature = qMax(0.0f, temp); }
    void setTopP(float p) { context_.topP = qBound(0.0f, p, 1.0f); }
    void setRepeatPenalty(float penalty) { context_.repeatPenalty = qMax(1.0f, penalty); }
    
    // Model info getters
    QString modelPath() const { return context_.modelPath; }
    QString modelName() const { return context_.modelName; }
    QString architecture() const { return context_.architecture; }
    qsizetype vocabularySize() const { return context_.vocabSize; }
    qsizetype embeddingDim() const { return context_.embedDim; }
    bool isLoaded() const { return context_.mappedData != nullptr; }

    /**
     * @brief Compresses a raw buffer using the "Brutal" stored-block algorithm.
     *        This is extremely fast (0.2ms/MB) but offers no compression ratio.
     *        Useful for wrapping data in gzip format for compatibility without CPU cost.
     * @param data Pointer to raw data
     * @param len Length of data
     * @return QByteArray containing the gzip stream
     */
    static QByteArray compressBrutal(const void* data, size_t len);

signals:
    void tokenChunkGenerated(const QString& chunk);
    void inferenceComplete(bool success);
    void modelLoaded(const QString& path, qint64 sizeBytes);
    void loadingProgress(int percent);

private:
    enum class QuantType {
        F32,      // Full precision (13 GB for 7B)
        F16,      // Half precision (6.5 GB)
        Q4_0,     // 4-bit quantization (3.5 GB) - llama.cpp standard
        Q4_1,     // 4-bit with min/max (slightly better quality)
        Q5_0,     // 5-bit quantization (4.3 GB)
        Q5_1,     // 5-bit with min/max
        Q8_0      // 8-bit quantization (6.7 GB)
    };

    struct ModelContext {
        // Hardware features
        bool hasAVX2{false};
        bool hasAVX512{false};
        bool hasFMA{false};
        
        // Memory management
        float* mappedData{nullptr};
        bool usesMmap{false};
        qsizetype embedDim{0};
        qsizetype vocabSize{0};
        qsizetype nLayers{0};
        qsizetype nHeads{0};
        qsizetype nKVHeads{0};
        qsizetype headDim{0};       // embedDim / nHeads
        float ropeBase{10000.0f};   // RoPE frequency base
        std::vector<float> invFreq; // Precomputed inverse frequencies for RoPE [headDim/2]
        qint64 modelFileSize{0};
        
        // Inference state
        std::vector<float> logits;
        QVector<QString> vocabulary;
        QString modelPath;
        
        // Generation parameters
        int maxTokens{64};
        int eosTokenId{-1};
        float temperature{0.8f};     // 0.0 = greedy, 1.0 = creative, 2.0 = chaos
        float topP{0.95f};           // nucleus sampling threshold
        float repeatPenalty{1.1f};   // penalize token repetition
        
        // Quantization
        QuantType quantType{QuantType::F32};
        
        // GGUF metadata
        uint32_t ggufVersion{0};
        QString modelName;
        QString architecture;

        // GGUF tensors (essential weights)
        std::vector<float> tok_embeddings;           // [vocabSize, embedDim]
        std::vector<float> output_norm_w;            // output norm weight
        std::vector<float> output_w;                 // output projection weight
        std::vector<uint8_t> raw_q4_output;          // raw Q4_0 bytes for output.weight (optional)
        std::vector<int8_t> raw_q8_output;           // raw Q8_0 bytes for output.weight (optional)
        std::vector<float> ln_f_g;                   // final layernorm gamma [embedDim]
        std::vector<float> ln_f_b;                   // final layernorm beta [embedDim]

        struct Layer {
            // Attention projections: [embedDim, embedDim]
            std::vector<float> attn_q_w;
            std::vector<float> attn_k_w;
            std::vector<float> attn_v_w;
            std::vector<float> attn_o_w;
            // LayerNorm params
            std::vector<float> ln_1_g;
            std::vector<float> ln_1_b;
            std::vector<float> ln_2_g;
            std::vector<float> ln_2_b;
            // MLP (SwiGLU): up, gate, down: [embedDim, 4*embedDim] and [4*embedDim, embedDim]
            std::vector<float> mlp_up_w;
            std::vector<float> mlp_gate_w;
            std::vector<float> mlp_down_w;
        };
        std::vector<Layer> layers;

        // KV-cache: per layer K/V for past tokens (multi-head GQA)
        std::vector<float> keyCache;   // [nLayers, nKVHeads, maxTokens, headDim]
        std::vector<float> valueCache; // [nLayers, nKVHeads, maxTokens, headDim]
        size_t kvLen{0};

        // Tensor directory
        struct TensorDesc { QString name; std::vector<uint32_t> dims; GgmlType type; uint64_t offset; };
        QHash<QString, TensorDesc> tensorTable;
    };

    void checkCpuFeatures();
    void loadGGUFModel(const QString& filePath);
    void loadVocabulary(const QString& vocabPath);
    float* getLayerWeights();
    bool prepareLLMInput(const QString& prompt, std::vector<float>& embeddings);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    void applySoftmax(float* buffer);
    void applyTemperature(float* buffer, float temperature);
    size_t sampleNextToken(float* buffer);
    size_t sampleTopP(float* buffer, float topP);
    size_t sampleGreedy(float* buffer);
<<<<<<< HEAD
    std::string decodeToken(size_t tokenId) const;
    void fallback_matrix_multiply(float* A, float* B, float* C, int N, int M, int K);

    bool parseGgufTensors(std::ifstream& file);
    bool parseGgufTensorTable(std::ifstream& file);
    bool loadTensor(std::ifstream& file, const std::string& name, std::vector<float>& weights);
    size_t ggmlTypeSize(GgmlType type);
    std::vector<uint8_t> readTensorData(std::ifstream& file, uint64_t offset, uint64_t numBytes);

    void layerNorm(const float* x, float* y, const std::vector<float>& gamma, const std::vector<float>& beta, size_t dim);
=======
    QString decodeToken(size_t tokenId) const;
    void fallback_matrix_multiply(float* A, float* B, float* C, int N, int M, int K);
    void detectExtendedCpuFeatures();

    // GGUF tensor parsing
    bool parseGgufTensors(class QFile& file);
    bool parseGgufTensorTable(class QFile& file);
    bool readTensorFloat32(class QFile& file, qint64 offset, qint64 count, std::vector<float>& out);
    bool loadTensor(class QFile& file, const QString& name, std::vector<float>& weights);
    size_t ggmlTypeSize(GgmlType type);
    QByteArray readTensorData(class QFile& file, quint64 offset, quint64 numBytes);

    // Transformer forward (scalar)
private:
    void layerNorm(const float* x, float* y, const std::vector<float>& gamma, const std::vector<float>& beta, qsizetype dim);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    void matmul(const float* A, const float* B, float* C, int N, int M, int K);
    void attentionForward(int layerIdx, const float* x, float* y);
    void mlpForward(int layerIdx, const float* x, float* y);

    ModelContext context_;
};
