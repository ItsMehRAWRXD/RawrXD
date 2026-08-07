#include "GGUFRunner.h"
#include "brutal_gzip.h"

<<<<<<< HEAD
#include <algorithm>
#include <cmath>
#include <cstring>
#include <fstream>
#include <chrono>
#include <random>
#include <sstream>
#include <thread>
=======
#include <QByteArray>
#include <QCoreApplication>
#include <QDebug>
#include <QRandomGenerator>
#include <QElapsedTimer>
#include <QFile>
#include <QTextStream>
#include <QHash>

#include <algorithm>
#include <cmath>
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

#if defined(_MSC_VER)
#include <intrin.h>
#endif

<<<<<<< HEAD
=======
// AVX2 intrinsics for SIMD matrix multiplication
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
#if defined(__AVX2__) || (defined(_MSC_VER) && defined(__AVX2__))
#include <immintrin.h>
#define GGUF_USE_AVX2 1
#endif

<<<<<<< HEAD
#ifndef _WIN32
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#define USE_MMAP
#endif

=======
#ifdef Q_OS_UNIX
#include <sys/mman.h>
#include <unistd.h>
#define USE_MMAP
#endif

// Keep linkage visible to the ASM translation unit.
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
extern "C" void matmul_kernel_avx2(float* A, float* B, float* C, int N, int M, int K, bool accumulate = false);
extern "C" void ggml_gemm_q4_0(int M, int N, int K, const float* A, const uint8_t* Bq4, float scale, float* C);

namespace {
<<<<<<< HEAD

constexpr const char* kDefaultModelPath = "model/llama-7b-q4_0.gguf";
struct GGUFHeader { uint32_t magic{0}; uint32_t version{0}; uint64_t tensorCount{0}; uint64_t kvCount{0}; };

template<typename T>
static bool readLE(std::ifstream& f, T& v) {
    return !!f.read(reinterpret_cast<char*>(&v), sizeof(T));
}

static void skipGgufValue(std::ifstream& f, uint32_t type) {
    switch (type) {
        case 0: { uint8_t v; readLE(f, v); break; }
        case 1: { int8_t v; readLE(f, v); break; }
        case 2: { uint16_t v; readLE(f, v); break; }
        case 3: { int16_t v; readLE(f, v); break; }
        case 4: { uint32_t v; readLE(f, v); break; }
        case 5: { int32_t v; readLE(f, v); break; }
        case 6: { float v; readLE(f, v); break; }
        case 7: { uint8_t v; readLE(f, v); break; }
        case 8: {
            uint64_t len; readLE(f, len);
            f.seekg(static_cast<std::streamoff>(len), std::ios::cur);
            break;
        }
        case 9: {
            uint32_t elemType; readLE(f, elemType);
            uint64_t len; readLE(f, len);
            for (uint64_t i = 0; i < len; ++i) skipGgufValue(f, elemType);
            break;
        }
        default:
=======
constexpr const char* kDefaultModelPath = "model/llama-7b-q4_0.gguf";
struct GGUFHeader { uint32_t magic{0}; uint32_t version{0}; uint64_t tensorCount{0}; uint64_t kvCount{0}; };

void skipGgufValue(QDataStream& ds, quint32 type) {
    // Skip GGUF value based on type
    switch (type) {
        case 0: { quint8 v; ds >> v; break; }  // UINT8
        case 1: { qint8 v; ds >> v; break; }   // INT8
        case 2: { quint16 v; ds >> v; break; } // UINT16
        case 3: { qint16 v; ds >> v; break; }  // INT16
        case 4: { quint32 v; ds >> v; break; } // UINT32
        case 5: { qint32 v; ds >> v; break; }  // INT32
        case 6: { float v; ds >> v; break; }   // FLOAT32
        case 7: { bool v; ds >> v; break; }    // BOOL
        case 8: { // STRING
            quint64 len; ds >> len;
            ds.skipRawData(static_cast<int>(len));
            break;
        }
        case 9: { // ARRAY
            quint32 elemType; ds >> elemType;
            quint64 len; ds >> len;
            for (quint64 i = 0; i < len; ++i) {
                skipGgufValue(ds, elemType);
            }
            break;
        }
        default:
            ds.setStatus(QDataStream::ReadCorruptData);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
            break;
    }
}

<<<<<<< HEAD
static std::string readGgufStr(std::ifstream& f) {
    uint64_t len; readLE(f, len);
    std::string s(static_cast<size_t>(len), '\0');
    if (len) f.read(&s[0], static_cast<std::streamsize>(len));
    return s;
}

static float f16ToF32(uint16_t h) {
    uint32_t sign = (h >> 15) & 1;
    uint32_t exp  = (h >> 10) & 0x1F;
    uint32_t mant = h & 0x3FF;
=======
QString readGgufStr(QDataStream& ds) {
    quint64 len; ds >> len;
    QByteArray ba(static_cast<int>(len), '\0');
    ds.readRawData(ba.data(), static_cast<int>(len));
    return QString::fromUtf8(ba);
}

// F16 to F32 conversion
float f16ToF32(quint16 h) {
    quint32 sign = (h >> 15) & 1;
    quint32 exp  = (h >> 10) & 0x1F;
    quint32 mant = h & 0x3FF;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    
    if (exp == 0) {
        if (mant == 0) return sign ? -0.0f : 0.0f;
        // Denormal
        while ((mant & 0x400) == 0) { mant <<= 1; exp--; }
        exp++; mant &= 0x3FF;
    } else if (exp == 31) {
        return mant ? NAN : (sign ? -INFINITY : INFINITY);
    }
    
    exp = exp - 15 + 127;
<<<<<<< HEAD
    uint32_t f32 = (sign << 31) | (exp << 23) | (mant << 13);
=======
    quint32 f32 = (sign << 31) | (exp << 23) | (mant << 13);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    float result;
    std::memcpy(&result, &f32, sizeof(float));
    return result;
}

// Scalar Q4_0 dequantization: 32 weights per block (16 bytes + 2 bytes delta)
void dequantizeRowQ4_0_scalar(const void* src, float* dst, size_t n) {
    const BlockQ4_0* b = reinterpret_cast<const BlockQ4_0*>(src);
    size_t nb = n / 32;  // 32 weights per block
    for (size_t i = 0; i < nb; ++i) {
        float d = f16ToF32(b[i].d);
        for (size_t j = 0; j < 16; ++j) {
            int vi = (b[i].qs[j] & 0xF) - 8;
            dst[i*32 + j] = vi * d;
        }
        for (size_t j = 0; j < 16; ++j) {
            int vi = (b[i].qs[j] >> 4) - 8;
            dst[i*32 + j + 16] = vi * d;
        }
    }
}

// Scalar Q8_0 dequantization: 32 weights per block (32 bytes + 2 bytes delta)
void dequantizeRowQ8_0_scalar(const void* src, float* dst, size_t n) {
    const BlockQ8_0* b = reinterpret_cast<const BlockQ8_0*>(src);
    size_t nb = n / 32;
    for (size_t i = 0; i < nb; ++i) {
        float d = f16ToF32(b[i].d);
        for (size_t j = 0; j < 32; ++j) {
            dst[i*32 + j] = static_cast<float>(b[i].qs[j]) * d;
        }
    }
}

}  // namespace

<<<<<<< HEAD
bool GGUFRunner::parseGgufTensorTable(std::ifstream& file) {
    file.seekg(0);
    uint32_t magic, version;
    uint64_t tensorCount, kvCount;
    if (!readLE(file, magic) || !readLE(file, version) || !readLE(file, tensorCount) || !readLE(file, kvCount))
        return false;
    if (magic != 0x46554747) return false;
    if (version < 2) return false;

    for (uint64_t i = 0; i < kvCount; ++i) {
        uint64_t keyLen; if (!readLE(file, keyLen)) return false;
        if (keyLen > 0) file.seekg(static_cast<std::streamoff>(keyLen), std::ios::cur);
        uint32_t valueType; if (!readLE(file, valueType)) return false;
        skipGgufValue(file, valueType);
    }

    context_.tensorTable.clear();
    for (uint64_t i = 0; i < tensorCount; ++i) {
        ModelContext::TensorDesc desc;
        uint64_t nameLen; if (!readLE(file, nameLen)) return false;
        desc.name.resize(static_cast<size_t>(nameLen));
        if (nameLen) file.read(&desc.name[0], static_cast<std::streamsize>(nameLen));
        uint32_t nDims; if (!readLE(file, nDims)) return false;
        desc.dims.resize(nDims);
        for (uint32_t d = 0; d < nDims; ++d) {
            uint64_t dim; if (!readLE(file, dim)) return false;
            desc.dims[d] = static_cast<uint32_t>(dim);
        }
        uint32_t typeRaw; if (!readLE(file, typeRaw)) return false;
        desc.type = static_cast<GgmlType>(typeRaw);
        uint64_t offset; if (!readLE(file, offset)) return false;
        desc.offset = offset;
        context_.tensorTable[desc.name] = desc;
    }
    return file.good();
}

GGUFRunner::GGUFRunner() {
    checkCpuFeatures();
    loadGGUFModel(kDefaultModelPath);
    if (context_.vocabSize > 0)
        context_.logits.resize(context_.vocabSize);
}

GGUFRunner::~GGUFRunner() {
#ifdef USE_MMAP
    if (context_.mappedData && context_.usesMmap) {
        (void)::munmap(static_cast<void*>(context_.mappedData), static_cast<size_t>(context_.modelFileSize));
        context_.mappedData = nullptr;
    }
#endif
=======
bool GGUFRunner::parseGgufTensorTable(QFile& file)
{
    file.seek(0);
    QDataStream ds(&file);
    ds.setByteOrder(QDataStream::LittleEndian);

    quint32 magic, version;
    quint64 tensorCount, kvCount;
    ds >> magic >> version >> tensorCount >> kvCount;
    if (magic != 0x46554747) return false; // 'GGUF'
    if (version < 2) return false;

    // Consume KV section to reach tensor table
    for (quint64 i = 0; i < kvCount; ++i) {
        quint64 keyLen; ds >> keyLen;
        if (ds.status() != QDataStream::Ok) return false;
        if (keyLen > 0) { file.read(static_cast<qint64>(keyLen)); }
        quint32 valueType; ds >> valueType;
        if (ds.status() != QDataStream::Ok) return false;
        skipGgufValue(ds, valueType);
        if (ds.status() != QDataStream::Ok) return false;
    }

    // Tensor table
    context_.tensorTable.clear();
    for (quint64 i = 0; i < tensorCount; ++i) {
        ModelContext::TensorDesc desc;
        quint64 nameLen; ds >> nameLen;
        QByteArray nameBa = file.read(static_cast<qint64>(nameLen));
        desc.name = QString::fromUtf8(nameBa);
        quint32 nDims; ds >> nDims;
        desc.dims.resize(nDims);
        for (quint32 d = 0; d < nDims; ++d) {
            quint64 dim; ds >> dim; desc.dims[d] = static_cast<uint32_t>(dim);
        }
        quint32 typeRaw; ds >> typeRaw;
        desc.type = static_cast<GgmlType>(typeRaw);
        quint64 offset; ds >> offset; desc.offset = offset;
        context_.tensorTable.insert(desc.name, desc);
    }
    return ds.status() == QDataStream::Ok;
}

GGUFRunner::GGUFRunner(QObject* parent)
    : QObject(parent)
{
    checkCpuFeatures();
    loadGGUFModel(QString::fromLatin1(kDefaultModelPath));

    if (context_.vocabSize > 0) {
        context_.logits.resize(context_.vocabSize);
    }

    qDebug() << "[GGUFRunner] Initialized"
             << "| Dims:" << context_.embedDim << "x" << context_.vocabSize
             << "| CPU: AVX2=" << context_.hasAVX2 << "AVX512=" << context_.hasAVX512 << "FMA=" << context_.hasFMA
             << "| Gen: temp=" << context_.temperature << "top_p=" << context_.topP << "max_tokens=" << context_.maxTokens;
}

GGUFRunner::~GGUFRunner()
{
#ifdef USE_MMAP
    if (context_.mappedData && context_.usesMmap) {
        if (::munmap(static_cast<void*>(context_.mappedData), static_cast<size_t>(context_.modelFileSize)) != 0) {
            qWarning() << "munmap failed for" << context_.modelPath;
        }
        context_.mappedData = nullptr;
    }
#endif

>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    if (context_.mappedData) {
        delete[] context_.mappedData;
        context_.mappedData = nullptr;
    }
<<<<<<< HEAD
=======

>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    context_.logits.clear();
    context_.vocabulary.clear();
}

<<<<<<< HEAD
bool GGUFRunner::runInference(const std::string& prompt, float* outputBuffer) {
    if (!context_.mappedData) {
        if (onInferenceComplete_) onInferenceComplete_(false);
        return false;
    }
    if (!outputBuffer) {
        if (onInferenceComplete_) onInferenceComplete_(false);
        return false;
    }
    std::vector<float> embeddings;
    if (!prepareLLMInput(prompt, embeddings)) {
        if (onInferenceComplete_) onInferenceComplete_(false);
        return false;
    }
    const int M = static_cast<int>(context_.embedDim);
    const int K = static_cast<int>(context_.vocabSize);
    float* layerWeightMatrix = getLayerWeights();
    if (!layerWeightMatrix) {
        if (onInferenceComplete_) onInferenceComplete_(false);
        return false;
    }
    auto totalStart = std::chrono::steady_clock::now();
=======
bool GGUFRunner::runInference(const QString& prompt, float* outputBuffer)
{
    if (!context_.mappedData) {
        qCritical() << "GGUFRunner: Model weights not loaded.";
        emit inferenceComplete(false);
        return false;
    }

    if (!outputBuffer) {
        qCritical() << "GGUFRunner: Output buffer is null.";
        emit inferenceComplete(false);
        return false;
    }

    std::vector<float> embeddings;
    if (!prepareLLMInput(prompt, embeddings)) {
        qCritical() << "GGUFRunner: Failed to prepare embeddings for prompt.";
        emit inferenceComplete(false);
        return false;
    }

    const int N = 1;
    const int M = static_cast<int>(context_.embedDim);
    const int K = static_cast<int>(context_.vocabSize);

    float* layerWeightMatrix = getLayerWeights();
    if (!layerWeightMatrix) {
        qCritical() << "GGUFRunner: Layer weights unavailable.";
        emit inferenceComplete(false);
        return false;
    }

    QElapsedTimer totalTimer;
    totalTimer.start();

>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    const int maxTokens = std::max(1, context_.maxTokens > 0 ? context_.maxTokens : 64);
    size_t lastTokenId = 0;

    for (int t = 0; t < maxTokens; ++t) {
<<<<<<< HEAD
        if (context_.logits.size() != context_.vocabSize)
            context_.logits.resize(context_.vocabSize);
        std::vector<float> x(context_.embedDim);
        std::memcpy(x.data(), embeddings.data(), context_.embedDim * sizeof(float));
        for (size_t l = 0; l < context_.nLayers; ++l) {
            std::vector<float> attn(context_.embedDim);
            attentionForward(static_cast<int>(l), x.data(), attn.data());
            for (size_t i = 0; i < context_.embedDim; ++i) x[i] += attn[i];
            std::vector<float> ff(context_.embedDim);
            mlpForward(static_cast<int>(l), x.data(), ff.data());
            for (size_t i = 0; i < context_.embedDim; ++i) x[i] += ff[i];
        }
        std::vector<float> xnorm(context_.embedDim);
        layerNorm(x.data(), xnorm.data(), context_.ln_f_g, context_.ln_f_b, context_.embedDim);
=======
        // Transformer forward (scalar) to produce logits
        if (context_.logits.size() != context_.vocabSize) {
            context_.logits.resize(context_.vocabSize);
        }

        std::vector<float> x(context_.embedDim);
        std::memcpy(x.data(), embeddings.data(), context_.embedDim * sizeof(float));
        for (qsizetype l = 0; l < context_.nLayers; ++l) {
            std::vector<float> attn(context_.embedDim);
            attentionForward(static_cast<int>(l), x.data(), attn.data());
            for (qsizetype i = 0; i < context_.embedDim; ++i) x[i] += attn[i]; // residual
            std::vector<float> ff(context_.embedDim);
            mlpForward(static_cast<int>(l), x.data(), ff.data());
            for (qsizetype i = 0; i < context_.embedDim; ++i) x[i] += ff[i]; // residual
        }
        // Final layernorm then logits projection
        std::vector<float> xnorm(context_.embedDim);
        layerNorm(x.data(), xnorm.data(), context_.ln_f_g, context_.ln_f_b, context_.embedDim);
        // Prefer raw Q4_0 output.weight if available (runtime-dispatched GEMM)
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        if (!context_.raw_q4_output.empty()) {
            if (context_.logits.size() != context_.vocabSize) context_.logits.resize(context_.vocabSize);
            ggml_gemm_q4_0(1, static_cast<int>(context_.vocabSize), static_cast<int>(context_.embedDim),
                           xnorm.data(), context_.raw_q4_output.data(), 1.0f, context_.logits.data());
<<<<<<< HEAD
        } else if (context_.tok_embeddings.size() == context_.vocabSize * context_.embedDim) {
            for (size_t v = 0; v < context_.vocabSize; ++v) {
                const float* Ev = context_.tok_embeddings.data() + v * context_.embedDim;
                float dot = 0.0f;
                for (size_t d = 0; d < context_.embedDim; ++d) dot += xnorm[d] * Ev[d];
                context_.logits[v] = dot;
            }
        } else {
            fallback_matrix_multiply(xnorm.data(), layerWeightMatrix, context_.logits.data(), 1, M, K);
        }
        std::copy(context_.logits.cbegin(), context_.logits.cend(), outputBuffer);
        if (context_.temperature > 0.0f && std::abs(context_.temperature - 1.0f) > 0.001f)
            applyTemperature(context_.logits.data(), context_.temperature);
        applySoftmax(context_.logits.data());
        std::copy(context_.logits.cbegin(), context_.logits.cend(), outputBuffer);
        size_t tokenId;
        if (context_.temperature < 0.01f)
            tokenId = sampleGreedy(context_.logits.data());
        else if (context_.topP < 1.0f && context_.topP > 0.0f)
            tokenId = sampleTopP(context_.logits.data(), context_.topP);
        else
            tokenId = sampleNextToken(context_.logits.data());
        lastTokenId = tokenId;
        if (onTokenChunk_) onTokenChunk_(decodeToken(tokenId));
        if (!embeddings.empty())
            embeddings.back() = static_cast<float>(tokenId % 1024) / 1024.0f;
        if (context_.eosTokenId >= 0 && static_cast<size_t>(context_.eosTokenId) == tokenId)
            break;
        context_.kvLen = std::min(context_.kvLen + 1, static_cast<size_t>(context_.maxTokens - 1));
    }
    if (onInferenceComplete_) onInferenceComplete_(true);
    (void)lastTokenId;
    (void)totalStart;
    return true;
}

void GGUFRunner::checkCpuFeatures() {
    context_.hasAVX2 = false;
    context_.hasAVX512 = false;
    context_.hasFMA = false;
#if defined(__AVX2__)
    context_.hasAVX2 = true;
#endif
#if defined(__AVX512F__)
    context_.hasAVX512 = true;
#endif
#if defined(__FMA__)
    context_.hasFMA = true;
#endif
#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 0x7);
    if ((cpuInfo[1] & (1 << 5)) != 0) context_.hasAVX2 = true;
    if ((cpuInfo[1] & (1 << 16)) != 0) context_.hasAVX512 = true;
    if ((cpuInfo[1] & (1 << 12)) != 0) context_.hasFMA = true;
#endif
}

static std::string toLower(std::string s) {
    for (char& c : s) if (c >= 'A' && c <= 'Z') c += 32;
    return s;
}

void GGUFRunner::loadGGUFModel(const std::string& filePath) {
=======
        } else if (context_.tok_embeddings.size() == static_cast<size_t>(context_.vocabSize * context_.embedDim)) {
            for (qsizetype v = 0; v < context_.vocabSize; ++v) {
                const float* Ev = context_.tok_embeddings.data() + v * context_.embedDim;
                float dot = 0.0f;
                for (qsizetype d = 0; d < context_.embedDim; ++d) dot += xnorm[d] * Ev[d];
                context_.logits[v] = dot;
            }
        } else {
            // Fallback to previous dense matmul path
            fallback_matrix_multiply(xnorm.data(), layerWeightMatrix, context_.logits.data(), 1, M, K);
        }
        std::copy(context_.logits.cbegin(), context_.logits.cend(), outputBuffer);
        
        // Apply temperature before softmax for better distribution
        if (context_.temperature > 0.0f && std::abs(context_.temperature - 1.0f) > 0.001f) {
            applyTemperature(context_.logits.data(), context_.temperature);
        }
        
        applySoftmax(context_.logits.data());
        std::copy(context_.logits.cbegin(), context_.logits.cend(), outputBuffer);

        // Sample based on temperature setting
        size_t tokenId;
        if (context_.temperature < 0.01f) {
            tokenId = sampleGreedy(context_.logits.data());  // Greedy for temp ≈ 0
        } else if (context_.topP < 1.0f && context_.topP > 0.0f) {
            tokenId = sampleTopP(context_.logits.data(), context_.topP);  // Nucleus sampling
        } else {
            tokenId = sampleNextToken(context_.logits.data());  // Standard sampling
        }
        lastTokenId = tokenId;
        emit tokenChunkGenerated(decodeToken(tokenId));

        if (!embeddings.empty()) {
            embeddings.back() = static_cast<float>(tokenId % 1024) / 1024.0f;
        }

        if (context_.eosTokenId >= 0 && static_cast<size_t>(context_.eosTokenId) == tokenId) {
            break;
        }

        // advance KV position
        context_.kvLen = std::min<size_t>(context_.kvLen + 1, static_cast<size_t>(context_.maxTokens - 1));
        QCoreApplication::processEvents();
    }

    emit inferenceComplete(true);
    qDebug() << "[GGUFRunner] Inference finished in" << totalTimer.elapsed() << "ms. Last token" << lastTokenId << "emitted.";
    return true;
}

void GGUFRunner::checkCpuFeatures()
{
    context_.hasAVX2 = false;
    context_.hasAVX512 = false;
    context_.hasFMA = false;

#if defined(__AVX2__)
    context_.hasAVX2 = true;
#endif

#if defined(__AVX512F__)
    context_.hasAVX512 = true;
#endif

#if defined(__FMA__)
    context_.hasFMA = true;
#endif

#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 0x7);
    if ((cpuInfo[1] & (1 << 5)) != 0) {
        context_.hasAVX2 = true;
    }
    if ((cpuInfo[1] & (1 << 16)) != 0) {
        context_.hasAVX512 = true;
    }
    if ((cpuInfo[1] & (1 << 12)) != 0) {
        context_.hasFMA = true;
    }
#endif

    qDebug() << "CPU Features: AVX2=" << context_.hasAVX2 
             << "AVX512=" << context_.hasAVX512 
             << "FMA=" << context_.hasFMA;
}

void GGUFRunner::loadGGUFModel(const QString& filePath)
{
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    context_.modelPath = filePath;
    context_.embedDim = 0;
    context_.vocabSize = 0;
    context_.usesMmap = false;
    context_.mappedData = nullptr;

<<<<<<< HEAD
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        loadVocabulary(filePath + ".vocab");
        return;
    }
    file.seekg(0, std::ios::end);
    context_.modelFileSize = static_cast<int64_t>(file.tellg());
    file.seekg(0);

    size_t headSize = static_cast<size_t>(std::min<int64_t>(context_.modelFileSize, 8 * 1024 * 1024));
    std::string head(headSize, '\0');
    file.read(&head[0], static_cast<std::streamsize>(headSize));
    file.seekg(0);

    auto findInt = [&](const char* key, int defVal) {
        std::string k(key);
        auto idx = head.find(k);
        if (idx == std::string::npos) return defVal;
        auto nl = head.find('\n', idx);
        std::string line = head.substr(idx, (nl != std::string::npos ? nl - idx : 128));
        auto eq = line.find('=');
        if (eq == std::string::npos) return defVal;
        std::string val = line.substr(eq + 1);
        while (!val.empty() && (val.back() == '\r' || val.back() == ' ')) val.pop_back();
        try { return std::stoi(val); } catch (...) { return defVal; }
    };
    auto findString = [&](const char* key) -> std::string {
        std::string k(key);
        auto idx = head.find(k);
        if (idx == std::string::npos) return {};
        auto nl = head.find('\n', idx);
        std::string line = head.substr(idx, (nl != std::string::npos ? nl - idx : 128));
        auto eq = line.find('=');
        if (eq == std::string::npos) return {};
        std::string val = line.substr(eq + 1);
        while (!val.empty() && (val.back() == '\r' || val.back() == ' ')) val.pop_back();
        return val;
    };

    context_.embedDim = findInt("ggml.embedding_length", 4096);
    context_.vocabSize = findInt("ggml.vocab_size", 32000);
    context_.nLayers = findInt("llama.block_count", 32);
    context_.nHeads = findInt("llama.attention.head_count", 32);
    context_.nKVHeads = findInt("llama.attention.head_count_kv", context_.nHeads);
    context_.modelName = findString("general.name");
    context_.architecture = findString("general.architecture");
    std::string quantStr = toLower(findString("general.file_type"));
    std::string pathLower = toLower(filePath);
    if (quantStr.find("q4_0") != std::string::npos || pathLower.find("q4_0") != std::string::npos)
        context_.quantType = QuantType::Q4_0;
    else if (quantStr.find("q4_1") != std::string::npos) context_.quantType = QuantType::Q4_1;
    else if (quantStr.find("q8_0") != std::string::npos) context_.quantType = QuantType::Q8_0;
    else if (quantStr.find("f16") != std::string::npos) context_.quantType = QuantType::F16;

    if (context_.embedDim <= 0) context_.embedDim = 4096;
    if (context_.vocabSize <= 0) context_.vocabSize = 32000;
    context_.headDim = (context_.nHeads > 0) ? (context_.embedDim / context_.nHeads) : 128;
    context_.ropeBase = 10000.0f;
    if (context_.headDim > 0) {
        context_.invFreq.resize(context_.headDim / 2);
        for (size_t i = 0; i < context_.headDim / 2; ++i)
            context_.invFreq[i] = 1.0f / std::pow(context_.ropeBase, 2.0f * static_cast<float>(i) / static_cast<float>(context_.headDim));
    }

    size_t byteCount = static_cast<size_t>(context_.modelFileSize);
    context_.mappedData = new float[(byteCount + sizeof(float) - 1) / sizeof(float)]{};
    file.seekg(0);
    file.read(reinterpret_cast<char*>(context_.mappedData), static_cast<std::streamsize>(context_.modelFileSize));

    if (!parseGgufTensorTable(file) || !parseGgufTensors(file)) { /* minimal weights may be missing */ }

    if (context_.nLayers > 0 && context_.nKVHeads > 0 && context_.headDim > 0) {
        size_t cacheSize = context_.nLayers * context_.nKVHeads * static_cast<size_t>(context_.maxTokens) * context_.headDim;
        context_.keyCache.resize(cacheSize, 0.0f);
        context_.valueCache.resize(cacheSize, 0.0f);
        context_.kvLen = 0;
    }
    loadVocabulary(filePath + ".vocab");
    if (context_.vocabulary.empty()) {
        context_.vocabulary.reserve(context_.vocabSize);
        for (size_t i = 0; i < context_.vocabSize; ++i)
            context_.vocabulary.push_back("<" + std::to_string(i) + ">");
    }
}

void GGUFRunner::loadVocabulary(const std::string& vocabPath) {
    context_.vocabulary.clear();
    std::ifstream f(vocabPath);
    if (!f.is_open()) return;
    std::string line;
    while (std::getline(f, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
        context_.vocabulary.push_back(std::move(line));
    }
=======
    QFile file(filePath);
    if (!file.exists()) {
        qWarning() << "GGUF file not found at" << filePath << "- allocating fallback buffer.";
        context_.modelFileSize = static_cast<qint64>(context_.embedDim * context_.vocabSize * sizeof(float));
        context_.mappedData = new float[context_.embedDim * context_.vocabSize]{};
        loadVocabulary(filePath + QStringLiteral(".vocab"));
        return;
    }

    if (!file.open(QIODevice::ReadOnly)) {
        qCritical() << "Failed to open GGUF file" << filePath;
        return;
    }

    context_.modelFileSize = file.size();

    // Parse GGUF header and metadata
    {
        QDataStream ds(&file);
        ds.setByteOrder(QDataStream::LittleEndian);
        GGUFHeader h{};
        ds >> h.magic >> h.version >> h.tensorCount >> h.kvCount;
        
        if (h.magic == 0x46554747) {  // 'GGUF'
            context_.ggufVersion = h.version;
            qDebug() << "GGUF v" << h.version << "detected, tensors:" << h.tensorCount << "kvs:" << h.kvCount;
        }
        
        file.seek(0);
        QByteArray head = file.read(qMin<qint64>(context_.modelFileSize, 8 * 1024 * 1024));  // Read 8MB for metadata
        
        auto findInt = [&](const char* key, int defVal) {
            int idx = head.indexOf(key);
            if (idx < 0) return defVal;
            int nl = head.indexOf('\n', idx);
            QByteArray line = head.mid(idx, (nl > idx ? nl - idx : 128));
            QList<QByteArray> parts = line.split('=');
            if (parts.size() >= 2) { 
                bool ok=false; 
                int v = parts.last().trimmed().toInt(&ok); 
                if (ok) return v; 
            }
            return defVal;
        };
        
        auto findString = [&](const char* key) -> QString {
            int idx = head.indexOf(key);
            if (idx < 0) return QString();
            int nl = head.indexOf('\n', idx);
            QByteArray line = head.mid(idx, (nl > idx ? nl - idx : 128));
            QList<QByteArray> parts = line.split('=');
            if (parts.size() >= 2) {
                return QString::fromUtf8(parts.last().trimmed());
            }
            return QString();
        };
        
        context_.embedDim = findInt("ggml.embedding_length", 4096);
        context_.vocabSize = findInt("ggml.vocab_size", 32000);
        context_.nLayers = findInt("llama.block_count", 32);
        context_.nHeads = findInt("llama.attention.head_count", 32);
        context_.nKVHeads = findInt("llama.attention.head_count_kv", context_.nHeads);
        
        context_.modelName = findString("general.name");
        context_.architecture = findString("general.architecture");
        QString quantStr = findString("general.file_type");
        
        // Detect quantization type
        if (quantStr.contains("q4_0", Qt::CaseInsensitive) || filePath.contains("q4_0", Qt::CaseInsensitive)) {
            context_.quantType = QuantType::Q4_0;
            qDebug() << "Detected Q4_0 quantization";
        } else if (quantStr.contains("q4_1", Qt::CaseInsensitive)) {
            context_.quantType = QuantType::Q4_1;
        } else if (quantStr.contains("q8_0", Qt::CaseInsensitive)) {
            context_.quantType = QuantType::Q8_0;
        } else if (quantStr.contains("f16", Qt::CaseInsensitive)) {
            context_.quantType = QuantType::F16;
        }
        
        if (context_.embedDim <= 0) context_.embedDim = 4096;
        if (context_.vocabSize <= 0) context_.vocabSize = 32000;
        
        // Multi-head attention parameters
        context_.headDim = (context_.nHeads > 0) ? (context_.embedDim / context_.nHeads) : 128;
        context_.ropeBase = 10000.0f;  // RoPE frequency base (standard LLaMA default)
        
        // Precompute inverse frequencies for RoPE (once per model)
        if (context_.headDim > 0) {
            context_.invFreq.resize(context_.headDim / 2);
            for (int i = 0; i < context_.headDim / 2; ++i) {
                context_.invFreq[i] = 1.0f / std::pow(context_.ropeBase, 2.0f * i / static_cast<float>(context_.headDim));
            }
        }
        
        qDebug() << "Model:" << context_.modelName << "Arch:" << context_.architecture
                 << "Layers:" << context_.nLayers << "Heads:" << context_.nHeads
                 << "KVHeads:" << context_.nKVHeads << "HeadDim:" << context_.headDim;
        
        file.seek(0);
    }

#ifdef USE_MMAP
    void* mapped = ::mmap(nullptr,
                          static_cast<size_t>(context_.modelFileSize),
                          PROT_READ,
                          MAP_PRIVATE,
                          file.handle(),
                          0);
    if (mapped == MAP_FAILED) {
        qWarning() << "mmap failed for" << filePath << "- falling back to heap allocation.";
    } else {
        context_.mappedData = static_cast<float*>(mapped);
        context_.usesMmap = true;
    }
#endif

    if (!context_.mappedData) {
        const qsizetype floatCount = static_cast<qsizetype>(context_.modelFileSize / sizeof(float));
        context_.mappedData = new float[floatCount];
        const qint64 bytesRead = file.read(reinterpret_cast<char*>(context_.mappedData), context_.modelFileSize);
        if (bytesRead != context_.modelFileSize) {
            qWarning() << "Incomplete read for" << filePath << "(" << bytesRead << "/" << context_.modelFileSize << " bytes).";
        }
    }

    // Build tensor directory and read essential weights
    if (!parseGgufTensorTable(file) || !parseGgufTensors(file)) {
        qWarning() << "GGUF tensor parsing failed; minimal weights may be missing";
    }

    // Allocate KV-cache for multi-head GQA: [nLayers, nKVHeads, maxTokens, headDim]
    if (context_.nLayers > 0 && context_.nKVHeads > 0 && context_.headDim > 0) {
        size_t cacheSize = static_cast<size_t>(context_.nLayers) * 
                          static_cast<size_t>(context_.nKVHeads) * 
                          static_cast<size_t>(context_.maxTokens) * 
                          static_cast<size_t>(context_.headDim);
        context_.keyCache.resize(cacheSize, 0.0f);
        context_.valueCache.resize(cacheSize, 0.0f);
        context_.kvLen = 0;
        qDebug() << "KV-cache allocated:" << (cacheSize * sizeof(float) * 2 / 1024 / 1024) << "MB"
                 << "(nLayers=" << context_.nLayers << "nKVHeads=" << context_.nKVHeads 
                 << "maxTokens=" << context_.maxTokens << "headDim=" << context_.headDim << ")";
    }

    file.close();
    loadVocabulary(filePath + QStringLiteral(".vocab"));
    if (context_.vocabulary.isEmpty()) {
        context_.vocabulary.reserve(static_cast<int>(context_.vocabSize));
        for (qsizetype i = 0; i < context_.vocabSize; ++i) {
            context_.vocabulary.append(QStringLiteral("<%1>").arg(i));
        }
        qWarning() << "Vocabulary not found; synthesized" << context_.vocabSize << "tokens.";
    }
}

void GGUFRunner::loadVocabulary(const QString& vocabPath)
{
    context_.vocabulary.clear();

    QFile vocabFile(vocabPath);
    if (!vocabFile.exists()) {
        qWarning() << "Vocabulary file not found at" << vocabPath << "- continuing without token strings.";
        return;
    }

    if (!vocabFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
        qWarning() << "Unable to open vocabulary file" << vocabPath;
        return;
    }

    QTextStream stream(&vocabFile);
    while (!stream.atEnd()) {
        context_.vocabulary.append(stream.readLine());
    }

    qDebug() << "Loaded" << context_.vocabulary.size() << "tokens from vocabulary.";
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

float* GGUFRunner::getLayerWeights()
{
    return context_.mappedData;
}

<<<<<<< HEAD
bool GGUFRunner::prepareLLMInput(const std::string& prompt, std::vector<float>& embeddings) {
    if (context_.embedDim <= 0) return false;
    embeddings.assign(context_.embedDim, 0.0f);
    size_t limit = std::min(prompt.size(), context_.embedDim);
    for (size_t i = 0; i < limit; ++i) {
        float v = static_cast<unsigned char>(prompt[i]) / 255.0f;
        float pos = static_cast<float>(i) / static_cast<float>(context_.embedDim);
        embeddings[i] = v + 0.01f * pos;
    }
    return true;
}

void GGUFRunner::applySoftmax(float* buffer) {
    if (!buffer || context_.vocabSize == 0) return;
    float maxVal = buffer[0];
    for (size_t i = 1; i < context_.vocabSize; ++i) if (buffer[i] > maxVal) maxVal = buffer[i];
    float sumExp = 0.0f;
    for (size_t i = 0; i < context_.vocabSize; ++i) {
        buffer[i] = std::exp(buffer[i] - maxVal);
        sumExp += buffer[i];
    }
    if (sumExp <= 0.0f) return;
    float invSum = 1.0f / sumExp;
    for (size_t i = 0; i < context_.vocabSize; ++i) buffer[i] *= invSum;
}

size_t GGUFRunner::sampleNextToken(float* buffer) {
    if (!buffer || context_.vocabSize == 0) return 0;
    float maxProb = buffer[0];
    size_t bestIdx = 0;
    for (size_t i = 1; i < context_.vocabSize; ++i) {
        if (buffer[i] > maxProb) { maxProb = buffer[i]; bestIdx = i; }
    }
    return bestIdx;
}

std::string GGUFRunner::decodeToken(size_t tokenId) const {
    if (!context_.vocabulary.empty() && tokenId < context_.vocabulary.size())
        return context_.vocabulary[tokenId];
    return "<token_" + std::to_string(tokenId) + ">";
}

void GGUFRunner::applyTemperature(float* buffer, float temperature) {
    if (!buffer || context_.vocabSize == 0 || temperature <= 0.0f) return;
    if (std::abs(temperature - 1.0f) < 0.001f) return;
    for (size_t i = 0; i < context_.vocabSize; ++i) buffer[i] /= temperature;
}

size_t GGUFRunner::sampleTopP(float* buffer, float topP) {
    if (!buffer || context_.vocabSize == 0) return 0;
    std::vector<std::pair<size_t, float>> sorted;
    sorted.reserve(context_.vocabSize);
    for (size_t i = 0; i < context_.vocabSize; ++i) sorted.emplace_back(i, buffer[i]);
    std::sort(sorted.begin(), sorted.end(), [](const auto& a, const auto& b) { return a.second > b.second; });
=======
bool GGUFRunner::prepareLLMInput(const QString& prompt, std::vector<float>& embeddings)
{
    if (context_.embedDim <= 0) {
        qWarning() << "GGUFRunner: Invalid embedding dimension.";
        return false;
    }

    embeddings.assign(static_cast<size_t>(context_.embedDim), 0.0f);

    const QByteArray utf8 = prompt.toUtf8();
    const int limit = std::min<int>(utf8.size(), static_cast<int>(context_.embedDim));
    for (int i = 0; i < limit; ++i) {
        const float v = static_cast<unsigned char>(utf8.at(i)) / 255.0f;
        const float pos = static_cast<float>(i) / static_cast<float>(context_.embedDim);
        embeddings[static_cast<size_t>(i)] = v + 0.01f * pos;
    }

    return true;
}

void GGUFRunner::applySoftmax(float* buffer)
{
    if (!buffer || context_.vocabSize == 0) {
        return;
    }

    float maxVal = buffer[0];
    for (qsizetype i = 1; i < context_.vocabSize; ++i) {
        if (buffer[i] > maxVal) {
            maxVal = buffer[i];
        }
    }

    float sumExp = 0.0f;
    for (qsizetype i = 0; i < context_.vocabSize; ++i) {
        buffer[i] = std::exp(buffer[i] - maxVal);
        sumExp += buffer[i];
    }

    if (sumExp <= 0.0f) {
        return;
    }

    const float invSum = 1.0f / sumExp;
    for (qsizetype i = 0; i < context_.vocabSize; ++i) {
        buffer[i] *= invSum;
    }
}

size_t GGUFRunner::sampleNextToken(float* buffer)
{
    if (!buffer || context_.vocabSize == 0) {
        return 0;
    }

    float maxProb = buffer[0];
    size_t bestIdx = 0;
    for (qsizetype i = 1; i < context_.vocabSize; ++i) {
        if (buffer[i] > maxProb) {
            maxProb = buffer[i];
            bestIdx = static_cast<size_t>(i);
        }
    }

    qDebug() << "[GGUFRunner] Sampled token" << bestIdx << "with probability" << maxProb;
    return bestIdx;
}

QString GGUFRunner::decodeToken(size_t tokenId) const
{
    if (!context_.vocabulary.isEmpty() && tokenId < static_cast<size_t>(context_.vocabulary.size())) {
        return context_.vocabulary[static_cast<qsizetype>(tokenId)];
    }

    return QStringLiteral("<token_%1>").arg(static_cast<qulonglong>(tokenId));
}

void GGUFRunner::applyTemperature(float* buffer, float temperature)
{
    if (!buffer || context_.vocabSize == 0 || temperature <= 0.0f) {
        return;
    }
    
    if (std::abs(temperature - 1.0f) < 0.001f) {
        return;  // No-op for temperature = 1.0
    }
    
    for (qsizetype i = 0; i < context_.vocabSize; ++i) {
        buffer[i] /= temperature;
    }
}

size_t GGUFRunner::sampleTopP(float* buffer, float topP)
{
    if (!buffer || context_.vocabSize == 0) {
        return 0;
    }
    
    // Create index-probability pairs
    std::vector<std::pair<size_t, float>> sorted;
    sorted.reserve(context_.vocabSize);
    for (qsizetype i = 0; i < context_.vocabSize; ++i) {
        sorted.emplace_back(i, buffer[i]);
    }
    
    // Sort descending by probability
    std::sort(sorted.begin(), sorted.end(), 
        [](const auto& a, const auto& b) { return a.second > b.second; });
    
    // Accumulate until we reach topP
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    float cumSum = 0.0f;
    size_t cutoff = 0;
    for (size_t i = 0; i < sorted.size(); ++i) {
        cumSum += sorted[i].second;
        cutoff = i + 1;
<<<<<<< HEAD
        if (cumSum >= topP) break;
    }
    static std::mt19937 rng(static_cast<unsigned>(std::chrono::steady_clock::now().time_since_epoch().count()));
    std::uniform_real_distribution<double> dist(0, 1);
    float r = static_cast<float>(dist(rng)) * cumSum;
    float acc = 0.0f;
    for (size_t i = 0; i < cutoff; ++i) {
        acc += sorted[i].second;
        if (acc >= r) return sorted[i].first;
    }
    return sorted[0].first;
}

size_t GGUFRunner::sampleGreedy(float* buffer) {
    if (!buffer || context_.vocabSize == 0) return 0;
    float maxProb = buffer[0];
    size_t bestIdx = 0;
    for (size_t i = 1; i < context_.vocabSize; ++i) {
        if (buffer[i] > maxProb) { maxProb = buffer[i]; bestIdx = i; }
=======
        if (cumSum >= topP) {
            break;
        }
    }
    
    // Sample from top candidates
    float r = QRandomGenerator::global()->generateDouble() * cumSum;
    float acc = 0.0f;
    for (size_t i = 0; i < cutoff; ++i) {
        acc += sorted[i].second;
        if (acc >= r) {
            return sorted[i].first;
        }
    }
    
    return sorted[0].first;  // Fallback to top token
}

size_t GGUFRunner::sampleGreedy(float* buffer)
{
    if (!buffer || context_.vocabSize == 0) {
        return 0;
    }
    
    float maxProb = buffer[0];
    size_t bestIdx = 0;
    for (qsizetype i = 1; i < context_.vocabSize; ++i) {
        if (buffer[i] > maxProb) {
            maxProb = buffer[i];
            bestIdx = static_cast<size_t>(i);
        }
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    }
    return bestIdx;
}

// ---- Scalar transformer helpers ----
<<<<<<< HEAD
void GGUFRunner::layerNorm(const float* x, float* y, const std::vector<float>& gamma, const std::vector<float>& beta, size_t dim) {
    float mean = 0.0f;
    for (size_t i = 0; i < dim; ++i) mean += x[i];
    mean /= static_cast<float>(dim);
    float var = 0.0f;
    for (size_t i = 0; i < dim; ++i) { float d = x[i] - mean; var += d * d; }
    var /= static_cast<float>(dim);
    float invStd = 1.0f / std::sqrt(var + 1e-5f);
    for (size_t i = 0; i < dim; ++i) {
        float n = (x[i] - mean) * invStd;
        float g = gamma.empty() ? 1.0f : gamma[i];
        float b = beta.empty() ? 0.0f : beta[i];
=======
void GGUFRunner::layerNorm(const float* x, float* y, const std::vector<float>& gamma, const std::vector<float>& beta, qsizetype dim)
{
    float mean = 0.0f;
    for (qsizetype i = 0; i < dim; ++i) mean += x[i];
    mean /= static_cast<float>(dim);
    float var = 0.0f;
    for (qsizetype i = 0; i < dim; ++i) { float d = x[i] - mean; var += d * d; }
    var /= static_cast<float>(dim);
    float invStd = 1.0f / std::sqrt(var + 1e-5f);
    for (qsizetype i = 0; i < dim; ++i) {
        float n = (x[i] - mean) * invStd;
        float g = gamma.empty() ? 1.0f : gamma[static_cast<size_t>(i)];
        float b = beta.empty() ? 0.0f : beta[static_cast<size_t>(i)];
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        y[i] = n * g + b;
    }
}

void GGUFRunner::matmul(const float* A, const float* B, float* C, int N, int M, int K)
{
#ifdef GGUF_USE_AVX2
    // Runtime dispatch: use AVX2 if available, otherwise fall back to scalar
    if (context_.hasAVX2) {
        // Use the optimized AVX2 micro-kernel when available
        // Signature: matmul_kernel_avx2(A[NxM], B[MxK], C[NxK], N, M, K, accumulate)
        matmul_kernel_avx2(const_cast<float*>(A), const_cast<float*>(B), C, N, M, K, false);
        return;
    }
#endif
    
    // Scalar fallback path (when AVX2 not available or not enabled)
    for (int i = 0; i < N; ++i) {
        for (int j = 0; j < K; ++j) {
            float s = 0.0f;
            for (int k = 0; k < M; ++k) s += A[i * M + k] * B[k * K + j];
            C[i * K + j] = s;
        }
    }
}

<<<<<<< HEAD
void GGUFRunner::attentionForward(int layerIdx, const float* x, float* y) {
    const size_t D = context_.embedDim;
    const size_t nHead = context_.nHeads;
    const size_t nKVHead = context_.nKVHeads;
    const size_t headDim = context_.headDim;
=======
void GGUFRunner::attentionForward(int layerIdx, const float* x, float* y)
{
    const qsizetype D = context_.embedDim;
    const qsizetype nHead = context_.nHeads;
    const qsizetype nKVHead = context_.nKVHeads;
    const qsizetype headDim = context_.headDim;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    
    if (nHead == 0 || headDim == 0 || nKVHead == 0) {
        // Fallback to single-head scalar path if metadata missing
        std::vector<float> n(D), q(D), k(D), v(D), attnOut(D);
        const auto& L = context_.layers[static_cast<size_t>(layerIdx)];
        layerNorm(x, n.data(), L.ln_1_g, L.ln_1_b, D);
        matmul(n.data(), L.attn_q_w.data(), q.data(), 1, static_cast<int>(D), static_cast<int>(D));
        matmul(x, L.attn_k_w.data(), k.data(), 1, static_cast<int>(D), static_cast<int>(D));
        matmul(x, L.attn_v_w.data(), v.data(), 1, static_cast<int>(D), static_cast<int>(D));
        size_t pos = context_.kvLen;
        size_t stride = static_cast<size_t>(D);
        size_t layerStride = static_cast<size_t>(context_.maxTokens) * stride;
        float* Kc = context_.keyCache.data() + static_cast<size_t>(layerIdx) * layerStride + pos * stride;
        float* Vc = context_.valueCache.data() + static_cast<size_t>(layerIdx) * layerStride + pos * stride;
        std::memcpy(Kc, k.data(), static_cast<size_t>(D) * sizeof(float));
        std::memcpy(Vc, v.data(), static_cast<size_t>(D) * sizeof(float));
        std::vector<float> weights(pos + 1);
        float scale = 1.0f / std::sqrt(static_cast<float>(D));
        for (size_t t = 0; t <= pos; ++t) {
            const float* Kt = context_.keyCache.data() + static_cast<size_t>(layerIdx) * layerStride + t * stride;
<<<<<<< HEAD
            float dot = 0.0f; for (size_t i = 0; i < D; ++i) dot += q[i] * Kt[i];
=======
            float dot = 0.0f; for (qsizetype i = 0; i < D; ++i) dot += q[i] * Kt[i];
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
            weights[t] = dot * scale;
        }
        float maxw = weights[0]; for (size_t t = 1; t < weights.size(); ++t) if (weights[t] > maxw) maxw = weights[t];
        float sumw = 0.0f; for (size_t t = 0; t < weights.size(); ++t) { weights[t] = std::exp(weights[t] - maxw); sumw += weights[t]; }
        for (size_t t = 0; t < weights.size(); ++t) weights[t] /= (sumw + 1e-9f);
        std::fill(attnOut.begin(), attnOut.end(), 0.0f);
        for (size_t t = 0; t < weights.size(); ++t) {
            const float* Vt = context_.valueCache.data() + static_cast<size_t>(layerIdx) * layerStride + t * stride;
<<<<<<< HEAD
            float wt = weights[t]; for (size_t i = 0; i < D; ++i) attnOut[i] += wt * Vt[i];
=======
            float wt = weights[t]; for (qsizetype i = 0; i < D; ++i) attnOut[i] += wt * Vt[i];
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        }
        matmul(attnOut.data(), context_.layers[static_cast<size_t>(layerIdx)].attn_o_w.data(), y, 1, static_cast<int>(D), static_cast<int>(D));
        return;
    }

    // Multi-head attention with GQA and RoPE
    std::vector<float> n(D), q(D), k(D), v(D);
    const auto& L = context_.layers[static_cast<size_t>(layerIdx)];
    layerNorm(x, n.data(), L.ln_1_g, L.ln_1_b, D);
    matmul(n.data(), L.attn_q_w.data(), q.data(), 1, static_cast<int>(D), static_cast<int>(D));
    matmul(x, L.attn_k_w.data(), k.data(), 1, static_cast<int>(D), static_cast<int>(D));
    matmul(x, L.attn_v_w.data(), v.data(), 1, static_cast<int>(D), static_cast<int>(D));

    // Apply RoPE to Q and K (in-place rotation per head)
    size_t pos = context_.kvLen;
    auto rotate = [&](float* vec, int head, size_t position) {
        float* h = vec + head * headDim;
        for (int i = 0; i < headDim; i += 2) {
            float fcr = std::cos(static_cast<float>(position) * context_.invFreq[i / 2]);
            float fsi = std::sin(static_cast<float>(position) * context_.invFreq[i / 2]);
            float v0 = h[i];
            float v1 = h[i + 1];
            h[i] = v0 * fcr - v1 * fsi;
            h[i + 1] = v0 * fsi + v1 * fcr;
        }
    };

    for (int h = 0; h < nHead; ++h) rotate(q.data(), h, pos);
    for (int h = 0; h < nKVHead; ++h) rotate(k.data(), h, pos);

    // Store K/V in cache: [nLayers, nKVHeads, maxTokens, headDim]
    size_t cacheHeadStride = static_cast<size_t>(context_.maxTokens) * static_cast<size_t>(headDim);
    size_t cacheLayerStride = static_cast<size_t>(nKVHead) * cacheHeadStride;
    for (int kvh = 0; kvh < nKVHead; ++kvh) {
<<<<<<< HEAD
        float* Kc = context_.keyCache.data() + static_cast<size_t>(layerIdx) * cacheLayerStride + kvh * cacheHeadStride + pos * headDim;
        float* Vc = context_.valueCache.data() + static_cast<size_t>(layerIdx) * cacheLayerStride + kvh * cacheHeadStride + pos * headDim;
=======
        float* Kc = context_.keyCache.data() + layerIdx * cacheLayerStride + kvh * cacheHeadStride + pos * headDim;
        float* Vc = context_.valueCache.data() + layerIdx * cacheLayerStride + kvh * cacheHeadStride + pos * headDim;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        std::memcpy(Kc, k.data() + kvh * headDim, static_cast<size_t>(headDim) * sizeof(float));
        std::memcpy(Vc, v.data() + kvh * headDim, static_cast<size_t>(headDim) * sizeof(float));
    }

    // Multi-head attention loop with GQA mapping
    std::vector<float> attnOut(D, 0.0f);
    std::vector<float> logits(pos + 1);
    float scale = 1.0f / std::sqrt(static_cast<float>(headDim));

    for (int h = 0; h < nHead; ++h) {
        int kvH = h * nKVHead / nHead;  // GQA mapping: multiple query heads share one KV head
        float* qHead = q.data() + h * headDim;

        // Compute attention scores for this head
        for (size_t t = 0; t <= pos; ++t) {
<<<<<<< HEAD
            const float* Kt = context_.keyCache.data() + static_cast<size_t>(layerIdx) * cacheLayerStride + kvH * cacheHeadStride + t * headDim;
=======
            const float* Kt = context_.keyCache.data() + layerIdx * cacheLayerStride + kvH * cacheHeadStride + t * headDim;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
            float score = 0.0f;
            for (int d = 0; d < headDim; ++d) score += qHead[d] * Kt[d];
            logits[t] = score * scale;
        }

        // Softmax over logits
        float maxScore = logits[0];
        for (size_t t = 1; t <= pos; ++t) if (logits[t] > maxScore) maxScore = logits[t];
        float sumExp = 0.0f;
        for (size_t t = 0; t <= pos; ++t) { logits[t] = std::exp(logits[t] - maxScore); sumExp += logits[t]; }
        for (size_t t = 0; t <= pos; ++t) logits[t] /= (sumExp + 1e-9f);

        // Accumulate weighted values into output
        for (int d = 0; d < headDim; ++d) {
            float acc = 0.0f;
            for (size_t t = 0; t <= pos; ++t) {
<<<<<<< HEAD
                const float* Vt = context_.valueCache.data() + static_cast<size_t>(layerIdx) * cacheLayerStride + kvH * cacheHeadStride + t * headDim;
=======
                const float* Vt = context_.valueCache.data() + layerIdx * cacheLayerStride + kvH * cacheHeadStride + t * headDim;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
                acc += logits[t] * Vt[d];
            }
            attnOut[h * headDim + d] = acc;
        }
    }

    // Output projection
    matmul(attnOut.data(), L.attn_o_w.data(), y, 1, static_cast<int>(D), static_cast<int>(D));
}

<<<<<<< HEAD
void GGUFRunner::mlpForward(int layerIdx, const float* x, float* y) {
    const size_t D = context_.embedDim;
=======
void GGUFRunner::mlpForward(int layerIdx, const float* x, float* y)
{
    const qsizetype D = context_.embedDim;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    const auto& L = context_.layers[static_cast<size_t>(layerIdx)];
    std::vector<float> n(D);
    layerNorm(x, n.data(), L.ln_2_g, L.ln_2_b, D);
    std::vector<float> up(4 * D), gate(4 * D), act(4 * D);
    matmul(n.data(), L.mlp_up_w.data(), up.data(), 1, static_cast<int>(D), static_cast<int>(4 * D));
    matmul(n.data(), L.mlp_gate_w.data(), gate.data(), 1, static_cast<int>(D), static_cast<int>(4 * D));
<<<<<<< HEAD
    for (size_t i = 0; i < 4 * D; ++i) { float s = 1.0f / (1.0f + std::exp(-gate[i])); act[i] = up[i] * (gate[i] * s); }
=======
    for (qsizetype i = 0; i < 4 * D; ++i) { float s = 1.0f / (1.0f + std::exp(-gate[i])); act[i] = up[i] * (gate[i] * s); }
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    matmul(act.data(), L.mlp_down_w.data(), y, 1, static_cast<int>(4 * D), static_cast<int>(D));
}

void GGUFRunner::fallback_matrix_multiply(float* A, float* B, float* C, int N, int M, int K)
{
    for (int i = 0; i < N; ++i) {
        for (int j = 0; j < K; ++j) {
            float sum = 0.0f;
            for (int k = 0; k < M; ++k) {
                sum += A[i * M + k] * B[k * K + j];
            }
            C[i * K + j] = sum;
        }
    }
}

<<<<<<< HEAD
bool GGUFRunner::loadModel(const std::string& filePath) {
    loadGGUFModel(filePath);
    if (context_.mappedData) {
        if (onModelLoaded_) onModelLoaded_(filePath, context_.modelFileSize);
=======
bool GGUFRunner::loadModel(const QString& filePath)
{
    loadGGUFModel(filePath);
    if (context_.mappedData) {
        emit modelLoaded(filePath, context_.modelFileSize);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        return true;
    }
    return false;
}

size_t GGUFRunner::ggmlTypeSize(GgmlType type)
{
    switch (type) {
    case GgmlType::F32:  return 4;  // 4 bytes per element
    case GgmlType::F16:  return 2;  // 2 bytes per element
    case GgmlType::Q4_0: return 18; // 18 bytes per 32-element block
    case GgmlType::Q8_0: return 34; // 34 bytes per 32-element block
    default: return 4;
    }
}

<<<<<<< HEAD
std::vector<uint8_t> GGUFRunner::readTensorData(std::ifstream& file, uint64_t offset, uint64_t numBytes) {
    file.seekg(static_cast<std::streamoff>(offset));
    std::vector<uint8_t> out(static_cast<size_t>(numBytes));
    if (numBytes) file.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(numBytes));
    return out;
}

bool GGUFRunner::loadTensor(std::ifstream& file, const std::string& name, std::vector<float>& weights) {
    auto it = context_.tensorTable.find(name);
    if (it == context_.tensorTable.end()) return false;
    const auto& desc = it->second;
    size_t totalElements = 1;
    for (auto dim : desc.dims) totalElements *= dim;
    size_t numBytes = 0;
    if (desc.type == GgmlType::F32) numBytes = totalElements * 4;
    else if (desc.type == GgmlType::Q4_0) numBytes = (totalElements / 32) * 18;
    else if (desc.type == GgmlType::Q8_0) numBytes = (totalElements / 32) * 34;

    std::vector<uint8_t> rawData = readTensorData(file, desc.offset, numBytes);
    if (rawData.empty()) return false;

    weights.resize(totalElements);
    if (desc.type == GgmlType::F32) {
        const float* ptr = reinterpret_cast<const float*>(rawData.data());
        std::copy(ptr, ptr + totalElements, weights.begin());
    } else if (desc.type == GgmlType::Q4_0) {
        if (name == "output.weight")
            context_.raw_q4_output = rawData;
        dequantizeRowQ4_0_scalar(rawData.data(), weights.data(), totalElements);
    } else if (desc.type == GgmlType::Q8_0) {
        dequantizeRowQ8_0_scalar(rawData.data(), weights.data(), totalElements);
=======
QByteArray GGUFRunner::readTensorData(QFile& file, quint64 offset, quint64 numBytes)
{
    if (!file.seek(static_cast<qint64>(offset))) return QByteArray();
    return file.read(static_cast<qint64>(numBytes));
}

bool GGUFRunner::loadTensor(QFile& file, const QString& name, std::vector<float>& weights)
{
    if (!context_.tensorTable.contains(name)) {
        qWarning() << "Tensor not found in table:" << name;
        return false;
    }
    const auto& desc = context_.tensorTable[name];
    size_t totalElements = 1;
    for (auto dim : desc.dims) totalElements *= dim;
    
    size_t numBytes = 0;
    if (desc.type == GgmlType::F32) {
        numBytes = totalElements * 4;
    } else if (desc.type == GgmlType::Q4_0) {
        numBytes = (totalElements / 32) * 18;
    } else if (desc.type == GgmlType::Q8_0) {
        numBytes = (totalElements / 32) * 34;
    }

    QByteArray rawData = readTensorData(file, desc.offset, numBytes);
    if (rawData.isEmpty()) return false;

    weights.resize(totalElements);
    if (desc.type == GgmlType::F32) {
        const float* ptr = reinterpret_cast<const float*>(rawData.constData());
        std::copy(ptr, ptr + totalElements, weights.begin());
    } else if (desc.type == GgmlType::Q4_0) {
        // Keep raw bytes for output.weight to enable runtime-dispatched GEMM
        if (name == QLatin1String("output.weight")) {
            context_.raw_q4_output.assign(reinterpret_cast<const uint8_t*>(rawData.constData()),
                                          reinterpret_cast<const uint8_t*>(rawData.constData()) + rawData.size());
        }
        dequantizeRowQ4_0_scalar(rawData.constData(), weights.data(), totalElements);
    } else if (desc.type == GgmlType::Q8_0) {
        dequantizeRowQ8_0_scalar(rawData.constData(), weights.data(), totalElements);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    }
    return true;
}

<<<<<<< HEAD
bool GGUFRunner::parseGgufTensors(std::ifstream& file) {
    if (!loadTensor(file, "token_embd.weight", context_.tok_embeddings)) return false;
    (void)loadTensor(file, "output_norm.weight", context_.output_norm_w);
    (void)loadTensor(file, "output.weight", context_.output_w);
    return true;
}

bool GGUFRunner::readTensorFloat32(std::ifstream& file, int64_t offset, int64_t count, std::vector<float>& out) {
    const ModelContext::TensorDesc* desc = nullptr;
    for (const auto& p : context_.tensorTable) {
        if (p.second.offset == static_cast<uint64_t>(offset)) { desc = &p.second; break; }
    }
    if (!desc) return false;
    uint64_t expect = 1;
    for (uint64_t dim : desc->dims) expect *= dim;
    if (expect != static_cast<uint64_t>(count)) return false;
    size_t typeSize = ggmlTypeSize(desc->type);
    uint64_t byteSize = 0;
    if (desc->type == GgmlType::F32 || desc->type == GgmlType::F16)
        byteSize = expect * typeSize;
    else if (desc->type == GgmlType::Q4_0 || desc->type == GgmlType::Q8_0)
        byteSize = (expect / 32) * typeSize;
    file.seekg(static_cast<std::streamoff>(offset));
    std::vector<uint8_t> raw(static_cast<size_t>(byteSize));
    file.read(reinterpret_cast<char*>(raw.data()), static_cast<std::streamsize>(byteSize));
    if (file.gcount() != static_cast<std::streamsize>(byteSize)) return false;
    out.resize(static_cast<size_t>(count));
    const char* src = reinterpret_cast<const char*>(raw.data());
    switch (desc->type) {
    case GgmlType::F32: std::memcpy(out.data(), src, static_cast<size_t>(byteSize)); break;
    case GgmlType::F16: {
        const uint16_t* h = reinterpret_cast<const uint16_t*>(src);
        for (uint64_t i = 0; i < expect; ++i) out[i] = f16ToF32(h[i]);
        break;
    }
    case GgmlType::Q4_0: dequantizeRowQ4_0_scalar(src, out.data(), expect); break;
    case GgmlType::Q8_0: dequantizeRowQ8_0_scalar(src, out.data(), expect); break;
    default: return false;
=======
bool GGUFRunner::parseGgufTensors(QFile& file)
{
    // Load essential tensors using table-driven approach
    if (!loadTensor(file, "token_embd.weight", context_.tok_embeddings)) {
        qWarning() << "Failed to load token embeddings";
        return false;
    }
    
    // Load output norm and output weights
    if (!loadTensor(file, "output_norm.weight", context_.output_norm_w)) {
        qWarning() << "Warning: output_norm.weight not found";
    }
    if (!loadTensor(file, "output.weight", context_.output_w)) {
        qWarning() << "Warning: output.weight not found";
    }
    
    return true;
}

bool GGUFRunner::readTensorFloat32(QFile& file, qint64 offset, qint64 count, std::vector<float>& out)
{
    // 1. Look up the tensor that owns this byte range (exact offset match)
    const ModelContext::TensorDesc* desc = nullptr;
    for (const auto& d : context_.tensorTable) {
        if (d.offset == static_cast<quint64>(offset)) {
            desc = &d;
            break;
        }
    }
    if (!desc) {
        qWarning() << "GGUF: no tensor owns offset" << offset;
        return false;
    }

    // 2. Compute element count from shape
    quint64 expect = 1;
    for (quint64 dim : desc->dims) expect *= dim;
    if (expect != static_cast<quint64>(count)) {
        qWarning() << "GGUF: element-count mismatch for tensor at offset" << offset
                   << "expected" << expect << "got" << count;
        return false;
    }

    // 3. Compute byte size on disk
    quint64 typeSize = ggmlTypeSize(desc->type);
    quint64 byteSize = 0;
    if (desc->type == GgmlType::F32 || desc->type == GgmlType::F16) {
        byteSize = expect * typeSize;
    } else if (desc->type == GgmlType::Q4_0 || desc->type == GgmlType::Q8_0) {
        byteSize = (expect / 32) * typeSize;  // typeSize is bytes per block
    }

    // 4. Read raw bytes
    if (!file.seek(offset)) return false;
    QByteArray raw = file.read(static_cast<qint64>(byteSize));
    if (raw.size() != static_cast<qsizetype>(byteSize)) {
        qWarning() << "GGUF: short read for tensor at offset" << offset;
        return false;
    }

    // 5. Convert to float32 (scalar path only)
    out.resize(count);
    const char* src = raw.constData();
    switch (desc->type) {
    case GgmlType::F32:
        std::memcpy(out.data(), src, byteSize);
        break;

    case GgmlType::F16: {
        const quint16* h = reinterpret_cast<const quint16*>(src);
        for (quint64 i = 0; i < expect; ++i)
            out[i] = f16ToF32(h[i]);
        break;
    }
    case GgmlType::Q4_0:
        dequantizeRowQ4_0_scalar(src, out.data(), expect);
        break;
    case GgmlType::Q8_0:
        dequantizeRowQ8_0_scalar(src, out.data(), expect);
        break;
    default:
        qWarning() << "GGUF: unsupported type" << static_cast<int>(desc->type);
        return false;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    }
    return true;
}

<<<<<<< HEAD
std::vector<uint8_t> GGUFRunner::compressBrutal(const void* data, size_t len) {
    size_t out_len = 0;
    void* out_ptr = nullptr;
=======
QByteArray GGUFRunner::compressBrutal(const void* data, size_t len)
{
    size_t out_len = 0;
    void* out_ptr = nullptr;

    // Selects the brutal_gzip kernel that matched the current architecture (MASM for x64, NEON for ARM64).
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
#if defined(HAS_BRUTAL_GZIP_MASM)
    out_ptr = deflate_brutal_masm(data, len, &out_len);
#elif defined(HAS_BRUTAL_GZIP_NEON)
    out_ptr = deflate_brutal_neon(data, len, &out_len);
<<<<<<< HEAD
#endif
    if (!out_ptr) return {};
    std::vector<uint8_t> result(static_cast<const uint8_t*>(out_ptr), static_cast<const uint8_t*>(out_ptr) + out_len);
    std::free(out_ptr);
=======
#else
    // Fallback or no-op if architecture not supported
    // For now, return empty or implement a slow C++ fallback if needed
    return QByteArray();
#endif

    if (!out_ptr) return QByteArray();

    // Take ownership of the malloc-ed buffer into QByteArray
    // QByteArray makes a copy by default, so we copy and free.
    // To avoid copy, we would need to wrap it, but QByteArray doesn't easily take malloc ownership without custom deleter.
    // Given the speed, a memcpy here is negligible compared to qCompress.
    QByteArray result(reinterpret_cast<const char*>(out_ptr), static_cast<int>(out_len));
    free(out_ptr);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    return result;
}

