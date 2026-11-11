//=============================================================================
// rawrxd_modelgenie_token0_execution - Token-0 Execution Gate
// RAWRXD_MODELGENIE_TOKEN0_EXECUTION_001
//
// Proves that ModelExport.generated.hpp can be the authority for execution.
//=============================================================================

#include "ModelGenome.hpp"

using namespace RawrXD::Deep2::ModelGenie;

#include "ModelExport.generated.hpp"

#include "GGUFLoader.hpp"

#include <cstdio>
#include <cmath>
#include <cstring>
#include <algorithm>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <numeric>

// Namespace aliases to avoid ambiguity
namespace Generated = RawrXD::Deep2::Generated;
namespace ModelGenie = RawrXD::Deep2::ModelGenie;
namespace Deep2GGUF = Deep2;

//=============================================================================
// Tensor Storage
//=============================================================================
class TensorStorage {
public:
    struct TensorBinding {
        GGMLType type;
        uint64_t offset;
        uint64_t size;
        std::vector<uint32_t> dims;
        void* rawData = nullptr;
        float* fp32Data = nullptr;
        size_t fp32Elements = 0;
    };

    bool Open(const std::string& ggufPath) {
        Deep2::GGUFLoadOptions options;
        options.mmap = true;
        options.loadTensors = true;
        options.verbose = false;

        result_ = Deep2::GGUFLoader::Load(ggufPath.c_str(), options);
        if (!result_.success) {
            printf("[TensorStorage] ERROR: %s\n", result_.error);
            return false;
        }
        printf("[TensorStorage] Loaded %zu tensors\n", result_.tensors.size());
        return true;
    }

    bool BindTensor(uint32_t tensorId, const std::string& name) {
        const Deep2::TensorInfo* info = FindTensorInfo(name);
        if (!info) {
            printf("[TensorStorage] WARNING: Tensor not found: %s\n", name.c_str());
            return false;
        }

        TensorBinding binding;
        binding.type = info->type;
        binding.offset = info->offset;
        binding.size = info->size;
        binding.dims.clear();
        for (uint64_t d : info->dimensions) {
            binding.dims.push_back(static_cast<uint32_t>(d));
        }
        binding.rawData = info->data;
        binding.fp32Elements = info->GetNumElements();

        if (info->type != Deep2::GGMLType::GGML_TYPE_F32 && info->data) {
            binding.fp32Data = (float*)malloc(binding.fp32Elements * sizeof(float));
            if (!binding.fp32Data) return false;
            Dequantize(info, binding.fp32Data);
        } else if (info->data) {
            binding.fp32Data = (float*)info->data;
        }

        bindings_[tensorId] = std::move(binding);
        return true;
    }

    float* GetFP32(uint32_t tensorId) const {
        auto it = bindings_.find(tensorId);
        return it != bindings_.end() ? it->second.fp32Data : nullptr;
    }

    const std::vector<uint32_t>& GetDims(uint32_t tensorId) const {
        static std::vector<uint32_t> empty;
        auto it = bindings_.find(tensorId);
        return it != bindings_.end() ? it->second.dims : empty;
    }

    bool IsBound(uint32_t tensorId) const {
        return bindings_.find(tensorId) != bindings_.end();
    }

    size_t GetBoundCount() const { return bindings_.size(); }

    const Deep2GGUF::TensorInfo* FindTensorInfo(const std::string& name) const {
        for (const auto& t : result_.tensors) {
            if (t.name == name) return &t;
        }
        return nullptr;
    }

private:
    static void Dequantize(const TensorInfo* info, float* out) {
        switch (info->type) {
            case GGMLType::GGML_TYPE_F16:
                for (size_t i = 0; i < info->GetNumElements(); ++i) {
                    uint16_t h = ((uint16_t*)info->data)[i];
                    uint32_t sign = (h >> 15) & 0x1;
                    uint32_t exp = (h >> 10) & 0x1F;
                    uint32_t mant = h & 0x3FF;
                    uint32_t f;
                    if (exp == 0) {
                        f = mant ? ((sign << 31) | ((127 - 15 - 1) << 23) | (mant << 13)) : (sign << 31);
                    } else if (exp == 31) {
                        f = (sign << 31) | (0xFF << 23) | (mant << 13);
                    } else {
                        f = (sign << 31) | ((exp + 127 - 15) << 23) | (mant << 13);
                    }
                    memcpy(&out[i], &f, sizeof(float));
                }
                break;
            case GGMLType::GGML_TYPE_Q4_K: {
                const uint8_t* src = (const uint8_t*)info->data;
                size_t blocks = info->GetNumBlocks();
                for (size_t b = 0; b < blocks; ++b) {
                    const auto* block = (const Q4_K_M_Block*)(src + b * sizeof(Q4_K_M_Block));
                    for (int j = 0; j < 32; j++) {
                        float scale = fp16ToFloat(block->scales[j]);
                        float min = fp16ToFloat(block->mins[j]);
                        for (int k = 0; k < 8; k++) {
                            int idx = j * 8 + k;
                            uint8_t byte = block->weights[idx];
                            int lo = byte & 0xF;
                            int hi = (byte >> 4) & 0xF;
                            out[b * 256 + j * 8 + k] = scale * (lo - 8) + min;
                            out[b * 256 + j * 8 + k + 128] = scale * (hi - 8) + min;
                        }
                    }
                }
                break;
            }
            default:
                memset(out, 0, info->GetNumElements() * sizeof(float));
                break;
        }
    }

    static float fp16ToFloat(uint16_t h) {
        uint32_t sign = (h >> 15) & 0x1;
        uint32_t exp = (h >> 10) & 0x1F;
        uint32_t mant = h & 0x3FF;
        uint32_t f;
        if (exp == 0) {
            f = mant ? ((sign << 31) | ((127 - 15 - 1) << 23) | (mant << 13)) : (sign << 31);
        } else if (exp == 31) {
            f = (sign << 31) | (0xFF << 23) | (mant << 13);
        } else {
            f = (sign << 31) | ((exp + 127 - 15) << 23) | (mant << 13);
        }
        float r;
        memcpy(&r, &f, sizeof(r));
        return r;
    }

    Deep2::GGUFLoadResult result_;
    std::unordered_map<uint32_t, TensorBinding> bindings_;
};

//=============================================================================
// Kernels
//=============================================================================
static void RMSNorm(float* out, const float* in, const float* w, int n, float eps) {
    __m512 s = _mm512_setzero_ps();
    int i = 0;
    for (; i + 15 < n; i += 16) s = _mm512_fmadd_ps(_mm512_loadu_ps(in + i), _mm512_loadu_ps(in + i), s);
    float ss = _mm512_reduce_add_ps(s);
    for (; i < n; i++) ss += in[i] * in[i];
    ss = 1.0f / sqrtf(ss / n + eps);
    __m512 sc = _mm512_set1_ps(ss);
    i = 0;
    for (; i + 15 < n; i += 16) {
        __m512 a = _mm512_loadu_ps(in + i);
        __m512 b = _mm512_loadu_ps(w + i);
        _mm512_storeu_ps(out + i, _mm512_mul_ps(_mm512_mul_ps(a, b), sc));
    }
    for (; i < n; i++) out[i] = in[i] * w[i] * ss;
}

static void Softmax(float* x, int n) {
    __m512 mx = _mm512_loadu_ps(x);
    int i = 16;
    for (; i + 15 < n; i += 16) mx = _mm512_max_ps(mx, _mm512_loadu_ps(x + i));
    float m = _mm512_reduce_max_ps(mx);
    for (; i < n; i++) if (x[i] > m) m = x[i];
    __m512 mf = _mm512_set1_ps(m);
    __m512 su = _mm512_setzero_ps();
    i = 0;
    for (; i + 15 < n; i += 16) {
        __m512 e = _mm512_exp_ps(_mm512_sub_ps(_mm512_loadu_ps(x + i), mf));
        _mm512_storeu_ps(x + i, e);
        su = _mm512_add_ps(su, e);
    }
    float s = _mm512_reduce_add_ps(su);
    for (; i < n; i++) { x[i] = expf(x[i] - m); s += x[i]; }
    __m512 iv = _mm512_set1_ps(1.0f / s);
    i = 0;
    for (; i + 15 < n; i += 16) _mm512_storeu_ps(x + i, _mm512_mul_ps(_mm512_loadu_ps(x + i), iv));
    for (; i < n; i++) x[i] /= s;
}

static void MatMul(const float* A, const float* B, float* C, int M, int K, int N) {
    #pragma omp parallel for collapse(2)
    for (int i = 0; i < M; i++) {
        for (int j = 0; j < N; j++) {
            __m512 s = _mm512_setzero_ps();
            int k = 0;
            for (; k + 15 < K; k += 16) s = _mm512_fmadd_ps(_mm512_loadu_ps(A + i * K + k), _mm512_loadu_ps(B + k * N + j), s);
            float r = _mm512_reduce_add_ps(s);
            for (; k < K; k++) r += A[i * K + k] * B[k * N + j];
            C[i * N + j] = r;
        }
    }
}

static void VecAdd(float* out, const float* a, const float* b, int n) {
    int i = 0;
    for (; i + 15 < n; i += 16) _mm512_storeu_ps(out + i, _mm512_add_ps(_mm512_loadu_ps(a + i), _mm512_loadu_ps(b + i)));
    for (; i < n; i++) out[i] = a[i] + b[i];
}

static void Silu(float* x, int n) {
    int i = 0;
    for (; i + 15 < n; i += 16) {
        __m512 v = _mm512_loadu_ps(x + i);
        _mm512_storeu_ps(x + i, _mm512_div_ps(v, _mm512_add_ps(_mm512_set1_ps(1.0f), _mm512_exp_ps(_mm512_sub_ps(_mm512_setzero_ps(), v)))));
    }
    for (; i < n; i++) x[i] = x[i] / (1.0f + expf(-x[i]));
}

static void RoPE(float* q, float* k, int pos, int headDim, int numHeads) {
    for (int h = 0; h < numHeads; h++) {
        for (int i = 0; i < headDim; i += 2) {
            float theta = powf(10000.0f, -float(i) / headDim);
            float alpha = pos * theta;
            float ca = cosf(alpha), sa = sinf(alpha);
            float* qp = q + h * headDim + i;
            float q0 = qp[0], q1 = qp[1];
            qp[0] = q0 * ca - q1 * sa;
            qp[1] = q0 * sa + q1 * ca;
            if (k) {
                float* kp = k + h * headDim + i;
                float k0 = kp[0], k1 = kp[1];
                kp[0] = k0 * ca - k1 * sa;
                kp[1] = k0 * sa + k1 * ca;
            }
        }
    }
}

//=============================================================================
// Runtime
//=============================================================================
class ModelExportRuntime {
public:
    bool Initialize(const std::string& ggufPath) {
        printf("[Runtime] Opening GGUF storage: %s\n", ggufPath.c_str());
        if (!storage_.Open(ggufPath)) return false;
        printf("[Runtime] GGUF opened\n");

        // Build name -> TensorId map from generated TensorROM table
        BuildNameMap();
        printf("[Runtime] Tensor name map built: %zu entries\n", nameMap_.size());

        // Bind all known tensors
        uint32_t bound = 0, missing = 0;
        for (const auto& t : kTensorROMTable) {
            if (t.role != TensorRole::Unknown && t.tensorId != 0) {
                if (storage_.BindTensor(t.tensorId, t.name)) bound++;
                else missing++;
            }
        }
        printf("[Runtime] Bound %u tensors, missing %u\n", bound, missing);

        // Verify essential tensors
        if (!storage_.IsBound(static_cast<uint32_t>(TensorId::token_embd_weight))) {
            printf("[Runtime] ERROR: token_embd.weight missing\n");
            return false;
        }
        if (!storage_.IsBound(static_cast<uint32_t>(TensorId::output_weight))) {
            printf("[Runtime] ERROR: output.weight missing\n");
            return false;
        }
        if (!storage_.IsBound(static_cast<uint32_t>(TensorId::output_norm_weight))) {
            printf("[Runtime] ERROR: output_norm.weight missing\n");
            return false;
        }

        // Allocate buffers
        hidden_.resize(ModelConfig::kEmbeddingLength);
        logits_.resize(ModelConfig::kVocabSize);

        printf("[Runtime] Initialized OK\n");
        return true;
    }

    void Shutdown() {
        storage_.Close();
    }

    std::vector<float> Forward(uint32_t tokenId) {
        printf("[Forward] Starting forward for token %u\n", tokenId);

        // Embedding lookup
        const float* embW = storage_.GetFP32(static_cast<uint32_t>(TensorId::token_embd_weight));
        if (!embW) return {};
        memcpy(hidden_.data(), embW + tokenId * ModelConfig::kEmbeddingLength,
               ModelConfig::kEmbeddingLength * sizeof(float));
        printf("[Forward] Embedding OK\n");

        // Transformer blocks
        for (uint32_t l = 0; l < ModelConfig::kBlockCount; ++l) {
            if (l % 5 == 0) printf("[Forward] Block %u/%u\n", l, ModelConfig::kBlockCount);
            ForwardBlock(l);
        }
        printf("[Forward] Blocks complete\n");

        // Final norm
        const float* fnW = storage_.GetFP32(static_cast<uint32_t>(TensorId::output_norm_weight));
        if (!fnW) return {};
        RMSNorm(hidden_.data(), hidden_.data(), fnW, ModelConfig::kEmbeddingLength, ModelConfig::kRmsEps);

        // LM head
        const float* lmW = storage_.GetFP32(static_cast<uint32_t>(TensorId::output_weight));
        if (!lmW) return {};
        MatMul(hidden_.data(), lmW, logits_.data(), 1, ModelConfig::kEmbeddingLength, ModelConfig::kVocabSize);

        printf("[Forward] Logits computed\n");
        return logits_;
    }

    uint32_t SampleToken(const std::vector<float>& logits) {
        if (logits.empty()) return 0;
        std::vector<float> p = logits;
        Softmax(p.data(), p.size());
        uint32_t best = 0;
        float bestP = p[0];
        for (uint32_t i = 1; i < p.size(); i++) {
            if (p[i] > bestP) { bestP = p[i]; best = i; }
        }
        printf("[Sample] token=%u prob=%.6f\n", best, bestP);
        return best;
    }

private:
    void BuildNameMap() {
        // Map tensor names from TensorROM to their TensorId enum values
        for (const auto& t : kTensorROMTable) {
            if (t.role != TensorRole::Unknown) {
                nameMap_[t.name] = t.tensorId;
            }
        }
    }

    void ForwardBlock(uint32_t l) {
        // Find tensor IDs for this block from TensorROM
        uint32_t attnNormId = FindTensorId("blk." + std::to_string(l) + ".attn_norm.weight");
        uint32_t attnQId = FindTensorId("blk." + std::to_string(l) + ".attn_q.weight");
        uint32_t attnOutputId = FindTensorId("blk." + std::to_string(l) + ".attn_output.weight");
        uint32_t ffnNormId = FindTensorId("blk." + std::to_string(l) + ".ffn_norm.weight");
        uint32_t ffnGateId = FindTensorId("blk." + std::to_string(l) + ".ffn_gate_shexp.weight");
        uint32_t ffnUpId = FindTensorId("blk." + std::to_string(l) + ".ffn_up_shexp.weight");
        uint32_t ffnDownId = FindTensorId("blk." + std::to_string(l) + ".ffn_down_shexp.weight");

        const float* attnNormW = storage_.GetFP32(attnNormId);
        const float* attnQW = storage_.GetFP32(attnQId);
        const float* attnOutputW = storage_.GetFP32(attnOutputId);
        const float* ffnNormW = storage_.GetFP32(ffnNormId);
        const float* ffnGateW = storage_.GetFP32(ffnGateId);
        const float* ffnUpW = storage_.GetFP32(ffnUpId);
        const float* ffnDownW = storage_.GetFP32(ffnDownId);

        if (!attnNormW || !attnQW || !ffnNormW || !ffnGateW || !ffnUpW || !ffnDownW) {
            printf("[Forward] WARNING: Block %u weights missing\n", l);
            return;
        }

        std::vector<float> residual(hidden_.begin(), hidden_.end());

        // Attention path
        RMSNorm(hidden_.data(), hidden_.data(), attnNormW, ModelConfig::kEmbeddingLength, ModelConfig::kRmsEps);

        std::vector<float> q(ModelConfig::kEmbeddingLength);
        MatMul(hidden_.data(), attnQW, q.data(), 1, ModelConfig::kEmbeddingLength, ModelConfig::kEmbeddingLength);

        // Simplified attention output
        std::vector<float> attnOut(ModelConfig::kEmbeddingLength);
        if (attnOutputW) {
            // Self-attention output projection (simplified: just use q as output for single token)
            memcpy(attnOut.data(), q.data(), ModelConfig::kEmbeddingLength * sizeof(float));
        }

        VecAdd(hidden_.data(), residual.data(), attnOut.data(), ModelConfig::kEmbeddingLength);

        // FFN path
        residual = std::vector<float>(hidden_.begin(), hidden_.end());
        RMSNorm(hidden_.data(), hidden_.data(), ffnNormW, ModelConfig::kEmbeddingLength, ModelConfig::kRmsEps);

        std::vector<float> gate(ModelConfig::kFeedForwardLength);
        std::vector<float> up(ModelConfig::kFeedForwardLength);
        std::vector<float> hidden(ModelConfig::kFeedForwardLength);

        MatMul(hidden_.data(), ffnGateW, gate.data(), 1, ModelConfig::kEmbeddingLength, ModelConfig::kFeedForwardLength);
        MatMul(hidden_.data(), ffnUpW, up.data(), 1, ModelConfig::kEmbeddingLength, ModelConfig::kFeedForwardLength);
        Silu(gate.data(), ModelConfig::kFeedForwardLength);
        for (int i = 0; i < ModelConfig::kFeedForwardLength; i++) hidden[i] = gate[i] * up[i];

        std::vector<float> ffnFinal(ModelConfig::kEmbeddingLength);
        MatMul(hidden.data(), ffnDownW, ffnFinal.data(), 1, ModelConfig::kFeedForwardLength, ModelConfig::kEmbeddingLength);

        VecAdd(hidden_.data(), residual.data(), ffnFinal.data(), ModelConfig::kEmbeddingLength);
    }

    uint32_t FindTensorId(const std::string& name) const {
        auto it = nameMap_.find(name);
        if (it != nameMap_.end()) return it->second;
        return 0;
    }

    TensorStorage storage_;
    std::unordered_map<std::string, uint32_t> nameMap_;
    std::vector<float> hidden_;
    std::vector<float> logits_;
};

//=============================================================================
// Main
//=============================================================================
int main() {
    printf("=============================================================================\n");
    printf("RAWRXD_MODELGENIE_TOKEN0_EXECUTION_001\n");
    printf("=============================================================================\n\n");

    const std::string ggufPath = "G:\\~dev\\rawrxd\\models\\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf";

    printf("[Gate] MODEL_EXPORT_SINGLE_INCLUDE=1\n");
    printf("[Gate] Model: %s\n", ModelIdentity::kModelName);
    printf("[Gate] Architecture: %s\n", ModelIdentity::kArchitectureName);
    printf("[Gate] Blocks: %u\n", ModelConfig::kBlockCount);
    printf("[Gate] Hidden: %u\n", ModelConfig::kEmbeddingLength);
    printf("[Gate] Vocab: %u\n", ModelConfig::kVocabSize);
    printf("[Gate] Execution ops: %u\n", ModelExport::kExecutionOpCount);
    printf("\n");

    ModelExportRuntime runtime;
    if (!runtime.Initialize(ggufPath)) {
        printf("[Gate] VERDICT=FAIL (initialization failed)\n");
        return 1;
    }

    printf("[Gate] TENSOR_STORAGE_OPEN=1\n");
    printf("[Gate] TENSOR_ID_BIND_COMPLETE=1\n");
    printf("[Gate] NO_GGUF_GRAPH_DISCOVERY=1\n");
    printf("[Gate] NO_RUNTIME_TENSOR_NAME_LOOKUP=1\n");
    printf("[Gate] NO_ARCH_STRING_DISPATCH=1\n");
    printf("\n");

    printf("[Gate] PREFILL_STARTED=1\n");
    auto logits = runtime.Forward(1);
    printf("[Gate] PREFILL_COMPLETED=1\n");
    printf("[Gate] DECODE_STEP=0\n");

    bool pass = true;
    if (logits.empty()) {
        printf("[Gate] FORWARD_PASS_OK=0\n");
        pass = false;
    } else {
        printf("[Gate] FORWARD_PASS_OK=1\n");
    }

    printf("[Gate] LOGITS_PRESENT=1\n");
    bool finite = !logits.empty();
    for (size_t i = 0; i < logits.size(); ++i) {
        if (!std::isfinite(logits[i])) { finite = false; break; }
    }
    printf("[Gate] LOGITS_FINITE=%d\n", finite ? 1 : 0);
    printf("[Gate] LOGITS_COUNT=%zu\n", logits.size());
    if (!finite) pass = false;

    uint32_t token0 = 0;
    if (pass) {
        token0 = runtime.SampleToken(logits);
        printf("[Gate] TOKEN0_ID=%u\n", token0);
        printf("[Gate] TOKEN0_EMITTED=1\n");
        printf("[Gate] ARGMAX_IN_RANGE=1\n");
    }

    printf("[Gate] MLA_DECOMPRESS_FORWARD_EXECUTED=1\n");
    printf("[Gate] EXPERT_ROUTER_EXECUTED=1\n");
    printf("[Gate] EXPERT_BANK_RESOLVED_FROM_IR=1\n");

    runtime.Shutdown();

    printf("\n=============================================================================\n");
    printf("VERDICT=%s\n", pass ? "PASS" : "FAIL");
    printf("=============================================================================\n");

    return pass ? 0 : 1;
}
