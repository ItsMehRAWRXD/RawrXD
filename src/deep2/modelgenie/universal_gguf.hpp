// ============================================================================
// universal_gguf.hpp  --  RAWRXD_DEEP2_UNIVERSAL_INGEST
// ============================================================================
// Model-agnostic GGUF ingestion for Deep2.
//
// The old path used a GENERATED, per-model IR table (ExecutionIR.generated.hpp
// + TensorROM.generated.hpp) and ROMResolver compared the loaded GGUF against
// it byte-for-byte, fail-closing on ANY model that was not the one the table was
// generated from. That made Deep2 unable to load any other model.
//
// This layer replaces it: the architecture, config, tensor roles and op graph
// are all derived AT RUNTIME from the GGUF metadata and the tensor-name
// directory, so any GGUF can be ingested. Weights are resolved BY NAME and
// dequantised with ggml, so the whole quantisation zoo works; raw quantised
// bytes are retained for the types the GPU kernel consumes (Q4_K / Q6_K).
//
// No Qt, no third-party dependency beyond the Windows SDK and ggml.
// ============================================================================
#pragma once

#include <cstdint>
#include <cstddef>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

#include "ggml.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#endif

namespace RawrXD { namespace Deep2 { namespace Universal {

// ---------------------------------------------------------------------------
// Architecture families present in the model zoo, and the op graph each needs.
// ---------------------------------------------------------------------------
enum class ArchKind : uint8_t {
    Unknown = 0,
    LlamaLike,      // separate q/k/v + gate/up/down; llama, qwen*, granite, gemma3
    Phi3Fused,      // fused attn_qkv + ffn_up/down
    DeepSeekMLA,    // MLA (kv_a/kv_b) + MoE experts
    SsmHybrid,      // SSM blocks (+ attention on some blocks); nemotron_h
    Qwen3Next,      // SSM + linear attention hybrid + MoE
    MoeOnly,        // MoE with standard attention; gptoss, laguna, qwen35moe
    Encoder         // not a decoder (clip); ingest only, no decode graph
};

const char* ArchKindName(ArchKind k);

// A tensor's functional role, derived from its GGUF name. Global tensors carry
// block index -1; per-block tensors carry 0..block_count-1.
enum class Role : uint8_t {
    Other = 0,
    TokenEmbedding,
    OutputNorm,
    OutputWeight,      // final logit projection
    AttnNorm,
    AttnQ, AttnK, AttnV, AttnOutput,
    AttnQKV,           // phi3 fused
    AttnKNorm,         // q/k norm (gemma3)
    AttnKvANorm, AttnKvAMqa, AttnKvB, AttnO,   // deepseek MLA
    FfnNorm,
    FfnGate, FfnUp, FfnDown,
    ExpFfnGate, ExpFfnUp, ExpFfnDown,   // MoE experts (3-D: [ffn, experts, blocks])
    RouterGate,                          // MoE router
    SharedFfnGate, SharedFfnUp, SharedFfnDown, // deepseek2 shared experts (*_shexp)
    SsmA, SsmConv1dW, SsmConv1dB, SsmD, SsmDtB, SsmIn, SsmOut, SsmNorm,
    RopeFreqs, RopeFactors
};

// ---------------------------------------------------------------------------
// Tensor record (name-level, model-agnostic).
// ---------------------------------------------------------------------------
struct TensorRec {
    std::string name;
    std::vector<uint64_t> dims;   // dims[0] == ggml ne[0] (innermost)
    uint32_t gguf_type = 0;       // raw GGUF/ggml type id
    uint64_t rel_offset = 0;
    const uint8_t* data = nullptr;
    size_t bytes = 0;
    int32_t block = -1;
    Role role = Role::Other;
    ggml_type ggml_type = GGML_TYPE_COUNT;
    bool has_dequant = false;     // ggml can dequantise this type
    bool gpu_quant_capable = false;  // Q4_K / Q6_K: GPU dispatcher can consume raw bytes
};

// ---------------------------------------------------------------------------
// Derived model spec.
// ---------------------------------------------------------------------------
struct ModelSpec {
    std::string architecture;
    std::string model_name;
    ArchKind kind = ArchKind::Unknown;
    uint64_t block_count = 0;
    uint64_t embd = 0;
    uint64_t ffn = 0;
    uint64_t heads = 0;
    uint64_t heads_kv = 0;
    uint64_t rope_dim = 0;
    uint64_t rope_freq_base = 10000;
    // RoPE scaling. Read from the model's own metadata (llama.cpp's
    // .rope.scaling.*): deepseek2 ships type=yarn, factor=40,
    // original_context_length=4096 and yarn_log_multiplier=0.0707. An empty
    // type means plain, unscaled RoPE, which is what llama/qwen/gemma ship.
    std::string rope_scaling_type;
    double rope_scaling_factor = 1.0;        // yarn factor (40); freq_scale = 1/factor
    uint64_t rope_orig_ctx = 0;              // original_context_length (4096)
    double yarn_log_multiplier = 0.0;        // yarn_log_multiplier (0.0707)
    uint64_t vocab = 0;
    uint64_t context_length = 0;
    double rms_eps = 1e-5;
    // MoE
    uint64_t expert_count = 0;
    uint64_t expert_used = 0;
    uint64_t expert_shared = 0;
    uint64_t expert_ffn = 0;

    // Router weight post-processing, exactly as the GGUF declares it. The
    // reference renormalises the top-k weights to sum to 1 ONLY when
    // expert_weights_norm is set (qwen3-moe / gpt-oss style); DeepSeek-Coder-V2
    // omits the key, so its routing weights are the raw softmax probabilities
    // whose sum is < 1. expert_weights_scale is applied only when set to
    // something other than 0 (absent) or 1 (identity), matching the reference.
    bool expert_weights_norm = false;
    double expert_weights_scale = 0.0;
    // MLA
    uint64_t kv_lora_rank = 0;
    uint64_t key_length = 0;
    uint64_t value_length = 0;
    uint64_t leading_dense = 0;
    bool has_bias = false;        // qwen2-style attn_q/k/v .bias present
    // Mamba2 SSM (nemotron_h, qwen3-next). Read from the model's own metadata;
    // never defaulted, because a wrong state size silently corrupts the scan.
    uint64_t ssm_state_size = 0;   // d_state (N)
    uint64_t ssm_inner_size = 0;   // d_inner (D)
    uint64_t ssm_dt_rank = 0;      // time_step_rank
    uint64_t ssm_group_count = 0;  // n_groups
    uint64_t ssm_conv_kernel = 0;  // conv dim
    std::vector<std::string> notes;
};

// ---------------------------------------------------------------------------
// Op graph: same primitive vocabulary Deep2 already implements.
// ---------------------------------------------------------------------------
enum class Op : uint8_t {
    EmbeddingLookup, RmsNorm, Linear, Attention, MatMul,
    MlaDecompress, Router, TopK, MoEExecute, ResidualAdd, LmHead,
    SsmScan,      // Mamba2 selective scan (nemotron_h, qwen3-next)
    SwiGLU,       // out = silu(gate) * up, the dense-FFN activation
    Publish,      // copy an arena value to a named one (residual bookkeeping)
    SquaredReLU,  // out = relu(x)^2, Nemotron's gateless MLP activation
    Unsupported
};

struct GraphOp {
    Op op = Op::Unsupported;
    int32_t block = -1;
    std::string a, b, c, out;      // tensor names by role
    std::string detail;            // why unsupported, or extra info
};

struct OpGraph {
    std::vector<GraphOp> ops;
    size_t unsupported = 0;
};

// ---------------------------------------------------------------------------
// Ingest result.
// ---------------------------------------------------------------------------
struct IngestReport {
    bool ok = false;
    std::string error;
    ModelSpec spec;
    std::vector<TensorRec> tensors;
    OpGraph graph;
    size_t resolved = 0;          // tensors whose role+data were resolved
    size_t total = 0;
    size_t dequant_capable = 0;
    size_t gpu_quant_capable = 0;
    size_t no_dequant = 0;        // types ggml cannot dequantise
    std::map<uint32_t, size_t> type_histogram;
    std::vector<std::string> unsupported_types;
    // Resolution: name -> dequantised row for role-tested tensors.
    std::unordered_map<std::string, std::vector<float>> weights;
};

// Tokenizer, read from metadata. Everything a prompt-to-text run needs.
struct Tokenizer {
    bool ok = false;
    std::vector<std::string> tokens;   // tokenizer.ggml.tokens (index = id)
    std::vector<int32_t> types;        // tokenizer.ggml.token_type
    std::vector<std::string> merges;   // tokenizer.ggml.merges (BPE)
    int32_t bos_id = -1, eos_id = -1;
    // The chat template, if the model ships one.
    std::string chat_template;
};

// Provenance: what was actually loaded, so a run can be audited.
struct Provenance {    std::string path;
    std::string sha256;
    uint64_t file_bytes = 0;
    size_t tensor_count = 0;
    std::map<uint32_t, size_t> type_histogram;
    std::string architecture;
    std::string model_name;
};

const Tokenizer& GetTokenizer();

// Compute the SHA-256 of a file (self-contained, no dependency).
std::string Sha256File(const std::string& path);

// The provenance of the most recent Ingest() call: path, SHA-256, archive size,
// tensor count and the full type histogram.
const Provenance& GetProvenance();

// Ingest a GGUF. Memory maps the file; never loads it fully.
// `want_weights`: if true, dequantise every tensor ggml can dequantise
// (expensive for large models - callers should ask for a subset when probing).
const IngestReport& Ingest(const std::string& path, bool want_weights = false);
const IngestReport& IngestWeights(const std::string& path,
                                  const std::vector<std::string>& only_names);

} } }
