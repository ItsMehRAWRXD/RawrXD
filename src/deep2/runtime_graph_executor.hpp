// ============================================================================
// runtime_graph_executor.hpp  --  RAWRXD_DEEP2_RUNTIME_DISPATCH
// ============================================================================
// The execution authority for Deep2.
//
// RAWRXD_DEEP2_UNIVERSAL_INGEST made Deep2 able to RECOGNISE any GGUF. This
// makes it able to EXECUTE one: the runtime-derived graph is the single source
// of truth for dispatch, ROM-style generated tables are not consulted at all.
//
// Pipeline:
//   Bind(ingest report)
//     1. compile the runtime op graph into instructions with TENSOR HANDLES,
//        resolving every weight by name exactly once (no per-token string
//        search, which is what the old ROM path effectively did);
//     2. bind each instruction to a real kernel, and FAIL CLOSED if an
//        operator is unimplemented - an unsupported node prevents execution,
//        it is never silently skipped;
//     3. record the binding receipts so the caller can prove what ran.
//   ExecuteToken(token, position) -> logits
//
// Kernel selection is explicit and counted: quantised projections try the
// native Vulkan path first and fall back to the CPU reference with the reason
// recorded, so a CPU result is never reported as a GPU one.
// ============================================================================
#pragma once

#include "deep2_execution_trace.hpp"

#include <cstdint>
#include <cstddef>
#include <chrono>
#include <map>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "deep2_resource_governor.hpp"
#include "StrataExpertResidency.hpp"
#include "StrataInt8KVCache.hpp"
#include "modelgenie/universal_gguf.hpp"

// Short alias for the governor's move-only lease handle. The resource
// governor itself owns the accounting; the executor holds only leases.
using GovernorLease = rawrxd::deep2::Governor::Lease;

namespace RawrXD { namespace Deep2 { namespace RuntimeGraph {

enum class OpKind : uint8_t {
    EmbeddingLookup = 0, RmsNorm, Linear, Attention, MlaDecompress,
    Router, TopK, MoEExecute, ResidualAdd, LmHead,
    SsmScan,      // Mamba2 selective scan (nemotron_h, qwen3-next)
    Qsa,          // Qwen4Exp indexer + compressed-key sparse attention
    Gdn,          // Qwen4Exp gated delta-net recurrent state update
    Ple,          // Qwen4Exp per-layer n-gram embedding + short convolution
    Hyperconnection, // Qwen4Exp four-stream residual mix/down/up
    SparseMoE,    // Qwen4Exp top-k sparse expert grouped GEMM
    Publish,      // copy an arena value to a named one (residual bookkeeping)
    SwiGLU,       // out = silu(gate) * up, the dense-FFN activation
    SquaredReLU,  // out = relu(x)^2, Nemotron's gateless MLP activation
    Unsupported
};

const char* OpKindName(OpKind k);

// RAWRXD_MULTI_GPU: assign a transformer block's quant ops to a Vulkan device
// index (0 = default/primary) for split-model dual-GPU. Call before the first
// ExecuteToken; an empty mapping keeps the whole model on the default device
// (single-GPU behaviour, verified bit-identical).
void SetBlockVulkanDevice(uint32_t block, uint32_t vk_index);


// A tensor resolved once at bind time. `slot` indexes the executor's tensors_;
// `aux` carries optional companion slots (e.g. K and V for a fused QKV).
struct Instr {
    OpKind op = OpKind::Unsupported;
    int32_t block = -1;
    int32_t a = -1, b = -1, c = -1, out = -1;
    // SSA names from the runtime graph. An op's declared INPUT is an arena
    // value (e.g. "ffn_norm"), NOT the running hidden vector: a block's gate and
    // up projections both read "ffn_norm", so an executor that threads
    // `hidden_` through them would feed the gate's output into `up`.
    std::string aName, bName, outName;
    // attention: `q` carries the WEIGHT slot of the projection that consumes
    // this attention op's output (resolved at bind time). OpAttention uses it
    // to fail closed when the concatenated output width does not match the
    // projection's declared input width. `k`/`v` are unused by the current
    // graph shapes (the arena carries the q/k/v activations by name).
    int32_t q = -1;
    int32_t q_norm = -1;
    int32_t k_norm = -1;
    std::string detail;
};

struct BindStats {
    bool bound = false;
    std::string error;                 // why binding failed (fail-closed)
    size_t ops_total = 0;
    size_t ops_bound = 0;
    size_t ops_unbound = 0;
    size_t weights_resolved = 0;
    size_t weights_missing = 0;
    std::vector<std::string> unbound_ops;   // op kind + reason
    // Machine-readable fail-closed attribution. These fields describe the
    // first boundary that prevented binding; they never imply execution.
    std::string failure_stage;
    std::string first_blocking_operator;
    std::string failure_receipt_json;
    // Kernel receipts
    uint64_t gpu_calls = 0, cpu_calls = 0, gpu_rows = 0, cpu_rows = 0;
    std::string fallback_reason;
    std::string gpu_device;
    double cold_start_ms = 0, steady_kernel_ms = 0, dispatch_ms = 0, total_ms = 0;
};

class Executor {
public:
    Executor() = default;
    ~Executor();

    // Compile and bind. Returns false and fills Stats().error when any op
    // cannot be bound - the caller must not run in that case.
    bool Bind(const Universal::IngestReport& report);

    const BindStats& Stats() const { return stats_; }

    // Stable JSON receipt for callers and certification tooling. An empty
    // string means Bind has not failed in this executor instance.
    const std::string& FailureReceiptJson() const {
        return stats_.failure_receipt_json;
    }

    // Run one token at `position`. Returns false on any kernel failure.
    bool ExecuteToken(uint32_t token, size_t position);

    // Start a new independent session without rebinding model weights.
    // Recurrent state, KV state, logits, and admission counters are cleared;
    // immutable tensor bindings and compiled graph instructions are retained.
    void ResetState();

    // RAWRXD_DEEP2_D1_BATCHED_PREFILL: multi-token prefill. Ops run
    // op-major / token-minor: every Linear op queues one dot PER TOKEN into a
    // single submission (P dots, one command buffer, one fence for a whole
    // same-input projection group), while attention, MoE, SSM and norms run
    // per token in causal order so the KV cache and recurrent state are
    // byte-identical to the serial ExecuteToken path. After the call,
    // Logits() holds the LAST token's logits exactly as ExecuteToken would    // have produced them, and hidden_ is that token's final hidden state, so
    // generation continues with plain ExecuteToken. Opt-in; the serial path
    // is untouched. Returns false with LastError() set on any failure.
    //
    // RAWRXD_DEEP2_SPEC_VERIFY_001: when perPosLogits is non-null the pass
    // runs in VERIFY mode: LmHead executes for EVERY token, not just the
    // last, and (*perPosLogits)[t] receives the logits produced after
    // consuming tokens[t] at position startPos+t. That per-position logit
    // set IS the batched-verification primitive for speculative decoding:
    // gamma drafted tokens are checked against the verifier's own argmax at
    // each position in ONE batched pass. The last-token contract is kept
    // (Logits() and hidden_ are unchanged), and any non-finite value in any
    // captured position fails the pass closed - a speculative accept must
    // never be decided on garbage logits.
    bool PrefillBatch(const std::vector<uint32_t>& tokens, size_t startPos,
                      std::vector<std::vector<float>>* perPosLogits = nullptr);

    // Deep2 flight recorder: opt-in per-token / per-layer progress reporting so
    // the watchdog can distinguish "long-running kernel" from "stalled".
    // The path must already exist as a directory.
    void EnableFlightRecorder(const std::wstring& path);
    bool IsFlightRecorderEnabled() const;

    const std::vector<float>& Logits() const { return logits_; }
    size_t Position() const { return position_; }
    bool Ok() const { return bound_ && !last_error_.empty() == false; }
    const std::string& LastError() const { return last_error_; }
    uint32_t LastToken() const { return last_token_; }

    // ---- Intermediate tensors ----------------------------------------------
    //
    // RAWRXD_GATE7_NEMOTRON_MOE_001: a read-only view of an intermediate
    // tensor by its arena name, so a certification can compare the
    // execution's own buffers against an independent reference WITHOUT
    // recomputing anything. The view exposes the execution's actual buffer:
    // it is the same storage the operator wrote, not a copy.
    //
    // LIFETIME: the returned pointer is valid until the next ExecuteToken
    // replaces the arena's contents. CopyArenaValue is the lifetime-safe
    // form for a caller that needs to keep the data.
    const std::vector<float>* ArenaValue(const std::string& name) const {
        if (act_map_ == nullptr) return nullptr;
        const auto it = act_map_->find(name);
        return it == act_map_->end() ? nullptr : &it->second;
    }
    bool CopyArenaValue(const std::string& name, std::vector<float>& out) const {
        const std::vector<float>* value = ArenaValue(name);
        if (value == nullptr) return false;
        out = *value;
        return true;
    }

    // RAWRXD_GATE7_NEMOTRON_MOE_001: the routing's intermediate values, for
    // the numerical parity certificate. They are optional out-parameters so
    // the routing's behaviour is unchanged when they are not requested.
    struct RouterTrace {
        std::vector<float> logits;     // the raw router logits
        std::vector<float> probs;      // after the gating function
        std::vector<float> selection;  // probs + the selection bias
        double seventhScore = 0.0;     // the highest UNSELECTED selection score
    };
    // Run ONE MoE block's routing over a given hidden state. It uses the
    // execution's own routing arithmetic, so an independent reference is
    // compared against the real thing rather than against a reimplementation
    // of it in the test. The routing is a pure function of the hidden state
    // and the router's weights, which is what lets the certificate exercise
    // it without a forward pass.
    bool RunMoeRouting(int32_t block, const std::vector<float>& x,
                       std::vector<uint32_t>& ids, std::vector<float>& weights,
                       RouterTrace& trace, std::string& err);

    // ---- Context admission guard --------------------------------------------
    //
    // The three counters a host must keep straight, because conflating them is
    // how a 145-token context ends up reporting "context=1" and then decoding
    // over KV rows that were never written:
    //
    //   rendered_tokens    - tokens the host's prompt renderer produced
    //   submitted_tokens   - tokens handed to ExecuteToken
    //   committed_kv_      - tokens whose attention KV rows are written
    //
    // Admit() returns false when the requested decode position is not backed by
    // committed KV. A host must treat that as fatal for the turn, not as a hint.
    size_t CommittedKvTokens() const { return kv_committed_; }
    bool AdmitDecode(size_t position) const {
        return kv_committed_ >= position + 1;
    }

    // Diagnostics for activation health (prefill/decode gates).
    size_t NonFiniteLogits() const { return nonfinite_logits_; }
    double HiddenL2() const { return hidden_l2_; }

    // RAWRXD_DEEP2_SPEC_VERIFY_001: true when the bound graph contains a
    // recurrent (Mamba2 selective-scan) block. Speculative verification
    // cannot roll a rejected draft back out of a recurrent state - the state
    // IS the memory - so the verifier must fail closed on these graphs
    // instead of corrupting every later position.
    bool HasSsm() const { return has_ssm_; }

    // Force the CPU path for quantised projections (differential testing).
    void SetForceCpu(bool force) { force_cpu_ = force; }
    bool ForceCpu() const { return force_cpu_; }

    // ---- Execution Trace -----------------------------------------------------
    // Enable/disable execution tracing
    void SetExecutionTrace(bool enable) { trace_active_ = enable; }
    bool ExecutionTraceEnabled() const { return trace_active_; }
    
    // Get the execution trace (valid after trace is enabled and inference runs)
    const rawrxd::deep2::trace::ExecutionTrace& GetExecutionTrace() const { 
        return execution_trace_; 
    }
    
    // Clear the execution trace
    void ClearExecutionTrace() { 
        execution_trace_ = rawrxd::deep2::trace::ExecutionTrace{}; 
    }
    
    // Set model fingerprint for KV cache validation
    void SetModelFingerprint(const std::string& fp) { 
        execution_trace_.model_fingerprint = fp; 
    }

    // ---- RAWRXD_DEEP2_STRATA_S01..S08: MoE expert residency observation -----
    // The backend VRAM weight cache is observed and steered through this
    // ledger. Enabling it changes NO arithmetic: it records residency
    // outcomes the dispatch path reports anyway, and (optionally) prefetches
    // routed expert slices into the same fingerprint-validated cache ahead of
    // their dependent dispatch. Default OFF so every previously certified
    // harness runs bit-identically until it opts in.
    void SetStrataExpertTracking(bool enable) { strata_experts_ = enable; }
    bool StrataExpertTracking() const { return strata_experts_; }
    // Prefetch routed expert slices at MoE block entry (STRATA_S03). Implies
    // SetStrataExpertTracking(true).
    void SetStrataExpertPrefetch(bool enable) { strata_prefetch_ = enable; }
    // Eviction policy handed to the backend cache: 0 = LRU (baseline),
    // 1 = hotness (STRATA_S08).
    void SetStrataCachePolicy(int policy);
    // INT8 (Q8_0) KV storage tier (STRATA_S06). When enabled, every KV row
    // written is round-tripped through the INT8 representation and the
    // attention reads the round-tripped values, so the quantised tier's
    // parity is exercised on the real path. Default OFF; the FP32/F16 cache
    // keeps its exact certified numerics until a harness opts in. The MLA
    // latent cache is never touched by this switch.
    void SetStrataInt8KV(bool enable) { strata_int8_kv_ = enable; }
    bool StrataInt8KV() const { return strata_int8_kv_; }
    const Strata::Int8KVCache& StrataInt8Store() const { return strata_kv8_; }
    Strata::Int8KVStats StrataInt8KStats() const { return strata_kv8_.Snapshot(); }
    const Strata::ExpertResidencyLedger& StrataLedger() const { return strata_ledger_; }
    const Strata::ExpertResidencyLedger::Summary StrataExpertSummary() const
    {
        return strata_ledger_.Snapshot();
    }

    // ---- DEEP2_CONTEXT_SCALING_001: read-only KV inspection -----------------
    // Long-context certification needs to observe the cache without being
    // able to perturb it. These accessors are const and copy-free: they
    // report geometry and expose the actual cache rows, so a harness can
    // verify (a) the allocation horizon grew with position, (b) each
    // position's row is what the running model actually wrote, and (c) the
    // residency governor's admitted byte total.
    size_t KvBlocks() const { return kv_k_.size(); }
    // Per-block K row width in floats (0 before the first write).
    size_t KvRowWidthK(int block) const {
        if (block < 0 || (size_t)block >= kv_width_k_.size()) return 0;
        return kv_width_k_[(size_t)block];
    }
    // Per-block V row width in floats (0 before the first write).
    size_t KvRowWidthV(int block) const {
        if (block < 0 || (size_t)block >= kv_width_v_.size()) return 0;
        return kv_width_v_[(size_t)block];
    }
    // Positions currently allocated for a block's K cache.
    size_t KvRows(int block) const {
        const size_t w = KvRowWidthK(block);
        if (w == 0) return 0;
        if (block < 0 || (size_t)block >= kv_k_.size()) return 0;
        return kv_k_[(size_t)block].size() / w;
    }
    // The K row for `position` of `block`, or empty when out of range.
    std::vector<float> KvKRow(int block, size_t position) const {
        const size_t w = KvRowWidthK(block);
        if (w == 0 || block < 0 || (size_t)block >= kv_k_.size()) return {};
        const auto& K = kv_k_[(size_t)block];
        if ((position + 1) * w > K.size()) return {};
        return std::vector<float>(K.begin() + (long)(position * w),
                                  K.begin() + (long)((position + 1) * w));
    }
    // Same for the value stream.
    std::vector<float> KvVRow(int block, size_t position) const {
        const size_t w = KvRowWidthV(block);
        if (w == 0 || block < 0 || (size_t)block >= kv_v_.size()) return {};
        const auto& V = kv_v_[(size_t)block];
        if ((position + 1) * w > V.size()) return {};
        return std::vector<float>(V.begin() + (long)(position * w),
                                  V.begin() + (long)((position + 1) * w));
    }
    // Causal-consistency probe: count leading all-zero rows. Growth fills
    // unwritten positions with exactly 0.0f, so for a sequence decoded to
    // position N the count must be 0 (every position < N+1 was written).
    size_t KvLeadingZeroRows(int block) const;
    // Total KV cache bytes currently resident (both streams, all blocks).
    size_t KvResidentBytes() const;
    // Number of residency leases currently held by the KV governor.
    size_t KvLeaseCount() const { return kv_leases_.size(); }

    // ---- first-divergence instrumentation (RAWRXD_DEEP2 recovery) ----------
    // When enabled, every executed op appends a checksum of its output buffer
    // here. Two executors of the same graph (e.g. GPU vs CPU-pinned) can then
    // be compared op-by-op to find the FIRST divergent tensor instead of
    // debugging the final logits, which mix every layer's error together.
    struct OpTrace {
        int block = -1;
        int pc = -1;
        int op = -1;
        std::string name;
        std::string weight;   // bName: the weight operand, for isolated replay
        std::string input;    // aName: the activation operand
        size_t size = 0;
        uint64_t checksum = 0;
        // RAWRXD_GATE4_DISPATCH_001: per-op dispatch evidence, set where the
        // backend choice is actually made (OpLinear). `backend` is the device
        // that really executed (cpu/vulkan), `fallback` is non-empty only when
        // the selected implementation differs from the requested one, with the
        // reason. `forced` marks an authorized host pin (the certification
        // harness pins CPU with SetForceCpu); a fallback WITHOUT `forced` is a
        // policy violation the Gate-4 auditor fails on.
        std::string dispatch_backend;
        std::string dispatch_fallback;
        bool dispatch_forced = false;
        // First few output values, recorded so a divergence can be inspected
        // (garbage-vs-nearly-equal distinguishes a wrong kernel from a wrong
        // weight or activation without a second tool).
        float first_vals[8] = {0, 0, 0, 0, 0, 0, 0, 0};
        // Full output copy when value capture is on (single-token forensics).
        std::vector<float> values;
        // ---- RAWRXD_GATE7_TPS_001: the per-op execution measurement ----
        // The decode flame graph needs to know, for every operation, which
        // token and which layer it belonged to, how long it took on its own,
        // and how much weight it needed on the device. These are filled only
        // when the op trace is enabled, and they do not change execution
        // semantics.
        uint32_t token = 0;
        double exec_ms = 0.0;      // the op's own duration
        uint64_t weight_bytes = 0;  // the weight's size
        uint64_t upload_bytes = 0;  // bytes uploaded for this op
        int expert = -1;            // the MoE expert, -1 for shared ops
        uint64_t submit_id = 0;     // the command list submission it rode
        uint64_t fence_value = 0;   // the fence it waited on
        // The op KIND, so a trace can be grouped by what the operation IS
        // rather than only by the name of the tensor it wrote. Grouping by
        // tensor name alone makes every expert and every projection of the
        // same role look like one operation.
        std::string op_kind;
        // The weight's shape, so the bytes an op had to read can be checked
        // against the arithmetic the op represents.
        uint64_t weight_rows = 0;
        uint64_t weight_cols = 0;
        int weight_type = 0;        // the ggml type of the weight
    };
    // enable: checksum per op. capture_values: also copies each op's full
    // output so a divergence can be diffed element-by-element. Both default
    // off; neither changes execution semantics.
    void SetOpTrace(bool enable, bool capture_values = false, bool checksum = true) {
        trace_ops_ = enable;
        trace_capture_values_ = capture_values;
        trace_checksum_ = checksum;
    }
    const std::vector<OpTrace>& OpTraces() const { return op_traces_; }

private:
    // kernels
    bool OpRmsNorm(const Instr& in, const std::vector<float>& x, std::vector<float>& y);
    // join_batch: the op loop handed us an open quant-dot batch for this
    // input, so this dot QUEUES into that batch (one command buffer, one
    // fence for the whole group) instead of submitting on its own. Default
    // false keeps every other call site on the single-submit path.
    bool OpLinear(int32_t wslot, const std::vector<float>& x,
                  std::vector<float>& y, std::string& err, bool join_batch = false);
    bool OpAttention(const Instr& in, const std::vector<float>& q,
                     const std::vector<float>& k, const std::vector<float>& v,
                     std::vector<float>& y, size_t position, std::string& err);
    // RoPE angle for rotary pair `pair` (elements 2*pair, 2*pair+1) at token
    // position `position`, over `nDims` rotary ELEMENTS. Plain RoPE:
    //   theta = position * freq_base^(-2*pair/nDims)
    // exactly as ggml computes it (theta_scale = base^(-2/n_dims)).
    // When the model ships rope.scaling.type == "yarn" (deepseek2), the angle is
    // interpolated between the extrapolated frequency and 1/factor of it, with
    // the corr_dim ramp -- ggml's rope_yarn() ramp_mix formula.
    double RopeAngle(size_t position, size_t pair, size_t nDims, bool yarn) const;
    // One-shot (per position) latch for the ATTN_TRACE angle witness.
    mutable int n_dims_seen_ = -1;
    // One-shot (per position) latch for the score witness.
    mutable int score_seen_ = -1;
    // Attention score scale for head width `headDim`. Plain models use
    // 1/sqrt(headDim). A yarn model (deepseek2) uses llama.cpp deepseek2.cpp's
    // mscale^2 / sqrt(n_embd_head_k), where the mscale derivation is in
    // modelgenie/ModelGenieExecutor.cpp and was certified against a llama.cpp
    // dump by RAWRXD_ATTENTION_SCALE_AB_001.
    double AttentionScoreScale(size_t headDim, bool yarn) const;
    bool OpRouterTopK(const Instr& router, const Instr& topk,
                      const std::vector<float>& x,
                      std::vector<uint32_t>& ids, std::vector<float>& w,
                      RouterTrace* trace = nullptr);
    bool OpMoEExecute(const Instr& moe, const std::vector<float>& x,
                      const std::vector<uint32_t>& ids, const std::vector<float>& w,
                      std::vector<float>& y, std::string& err);
      bool OpSsmScan(const Instr& in, const std::vector<float>& x,
                     std::vector<float>& y, std::string& err);
    bool OpGdn(const Instr& in, const std::vector<float>& x,
               std::vector<float>& y, std::string& err);
      bool OpMlaDecompress(const Instr& mla, const std::vector<float>& x,
                           std::vector<float>& k_out, std::vector<float>& v_out,
                           size_t position, std::string& err);
      // Mamba2 selective scan.
      //
      // state_ [slot] holds the per-channel recurrence state, laid out as
      // [d_state x d_inner] so the scan updates it in place:
      //     dt   = softplus(dt_b + dt_bias)
      //     h   *= exp(dt * A)                  (A is the learned decay, negative)
      //     h   += dt * x * B
      //     y    = sum_C(h) + D * x
      // The scan is the ONLY correct way to evaluate an SSM: an attention-style
      // parallel form does not exist for it, so this is not an optimisation of
      // an existing kernel, it is the missing primitive.
      float* WeightData(int32_t slot, size_t& floats_out);

    bool bound_ = false;
    std::string last_error_;
    // Graph operands that resolveIn could not find in the arena. resolveIn is
    // fail-closed, so a non-empty list means the graph referenced an activation
    // that was never produced: an explicit error, not a silent substitution.
    std::vector<std::string> unresolved_inputs_;
    std::vector<float> unresolved_;
    uint32_t last_token_ = 0;
    size_t position_ = 0;
    size_t nonfinite_logits_ = 0;
    double hidden_l2_ = 0;

    Universal::ModelSpec spec_;
    std::vector<Universal::TensorRec> tensors_;          // resolved once
    std::vector<Instr> program_;
    std::unordered_map<std::string, int32_t> slot_by_name_;

      // per-layer KV cache: kv_k_[layer][pos * kvW + i]
      std::vector<std::vector<float>> kv_k_, kv_v_;
      std::vector<std::vector<float>> kvat_;   // latent cache for MLA

      // DEEP2_CONTEXT_SCALING_001: per-block cache row widths, latched on the
      // first write so certification accessors can slice rows without
      // guessing geometry. 0 = never written.
      std::vector<size_t> kv_width_k_, kv_width_v_;

      // RAWRXD_RESOURCE_GOVERNOR_001: KV residency is admitted, not unbounded.
      // Every cache growth acquires a lease against the process host budget;
      // growth that does not fit fails the forward pass closed rather than
      // silently truncating the cache (which would corrupt every later
      // position). The leases live as long as the cache they paid for.
      std::vector<std::optional<GovernorLease>> kv_leases_;
      static std::optional<GovernorLease> TryLeaseKv(size_t bytes);

      // SSM recurrence state, one row per SSM block. Allocated at bind time
      // from the model's declared d_state and d_inner, and carried across
      // decode positions because the recurrence IS the state.
      // RAWRXD_GATE7_MAMBA2_001: state is head-grouped (n_heads x head_dim x
      // d_state), and ssm_conv_ carries each block's causal conv1d history
      // ((kernel-1) samples per channel) across tokens.
      std::vector<std::vector<float> > ssm_state_;
      std::vector<std::vector<float> > ssm_conv_;
      // SSM parameters are immutable after Bind. Decode them once per block
      // instead of re-running DequantPrefix for every generated token.
      struct SsmWeightCache {
          bool ready = false;
          std::vector<float> A, DtB, Dv, ConvB, NormW, ConvW;
      };
      std::vector<SsmWeightCache> ssm_weights_;
      // A GPU GDN state is owned by VulkanCompute and keyed by this executor
      // plus block. This mirror records whether that block has crossed from
      // the reference path to the device-authoritative path; a later device
      // failure must not silently resume with an unsynchronised host state.
      std::vector<uint8_t> gdn_gpu_active_;
      // Optional SSM profiling counters. They remain dormant unless
      // DEEP2_SSM_PROFILE=1 is set, so production execution has no logging
      // cost while controlled runs can separate cache and recurrent work.
      uint64_t ssm_profile_calls_ = 0;
      uint64_t ssm_profile_cache_hits_ = 0;
      uint64_t ssm_profile_cache_misses_ = 0;
      double ssm_profile_cache_ms_ = 0.0;
      double ssm_profile_total_ms_ = 0.0;
      double ssm_profile_linear_ms_ = 0.0;
      double ssm_profile_post_ms_ = 0.0;
      bool first_bind_ = true;   // trace only the primary executor
      std::vector<uint32_t> ssm_state_slots_;
    std::vector<float> logits_;
    std::vector<float> hidden_;

    BindStats stats_;

    // quantised dispatch counters (mirrored into stats_ at bind/first run)
    uint64_t gpu_calls_ = 0, cpu_calls_ = 0;
    // RAWRXD_DEEP2_BATCH_ACCOUNTING_001: batched-prefill accounting. One
    // submission can carry many kernel invocations; both are recorded so a
    // receipt cannot claim "0 dispatches" for a pass that submitted work.
    uint64_t gpu_batch_submissions_ = 0, gpu_batch_dots_ = 0;
    // Per-executor CPU pin. It MUST stay per-executor: the parity harness binds a
    // second "reference" executor with this set, and the earlier implementation
    // forwarded it to the PROCESS-WIDE QuantDot switch, which the harness then
    // restored before the comparison loop. The "reference" therefore ran on the
    // GPU too, and GPU-vs-GPU agreement printed an exact zero error that looked
    // like a perfect parity pass while certifying nothing.
    bool force_cpu_ = false;
    // First-divergence instrumentation state (public SetOpTrace/OpTraces).
    std::vector<OpTrace> op_traces_;
    bool trace_ops_ = false;
    bool trace_capture_values_ = false;
    // The per-op checksum walks the whole output buffer of every op, which
    // is exactly what first-divergence forensics needs and exactly what a
    // TIMING measurement must not pay for. The flame graph therefore runs
    // with the checksum off.
    bool trace_checksum_ = true;
    // The weight size and the MoE expert for the op currently being
    // dispatched, stashed the way the dispatch backend already is, so the
    // trace record can pick them up.
    uint64_t trace_last_weight_bytes_ = 0;
    int trace_last_expert_ = -1;
    uint64_t trace_last_weight_rows_ = 0;
    uint64_t trace_last_weight_cols_ = 0;
    int trace_last_weight_type_ = 0;

    // RAWRXD_GATE7_TPS_001: the per-op-kind execution census. A cache hit
    // rate only means something if the counters cover the path that the
    // cache serves: these say how many router, top-k, expert, projection
    // and LM-head operations actually executed, so the MoE accounting can be
    // reconciled against the model's own parsed topology.
    uint64_t census_router_ = 0;
    uint64_t census_topk_ = 0;
    uint64_t census_moe_ = 0;
    uint64_t census_linear_ = 0;
    uint64_t census_lmhead_ = 0;
    uint64_t census_ssm_ = 0;
    uint64_t census_attention_ = 0;
    uint64_t census_rmsnorm_ = 0;
    uint64_t census_other_ = 0;
    // The same census as a histogram over the kind NAME, so every kind the
    // executor can run is visible by name.
    std::map<std::string, uint64_t> census_by_kind_;

public:
    // The census of executed operations, by kind. A histogram rather than a
    // fixed struct, because a fixed struct hides the kinds it does not name:
    // a "other" bucket is how a whole execution path disappears from a
    // diagnosis.
    const std::map<std::string, uint64_t>& CensusByKind() const { return census_by_kind_; }

    // RAWRXD_DEEP2_STRATA_S01..S08: expert residency ledger + policy switches.
    Strata::ExpertResidencyLedger strata_ledger_;
    bool strata_experts_ = false;
    bool strata_prefetch_ = false;
    // RAWRXD_DEEP2_STRATA_S06: INT8 KV tier (default off, opt-in per harness).
    bool strata_int8_kv_ = false;
    Strata::Int8KVCache strata_kv8_;
    // Every kernel completes, all quantized dots only through GPU kernels.
    std::string cpu_fallback_reason_;

    // ---- RAWRXD_GATE7_TPS_001: per-token quant-dot batching -----------------
    // Consecutive LINEAR ops reading the SAME arena input (a block's q/k/v,
    // its gate/up) are independent, so they can share ONE command buffer and
    // ONE fence instead of one submit+fence each. The op loop opens and
    // flushes groups by input name; the executor owns the batch lifetime and
    // the honest accounting when a batch submission fails (EndBatch replays
    // the group on the CPU fallback, so the counters must say CPU).
    // DEEP2_NO_DOT_BATCH=1 disables grouping entirely (differential testing).
    bool FlushDotBatch();
    bool dot_batch_open_ = false;
    bool dot_batch_broken_ = false;          // a failed group disables grouping
    std::string dot_batch_input_;
    size_t dot_batch_ops_ = 0;
    size_t dot_batch_rows_ = 0;
    std::vector<size_t> dot_batch_trace_idx_;  // trace records to correct on replay
    // Set for the duration of ExecuteToken so FlushDotBatch can refresh
    // hidden_ from the finished arena buffer (the non-batched path's
    // "hidden_ = y" after the last queued dot).
    std::string dot_batch_last_out_slot_;
    std::unordered_map<std::string, std::vector<float>>* act_map_ = nullptr;

    // RAWRXD_GATE4_DISPATCH_001: dispatch evidence for the op trace currently
    // being produced (set by OpLinear, copied into the trace record).
    std::string trace_dispatch_backend_;
    std::string trace_dispatch_fallback_;
    bool trace_dispatch_forced_ = false;

    // Tokens executed so far. Distinguishes the first token (cold start:
    // cache warm-up and lazy pipeline creation) from steady-state decode so
    // BindStats::cold_start_ms and steady_kernel_ms mean something.
    uint64_t tokens_executed_ = 0;
    // RAWRXD_DEEP2_SPEC_VERIFY_001: recurrent-state detection for the
    // speculative-verification fail-closed gate. Set once at bind time.
    bool has_ssm_ = false;

    // Execution trace
    rawrxd::deep2::trace::ExecutionTrace execution_trace_;
    bool trace_active_ = false;
    uint64_t trace_request_id_ = 0;

    // Number of attention KV rows actually committed. Incremented only after a
    // token's attention has written its K/V, never when a token is merely
    // submitted. See AdmitDecode().
    size_t kv_committed_ = 0;
};

} } }  // namespace
