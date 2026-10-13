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

#include <cstdint>
#include <cstddef>
#include <chrono>
#include <map>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "deep2_resource_governor.hpp"
#include "universal_gguf.hpp"

// Short alias for the governor's move-only lease handle. The resource
// governor itself owns the accounting; the executor holds only leases.
using GovernorLease = rawrxd::deep2::Governor::Lease;

namespace RawrXD { namespace Deep2 { namespace RuntimeGraph {

enum class OpKind : uint8_t {
    EmbeddingLookup = 0, RmsNorm, Linear, Attention, MlaDecompress,
    Router, TopK, MoEExecute, ResidualAdd, LmHead,
    SsmScan,      // Mamba2 selective scan (nemotron_h, qwen3-next)
    Publish,      // copy an arena value to a named one (residual bookkeeping)
    SwiGLU,       // out = silu(gate) * up, the dense-FFN activation
    Unsupported
};

const char* OpKindName(OpKind k);

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

    // Run one token at `position`. Returns false on any kernel failure.
    bool ExecuteToken(uint32_t token, size_t position);

    const std::vector<float>& Logits() const { return logits_; }
    size_t Position() const { return position_; }
    bool Ok() const { return bound_ && !last_error_.empty() == false; }
    const std::string& LastError() const { return last_error_; }
    uint32_t LastToken() const { return last_token_; }

    // Diagnostics for activation health (prefill/decode gates).
    size_t NonFiniteLogits() const { return nonfinite_logits_; }
    double HiddenL2() const { return hidden_l2_; }

    // Force the CPU path for quantised projections (differential testing).
    void SetForceCpu(bool force) { force_cpu_ = force; }
    bool ForceCpu() const { return force_cpu_; }

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
        // First few output values, recorded so a divergence can be inspected
        // (garbage-vs-nearly-equal distinguishes a wrong kernel from a wrong
        // weight or activation without a second tool).
        float first_vals[8] = {0, 0, 0, 0, 0, 0, 0, 0};
        // Full output copy when value capture is on (single-token forensics).
        std::vector<float> values;
    };
    // enable: checksum per op. capture_values: also copies each op's full
    // output so a divergence can be diffed element-by-element. Both default
    // off; neither changes execution semantics.
    void SetOpTrace(bool enable, bool capture_values = false) {
        trace_ops_ = enable;
        trace_capture_values_ = capture_values;
        op_traces_.clear();
    }
    const std::vector<OpTrace>& OpTraces() const { return op_traces_; }

private:
    // kernels
    bool OpRmsNorm(const Instr& in, const std::vector<float>& x, std::vector<float>& y);
    bool OpLinear(int32_t wslot, const std::vector<float>& x,
                  std::vector<float>& y, std::string& err);
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
                      std::vector<uint32_t>& ids, std::vector<float>& w);
    bool OpMoEExecute(const Instr& moe, const std::vector<float>& x,
                      const std::vector<uint32_t>& ids, const std::vector<float>& w,
                      std::vector<float>& y, std::string& err);
      bool OpSsmScan(const Instr& in, const std::vector<float>& x,
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
      std::vector<std::vector<float> > ssm_state_;
      bool first_bind_ = true;   // trace only the primary executor
      std::vector<uint32_t> ssm_state_slots_;
    std::vector<float> logits_;
    std::vector<float> hidden_;

    BindStats stats_;

    // quantised dispatch counters (mirrored into stats_ at bind/first run)
    uint64_t gpu_calls_ = 0, cpu_calls_ = 0;
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
    // First observed reason a quantised projection did NOT run on the GPU.
    // Mirrored into BindStats::fallback_reason so the receipt can never claim
    // fallback='<none>' while cpu_calls > 0.
    std::string cpu_fallback_reason_;

    // Tokens executed so far. Distinguishes the first token (cold start:
    // cache warm-up and lazy pipeline creation) from steady-state decode so
    // BindStats::cold_start_ms and steady_kernel_ms mean something.
    uint64_t tokens_executed_ = 0;
};

} } }  // namespace
