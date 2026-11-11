// ============================================================================
// dispatch_trace.hpp  --  RAWRXD Gate 4 native-forward dispatch instrumentation
// ============================================================================
// Records, for EVERY forward operation the runtime graph executes, the facts a
// native-forward gate needs to decide whether dispatch was honest:
//
//   * requested backend        (CPU or GPU -- what the run asked for)
//   * selected backend used    (what actually ran)
//   * execution status         (Ran / Failed / NoOp -- a skipped or no-op kernel
//                               must never be reported as a success)
//   * fallback reason          (why the selected backend differs from requested)
//   * whether a real kernel completed   (GPU kernel, or a real CPU kernel)
//   * has_gpu_primitive        (does a GPU kernel exist for this op's type)
//   * operation name + layer index
//
// This is a PROCESS-GLOBAL recorder with no ggml/gguf dependency, so both the
// executor (src/deep2/runtime_graph_executor.cpp) and the audit tool
// (tools/native_forward_audit.cpp) can talk to it without touching the
// executor's public header. It is deliberately separate from the executor's own
// gpu_calls_/cpu_calls_ counters so the gate can cross-check the HOST-derived
// counters against the recorded events (gate condition 6).
//
// The gate verdict logic lives here too, so the executor instrumentation and
// the audit tool cannot disagree on what "PASS" means.
// ============================================================================
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace RawrXD {
namespace Deep2 {
namespace RuntimeGraph {
namespace DispatchTrace {

enum class Backend : uint8_t { CPU = 0, GPU = 1 };
enum class Category : uint8_t { Matmul = 0, Host = 1 };
enum class Status   : uint8_t { Ran = 0, Failed = 1, NoOp = 2 };

struct Event {
    std::string op;                 // OpKindName (e.g. "Linear", "RmsNorm")
    int         op_kind = -1;       // numeric OpKind
    int         layer = -1;        // block index (-1 for model-global ops)
    std::string weight;             // bName / weight tensor (matmul ops)
    std::string out;                // outName (SSA output)
    Category    category = Category::Host;
    Backend     requested = Backend::CPU;
    Backend     selected  = Backend::CPU;
    bool        has_gpu_primitive = false;       // a GPU kernel exists for this type
    bool        real_kernel_completed = false;   // a real kernel produced the result
    Status      status = Status::Ran;
    bool        declared_unimplemented = false;  // GPU primitive genuinely absent
    bool        unauthorized_fallback = false;   // primitive existed but CPU ran anyway
    std::string fallback_reason;                 // non-empty when selected != requested
    int         ggml_type = -1;                  // ggml_type for quant ops
};

const char* BackendName(Backend b);
const char* CategoryName(Category c);
const char* StatusName(Status s);

// ---- recorder lifecycle ----------------------------------------------------
void Reset();
void SetRunConfig(const std::string& config, Backend requested_policy);
Backend RequestedPolicy();
const std::string& RunConfigName();

// Record one event (classification fields are computed from RequestedPolicy()).
void Record(const Event& e);
// Record n identical events at once (used by the batched MoE accounting where a
// single submission runs several queued dots with one outcome).
void RecordN(const Event& e, uint64_t n);

// ---- aggregates (all derived from the event log since Reset) ---------------
uint64_t TotalEvents();
uint64_t MatmulCount();                 // events with category==Matmul
uint64_t SelectedGPU();                 // matmul events with selected==GPU
uint64_t SelectedCPU();                 // matmul events with selected==CPU
uint64_t UnauthorizedFallback();        // matmul events flagged unauthorized_fallback
uint64_t DeclaredUnimplemented();       // matmul events flagged declared_unimplemented
uint64_t SilentMissingKernelSuccess();  // status==Ran && !real_kernel_completed (MUST be 0)
uint64_t FailedEvents();
uint64_t NoOpEvents();
uint64_t DistinctLayers();             // distinct layer indices (>=0) seen
int      MaxLayer();

// ---- gate evaluation -------------------------------------------------------
// One config's full result. The executor instrumentation + the audit tool share
// this so the verdict cannot be gamed on either side.
struct GateInput {
    std::string model_path;
    std::string model_sha256;
    std::string source_sha;      // git commit SHA the binary was built from
    std::string binary_sha256;   // sha256 of the audited executable
    std::string command;         // the exact command line run
    bool        have_gpu_device = false;
    std::string gpu_device_name;
    // host-derived counters from the executor (NOT asserted by the recorder).
    uint64_t    host_gpu_calls = 0;
    uint64_t    host_cpu_calls = 0;
    uint64_t    program_ops = 0;     // ops the compiled program contains
    uint64_t    executed_ops = 0;    // ops that produced output this pass
    uint64_t    block_count = 0;     // model layer count
    uint64_t    tensor_count = 0;    // tensor inventory (must match geometry: 255)
    bool        logits_finite = false;
    uint64_t    nonfinite_logits = 0;
    uint64_t    logits_count = 0;
};

struct GateResult {
    bool cond1_all_ops_execute = false;
    bool cond2_no_unauthorized_fallback = false;
    bool cond3_no_silent_missing_kernel = false;
    bool cond4_all_layers_execute = false;
    bool cond5_finite_logits = false;
    bool cond6_counters_agree = false;
    bool cond7_provenance_tie = false;
    bool native_forward_complete = false;  // every matmul ran on the requested backend
    bool gate_pass = false;
    std::string reason;                    // human summary of the verdict
};

GateResult EvaluateGate(const GateInput& in);

// Emit one config's evidence object as JSON (events + aggregates + gate).
std::string ToJson(const GateInput& in, const GateResult& r);

}  // namespace DispatchTrace
}  // namespace RuntimeGraph
}  // namespace Deep2
}  // namespace RawrXD
