// ============================================================================
// dispatch_trace.cpp  --  Gate 4 dispatch recorder + shared gate evaluation
// ============================================================================
#include "dispatch_trace.hpp"

#include <algorithm>
#include <cstdio>
#include <mutex>
#include <set>
#include <sstream>

namespace RawrXD {
namespace Deep2 {
namespace RuntimeGraph {
namespace DispatchTrace {

namespace {

std::mutex        g_mu;
std::vector<Event> g_events;
Backend           g_requested = Backend::CPU;
std::string       g_run_config;

void Classify(Event& e)
{
    // A fallback is "dispatch substitutes another implementation without the
    // execution policy permitting it". CPU execution is NOT automatically a
    // fallback: when CPU is the requested backend it is legitimate.
    if (e.category == Category::Matmul &&
        e.requested == Backend::GPU && e.selected == Backend::CPU) {
        if (e.fallback_reason.empty())
            e.fallback_reason = "CPU executed where GPU was requested";
        if (e.has_gpu_primitive)
            e.unauthorized_fallback = true;   // a GPU primitive existed, CPU ran anyway
        else
            e.declared_unimplemented = true;  // no GPU primitive existed at all
    }
}

// Escape a string for embedding in a JSON string literal.
std::string Jstr(const std::string& s)
{
    std::string o;
    o.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"':  o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\b': o += "\\b";  break;
            case '\f': o += "\\f";  break;
            case '\n': o += "\\n";  break;
            case '\r': o += "\\r";  break;
            case '\t': o += "\\t";  break;
            default:
                if ((unsigned char)c < 0x20) {
                    char b[8];
                    std::snprintf(b, sizeof(b), "\\u%04x", (unsigned)(unsigned char)c);
                    o += b;
                } else {
                    o += c;
                }
        }
    }
    return o;
}

}  // namespace

const char* BackendName(Backend b) { return b == Backend::GPU ? "GPU" : "CPU"; }
const char* CategoryName(Category c) { return c == Category::Matmul ? "matmul" : "host"; }
const char* StatusName(Status s)
{
    switch (s) {
        case Status::Failed: return "failed";
        case Status::NoOp:   return "noop";
        default:             return "ran";
    }
}

void Reset()
{
    std::lock_guard<std::mutex> lk(g_mu);
    g_events.clear();
}

void SetRunConfig(const std::string& config, Backend requested_policy)
{
    std::lock_guard<std::mutex> lk(g_mu);
    g_run_config = config;
    g_requested = requested_policy;
}

Backend RequestedPolicy()
{
    std::lock_guard<std::mutex> lk(g_mu);
    return g_requested;
}

const std::string& RunConfigName()
{
    std::lock_guard<std::mutex> lk(g_mu);
    return g_run_config;
}

void Record(const Event& e)
{
    Event c = e;
    Classify(c);
    std::lock_guard<std::mutex> lk(g_mu);
    g_events.push_back(std::move(c));
}

void RecordN(const Event& e, uint64_t n)
{
    Event c = e;
    Classify(c);
    std::lock_guard<std::mutex> lk(g_mu);
    for (uint64_t i = 0; i < n; ++i) g_events.push_back(c);
}

uint64_t TotalEvents()
{
    std::lock_guard<std::mutex> lk(g_mu);
    return g_events.size();
}

uint64_t MatmulCount()
{
    std::lock_guard<std::mutex> lk(g_mu);
    uint64_t n = 0;
    for (const auto& e : g_events) if (e.category == Category::Matmul) ++n;
    return n;
}

uint64_t SelectedGPU()
{
    std::lock_guard<std::mutex> lk(g_mu);
    uint64_t n = 0;
    for (const auto& e : g_events)
        if (e.category == Category::Matmul && e.selected == Backend::GPU) ++n;
    return n;
}

uint64_t SelectedCPU()
{
    std::lock_guard<std::mutex> lk(g_mu);
    uint64_t n = 0;
    for (const auto& e : g_events)
        if (e.category == Category::Matmul && e.selected == Backend::CPU) ++n;
    return n;
}

uint64_t UnauthorizedFallback()
{
    std::lock_guard<std::mutex> lk(g_mu);
    uint64_t n = 0;
    for (const auto& e : g_events) if (e.unauthorized_fallback) ++n;
    return n;
}

uint64_t DeclaredUnimplemented()
{
    std::lock_guard<std::mutex> lk(g_mu);
    uint64_t n = 0;
    for (const auto& e : g_events) if (e.declared_unimplemented) ++n;
    return n;
}

uint64_t SilentMissingKernelSuccess()
{
    std::lock_guard<std::mutex> lk(g_mu);
    uint64_t n = 0;
    for (const auto& e : g_events)
        if (e.status == Status::Ran && !e.real_kernel_completed) ++n;
    return n;
}

uint64_t FailedEvents()
{
    std::lock_guard<std::mutex> lk(g_mu);
    uint64_t n = 0;
    for (const auto& e : g_events) if (e.status == Status::Failed) ++n;
    return n;
}

uint64_t NoOpEvents()
{
    std::lock_guard<std::mutex> lk(g_mu);
    uint64_t n = 0;
    for (const auto& e : g_events) if (e.status == Status::NoOp) ++n;
    return n;
}

uint64_t DistinctLayers()
{
    std::lock_guard<std::mutex> lk(g_mu);
    std::set<int> s;
    for (const auto& e : g_events) if (e.layer >= 0) s.insert(e.layer);
    return s.size();
}

int MaxLayer()
{
    std::lock_guard<std::mutex> lk(g_mu);
    int m = -1;
    for (const auto& e : g_events) m = std::max(m, e.layer);
    return m;
}

GateResult EvaluateGate(const GateInput& in)
{
    GateResult r;
    const uint64_t total    = TotalEvents();
    const uint64_t failed   = FailedEvents();
    const uint64_t noop     = NoOpEvents();
    const uint64_t executed = total - failed - noop;
    const uint64_t gpuSel   = SelectedGPU();
    const uint64_t cpuSel   = SelectedCPU();
    const uint64_t mm       = MatmulCount();
    const uint64_t unAuth   = UnauthorizedFallback();
    const uint64_t declImp  = DeclaredUnimplemented();
    const uint64_t silentMK = SilentMissingKernelSuccess();
    const uint64_t layers   = DistinctLayers();
    const int      maxLayer = MaxLayer();
    const Backend  requested = RequestedPolicy();

    // 1. Every required forward operation executes.
    r.cond1_all_ops_execute =
        failed == 0 && noop == 0 && in.program_ops > 0 && executed >= in.program_ops;

    // 2. No UNAUTHORIZED fallback: no op with an implemented GPU primitive ran
    //    on the CPU while the GPU was requested.
    r.cond2_no_unauthorized_fallback = (unAuth == 0);

    // 3. No missing kernel silently becomes a success: an op may never report
    //    Ran without a real kernel having completed. Unimplemented primitives
    //    must be declared (declImp), never faked as a GPU success.
    r.cond3_no_silent_missing_kernel = (silentMK == 0);

    // 4. All expected model layers execute.
    r.cond4_all_layers_execute =
        in.block_count > 0 && layers == in.block_count &&
        maxLayer == (int)in.block_count - 1;

    // 5. Finite logits.
    r.cond5_finite_logits = in.logits_finite && in.nonfinite_logits == 0 && in.logits_count > 0;

    // 6. Host counters agree EXACTLY with the recorded dispatch events. These
    //    host counts come from the executor's own BindStats, not the recorder.
    r.cond6_counters_agree =
        gpuSel == in.host_gpu_calls && cpuSel == in.host_cpu_calls &&
        mm == (in.host_gpu_calls + in.host_cpu_calls);

    // 7. Executable and results tied to the same source revision (SHA of the
    //    binary and of the source commit both present) and the tensor inventory
    //    matches the geometry evidence (255 tensors).
    r.cond7_provenance_tie =
        !in.source_sha.empty() && !in.binary_sha256.empty() && in.tensor_count == 255;

    // Native-forward completeness: for the requested policy, EVERY matmul must
    // have run on the requested backend. A "native" forward that mostly ran on a
    // different backend is not native -- the off-native matmuls are reported
    // (as declared-unimplemented or unauthorized fallbacks), never hidden.
    const uint64_t off_native =
        (requested == Backend::GPU) ? cpuSel : gpuSel;
    r.native_forward_complete = (in.program_ops > 0) && (mm > 0) && (off_native == 0);

    r.gate_pass = r.cond1_all_ops_execute && r.cond2_no_unauthorized_fallback &&
                  r.cond3_no_silent_missing_kernel && r.cond4_all_layers_execute &&
                  r.cond5_finite_logits && r.cond6_counters_agree &&
                  r.cond7_provenance_tie && r.native_forward_complete;

    std::ostringstream rs;
    rs << "config=" << RunConfigName()
       << " requested=" << BackendName(requested)
       << " matmul=" << mm << " (gpu=" << gpuSel << " cpu=" << cpuSel << ")"
       << " program_ops=" << in.program_ops
       << " unauthorized_fallback=" << unAuth
       << " declared_unimplemented=" << declImp
       << " silent_missing_kernel_success=" << silentMK
       << " failed=" << failed << " noop=" << noop
       << " layers=" << layers << "/" << in.block_count
       << " host_counters=(gpu=" << in.host_gpu_calls << ",cpu=" << in.host_cpu_calls << ")";
    if (!r.gate_pass) {
        rs << " :: FAILING:";
        if (!r.cond1_all_ops_execute) rs << " not-all-ops-executed";
        if (!r.cond2_no_unauthorized_fallback) rs << " " << unAuth << "-unauthorized-fallback";
        if (!r.cond3_no_silent_missing_kernel) rs << " " << silentMK << "-silent-missing-kernel-success";
        if (!r.cond4_all_layers_execute) rs << " layers(" << layers << "!=block_count(" << in.block_count << "))";
        if (!r.cond5_finite_logits) rs << " nonfinite-logits(" << in.nonfinite_logits << "/" << in.logits_count << ")";
        if (!r.cond6_counters_agree) rs << " host-counters-mismatch";
        if (!r.cond7_provenance_tie) rs << " provenance-tie";
        if (!r.native_forward_complete)
            rs << " native-incomplete(off-native-matmul=" << off_native
               << ", declared_unimplemented=" << declImp << ")";
    }
    r.reason = rs.str();
    return r;
}

std::string ToJson(const GateInput& in, const GateResult& r)
{
    std::lock_guard<std::mutex> lk(g_mu);
    std::ostringstream o;
    o << "{\n";
    o << "  \"config\": \"" << Jstr(RunConfigName()) << "\",\n";
    o << "  \"requested_backend\": \"" << BackendName(RequestedPolicy()) << "\",\n";
    o << "  \"command\": \"" << Jstr(in.command) << "\",\n";
    o << "  \"provenance\": {\n";
    o << "    \"source_commit_sha\": \"" << Jstr(in.source_sha) << "\",\n";
    o << "    \"binary_sha256\": \"" << Jstr(in.binary_sha256) << "\",\n";
    o << "    \"model_path\": \"" << Jstr(in.model_path) << "\",\n";
    o << "    \"model_sha256\": \"" << Jstr(in.model_sha256) << "\",\n";
    o << "    \"tensor_count\": " << in.tensor_count << ",\n";
    o << "    \"geometry_report_tensor_count\": 255\n";
    o << "  },\n";
    o << "  \"gpu\": { \"present\": " << (in.have_gpu_device ? "true" : "false")
      << ", \"device\": \"" << Jstr(in.gpu_device_name) << "\" },\n";

    // aggregates
    uint64_t gpu = 0, cpu = 0, mm = 0, una = 0, dec = 0, fail = 0, noop = 0, silent = 0;
    std::set<int> layers;
    for (const auto& e : g_events) {
        if (e.category == Category::Matmul) { ++mm; if (e.selected == Backend::GPU) ++gpu; else ++cpu; }
        if (e.unauthorized_fallback) ++una;
        if (e.declared_unimplemented) ++dec;
        if (e.status == Status::Failed) ++fail;
        if (e.status == Status::NoOp) ++noop;
        if (e.status == Status::Ran && !e.real_kernel_completed) ++silent;
        if (e.layer >= 0) layers.insert(e.layer);
    }
    o << "  \"summary\": {\n";
    o << "    \"total_events\": " << g_events.size() << ",\n";
    o << "    \"matmul_calls\": " << mm << ",\n";
    o << "    \"selected_gpu\": " << gpu << ",\n";
    o << "    \"selected_cpu\": " << cpu << ",\n";
    o << "    \"unauthorized_fallback\": " << una << ",\n";
    o << "    \"declared_unimplemented\": " << dec << ",\n";
    o << "    \"silent_missing_kernel_success\": " << silent << ",\n";
    o << "    \"failed_events\": " << fail << ",\n";
    o << "    \"noop_events\": " << noop << ",\n";
    o << "    \"distinct_layers\": " << layers.size() << ",\n";
    o << "    \"max_layer\": " << MaxLayer() << ",\n";
    o << "    \"block_count\": " << in.block_count << ",\n";
    o << "    \"host_gpu_calls\": " << in.host_gpu_calls << ",\n";
    o << "    \"host_cpu_calls\": " << in.host_cpu_calls << ",\n";
    o << "    \"program_ops\": " << in.program_ops << ",\n";
    o << "    \"executed_ops\": " << in.executed_ops << ",\n";
    o << "    \"logits_count\": " << in.logits_count << ",\n";
    o << "    \"nonfinite_logits\": " << in.nonfinite_logits << "\n";
    o << "  },\n";

    o << "  \"conditions\": {\n";
    o << "    \"1_all_ops_execute\": "            << (r.cond1_all_ops_execute?"true":"false") << ",\n";
    o << "    \"2_no_unauthorized_fallback\": "    << (r.cond2_no_unauthorized_fallback?"true":"false") << ",\n";
    o << "    \"3_no_silent_missing_kernel\": "    << (r.cond3_no_silent_missing_kernel?"true":"false") << ",\n";
    o << "    \"4_all_layers_execute\": "          << (r.cond4_all_layers_execute?"true":"false") << ",\n";
    o << "    \"5_finite_logits\": "               << (r.cond5_finite_logits?"true":"false") << ",\n";
    o << "    \"6_counters_agree\": "              << (r.cond6_counters_agree?"true":"false") << ",\n";
    o << "    \"7_provenance_tie\": "              << (r.cond7_provenance_tie?"true":"false") << ",\n";
    o << "    \"native_forward_complete\": "       << (r.native_forward_complete?"true":"false") << "\n";
    o << "  },\n";

    o << "  \"gate_pass\": " << (r.gate_pass?"true":"false") << ",\n";
    o << "  \"reason\": \"" << Jstr(r.reason) << "\",\n";

    // declared_unimplemented primitives (symbol/file/reason), de-duplicated by
    // op output name. These are REPORTED, never hidden and never faked as GPU.
    o << "  \"declared_unimplemented\": [";
    {
        bool first = true;
        std::vector<std::string> emitted;   // keys: op|ggml_type|reason
        for (const auto& e : g_events) {
            if (!e.declared_unimplemented) continue;
            const std::string key = e.op + "|" + std::to_string(e.ggml_type) + "|" + e.fallback_reason;
            bool dup = false;
            for (const auto& s : emitted) if (s == key) { dup = true; break; }
            if (dup) continue;
            emitted.push_back(key);
            uint64_t cnt = 0;
            for (const auto& x : g_events)
                if (x.declared_unimplemented && x.op == e.op &&
                    x.ggml_type == e.ggml_type && x.fallback_reason == e.fallback_reason) ++cnt;
            o << (first ? "\n    " : ",\n    ");
            first = false;
            o << "{\"op\": \"" << Jstr(e.op) << "\""
              << ", \"ggml_type\": " << e.ggml_type
              << ", \"symbol\": \"RawrXD::Deep2::QuantDot::DotBlocked\""
              << ", \"file\": \"src/deep2/quant_dot_dispatch.cpp\""
              << ", \"reason\": \"no GPU kernel implemented for this ggml_type\""
              << ", \"count\": " << cnt << "}";
        }
        o << (first ? "" : "\n  ") << "],\n";
    }

    // full event log (bounded)
    o << "  \"events\": [\n";
    for (size_t i = 0; i < g_events.size(); ++i) {
        const Event& e = g_events[i];
        o << "    {\"op\": \"" << Jstr(e.op) << "\", \"kind\": " << e.op_kind
          << ", \"layer\": " << e.layer
          << ", \"category\": \"" << CategoryName(e.category) << "\""
          << ", \"requested\": \"" << BackendName(e.requested) << "\""
          << ", \"selected\": \"" << BackendName(e.selected) << "\""
          << ", \"has_gpu_primitive\": " << (e.has_gpu_primitive?"true":"false")
          << ", \"real_kernel_completed\": " << (e.real_kernel_completed?"true":"false")
          << ", \"status\": \"" << StatusName(e.status) << "\""
          << ", \"declared_unimplemented\": " << (e.declared_unimplemented?"true":"false")
          << ", \"unauthorized_fallback\": " << (e.unauthorized_fallback?"true":"false")
          << ", \"ggml_type\": " << e.ggml_type;
        if (!e.fallback_reason.empty())
            o << ", \"fallback_reason\": \"" << Jstr(e.fallback_reason) << "\"";
        o << "}" << (i + 1 < g_events.size() ? "," : "") << "\n";
    }
    o << "  ]\n";
    o << "}\n";
    return o.str();
}

}  // namespace DispatchTrace
}  // namespace RuntimeGraph
}  // namespace Deep2
}  // namespace RawrXD
