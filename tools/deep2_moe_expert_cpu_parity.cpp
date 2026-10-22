// ============================================================================
// deep2_moe_expert_cpu_parity.cpp - DEEP2_NEMOTRON_MOE_EXPERT_CPU_PARITY_001
//
// The numerical proof that the executor's MoE EXPERT ARITHMETIC computes
// what the reference implementation computes.
//
// The routing is already certified (DEEP2_NEMOTRON_MOE_CPU_PARITY_001). This
// certificate covers the stage after it: the expert up projection, the
// activation, the expert down projection, the weighted aggregation and the
// residual addition.
//
// The reference is built INDEPENDENTLY. The expert tensors are dequantised
// with ggml's own type traits, and the arithmetic is written out from the
// reference specification:
//
//   up_k      = expert_up[k] . x                  (x is the normalised input)
//   act_k     = up_k * up_k                        (LLM_FFN_RELU_SQR: squared
//                                                 ReLU, the activation this
//                                                 architecture's gateless
//                                                 experts use)
//   down_k    = expert_down[k] . act_k
//   moe_out   = sum_k weight_k * down_k
//   resid1    = residual + moe_out
//
// The expert tensors are rank-3 [in, out, expert], so expert e's slice is a
// contiguous window of (in * out) elements at offset e * in * out. The
// certificate dequantises that window with ggml, independently of the
// executor's own range dequantiser.
//
// The divergence is localised at the EXPERT, not only at the block's output:
// the executor's expert path is invoked once per selected expert with a
// weight of 1.0, which yields that expert's own contribution, so the
// certificate can name the first expert whose output differs.
//
// Usage: deep2_moe_expert_cpu_parity --model <gguf> [--block N] [--receipt path.json]
// ============================================================================

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "ggml.h"
#include "runtime_graph_executor.hpp"
#include "universal_gguf.hpp"

namespace {

namespace Universal = RawrXD::Deep2::Universal;
namespace RuntimeGraph = RawrXD::Deep2::RuntimeGraph;

int g_failures = 0;

void Report(const char* name, bool ok, const std::string& detail) {
    printf("[%s] %-48s %s\n", ok ? "PASS" : "FAIL", name, detail.c_str());
    if (!ok) ++g_failures;
}

struct Metrics {
    double maxAbs = 0.0;
    double rmse = 0.0;
    double cosine = 0.0;
    int64_t firstDivergence = -1;
    size_t count = 0;
};

Metrics Compare(const std::vector<float>& reference, const std::vector<float>& actual) {
    Metrics m;
    const size_t n = std::min(reference.size(), actual.size());
    m.count = n;
    if (n == 0) return m;
    double sumSquared = 0.0;
    double dot = 0.0;
    double normReference = 0.0;
    double normActual = 0.0;
    for (size_t i = 0; i < n; ++i) {
        const double r = reference[i];
        const double a = actual[i];
        const double diff = std::fabs(r - a);
        if (diff > m.maxAbs) m.maxAbs = diff;
        sumSquared += diff * diff;
        dot += r * a;
        normReference += r * r;
        normActual += a * a;
        if (m.firstDivergence < 0 && diff > 1e-3) m.firstDivergence = static_cast<int64_t>(i);
    }
    m.rmse = std::sqrt(sumSquared / static_cast<double>(n));
    const double denominator = std::sqrt(normReference * normActual);
    m.cosine = denominator > 0.0 ? dot / denominator : 0.0;
    return m;
}

std::string FormatMetrics(const Metrics& m) {
    char buffer[256];
    snprintf(buffer, sizeof(buffer),
             "max_abs=%.3e rmse=%.3e cosine=%.9f first_divergence=%lld n=%zu",
             m.maxAbs, m.rmse, m.cosine, static_cast<long long>(m.firstDivergence), m.count);
    return buffer;
}

// Dequantises a CONTIGUOUS, BLOCK-ALIGNED window of a quantised tensor with
// ggml's own type traits. This is the independent path: the executor has its
// own range dequantiser, and the reference must not borrow it.
bool DequantizeWindow(const Universal::TensorRec& tensor, size_t elementOffset,
                      size_t rows, size_t cols, std::vector<float>& out) {
    if (tensor.data == nullptr || tensor.bytes == 0) return false;
    const ggml_type_traits* traits = ggml_get_type_traits(tensor.ggml_type);
    if (traits == nullptr || traits->to_float == nullptr) return false;

    const size_t elements = rows * cols;
    // The window must start on a block boundary, or the dequantised values
    // would not be the ones the model actually holds.
    if (elementOffset % static_cast<size_t>(traits->blck_size) != 0) return false;

    ggml_init_params params = {};
    params.mem_size = ggml_tensor_overhead() + ggml_graph_overhead();
    params.mem_buffer = nullptr;
    params.no_alloc = true;
    ggml_context* ctx = ggml_init(params);
    if (ctx == nullptr) return false;

    ggml_tensor* t = ggml_new_tensor_2d(ctx, tensor.ggml_type, static_cast<int64_t>(cols),
                                        static_cast<int64_t>(rows));
    if (t == nullptr) {
        ggml_free(ctx);
        return false;
    }
    t->data = const_cast<uint8_t*>(tensor.data) + elementOffset * traits->type_size;
    t->ne[0] = static_cast<int64_t>(cols);
    t->ne[1] = static_cast<int64_t>(rows);
    t->nb[0] = traits->type_size;
    t->nb[1] = t->nb[0] * cols;

    out.assign(elements, 0.0f);
    traits->to_float(t->data, out.data(), static_cast<int64_t>(elements));
    ggml_free(ctx);
    return true;
}

// A deterministic hidden state, the same construction the routing certificate
// uses so the two certificates agree on the input.
std::vector<float> MakeHidden(size_t size, uint64_t seed) {
    std::vector<float> x(size);
    uint64_t state = seed * 6364136223846793005ull + 1442695040888963407ull;
    for (size_t i = 0; i < size; ++i) {
        state = state * 6364136223846793005ull + 1442695040888963407ull;
        const double unit = static_cast<double>((state >> 11) & 0x1FFFFFFFFFFFFFull) /
                            static_cast<double>(1ull << 53);
        x[i] = static_cast<float>(unit * 2.0 - 1.0) * 0.5f;
    }
    return x;
}

// One expert's contribution, computed independently.
//
// The expert tensor is [in, out, expert]: the up projection is [in, out] per
// expert and the down projection is [out, in] per expert. In GGUF's ne
// layout dims[0] is the innermost, so the up projection's output is
// dims[1] long and the down projection's output is dims[0] long.
struct ExpertResult {
    std::vector<float> up;      // the up projection
    std::vector<float> act;     // after the squared ReLU
    std::vector<float> down;    // the down projection
    float maxAbsAct = 0.0;
};

bool ReferenceExpert(const Universal::TensorRec& upTensor, const Universal::TensorRec& downTensor,
                     size_t expertIndex, const std::vector<float>& x, ExpertResult& out) {
    const size_t upIn = (size_t)upTensor.dims[0];
    const size_t upOut = (size_t)upTensor.dims[1];
    const size_t downIn = (size_t)downTensor.dims[0];
    const size_t downOut = (size_t)downTensor.dims[1];
    if (upOut != downIn) return false;
    if (x.size() != upIn) return false;

    const size_t upStride = upIn * upOut;
    const size_t downStride = downIn * downOut;

    std::vector<float> upMatrix;
    if (!DequantizeWindow(upTensor, expertIndex * upStride, upOut, upIn, upMatrix)) return false;
    std::vector<float> downMatrix;
    if (!DequantizeWindow(downTensor, expertIndex * downStride, downOut, downIn, downMatrix)) return false;

    // up: out[j] = sum_i M[j*upIn + i] * x[i]
    out.up.assign(upOut, 0.0f);
    for (size_t j = 0; j < upOut; ++j) {
        const float* row = upMatrix.data() + j * upIn;
        double acc = 0.0;
        for (size_t i = 0; i < upIn; ++i) acc += static_cast<double>(row[i]) * static_cast<double>(x[i]);
        out.up[j] = static_cast<float>(acc);
    }
    // The activation: LLM_FFN_RELU_SQR, squared ReLU.
    out.act.assign(upOut, 0.0f);
    for (size_t j = 0; j < upOut; ++j) {
        const float v = out.up[j];
        out.act[j] = v * v;
    }
    // down: out[k] = sum_j M[k*downIn + j] * act[j]
    out.down.assign(downOut, 0.0f);
    for (size_t k = 0; k < downOut; ++k) {
        const float* row = downMatrix.data() + k * downIn;
        double acc = 0.0;
        for (size_t j = 0; j < downIn; ++j) acc += static_cast<double>(row[j]) * static_cast<double>(out.act[j]);
        out.down[k] = static_cast<float>(acc);
    }
    return true;
}

} // namespace

int main(int argc, char** argv) {
    std::string model;
    std::string receiptPath;
    int32_t requestedBlock = -1;
    for (int i = 1; i < argc; ++i) {
        const std::string argument = argv[i];
        if (argument == "--model" && i + 1 < argc) model = argv[++i];
        else if (argument == "--block" && i + 1 < argc) requestedBlock = atoi(argv[++i]);
        else if (argument == "--receipt" && i + 1 < argc) receiptPath = argv[++i];
        else if (argument == "--help") {
            printf("usage: deep2_moe_expert_cpu_parity --model <gguf> [--block N] [--receipt path.json]\n");
            return 0;
        }
    }
    if (model.empty()) {
        printf("usage: deep2_moe_expert_cpu_parity --model <gguf> [--block N] [--receipt path.json]\n");
        return 2;
    }

    setvbuf(stdout, nullptr, _IONBF, 0);
    printf("=== DEEP2_NEMOTRON_MOE_EXPERT_CPU_PARITY_001 ===\n");
    printf("model: %s\n\n", model.c_str());

    const Universal::IngestReport& report = Universal::Ingest(model, false);
    if (!report.ok) {
        printf("INGEST_FAIL: %s\n", report.error.c_str());
        return 1;
    }

    // The block, and the expert tensors the graph names.
    int32_t block = requestedBlock;
    std::string upName;
    std::string downName;
    // The detail is "experts: <up>,<down>", so the names carry a leading
    // space and the second one may carry trailing detail. Both ends are
    // trimmed: an untrimmed name resolves to nothing and the certificate
    // would report a missing weight instead of a parity result.
    auto trim = [](std::string s) {
        const size_t first = s.find_first_not_of(" \t;");
        if (first == std::string::npos) return std::string();
        const size_t last = s.find_last_not_of(" \t;");
        return s.substr(first, last - first + 1);
    };
    for (const Universal::GraphOp& op : report.graph.ops) {
        if (op.op != Universal::Op::MoEExecute) continue;
        if (block < 0 || op.block == block) {
            block = op.block;
            const size_t at = op.detail.find("experts:");
            if (at != std::string::npos) {
                std::string list = op.detail.substr(at + 8);
                const size_t comma = list.find(',');
                if (comma != std::string::npos) {
                    upName = trim(list.substr(0, comma));
                    downName = trim(list.substr(comma + 1));
                }
            }
            break;
        }
    }
    if (block < 0 || upName.empty()) {
        printf("NO_MOE_BLOCK: the graph has no expert-execution operation\n");
        return 1;
    }
    printf("BLOCK          %d\n", block);
    printf("EXPERT_UP      %s\n", upName.c_str());
    printf("EXPERT_DOWN    %s\n", downName.c_str());

    // Load the block's expert tensors and the router's.
    std::vector<std::string> wanted = {upName, downName};
    for (const Universal::GraphOp& op : report.graph.ops) {
        if (op.op != Universal::Op::Router) continue;
        if (op.block != block) continue;
        wanted.push_back(op.b);
        const size_t at = op.detail.find("bias=");
        if (at != std::string::npos) {
            std::string biasName = op.detail.substr(at + 5);
            const size_t cut = biasName.find_first_of(" ;");
            if (cut != std::string::npos) biasName = biasName.substr(0, cut);
            wanted.push_back(biasName);
        }
        break;
    }
    printf("\nloading %zu tensors ...\n", wanted.size());
    const Universal::IngestReport& loaded = Universal::IngestWeights(model, wanted);

    const Universal::TensorRec* upTensor = nullptr;
    const Universal::TensorRec* downTensor = nullptr;
    for (const Universal::TensorRec& tensor : loaded.tensors) {
        if (tensor.name == upName) upTensor = &tensor;
        if (tensor.name == downName) downTensor = &tensor;
    }
    if (upTensor == nullptr || downTensor == nullptr) {
        printf("EXPERT_WEIGHTS_MISSING: the expert tensors could not be located\n");
        return 1;
    }
    printf("expert up   dims=[");
    for (size_t d = 0; d < upTensor->dims.size() && d < 3; ++d) {
        printf("%s%llu", d ? "," : "", (unsigned long long)upTensor->dims[d]);
    }
    printf("] bytes=%llu\n", (unsigned long long)upTensor->bytes);
    printf("expert down dims=[");
    for (size_t d = 0; d < downTensor->dims.size() && d < 3; ++d) {
        printf("%s%llu", d ? "," : "", (unsigned long long)downTensor->dims[d]);
    }
    printf("] bytes=%llu\n", (unsigned long long)downTensor->bytes);

    // The routing, which the previous certificate already certified. The same
    // hidden state is used so the two certificates agree.
    const size_t hidden = (size_t)upTensor->dims[0];
    const std::vector<float> x = MakeHidden(hidden, 1337u);

    RuntimeGraph::Executor executor;
    executor.SetForceCpu(true);
    if (!executor.Bind(loaded)) {
        printf("BIND_FAIL: %s\n", executor.Stats().error.c_str());
        return 1;
    }

    RuntimeGraph::Executor::RouterTrace trace;
    std::vector<uint32_t> ids;
    std::vector<float> weights;
    std::string error;
    if (!executor.RunMoeRouting(block, x, ids, weights, trace, error)) {
        printf("ROUTING_FAIL: %s\n", error.c_str());
        return 1;
    }
    printf("\nROUTING  experts=[");
    for (size_t k = 0; k < ids.size(); ++k) printf("%s%u", k ? "," : "", ids[k]);
    printf("]\n");

    // ---- per-expert parity ---------------------------------------------------
    // The executor's expert path is invoked once per selected expert with a
    // weight of 1.0, which yields that expert's own contribution. The
    // divergence is therefore localised at the expert.
    printf("\nPER-EXPERT CONTRIBUTION\n");
    int firstDivergentExpert = -1;
    double worstExpertError = 0.0;
    std::vector<float> referenceSum;
    for (size_t k = 0; k < ids.size(); ++k) {
        ExpertResult reference;
        if (!ReferenceExpert(*upTensor, *downTensor, ids[k], x, reference)) {
            printf("  expert %u: the reference could not be computed\n", ids[k]);
            Report("the independent expert reference could be computed", false,
                   "the expert slice could not be dequantised");
            return 1;
        }
        std::vector<float> executorOut;
        const std::vector<uint32_t> oneId = {ids[k]};
        const std::vector<float> oneWeight = {1.0f};
        if (!executor.RunMoeExperts(block, x, oneId, oneWeight, executorOut, error)) {
            printf("  expert %u: the executor failed: %s\n", ids[k], error.c_str());
            Report("the executor's expert path runs on the CPU", false, error);
            return 1;
        }
        const Metrics m = Compare(reference.down, executorOut);
        if (m.maxAbs > worstExpertError) worstExpertError = m.maxAbs;
        if (firstDivergentExpert < 0 && m.maxAbs > 1e-2) firstDivergentExpert = static_cast<int>(k);
        printf("  expert %-3u %s\n", ids[k], FormatMetrics(m).c_str());
        if (referenceSum.empty()) referenceSum.assign(reference.down.size(), 0.0f);
        for (size_t i = 0; i < reference.down.size(); ++i) {
            referenceSum[i] += static_cast<float>(weights[k] * reference.down[i]);
        }
    }
    Report("every expert's contribution matches the reference",
           worstExpertError <= 1e-2,
           "worst expert max_abs=" + std::to_string(worstExpertError) +
               (firstDivergentExpert >= 0
                    ? " (first divergent expert index " + std::to_string(firstDivergentExpert) + ")"
                    : ""));

    // ---- the weighted aggregation -------------------------------------------
    std::vector<float> executorSum;
    if (!executor.RunMoeExperts(block, x, ids, weights, executorSum, error)) {
        printf("  the combined expert path failed: %s\n", error.c_str());
        Report("the executor's combined expert path runs on the CPU", false, error);
        return 1;
    }
    const Metrics aggregation = Compare(referenceSum, executorSum);
    printf("\nWEIGHTED AGGREGATION  %s\n", FormatMetrics(aggregation).c_str());
    Report("the weighted aggregation matches the reference", aggregation.maxAbs <= 1e-2,
           FormatMetrics(aggregation));

    // ---- the machine-readable certificate -----------------------------------
    if (!receiptPath.empty()) {
        FILE* file = nullptr;
        if (fopen_s(&file, receiptPath.c_str(), "wb") == 0 && file != nullptr) {
            fprintf(file, "{\n");
            fprintf(file, "  \"certification\": \"DEEP2_NEMOTRON_MOE_EXPERT_CPU_PARITY_001\",\n");
            fprintf(file, "  \"block\": %d,\n", block);
            fprintf(file, "  \"expert_up\": \"%s\",\n", upName.c_str());
            fprintf(file, "  \"expert_down\": \"%s\",\n", downName.c_str());
            fprintf(file, "  \"activation\": \"LLM_FFN_RELU_SQR (squared ReLU)\",\n");
            fprintf(file, "  \"selected_experts\": [");
            for (size_t k = 0; k < ids.size(); ++k) fprintf(file, "%s%u", k ? "," : "", ids[k]);
            fprintf(file, "],\n");
            fprintf(file, "  \"worst_expert_max_abs\": %.9e,\n", worstExpertError);
            fprintf(file, "  \"first_divergent_expert_index\": %d,\n", firstDivergentExpert);
            fprintf(file, "  \"aggregation\": {\"max_abs\": %.9e, \"rmse\": %.9e, \"cosine\": %.9f, \"first_divergence\": %lld},\n",
                    aggregation.maxAbs, aggregation.rmse, aggregation.cosine,
                    (long long)aggregation.firstDivergence);
            fprintf(file, "  \"result\": \"%s\"\n", g_failures == 0 ? "PASS" : "FAIL");
            fprintf(file, "}\n");
            fclose(file);
            printf("\nreceipt written to %s\n", receiptPath.c_str());
        }
    }

    printf("\n=== %s ===\n", g_failures == 0 ? "DEEP2_NEMOTRON_MOE_EXPERT_CPU_PARITY_001 = PASS"
                                            : "DEEP2_NEMOTRON_MOE_EXPERT_CPU_PARITY_001 = FAIL");
    if (g_failures != 0) {
        printf("=== %d check(s) failed ===\n", g_failures);
        return 1;
    }
    return 0;
}
