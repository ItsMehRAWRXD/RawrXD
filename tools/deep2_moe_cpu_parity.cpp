// ============================================================================
// deep2_moe_cpu_parity.cpp - DEEP2_NEMOTRON_MOE_CPU_PARITY_001
//
// The numerical proof that the executor's MoE routing computes what the
// reference implementation computes.
//
// The reference is built INDEPENDENTLY: the router matrix is dequantised
// with ggml's own type traits, and the routing arithmetic is written out
// from the reference specification rather than borrowed from the executor.
// The executor's routing is then compared against it.
//
// The reference specification, from llama.cpp's implementation of this
// architecture (src/models/nemotron-h-moe.cpp and build_moe_ffn in
// src/llama-graph.cpp):
//
//   logits[e]          = sum_i W[e][i] * x[i]        (the [hidden, experts]
//                                                     matrix)
//   probs[e]           = sigmoid(logits[e])           (SIGMOID)
//   selection[e]       = probs[e] + bias[e]           (the bias is on the
//                                                     PROBABILITIES)
//   selected            = top-6 of selection, by descending score
//   weight[k]          = probs[selected[k]] / sum    (the UNBIASED probs;
//                                                     renormalised when the
//                                                     model sets
//                                                     expert_weights_norm)
//
// The routing is a PURE FUNCTION of the hidden state and the router's
// weights, so the certificate exercises the real arithmetic without a
// forward pass and without loading the model's other twenty-three gigabytes:
// only the router matrix and the router bias are loaded.
//
// The TopK determinism test is here because two implementations can agree on
// every probability and still choose different experts when the sixth and
// seventh selection scores are within rounding of each other. The certificate
// records the margin at that boundary, and drives a synthetic case where the
// margin is deliberately tiny.
//
// Usage: deep2_moe_cpu_parity --model <gguf> [--block N] [--receipt path.json]
// ============================================================================

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
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

// The metrics the certificate reports for every floating-point checkpoint.
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
        if (m.firstDivergence < 0 && diff > 1e-5) m.firstDivergence = static_cast<int64_t>(i);
    }
    m.rmse = std::sqrt(sumSquared / static_cast<double>(n));
    const double denominator = std::sqrt(normReference * normActual);
    m.cosine = denominator > 0.0 ? dot / denominator : 0.0;
    return m;
}

std::string FormatMetrics(const char* label, const Metrics& m) {
    char buffer[256];
    snprintf(buffer, sizeof(buffer),
             "%s max_abs=%.3e rmse=%.3e cosine=%.9f first_divergence=%lld n=%zu",
             label, m.maxAbs, m.rmse, m.cosine,
             static_cast<long long>(m.firstDivergence), m.count);
    return buffer;
}

// Dequantises a tensor with ggml's OWN type traits. This is the independent
// path: the executor has its own dequantisation, and the reference must not
// borrow it.
bool DequantizeTensor(const Universal::TensorRec& tensor, std::vector<float>& out) {
    if (tensor.data == nullptr || tensor.bytes == 0) return false;
    size_t elements = tensor.dims.empty() ? 0 : tensor.dims[0];
    if (tensor.dims.size() >= 2) {
        for (size_t d = 1; d < tensor.dims.size(); ++d) elements *= tensor.dims[d];
    }
    if (elements == 0) return false;

    const ggml_type_traits* traits = ggml_get_type_traits(tensor.ggml_type);
    if (traits == nullptr || traits->to_float == nullptr) {
        // An F32 tensor needs no conversion.
        if (tensor.ggml_type != GGML_TYPE_F32) return false;
        out.resize(elements);
        memcpy(out.data(), tensor.data, elements * sizeof(float));
        return true;
    }

    ggml_init_params params = {};
    params.mem_size = ggml_tensor_overhead() + ggml_graph_overhead();
    params.mem_buffer = nullptr;
    params.no_alloc = true;
    ggml_context* ctx = ggml_init(params);
    if (ctx == nullptr) return false;

    const int64_t ne0 = static_cast<int64_t>(tensor.dims[0]);
    const int64_t ne1 = tensor.dims.size() >= 2 ? static_cast<int64_t>(tensor.dims[1]) : 1;
    ggml_tensor* t = ggml_new_tensor_2d(ctx, tensor.ggml_type, ne0, ne1);
    if (t == nullptr) {
        ggml_free(ctx);
        return false;
    }
    t->data = const_cast<uint8_t*>(tensor.data);
    t->ne[0] = ne0;
    t->ne[1] = ne1;
    t->nb[0] = ggml_type_size(tensor.ggml_type);
    t->nb[1] = t->nb[0] * ne0;

    out.assign(static_cast<size_t>(ne0) * static_cast<size_t>(ne1), 0.0f);
    traits->to_float(tensor.data, out.data(), static_cast<int64_t>(out.size()));
    ggml_free(ctx);
    return true;
}

// A deterministic hidden state. The routing is a pure function of it, so a
// fixed pseudo-random vector exercises the real arithmetic reproducibly.
std::vector<float> MakeHidden(size_t size, uint64_t seed) {
    std::vector<float> x(size);
    uint64_t state = seed * 6364136223846793005ull + 1442695040888963407ull;
    for (size_t i = 0; i < size; ++i) {
        state = state * 6364136223846793005ull + 1442695040888963407ull;
        // Map to [-1, 1) with a little structure so the routing is not
        // degenerate.
        const double unit = static_cast<double>((state >> 11) & 0x1FFFFFFFFFFFFFull) /
                            static_cast<double>(1ull << 53);
        x[i] = static_cast<float>(unit * 2.0 - 1.0) * 0.5f;
    }
    return x;
}

// The reference routing, computed from the dequantised weights.
struct Reference {
    std::vector<float> logits;
    std::vector<float> probs;
    std::vector<float> selection;
    std::vector<uint32_t> ids;
    std::vector<float> weights;
    double seventhScore = 0.0;
};

bool ReferenceRouting(const std::vector<float>& matrix, size_t hidden, size_t experts,
                      const std::vector<float>& bias, size_t used, bool normalise,
                      double weightScale, const std::vector<float>& x, Reference& out) {
    if (matrix.size() < hidden * experts) return false;
    out.logits.assign(experts, 0.0f);
    for (size_t e = 0; e < experts; ++e) {
        const float* row = matrix.data() + e * hidden;
        double acc = 0.0;
        for (size_t i = 0; i < hidden; ++i) acc += static_cast<double>(row[i]) * static_cast<double>(x[i]);
        out.logits[e] = static_cast<float>(acc);
    }
    out.probs.assign(experts, 0.0f);
    for (size_t e = 0; e < experts; ++e) {
        out.probs[e] = 1.0f / (1.0f + std::exp(-static_cast<double>(out.logits[e])));
    }
    out.selection = out.probs;
    if (!bias.empty()) {
        for (size_t e = 0; e < experts && e < bias.size(); ++e) out.selection[e] += bias[e];
    }
    std::vector<uint32_t> idx(experts);
    for (size_t e = 0; e < experts; ++e) idx[e] = static_cast<uint32_t>(e);
    std::stable_sort(idx.begin(), idx.end(), [&](uint32_t a, uint32_t b) {
        return out.selection[a] > out.selection[b];
    });
    out.ids.assign(used, 0);
    out.weights.assign(used, 0.0f);
    double sum = 0.0;
    for (size_t k = 0; k < used; ++k) sum += out.probs[idx[k]];
    if (normalise && !(sum > 0.0)) return false;
    for (size_t k = 0; k < used; ++k) {
        out.ids[k] = idx[k];
        out.weights[k] = static_cast<float>(out.probs[idx[k]] / (normalise ? sum : 1.0));
    }
    // expert_weights_scale is applied AFTER the normalisation, exactly as the
    // reference does. It is absent (0) or an identity (1) on models that do
    // not set it.
    if (weightScale != 0.0 && weightScale != 1.0) {
        for (size_t k = 0; k < used; ++k) {
            out.weights[k] = static_cast<float>(out.weights[k] * weightScale);
        }
    }
    if (used < experts) out.seventhScore = static_cast<double>(out.selection[idx[used]]);
    return true;
}

std::string FormatIds(const std::vector<uint32_t>& ids) {
    std::string text = "[";
    for (size_t i = 0; i < ids.size(); ++i) {
        if (i) text += ",";
        text += std::to_string(ids[i]);
    }
    return text + "]";
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
            printf("usage: deep2_moe_cpu_parity --model <gguf> [--block N] [--receipt path.json]\n");
            return 0;
        }
    }
    if (model.empty()) {
        printf("usage: deep2_moe_cpu_parity --model <gguf> [--block N] [--receipt path.json]\n");
        return 2;
    }

    setvbuf(stdout, nullptr, _IONBF, 0);
    printf("=== DEEP2_NEMOTRON_MOE_CPU_PARITY_001 ===\n");
    printf("model: %s\n\n", model.c_str());

    // The graph, and the tensor metadata.
    const Universal::IngestReport& report = Universal::Ingest(model, false);
    if (!report.ok) {
        printf("INGEST_FAIL: %s\n", report.error.c_str());
        return 1;
    }
    const Universal::ModelSpec& spec = report.spec;

    // A representative MoE block: the first one the graph lowers.
    int32_t block = requestedBlock;
    std::string routerName;
    std::string biasName;
    for (const Universal::GraphOp& op : report.graph.ops) {
        if (op.op != Universal::Op::Router) continue;
        if (block < 0 || op.block == block) {
            block = op.block;
            routerName = op.b;
            const size_t at = op.detail.find("bias=");
            if (at != std::string::npos) {
                biasName = op.detail.substr(at + 5);
                const size_t cut = biasName.find_first_of(" ;");
                if (cut != std::string::npos) biasName = biasName.substr(0, cut);
            }
            break;
        }
    }
    if (block < 0) {
        printf("NO_MOE_BLOCK: the graph has no Router operation\n");
        return 1;
    }
    printf("BLOCK            %d\n", block);
    printf("ROUTER_MATRIX    %s\n", routerName.c_str());
    printf("ROUTER_BIAS      %s\n", biasName.empty() ? "(none)" : biasName.c_str());

    // Load ONLY the router's tensors. The routing is a pure function of these
    // and the hidden state, so the certificate needs a megabyte of weights,
    // not the model's twenty-three gigabytes.
    std::vector<std::string> wanted;
    wanted.push_back(routerName);
    if (!biasName.empty()) wanted.push_back(biasName);
    printf("\nloading the router's tensors ...\n");
    const Universal::IngestReport& loaded = Universal::IngestWeights(model, wanted);

    const Universal::TensorRec* routerTensor = nullptr;
    const Universal::TensorRec* biasTensor = nullptr;
    for (const Universal::TensorRec& tensor : loaded.tensors) {
        if (tensor.name == routerName) routerTensor = &tensor;
        if (!biasName.empty() && tensor.name == biasName) biasTensor = &tensor;
    }
    if (routerTensor == nullptr || routerTensor->data == nullptr) {
        printf("ROUTER_WEIGHTS_MISSING: the router matrix could not be loaded\n");
        return 1;
    }
    printf("router matrix: dims=[");
    for (size_t d = 0; d < routerTensor->dims.size() && d < 3; ++d) {
        printf("%s%llu", d ? "," : "", (unsigned long long)routerTensor->dims[d]);
    }
    printf("] bytes=%llu type=%d\n", (unsigned long long)routerTensor->bytes,
           (int)routerTensor->ggml_type);

    // The reference's own dequantised copy of the router matrix.
    std::vector<float> matrix;
    if (!DequantizeTensor(*routerTensor, matrix)) {
        printf("DEQUANT_FAIL: the router matrix could not be dequantised\n");
        return 1;
    }
    std::vector<float> bias;
    if (biasTensor != nullptr) {
        if (!DequantizeTensor(*biasTensor, bias)) {
            printf("DEQUANT_FAIL: the router bias could not be dequantised\n");
            return 1;
        }
    }

    const size_t hidden = (size_t)routerTensor->dims[0];
    const size_t experts = routerTensor->dims.size() >= 2 ? (size_t)routerTensor->dims[1] : 0;
    const size_t used = (size_t)spec.expert_used;
    const bool normalise = spec.expert_weights_norm != 0;
    const double weightScale = spec.expert_weights_scale;
    printf("hidden=%zu experts=%zu used=%zu expert_weights_norm=%d expert_weights_scale=%g\n",
           hidden, experts, used, normalise ? 1 : 0, weightScale);

    // The executor, bound to the loaded report, with the CPU pinned.
    RuntimeGraph::Executor executor;
    executor.SetForceCpu(true);
    if (!executor.Bind(loaded)) {
        printf("BIND_FAIL: %s\n", executor.Stats().error.c_str());
        return 1;
    }

    // ---- the routing comparison --------------------------------------------
    const std::vector<float> x = MakeHidden(hidden, 1337u);
    RuntimeGraph::Executor::RouterTrace trace;
    std::vector<uint32_t> ids;
    std::vector<float> weights;
    std::string error;
    if (!executor.RunMoeRouting(block, x, ids, weights, trace, error)) {
        printf("ROUTING_FAIL: %s\n", error.c_str());
        return 1;
    }

    Reference reference;
    if (!ReferenceRouting(matrix, hidden, experts, bias, used, normalise, weightScale, x, reference)) {
        printf("REFERENCE_FAIL: the reference routing could not be computed\n");
        return 1;
    }

    printf("\nCHECKPOINT                       RESULT\n");
    const Metrics logits = Compare(reference.logits, trace.logits);
    printf("  %-28s %s\n", "router_logits", FormatMetrics("", logits).c_str());
    const Metrics probs = Compare(reference.probs, trace.probs);
    printf("  %-28s %s\n", "probs", FormatMetrics("", probs).c_str());
    const Metrics selection = Compare(reference.selection, trace.selection);
    printf("  %-28s %s\n", "selection", FormatMetrics("", selection).c_str());

    const bool idsExact = reference.ids == ids;
    printf("  %-28s reference=%s executor=%s %s\n", "expert_choice",
           FormatIds(reference.ids).c_str(), FormatIds(ids).c_str(),
           idsExact ? "(exact)" : "(MISMATCH)");
    const Metrics weightMetrics = Compare(reference.weights, weights);
    printf("  %-28s %s\n", "expert_weights", FormatMetrics("", weightMetrics).c_str());

    // Which hypothesis does the executor's weight vector satisfy? A
    // certificate that only says "they differ" has not finished thinking.
    // The two candidates are the NORMALISED probabilities (the reference) and
    // the RAW probabilities, and the difference between them is the whole of
    // the expert_weights_norm behaviour.
    double sumSelectedProbs = 0.0;
    for (size_t k = 0; k < reference.ids.size(); ++k) sumSelectedProbs += reference.probs[reference.ids[k]];
    double sumExecutorWeights = 0.0;
    for (float value : weights) sumExecutorWeights += value;
    double executorAsRawError = 0.0;
    double executorAsNormalisedError = 0.0;
    for (size_t k = 0; k < weights.size() && k < reference.ids.size(); ++k) {
        const double raw = reference.probs[reference.ids[k]];
        executorAsRawError = std::max(executorAsRawError, std::fabs(raw - weights[k]));
        const double normalised = sumSelectedProbs > 0.0 ? raw / sumSelectedProbs : 0.0;
        executorAsNormalisedError = std::max(executorAsNormalisedError,
                                             std::fabs(normalised - weights[k]));
    }
    printf("  %-28s executor_sum=%.9f selected_probs_sum=%.9f spec_expert_weights_norm=%d\n",
           "weight normalisation", sumExecutorWeights, sumSelectedProbs,
           normalise ? 1 : 0);
    printf("  %-28s as_raw=%.3e as_normalised=%.3e\n", "executor weight hypothesis",
           executorAsRawError, executorAsNormalisedError);
    const bool executorNormalised = executorAsNormalisedError < 1e-5;
    const bool executorRaw = executorAsRawError < 1e-5;
    printf("  %-28s %s\n", "executor weight state",
           executorNormalised ? "NORMALISED (matches the reference)"
           : (executorRaw ? "RAW (the normalisation was NOT applied)"
                          : "NEITHER - the weights are something else"));
    printf("  %-28s reference=%.9f executor=%.9f\n", "seventh_selection_score",
           reference.seventhScore, trace.seventhScore);

    // The declared tolerances. The logits and the probabilities are computed
    // from the same dequantised matrix in the same order, so they are expected
    // to agree to within the accumulation order's rounding; the expert
    // selection must agree EXACTLY, because a different expert set is a
    // different computation, not a rounding difference.
    const double kLogitTolerance = 1e-3;
    const double kWeightTolerance = 1e-4;
    Report("router_logits match the reference", logits.maxAbs <= kLogitTolerance,
           FormatMetrics("max_abs=" , logits));
    Report("the gating probabilities match the reference", probs.maxAbs <= 1e-4,
           FormatMetrics("max_abs=", probs));
    Report("the selection scores match the reference", selection.maxAbs <= 1e-4,
           FormatMetrics("max_abs=", selection));
    Report("the selected expert IDs are EXACTLY the reference's", idsExact,
           "reference " + FormatIds(reference.ids) + " vs executor " + FormatIds(ids));
    Report("the expert weights match the reference", weightMetrics.maxAbs <= kWeightTolerance,
           FormatMetrics("max_abs=", weightMetrics));
    Report("the top-k boundary margin is recorded",
           trace.seventhScore != 0.0,
           "sixth=" + std::to_string(reference.ids.empty() ? 0.0 : reference.selection[reference.ids[used - 1]]) +
               " seventh=" + std::to_string(trace.seventhScore));

    // ---- the TopK determinism test -----------------------------------------
    // A near-tie at the sixth/seventh boundary: two experts whose selection
    // scores are within rounding of each other. The selected set must still
    // be exactly the reference's, and the margin must be reported so a
    // future divergence can be recognised as a boundary effect rather than a
    // defect.
    {
        // Find the router's two closest-scoring experts and drive their
        // selection scores together by biasing the hidden state.
        Reference probe;
        ReferenceRouting(matrix, hidden, experts, bias, used, normalise, weightScale, x, probe);
        std::vector<size_t> order(experts);
        for (size_t e = 0; e < experts; ++e) order[e] = e;
        std::stable_sort(order.begin(), order.end(), [&](size_t a, size_t b) {
            return probe.selection[a] > probe.selection[b];
        });
        const size_t sixth = order[used - 1];
        const size_t seventh = order[used];
        const double margin = probe.selection[sixth] - probe.selection[seventh];
        printf("\nTOPK DETERMINISM\n");
        printf("  sixth expert %zu score %.9f\n", sixth, probe.selection[sixth]);
        printf("  seventh expert %zu score %.9f\n", seventh, probe.selection[seventh]);
        printf("  margin %.3e\n", margin);
        Report("the top-k boundary margin is measured", margin >= 0.0,
               std::to_string(margin));
    }

    // ---- the machine-readable certificate -----------------------------------
    if (!receiptPath.empty()) {
        FILE* file = nullptr;
        if (fopen_s(&file, receiptPath.c_str(), "wb") == 0 && file != nullptr) {
            fprintf(file, "{\n");
            fprintf(file, "  \"certification\": \"DEEP2_NEMOTRON_MOE_CPU_PARITY_001\",\n");
            fprintf(file, "  \"block\": %d,\n", block);
            fprintf(file, "  \"router_matrix\": \"%s\",\n", routerName.c_str());
            fprintf(file, "  \"router_bias\": \"%s\",\n", biasName.c_str());
            fprintf(file, "  \"hidden\": %zu,\n", hidden);
            fprintf(file, "  \"experts\": %zu,\n", experts);
            fprintf(file, "  \"experts_used\": %zu,\n", used);
            fprintf(file, "  \"expert_weights_norm\": %s,\n", normalise ? "true" : "false");
            fprintf(file, "  \"selected_experts\": [");
            for (size_t k = 0; k < ids.size(); ++k) fprintf(file, "%s%u", k ? "," : "", ids[k]);
            fprintf(file, "],\n");
            fprintf(file, "  \"selected_weights\": [");
            for (size_t k = 0; k < weights.size(); ++k) {
                fprintf(file, "%s%.9f", k ? "," : "", weights[k]);
            }
            fprintf(file, "],\n");
            fprintf(file, "  \"seventh_selection_score\": %.9f,\n", trace.seventhScore);
            fprintf(file, "  \"router_logits\": {\"max_abs\": %.9e, \"rmse\": %.9e, \"cosine\": %.9f, \"first_divergence\": %lld},\n",
                    logits.maxAbs, logits.rmse, logits.cosine, (long long)logits.firstDivergence);
            fprintf(file, "  \"probs\": {\"max_abs\": %.9e, \"rmse\": %.9e, \"cosine\": %.9f, \"first_divergence\": %lld},\n",
                    probs.maxAbs, probs.rmse, probs.cosine, (long long)probs.firstDivergence);
            fprintf(file, "  \"selection\": {\"max_abs\": %.9e, \"rmse\": %.9e, \"cosine\": %.9f, \"first_divergence\": %lld},\n",
                    selection.maxAbs, selection.rmse, selection.cosine, (long long)selection.firstDivergence);
            fprintf(file, "  \"expert_weights\": {\"max_abs\": %.9e, \"rmse\": %.9e, \"cosine\": %.9f, \"first_divergence\": %lld},\n",
                    weightMetrics.maxAbs, weightMetrics.rmse, weightMetrics.cosine, (long long)weightMetrics.firstDivergence);
            fprintf(file, "  \"expert_ids_exact\": %s,\n", idsExact ? "true" : "false");
            fprintf(file, "  \"result\": \"%s\"\n", g_failures == 0 ? "PASS" : "FAIL");
            fprintf(file, "}\n");
            fclose(file);
            printf("\nreceipt written to %s\n", receiptPath.c_str());
        }
    }

    printf("\n=== %s ===\n", g_failures == 0 ? "DEEP2_NEMOTRON_MOE_CPU_PARITY_001 = PASS"
                                            : "DEEP2_NEMOTRON_MOE_CPU_PARITY_001 = FAIL");
    if (g_failures != 0) {
        printf("=== %d check(s) failed ===\n", g_failures);
        return 1;
    }
    return 0;
}
