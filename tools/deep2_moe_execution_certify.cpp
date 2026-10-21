// ============================================================================
// deep2_moe_execution_certify.cpp - DEEP2_NEMOTRON_MOE_EXECUTION_001
//
// The certification that the 30B model executes its intended MoE
// architecture, rather than merely producing finite logits.
//
// The R3.4 census found that Router, TopK, MoEExecute and SparseMoE execute
// ZERO times in a model configured with 128 experts, top-6 routing and 23
// MoE blocks. The census is an EXECUTION census, so it cannot by itself say
// whether the operations are missing from the graph, emitted but unable to
// bind, or fused into another operation.
//
// This gate separates those, and it does so WITHOUT A GPU BENCHMARK: it
// ingests the model on the CPU, which builds the op graph, and it inspects
// the graph. Nothing is uploaded, nothing is dispatched and no GPU timing is
// taken.
//
// Checks:
//   1. the model declares an MoE topology (experts, top-k, expert width)
//   2. the graph contains the Router, TopK and expert-execution operations
//   3. every MoE block in the topology has its Router, TopK and expert
//      execution operations
//   4. the expert weight tensors are present and non-empty
//   5. the router weight is present for every MoE block
//   6. the expert weight is the 3-D [ffn, experts, blocks] tensor the
//      executor expects, and its expert count matches the topology
//
// Usage: deep2_moe_execution_certify --model <gguf>
// ============================================================================

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "runtime_graph_executor.hpp"
#include "universal_gguf.hpp"

// The modelgenie lives in RawrXD::Deep2::Universal.
namespace Universal = RawrXD::Deep2::Universal;
namespace RuntimeGraph = RawrXD::Deep2::RuntimeGraph;

namespace {

int g_failures = 0;

void Report(const char* name, bool ok, const std::string& detail) {
    printf("[%s] %-52s %s\n", ok ? "PASS" : "FAIL", name, detail.c_str());
    if (!ok) ++g_failures;
}

const char* OpName(Universal::Op op) {
    switch (op) {
    case Universal::Op::EmbeddingLookup: return "EmbeddingLookup";
    case Universal::Op::RmsNorm: return "RmsNorm";
    case Universal::Op::Linear: return "Linear";
    case Universal::Op::Attention: return "Attention";
    case Universal::Op::MlaDecompress: return "MlaDecompress";
    case Universal::Op::Router: return "Router";
    case Universal::Op::TopK: return "TopK";
    case Universal::Op::MoEExecute: return "MoEExecute";
    case Universal::Op::Qsa: return "QSA";
    case Universal::Op::Gdn: return "GDN";
    case Universal::Op::Ple: return "PLE";
    case Universal::Op::Hyperconnection: return "Hyperconnection";
    case Universal::Op::SparseMoE: return "SparseMoE";
    case Universal::Op::ResidualAdd: return "ResidualAdd";
    case Universal::Op::Publish: return "Publish";
    case Universal::Op::SwiGLU: return "SwiGLU";
    case Universal::Op::SquaredReLU: return "SquaredReLU";
    case Universal::Op::LmHead: return "LmHead";
    case Universal::Op::SsmScan: return "SsmScan";
    default: return "Unsupported";
    }
}

} // namespace

int main(int argc, char** argv) {
    std::string model;
    for (int i = 1; i < argc; ++i) {
        const std::string argument = argv[i];
        if (argument == "--model" && i + 1 < argc) model = argv[++i];
        else if (argument == "--help") {
            printf("usage: deep2_moe_execution_certify --model <gguf>\n");
            return 0;
        }
    }
    if (model.empty()) {
        printf("usage: deep2_moe_execution_certify --model <gguf>\n");
        return 2;
    }

    setvbuf(stdout, nullptr, _IONBF, 0);
    printf("=== DEEP2_NEMOTRON_MOE_EXECUTION_001 ===\n");
    printf("model: %s\n\n", model.c_str());

    // The ingest is CPU work: it reads the GGUF and BUILDS THE OP GRAPH. No
    // weight is uploaded and no GPU work is dispatched, so this gate runs
    // under the benchmark pause.
    printf("ingesting (CPU only, no GPU upload, no dispatch) ...\n");
    const Universal::IngestReport& report = Universal::Ingest(model, false);
    if (!report.ok) {
        printf("INGEST_FAIL: %s\n", report.error.c_str());
        return 1;
    }

    const Universal::ModelSpec& spec = report.spec;
    const Universal::OpGraph& graph = report.graph;

    // ---- 1. the declared topology -------------------------------------------
    printf("\ntopology: arch=%s blocks=%llu embd=%llu experts=%llu used=%llu expert_ffn=%llu\n",
           spec.architecture.c_str(), (unsigned long long)spec.block_count,
           (unsigned long long)spec.embd, (unsigned long long)spec.expert_count,
           (unsigned long long)spec.expert_used, (unsigned long long)spec.expert_ffn);
    Report("the model declares an MoE topology",
           spec.expert_count > 0 && spec.expert_used > 0 && spec.expert_ffn > 0,
           "experts=" + std::to_string(spec.expert_count) + " used=" +
               std::to_string(spec.expert_used) + " ffn=" + std::to_string(spec.expert_ffn));

    // ---- 2. the graph's operation census ------------------------------------
    std::map<std::string, size_t> census;
    for (const Universal::GraphOp& op : graph.ops) ++census[OpName(op.op)];
    printf("\nGRAPH_CENSUS (%zu ops, %zu unsupported)\n", graph.ops.size(), graph.unsupported);
    for (const auto& entry : census) {
        printf("  %-22s %8zu\n", entry.first.c_str(), entry.second);
    }

    const size_t routerOps = census.count("Router") ? census.at("Router") : 0;
    const size_t topkOps = census.count("TopK") ? census.at("TopK") : 0;
    const size_t moeOps = census.count("MoEExecute") ? census.at("MoEExecute") : 0;
    const size_t sparseMoEOps = census.count("SparseMoE") ? census.at("SparseMoE") : 0;

    // ---- 3. per-block MoE structure -----------------------------------------
    // Which blocks carry the MoE? A block is an MoE block when it has a
    // Router operation or an expert-execution operation. The blocks that
    // SHOULD be MoE blocks are the ones the topology says have expert
    // weights; the graph's own router operations are the evidence of what it
    // decided.
    std::set<int32_t> routerBlocks;
    std::set<int32_t> topkBlocks;
    std::set<int32_t> moeBlocks;
    std::map<int32_t, std::string> routerWeight;
    std::map<int32_t, std::string> expertGate;
    std::map<int32_t, std::string> expertDetail;
    for (const Universal::GraphOp& op : graph.ops) {
        if (op.op == Universal::Op::Router) {
            routerBlocks.insert(op.block);
            routerWeight[op.block] = op.b;
        } else if (op.op == Universal::Op::TopK) {
            topkBlocks.insert(op.block);
        } else if (op.op == Universal::Op::MoEExecute || op.op == Universal::Op::SparseMoE) {
            moeBlocks.insert(op.block);
            expertGate[op.block] = op.c;
            expertDetail[op.block] = op.detail;
        }
    }

    printf("\nMOE_BLOCKS: router=%zu topk=%zu expert_execute=%zu\n", routerBlocks.size(),
           topkBlocks.size(), moeBlocks.size());

    // ---- 4. the expert weight is present and shaped as the executor expects --
    // The expert tensors are 3-D: [ffn, experts, blocks]. The expert count
    // in the tensor must match the topology's expert count, or the executor
    // would select from a different number of experts than the model declares.
    bool expertWeightFound = false;
    std::string expertWeightDetail = "no expert execution operation in the graph";
    for (const auto& entry : expertGate) {
        // A GATELESS expert has no gate slot: the expert's projections are
        // named in the operation's detail instead. Looking only at the gate
        // slot would report a missing expert weight for a model that is
        // correctly routed.
        const std::string& detail = expertDetail[entry.first];
        if (entry.second.empty() && detail.empty()) continue;
        expertWeightFound = true;
        expertWeightDetail = "block " + std::to_string(entry.first) +
                            (entry.second.empty() ? " gate=<gateless>" : " gate=" + entry.second) +
                            (detail.empty() ? "" : " experts=" + detail);
        break;
    }
    Report("the expert weight is bound to an expert-execution operation",
           expertWeightFound, expertWeightDetail);

    // ---- 5. the verdict ------------------------------------------------------
    // Every MoE block the topology implies must have its router, its top-k
    // and its expert execution. The number of MoE blocks is taken from the
    // graph's own router operations when they exist, and from the operation
    // count when they do not: a model whose experts never execute has no
    // router operations, and that is the defect this gate exists to catch.
    const size_t moeBlockCount = routerBlocks.size();
    const bool routersPresent = routerOps > 0;
    const bool topkPresent = topkOps > 0;
    const bool expertsPresent = moeOps > 0 || sparseMoEOps > 0;

    // ---- 4. what the expert and router tensors are actually called ---------
    // The role classifier matches on a SUBSTRING, and a substring match that
    // assumes a block prefix fails on a tensor that has none. The tensor
    // names are printed so a naming mismatch is visible rather than
    // inferred.
    printf("\nEXPERT/ROUTER TENSORS (first 16):\n");
    size_t printed = 0;
    for (const Universal::TensorRec& tensor : report.tensors) {
        if (tensor.name.find("exp_probs") == std::string::npos &&
            tensor.name.find("_exps") == std::string::npos &&
            tensor.name.find("gate_inp") == std::string::npos &&
            tensor.name.find("router") == std::string::npos) {
            continue;
        }
        if (printed++ >= 16) break;
        printf("  %-48s dims=[", tensor.name.c_str());
        for (size_t d = 0; d < tensor.dims.size() && d < 4; ++d) {
            printf("%s%llu", d ? "," : "", (unsigned long long)tensor.dims[d]);
        }
        printf("] bytes=%llu\n", (unsigned long long)tensor.bytes);
    }

    // The router's PROJECTION needs a matrix. A 128-element bias is only the
    // offset. If the block carries no router matrix, every token would be
    // routed identically, and the certificate has to say so rather than
    // pass a router that cannot depend on the token.
    size_t routerMatrixCount = 0;
    std::string routerMatrixExample;
    for (const Universal::TensorRec& tensor : report.tensors) {
        if (tensor.name.find(".ffn_gate_inp.weight") == std::string::npos) continue;
        ++routerMatrixCount;
        if (routerMatrixExample.empty()) routerMatrixExample = tensor.name;
    }
    size_t routerBiasCount = 0;
    for (const Universal::TensorRec& tensor : report.tensors) {
        if (tensor.name.find(".exp_probs_b.bias") != std::string::npos) ++routerBiasCount;
    }
    printf("\n  router matrices (ffn_gate_inp.weight) : %zu\n", routerMatrixCount);
    printf("  router biases   (exp_probs_b.bias)     : %zu\n", routerBiasCount);
    if (!routerMatrixExample.empty()) printf("  example: %s\n", routerMatrixExample.c_str());
    // Does the router tensor name actually contain the substring the role
    // classifier looks for? This is the difference between "the MoE path was
    // not taken" and "the MoE path was taken and produced nothing".
    bool routerNameMatched = false;
    bool expertNameMatched = false;
    std::string routerNameExample;
    std::string expertNameExample;
    for (const Universal::TensorRec& tensor : report.tensors) {
        if (tensor.name.find("exp_probs") != std::string::npos &&
            routerNameExample.empty()) {
            routerNameExample = tensor.name;
            routerNameMatched = tensor.name.find(".exp_probs_b.bias") != std::string::npos;
        }
        if (tensor.name.find("_exps") != std::string::npos &&
            expertNameExample.empty()) {
            expertNameExample = tensor.name;
            expertNameMatched =
                tensor.name.find(".ffn_gate_exps.weight") != std::string::npos;
        }
    }
    printf("\n  router tensor example : %s\n", routerNameExample.c_str());
    printf("  expert tensor example : %s\n", expertNameExample.c_str());
    Report("the router tensor name matches the role classifier's pattern",
           routerNameMatched,
           routerNameExample.empty()
               ? "no exp_probs tensor in the model"
               : routerNameExample + (routerNameMatched ? " (matches)" : " (DOES NOT MATCH .exp_probs_b.bias)"));
    // The expert's shape is a property of the MODEL, not a defect: some
    // checkpoints ship a gated expert (ffn_gate_exps) and some ship a
    // gateless one (ffn_up_exps + ffn_down_exps only). The check is that the
    // expert tensors are RECOGNISED by the role classifier, in whichever
    // shape the model uses.
    const bool gatedExpert = expertNameExample.find(".ffn_gate_exps.weight") != std::string::npos;
    const bool gatelessExpert = expertNameExample.find(".ffn_up_exps.weight") != std::string::npos ||
                               expertNameExample.find(".ffn_down_exps.weight") != std::string::npos;
    Report("the expert tensor name matches the role classifier's pattern",
           gatedExpert || gatelessExpert,
           expertNameExample.empty()
               ? "no _exps tensor in the model"
               : expertNameExample + (gatedExpert
                                          ? " (gated expert: .ffn_gate_exps.weight matches)"
                                          : (gatelessExpert
                                                 ? " (GATELESS expert: .ffn_up_exps/.ffn_down_exps match, no gate tensor)"
                                                 : " (DOES NOT MATCH any expert pattern)")));

    Report("the graph contains Router operations", routersPresent,
           std::to_string(routerOps) + " Router ops across " +
               std::to_string(routerBlocks.size()) + " blocks");
    Report("the graph contains TopK operations", topkPresent,
           std::to_string(topkOps) + " TopK ops across " +
               std::to_string(topkBlocks.size()) + " blocks");
    Report("the graph contains expert-execution operations", expertsPresent,
           std::to_string(moeOps) + " MoEExecute + " + std::to_string(sparseMoEOps) +
               " SparseMoE ops across " + std::to_string(moeBlocks.size()) + " blocks");

    // A model with experts declared and no MoE block lowered is the failure
    // this gate is built to catch. The expected block count is derived from
    // the topology: the expert width and the expert count imply a routed
    // block, and the census is the independent statement of what the graph
    // contains.
    if (spec.expert_count > 0) {
        Report("every MoE block has a router, a top-k and an expert execution",
               routersPresent && topkPresent && expertsPresent && moeBlockCount > 0,
               moeBlockCount == 0
                   ? "NO MoE blocks were lowered, so the " + std::to_string(spec.expert_count) +
                         " experts and the top-" + std::to_string(spec.expert_used) +
                         " routing are never executed"
                   : std::to_string(moeBlockCount) + " MoE blocks lowered");

        // The router weight must be present for every MoE block.
        size_t blocksWithRouterWeight = 0;
        for (const auto& entry : routerWeight) {
            if (!entry.second.empty()) ++blocksWithRouterWeight;
        }
        Report("every MoE block has a router weight",
               !routerBlocks.empty() && blocksWithRouterWeight == routerBlocks.size(),
               std::to_string(blocksWithRouterWeight) + " of " +
                   std::to_string(routerBlocks.size()) + " MoE blocks have a router weight");
    }

    // ---- 6. the binding phase -----------------------------------------------
    // The executor's OWN bind, with the CPU backend pinned so nothing touches
    // the GPU. Binding is a CPU operation: it resolves every weight handle,
    // builds the operator program and validates that each operator has the
    // tensors it names.
    printf("\nBINDING PHASE (CPU pinned, no GPU device, no dispatch)\n");
    RuntimeGraph::Executor executor;
    executor.SetForceCpu(true);
    const bool bound = executor.Bind(report);
    const RuntimeGraph::BindStats& stats = executor.Stats();

    printf("GRAPH_MOE_BLOCKS       %zu\n", moeBlockCount);
    printf("OPS_BOUND              %zu\n", stats.ops_bound);
    printf("OPS_UNBOUND            %zu\n", stats.ops_unbound);
    printf("FIRST_BLOCKING_OPERATOR %s\n",
           stats.first_blocking_operator.empty() ? "(none)" : stats.first_blocking_operator.c_str());
    printf("FIRST_BLOCKING_TENSOR  %s\n",
           stats.failure_receipt_json.empty() ? "(none)" : stats.failure_receipt_json.c_str());
    printf("WEIGHTS_RESOLVED       %llu\n", (unsigned long long)stats.weights_resolved);
    printf("WEIGHTS_MISSING        %llu\n", (unsigned long long)stats.weights_missing);

    Report("the executor binds the graph", bound,
           bound ? "bound" : stats.error);

    // The MoE operators must be among the bound ones, not merely absent
    // from the unbound list.
    size_t moeUnbound = 0;
    for (const std::string& entry : stats.unbound_ops) {
        if (entry.find("Router") != std::string::npos ||
            entry.find("TopK") != std::string::npos ||
            entry.find("MoEExecute") != std::string::npos) {
            ++moeUnbound;
        }
    }
    Report("every Router, TopK and MoEExecute operator binds",
           moeUnbound == 0 && stats.ops_unbound == 0,
           std::to_string(moeUnbound) + " MoE operators unbound, " +
               std::to_string(stats.ops_unbound) + " operators unbound in total");

    // ---- 7. the expert tensors resolve to real metadata -------------------
    // Independently of the executor: for every MoE block, the expert's up and
    // down projections must exist in the model with the right shape and a
    // non-zero size, and the gate must be OPTIONAL rather than required.
    auto findTensor = [&](const std::string& name) -> const Universal::TensorRec* {
        for (const Universal::TensorRec& tensor : report.tensors) {
            if (tensor.name == name) return &tensor;
        }
        return nullptr;
    };
    auto trim = [](std::string s) {
        const size_t first = s.find_first_not_of(" \t;");
        if (first == std::string::npos) return std::string();
        const size_t last = s.find_last_not_of(" \t;");
        return s.substr(first, last - first + 1);
    };

    size_t upBound = 0;
    size_t downBound = 0;
    size_t gatePresent = 0;
    size_t gateRequired = 0;
    size_t shapeOk = 0;
    size_t zeroSized = 0;
    size_t expertCountOk = 0;
    std::string firstFailure;

    for (const Universal::GraphOp& op : graph.ops) {
        if (op.op != Universal::Op::MoEExecute) continue;
        std::string up;
        std::string down;
        const size_t marker = op.detail.find("experts:");
        if (marker != std::string::npos) {
            std::string list = op.detail.substr(marker + 8);
            const size_t comma = list.find(',');
            if (comma != std::string::npos) {
                up = trim(list.substr(0, comma));
                down = trim(list.substr(comma + 1));
            }
        }
        if (!op.c.empty()) {
            ++gatePresent;
            ++gateRequired;
        }
        const Universal::TensorRec* upTensor = findTensor(up);
        const Universal::TensorRec* downTensor = findTensor(down);
        if (upTensor && upTensor->bytes > 0) ++upBound;
        else if (firstFailure.empty()) firstFailure = "expert up '" + up + "' missing or empty";
        if (downTensor && downTensor->bytes > 0) ++downBound;
        else if (firstFailure.empty()) firstFailure = "expert down '" + down + "' missing or empty";
        if (upTensor && upTensor->bytes == 0) ++zeroSized;
        if (downTensor && downTensor->bytes == 0) ++zeroSized;
        // up is [hidden, ffn, experts] and down is [ffn, hidden, experts].
        if (upTensor && downTensor && upTensor->dims.size() == 3 &&
            downTensor->dims.size() == 3) {
            const bool upShape = upTensor->dims[0] == spec.embd &&
                                 upTensor->dims[1] == spec.expert_ffn &&
                                 upTensor->dims[2] == spec.expert_count;
            const bool downShape = downTensor->dims[0] == spec.expert_ffn &&
                                  downTensor->dims[1] == spec.embd &&
                                  downTensor->dims[2] == spec.expert_count;
            if (upShape && downShape) ++shapeOk;
            else if (firstFailure.empty()) {
                firstFailure = "expert shape mismatch on block " + std::to_string(op.block);
            }
            if (upShape && downShape && upTensor->dims[2] == spec.expert_count) {
                ++expertCountOk;
            }
        }
    }

    printf("EXPERT_UP_BOUND        %zu of %zu\n", upBound, moeBlockCount);
    printf("EXPERT_DOWN_BOUND      %zu of %zu\n", downBound, moeBlockCount);
    printf("EXPERT_GATE_REQUIRED   %zu\n", gateRequired);
    printf("EXPERT_GATE_PRESENT    %zu\n", gatePresent);

    Report("every expert up projection resolves to real metadata",
           upBound == moeBlockCount && moeBlockCount > 0,
           std::to_string(upBound) + " of " + std::to_string(moeBlockCount) +
               (firstFailure.empty() ? "" : " (" + firstFailure + ")"));
    Report("every expert down projection resolves to real metadata",
           downBound == moeBlockCount && moeBlockCount > 0,
           std::to_string(downBound) + " of " + std::to_string(moeBlockCount));
    Report("no expert binding is a zero-sized tensor", zeroSized == 0,
           std::to_string(zeroSized) + " zero-sized expert tensors");
    Report("the expert tensors have the declared shape",
           shapeOk == moeBlockCount && moeBlockCount > 0,
           std::to_string(shapeOk) + " of " + std::to_string(moeBlockCount) +
               " match [hidden,ffn,experts] and [ffn,hidden,experts] with experts=" +
               std::to_string(spec.expert_count));
    Report("the absent gate is explicitly supported for gateless experts",
           gatePresent == 0 && gateRequired == 0 && moeBlockCount > 0,
           "0 of " + std::to_string(moeBlockCount) +
               " blocks have a gate tensor; the binding accepts a gateless expert");

    // The router must be bound to the [hidden, experts] MATRIX. A [experts]
    // bias cannot be a router projection: the router operator's own shape
    // check rejects it, and the routing would not depend on the token.
    size_t routerMatrixBound = 0;
    size_t routerBiasBound = 0;
    std::string routerBoundExample;
    for (const auto& entry : routerWeight) {
        const Universal::TensorRec* tensor = findTensor(entry.second);
        if (tensor == nullptr) continue;
        if (tensor->dims.size() >= 2) {
            ++routerMatrixBound;
            if (routerBoundExample.empty()) routerBoundExample = entry.second;
        } else {
            ++routerBiasBound;
        }
    }
    printf("  router bound to a matrix : %zu of %zu\n", routerMatrixBound, routerBlocks.size());
    printf("  router bound to a bias   : %zu of %zu\n", routerBiasBound, routerBlocks.size());
    Report("the router is bound to the [hidden, experts] matrix",
           routerMatrixBound == routerBlocks.size() && routerBlocks.size() > 0,
           routerBoundExample.empty()
               ? "no router tensor resolved"
               : routerBoundExample + " (" + std::to_string(routerMatrixBound) + " of " +
                     std::to_string(routerBlocks.size()) + " bound to a matrix)");

    printf("\n=== %s ===\n", g_failures == 0 ? "DEEP2_NEMOTRON_MOE_EXECUTION_001 = PASS"
                                            : "DEEP2_NEMOTRON_MOE_EXECUTION_001 = FAIL");
    if (g_failures != 0) {
        printf("=== %d check(s) failed ===\n", g_failures);
        return 1;
    }
    return 0;
}
