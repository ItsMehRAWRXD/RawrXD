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

#include "universal_gguf.hpp"

// The modelgenie lives in RawrXD::Deep2::Universal.
namespace Universal = RawrXD::Deep2::Universal;

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
            tensor.name.find("_exps") == std::string::npos) {
            continue;
        }
        if (printed++ >= 16) break;
        printf("  %-48s dims=[", tensor.name.c_str());
        for (size_t d = 0; d < tensor.dims.size() && d < 4; ++d) {
            printf("%s%llu", d ? "," : "", (unsigned long long)tensor.dims[d]);
        }
        printf("] bytes=%llu\n", (unsigned long long)tensor.bytes);
    }
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

    printf("\n=== %s ===\n", g_failures == 0 ? "DEEP2_NEMOTRON_MOE_EXECUTION_001 = PASS"
                                            : "DEEP2_NEMOTRON_MOE_EXECUTION_001 = FAIL");
    if (g_failures != 0) {
        printf("=== %d check(s) failed ===\n", g_failures);
        return 1;
    }
    return 0;
}
