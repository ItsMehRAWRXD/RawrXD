// deep2_runtime_ir.cpp - bind the runtime IR bridge to a real validated GGUF.
// RAWRXD_DEEP2_RUNTIME_IR_BINDING_001
//
// Reads a model through RawrXDGgufReader, converts every validated tensor
// descriptor into a bridge Tensor, derives each block's kind from the tensors
// actually present (never from a model-name lookup), and builds the execution
// graph with deep2bridge::build. kernelReady comes from the canonical
// QuantTypeTable, so an unsupported dtype fails closed.
#include "RawrXDGgufReader.hpp"
#include "QuantTypeTable.hpp"
#include "RuntimeIRBridge.hpp"

#include <algorithm>
#include <cstdio>
#include <map>
#include <set>
#include <string>
#include <vector>

using namespace rawrxd;

namespace {

bool Has(const std::set<std::string>& s, const char* sub) {
    for (const std::string& k : s)
        if (k.find(sub) != std::string::npos) return true;
    return false;
}

bool Has(const std::vector<std::string>& v, const char* sub) {
    for (const std::string& k : v)
        if (k.find(sub) != std::string::npos) return true;
    return false;
}

} // namespace

int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    if (argc < 2) {
        printf("usage: deep2_runtime_ir <model.gguf> [--dump]\n");
        return 2;
    }
    const bool dump = argc > 2 && std::string(argv[2]) == "--dump";

    // ---- open through the universal reader ----
    GgufReader r;
    if (!r.Open(argv[1])) {
        printf("OPEN_FAIL %s : %s\n", argv[1], r.why().c_str());
        return 1;
    }
    printf("FILE     %s\n", argv[1]);
    printf("ARCH     %s\n", r.architecture().c_str());
    printf("TENSORS  %llu\n", (unsigned long long)r.tensorCount());

    // Which kernels this build actually has. MLA and dense FFN are implemented
    // in ModelGenieExecutor today; MoE and SSM are not, and must fail closed
    // rather than silently produce a plan that cannot run.
    const bool has_mla = true;    // MlaDecompressFwd + MLA attention exist
    const bool has_moe = false;   // routed MoE dispatch not implemented yet
    const bool has_ssm = false;   // SSM scan not implemented in the executor

    // ---- convert the validated directory into bridge descriptors ----
    std::vector<deep2bridge::Tensor> dir;
    dir.reserve(r.tensorCount());
    int unsupported = 0, noKernel = 0;
    for (const auto& kv : r.tensors()) {
        const GgufTensor& t = kv.second;
        deep2bridge::Tensor bt;
        bt.name = t.name;
        bt.dtype = static_cast<uint32_t>(t.type);
        for (int64_t d : t.dims) bt.dims.push_back(static_cast<uint64_t>(d));
        bt.offset = t.abs_offset;
        bt.bytes = t.nbytes;

        const Deep2::QuantTypeDescriptor* q = Deep2::LookupQuantType(t.type);
        if (!q) { ++unsupported; bt.kernel_ready = false; }
        else {
            bt.kernel_ready = q->kernelReady;
            if (!q->kernelReady) ++noKernel;
        }
        dir.push_back(bt);
    }
    printf("UNSUPPORTED_DTYPE %d   KNOWN_BUT_NO_KERNEL %d\n", unsupported, noKernel);

    // ---- derive block kinds from the tensors actually present ----
    std::vector<int> blocks;
    r.blockIndices(blocks);
    if (blocks.empty()) { printf("NO_BLOCKS\n"); return 1; }

    std::vector<deep2bridge::Block> bblocks;
    int nDense = 0, nMoe = 0, nSsm = 0;
    for (int b : blocks) {
        std::vector<const GgufTensor*> ts;
        r.layerTensors(b, ts, "");
        std::set<std::string> suffixes;
        for (const GgufTensor* t : ts) {
            size_t st = t->name.find('.', t->name.find("blk.") + 4);
            suffixes.insert(st == std::string::npos ? "" : t->name.substr(st + 1));
        }
        deep2bridge::Block bb;
        bb.layer = static_cast<uint32_t>(b);
        // Tensor role detection from names only. MLA is detected by the
        // deepseek2 attention tensors; MoE by expert and router tensors; SSM by
        // ssm_ tensors. A block may combine them.
        const bool mla = Has(suffixes, "attn_q") ||
                         Has(suffixes, "attn_kv_a_mqa") ||
                         Has(suffixes, "attn_kv_b") ||
                         Has(suffixes, "attn_output");
        const bool ssm = Has(suffixes, "ssm_");
        const bool moe = Has(suffixes, "_exps") ||
                         Has(suffixes, "exp_probs");
        const bool dense = Has(suffixes, "ffn_down") || Has(suffixes, "ffn_gate") ||
                           Has(suffixes, "ffn_up");

        if (ssm && moe)      bb.kind = deep2bridge::BlockKind::SSMMoE;
        else if (ssm)        bb.kind = deep2bridge::BlockKind::SSM;
        else if (moe && mla) bb.kind = deep2bridge::BlockKind::MoEMLA;
        else if (moe)        bb.kind = deep2bridge::BlockKind::MoEAttention;
        else if (mla)        bb.kind = deep2bridge::BlockKind::DenseMLA;
        else                 bb.kind = deep2bridge::BlockKind::DenseAttention;

        if (moe) ++nMoe; else if (dense) ++nDense;
        if (ssm) ++nSsm;

        for (const GgufTensor* t : ts) bb.tensor_names.push_back(t->name);
        bblocks.push_back(bb);
    }
    printf("BLOCKS   %zu (dense_ffn=%d moe=%d ssm=%d)\n",
           bblocks.size(), nDense, nMoe, nSsm);

    // ---- build the execution graph ----
    deep2bridge::Plan plan;
    try {
        plan = deep2bridge::build(dir, bblocks, r.fileSize(), has_mla, has_moe, has_ssm);
    } catch (const std::exception& e) {
        printf("BUILD_FAIL %s\n", e.what());
        return 1;
    }

    printf("NODES    %zu\n", plan.nodes.size());
    printf("FINAL_HANDLE %u\n", plan.final_handle);

    // node census by op
    {
        std::map<deep2bridge::Op, int> census;
        for (const auto& n : plan.nodes) census[n.op]++;
        printf("OP_CENSUS");
        const char* names[] = {"Input","Norm","MLA","Attention","DenseFFN","Router","TopK",
                               "Experts","SharedExperts","Combine","SSMScan","Residual","Output"};
        for (int i = 0; i < 13; ++i)
            if (census.count(static_cast<deep2bridge::Op>(i)))
                printf(" %s=%d", names[i], census[static_cast<deep2bridge::Op>(i)]);
        printf("\n");
    }

    printf("VERDICT=RUNTIME_IR_BUILT\n");

    if (dump) {
        printf("\n--- first block nodes ---\n");
        const char* names[] = {"Input","Norm","MLA","Attention","DenseFFN","Router","TopK",
                               "Experts","SharedExperts","Combine","SSMScan","Residual","Output"};
        for (size_t i = 0; i < plan.nodes.size(); ++i) {
            const deep2bridge::Node& n = plan.nodes[i];
            if (n.layer > 1 && n.op != deep2bridge::Op::Output) continue;
            printf("  node %3zu  %-14s layer %2u  out=%u inputs=[%u] tensors=%zu\n",
                   i, names[static_cast<int>(n.op)], n.layer, n.output,
                   n.inputs.empty() ? 0u : n.inputs[0], n.tensor_handles.size());
        }
    }
    return 0;
}
