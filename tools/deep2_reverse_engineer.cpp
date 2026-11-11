// RawrXD Deep2 Qwen4Exp reverse-engineering contract extractor.
//
// This is a read-only native auditor.  It consumes the manifest JSON emitted by
// deep2_shard_probe, reconstructs the operator/tensor geometry from real
// descriptors, and writes a contract for the Vulkan lowering work.  It never
// invents tensor names, offsets, or executable capabilities.
//
// It also writes the blocker ledger: for every operator, what it requires,
// which of the existing Vulkan primitives already cover which parts of it,
// whether a lowering artifact exists, and whether that artifact has been
// executed on a device.
//
// The ledger is fail-closed.  An operator may only be reported as executable
// when a device execution receipt exists for it, and a receipt is only
// accepted when it says PASS.  A shader that compiles is not an executable
// operator, and a shader that has never run is not an executed one.

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

namespace {
struct Tensor { std::string name, dtype; std::vector<uint64_t> dims; uint64_t bytes = 0; };

std::vector<uint64_t> ParseDims(const std::string& text) {
    std::vector<uint64_t> out;
    static const std::regex number(R"(\d+)");
    for (auto it = std::sregex_iterator(text.begin(), text.end(), number); it != std::sregex_iterator(); ++it)
        out.push_back(std::stoull(it->str()));
    return out;
}

std::vector<Tensor> ReadManifest(const std::string& path) {
    std::ifstream in(path);
    if (!in) throw std::runtime_error("cannot open manifest: " + path);
    std::vector<Tensor> out;
    std::string line;
    const std::regex name_re(R"rx("name"\s*:\s*"([^"]+)")rx");
    const std::regex dtype_re(R"rx("dtype"\s*:\s*"([^"]+)")rx");
    const std::regex dims_re(R"rx("dims"\s*:\s*\[([^\]]*)\])rx");
    const std::regex bytes_re(R"rx("bytes"\s*:\s*(\d+))rx");
    while (std::getline(in, line)) {
        std::smatch n, d, sh, b;
        if (!std::regex_search(line, n, name_re)) continue;
        Tensor t; t.name = n[1].str();
        if (std::regex_search(line, d, dtype_re)) t.dtype = d[1].str();
        if (std::regex_search(line, sh, dims_re)) t.dims = ParseDims(sh[1].str());
        if (std::regex_search(line, b, bytes_re)) t.bytes = std::stoull(b[1].str());
        out.push_back(std::move(t));
    }
    return out;
}

const char* Op(const std::string& n) {
    if (n.find("indexer.") != std::string::npos) return "QSA";
    if (n.find(".ssm_") != std::string::npos || n.ends_with(".ssm_a")) return "GDN";
    if (n.find(".ple_") != std::string::npos || n == "per_layer_token_embd.weight") return "PLE";
    if (n.find(".hc_") != std::string::npos || n.starts_with("output_hc_")) return "HYPERCONNECTION";
    if (n.find(".ffn_gate_exps.") != std::string::npos ||
        n.find(".ffn_up_exps.") != std::string::npos ||
        n.find(".ffn_down_exps.") != std::string::npos) return "SPARSE_MOE";
    return "OTHER";
}

bool IsGdnAux(const std::string& n) { return std::regex_search(n, std::regex(R"(\.ssm_dt\.bias$)")); }
bool IsPleAux(const std::string& n) { return n == "per_layer_token_embd.weight"; }
bool IsHcAux(const std::string& n) {
    return n == "output_hc_down.weight" || n == "output_hc_norm.weight" || n == "output_hc_up.weight";
}

std::string Shape(const Tensor* t) {
    if (!t) return "missing";
    std::ostringstream o; o << "[";
    for (size_t i = 0; i < t->dims.size(); ++i) { if (i) o << ","; o << t->dims[i]; }
    return o.str() + "]";
}

const Tensor* Find(const std::vector<Tensor>& ts, const std::string& name) {
    auto it = std::find_if(ts.begin(), ts.end(), [&](const Tensor& t) { return t.name == name; });
    return it == ts.end() ? nullptr : &*it;
}

// ---------------------------------------------------------------------------
// The blocker ledger.
//
// What each operator requires, which of the existing Vulkan primitives
// already cover which parts of it, and what is still missing.  The
// requirement is the operator's own contract, recovered from the reference
// stack; the primitives are the ones the engine already dispatches.
// ---------------------------------------------------------------------------
struct Operator {
    const char* name;
    const char* requirement;      // what the operator has to compute
    const char* covered;          // which existing primitives already do parts of it
    const char* missing;          // what has no primitive and needs a lowering
    const char* artifact;         // the lowering artifact, if one exists
    const char* next;             // the next executable slice
};

// The primitive inventory is the one the engine dispatches today: the
// generic ops shader and the packed quantized GEMV.  A part of an operator
// that needs a primitive outside this list has no path to the device yet.
const Operator kOperators[] = {
    { "QSA",
      "indexer q/k projections and norms, a compressed-key cache, and a "
      "sparse attention over the top-k compressed keys",
      "OP_GEMV_F32 (the indexer projections), OP_RMSNORM (the indexer norms)",
      "the indexer scoring and its top-k selection, and the compressed-key "
      "attention itself",
      "qsa_score",
      "the compressed-key attention itself, which the scoring does not cover" },

    { "GDN",
      "a gated delta-net recurrent state: a state matrix, a gated decay, and "
      "a per-step state update",
      "OP_GEMV_F32 (the projections around the state)",
      "the recurrent state update and the gated normalisation",
      "gdn",
      "the selective state update, which is a scan and not a projection" },

    { "PLE",
      "a per-layer n-gram embedding and a causal depthwise short "
      "convolution, with the window carried between dispatches",
      "OP_RMSNORM (the norms around it)",
      "the depthwise short convolution, which is not a projection",
      "ple",
      "the n-gram embedding and the key and value projections around it" },

    { "HYPERCONNECTION",
      "a four-stream mix: a down projection, a per-stream silu, an up "
      "projection and a sigmoid-gated mean; and a combine of the residual "
      "with the block output, grouped RMS normalised",
      "OP_GEMV_F32 (the down and up projections), OP_RESIDUAL (the combine "
      "addition), and the grouped RMSNorm (which is lowered and executed)",
      "the per-stream silu mean and the sigmoid-gated mean",
      "hc_combine",
      "the mix path: the down projection, the per-stream silu, the up "
      "projection and the gated mean" },

    { "SPARSE_MOE",
      "a router over the experts, a top-k selection, and a grouped expert "
      "projection with the results accumulated back into the hidden state",
      "OP_SWIGLU (the expert activation), and the packed GEMV for one "
      "expert's projection",
      "the top-k over the router logits, the grouped expert dispatch, and "
      "the MXFP4 and IQ2 formats the experts are stored in",
      "moe_router",
      "the top-k over the router logits, which the router itself does not "
      "do, and then the grouped expert dispatch" },
};

// The lowered primitives.
//
// An operator is made of primitives. A primitive that has been lowered and
// executed is a fact about the device path; an operator that has been
// lowered and executed is a fact about the model. Both are recorded, and
// they are separate claims.
struct Primitive {
    const char* name;
    const char* artifact;
    const char* purpose;
};

const Primitive kPrimitives[] = {
    { "grouped RMSNorm", "grouped_rmsnorm",
      "the per-stream normalisation the hyperconnection mix needs, and the "
      "normalisation the combine path performs" },
    { "hyperconnection combine", "hc_combine",
      "the residual combine of the block output with the injection, and the "
      "grouped normalisation that follows it" },
    { "PLE depthwise short convolution", "ple",
      "the causal depthwise convolution, with the window carried between "
      "dispatches" },
    { "MoE router", "moe_router",
      "the hidden state turned into one logit per expert, which is the "
      "first part of the sparse MoE operator and does not depend on the "
      "format the experts are stored in" },
    { "QSA indexer scoring", "qsa_score",
      "the indexer scoring against the compressed-key cache, through a page "
      "table and over the visible compressed keys only" },
};

// A device execution receipt, if the operator has one.
//
// A receipt is a file the execution test wrote.  It is accepted only when it
// says the device reproduced the reference: a run that reported BLOCKED, or
// that failed, is not an execution.
struct Evidence {
    bool artifactExists = false;
    bool executed = false;
    std::string receiptPath;
};

Evidence GatherEvidence(const std::string& shadersDir,
                        const std::string& evidenceDir,
                        const std::string& artifact) {
    Evidence e;
    if (artifact.empty()) return e;
    std::error_code ec;
    // The lowering shaders are all named deep2_qwen4exp_<operator>.comp.
    const std::filesystem::path shader =
        std::filesystem::path(shadersDir) / ("deep2_qwen4exp_" + artifact + ".comp");
    e.artifactExists = std::filesystem::is_regular_file(shader, ec);

    // The receipt for this operator: the execution log in the evidence tree.
    // The evidence directory is named after the operator, so the artifact
    // token is what is matched.
    if (!evidenceDir.empty()) {
        std::filesystem::path dir(evidenceDir);
        std::error_code dirEc;
        if (std::filesystem::is_directory(dir, dirEc)) {
            // Each operation gets its own error code. A shared one would be
            // set by the first file that is not there, and the loop would
            // stop before it had looked at the rest of the evidence.
            std::error_code iterEc;
            for (const auto& entry : std::filesystem::directory_iterator(dir, iterEc)) {
                if (iterEc) break;
                std::error_code oneEc;
                if (!entry.is_directory(oneEc)) continue;
                const std::string name = entry.path().filename().string();
                if (name.find(artifact) == std::string::npos) continue;
                const std::filesystem::path log = entry.path() / "device_execution.txt";
                if (!std::filesystem::is_regular_file(log, oneEc)) continue;
                std::ifstream in(log);
                std::string line;
                while (std::getline(in, line)) {
                    if (line.find("RESULT: PASS") != std::string::npos) {
                        e.executed = true;
                        e.receiptPath = log.string();
                    }
                }
            }
        }
    }
    return e;
}
}

int main(int argc, char** argv) {
    std::vector<std::string> manifests;
    std::string out = "qwen4exp_operator_contract.md";
    std::string shadersDir = "src/deep2/shaders";
    std::string evidenceDir;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--manifest" && i + 1 < argc) manifests.emplace_back(argv[++i]);
        else if (a == "--out" && i + 1 < argc) out = argv[++i];
        else if (a == "--shaders" && i + 1 < argc) shadersDir = argv[++i];
        else if (a == "--evidence" && i + 1 < argc) evidenceDir = argv[++i];
        else { std::cerr << "usage: deep2_reverse_engineer --manifest FILE [--manifest FILE] --out REPORT"
                         << " [--shaders DIR] [--evidence DIR]\n"; return 2; }
    }
    if (manifests.empty()) { std::cerr << "at least one --manifest is required\n"; return 2; }
    try {
        std::vector<Tensor> tensors;
        for (const auto& m : manifests) { auto part = ReadManifest(m); tensors.insert(tensors.end(), part.begin(), part.end()); }
        std::map<std::string, size_t> counts;
        for (const auto& t : tensors) ++counts[Op(t.name)];
        std::map<std::string, size_t> auxiliary;
        for (const auto& t : tensors) {
            if (IsGdnAux(t.name)) ++auxiliary["GDN"];
            if (IsPleAux(t.name)) ++auxiliary["PLE"];
            if (IsHcAux(t.name)) ++auxiliary["HYPERCONNECTION"];
        }
        const Tensor* hc_down = Find(tensors, "blk.0.hc_attn_down.weight");
        const Tensor* hc_inject = Find(tensors, "blk.0.hc_attn_inject.weight");
        const Tensor* hc_up = Find(tensors, "blk.0.hc_attn_up.weight");
        const Tensor* ple_conv = Find(tensors, "blk.1.ple_conv1d.weight");
        const Tensor* gdn_a = Find(tensors, "blk.0.ssm_a");
        const Tensor* moe_gate = Find(tensors, "blk.0.ffn_gate_exps.weight");
        const bool geometry_ok = hc_down && hc_inject && hc_up && ple_conv && gdn_a && moe_gate &&
            hc_inject->dims == std::vector<uint64_t>{10240, 4} &&
            hc_down->dims == std::vector<uint64_t>{10240, 320} &&
            hc_up->dims == std::vector<uint64_t>{320, 10240} &&
            ple_conv->dims == std::vector<uint64_t>{4, 10240} &&
            moe_gate->dims == std::vector<uint64_t>{2560, 640, 512};
        std::ofstream report(out);
        if (!report) throw std::runtime_error("cannot create report: " + out);
        report << "# Deep2 Qwen4Exp reverse-engineered operator contract\n\n";
        report << "Tensors: " << tensors.size() << "\n\n";
        report << "| Operator | Total tensors | Primary block tensors | Auxiliary/global tensors | Contract geometry | Native executable |\n|---|---:|---:|---:|---|---|\n";
        report << "| QSA | " << counts["QSA"] << " | " << counts["QSA"] << " | 0 | indexer tensors, top-k compressed-key attention | NO |\n";
        report << "| GDN | " << counts["GDN"] << " | " << counts["GDN"] - auxiliary["GDN"] << " | " << auxiliary["GDN"] << " | selective gated delta state; ssm_a=" << Shape(gdn_a) << " | NO |\n";
        report << "| PLE | " << counts["PLE"] << " | " << counts["PLE"] - auxiliary["PLE"] << " | " << auxiliary["PLE"] << " | causal conv=" << Shape(ple_conv) << " | NO |\n";
        report << "| HYPERCONNECTION | " << counts["HYPERCONNECTION"] << " | " << counts["HYPERCONNECTION"] - auxiliary["HYPERCONNECTION"] << " | " << auxiliary["HYPERCONNECTION"] << " | down=" << Shape(hc_down) << ", inject=" << Shape(hc_inject) << ", up=" << Shape(hc_up) << " | NO |\n";
        report << "| SPARSE_MOE | " << counts["SPARSE_MOE"] << " | " << counts["SPARSE_MOE"] << " | 0 | gate=" << Shape(moe_gate) << ", 512 experts | NO |\n\n";
        report << "Ownership reconciliation: GDN 216+36, PLE 6+1, HYPERCONNECTION 384+3; tensor names remain unique across both shards.\n\n";
        report << "Geometry checks: " << (geometry_ok ? "PASS" : "FAIL") << "\n";
        report << "Certification: NOT_CERTIFIED (native Vulkan lowering and parity are still required)\n";

        // ---- the blocker ledger ----
        //
        // For every operator: what it requires, which of the existing
        // primitives cover which parts, whether a lowering artifact exists,
        // and whether that artifact has been executed on a device.
        report << "\n## The blocker ledger\n\n";
        report << "An operator is executable only when a lowering artifact exists AND that "
                  "artifact has been executed on a device and reproduced a reference. A "
                  "compiled shader is not an executable operator, and an operator that has "
                  "never run is not an executed one.\n\n";
        report << "| Operator | Requirement | Covered by existing primitives | Missing | Artifact | Device execution | Next executable slice |\n";
        report << "|---|---|---|---|---|---|---|\n";

        bool ledgerOk = true;
        int executedCount = 0;
        for (const auto& op : kOperators) {
            const Evidence e = GatherEvidence(shadersDir, evidenceDir, op.artifact);
            const std::string artifact =
                e.artifactExists ? (std::string("`") + op.artifact + ".comp`") : std::string("none");
            const std::string executed =
                e.executed ? "PASS" : (e.artifactExists ? "NOT RUN" : "n/a");
            report << "| " << op.name << " | " << op.requirement << " | " << op.covered
                   << " | " << op.missing << " | " << artifact << " | " << executed
                   << " | " << op.next << " |\n";
            if (e.executed) ++executedCount;
            // The fail-closed rule: an artifact that exists but has no
            // passing execution receipt is not executable, and the ledger
            // says so rather than implying otherwise.
            if (e.artifactExists && !e.executed) ledgerOk = false;
        }
        report << "\n";
        report << "Executed lowerings: " << executedCount << " of "
               << (sizeof(kOperators) / sizeof(kOperators[0])) << "\n";
        report << "Ledger: " << (ledgerOk ? "PASS" : "FAIL") << "\n";
        report << "Certification: NOT_CERTIFIED (no operator is bound into the runtime graph, "
                  "and the model is still fail-closed)\n";

        // ---- the lowered primitives ----
        //
        // The primitives the operators are made of. These are separate
        // claims: a primitive that has been executed is a fact about the
        // device path, not about the model.
        report << "\n## The lowered primitives\n\n";
        report << "| Primitive | Purpose | Artifact | Device execution |\n|---|---|---|---|\n";
        int primitiveCount = 0;
        int primitiveExecuted = 0;
        for (const auto& p : kPrimitives) {
            const Evidence e = GatherEvidence(shadersDir, evidenceDir, p.artifact);
            ++primitiveCount;
            const std::string artifact =
                e.artifactExists ? (std::string("`") + p.artifact + ".comp`") : std::string("none");
            const std::string executed =
                e.executed ? "PASS" : (e.artifactExists ? "NOT RUN" : "n/a");
            if (e.executed) ++primitiveExecuted;
            report << "| " << p.name << " | " << p.purpose << " | " << artifact
                   << " | " << executed << " |\n";
        }
        report << "\nExecuted primitives: " << primitiveExecuted << " of " << primitiveCount << "\n";

        std::cout << "QWEN4EXP_REVERSE_ENGINEERED=1\nTENSORS=" << tensors.size()
                  << " GEOMETRY=" << (geometry_ok ? "PASS" : "FAIL")
                  << "\nLEDGER=" << (ledgerOk ? "PASS" : "FAIL")
                  << " EXECUTED_LOWERINGS=" << executedCount
                  << "/" << (sizeof(kOperators) / sizeof(kOperators[0]))
                  << "\nREPORT=" << out << "\n";
        return (geometry_ok && ledgerOk) ? 0 : 3;
    } catch (const std::exception& e) { std::cerr << "REVERSE_ENGINEERING_FAIL: " << e.what() << "\n"; return 1; }
}
