// RawrXD Deep2 Qwen4Exp reverse-engineering contract extractor.
//
// This is a read-only native auditor.  It consumes the manifest JSON emitted by
// deep2_shard_probe, reconstructs the operator/tensor geometry from real
// descriptors, and writes a contract for the Vulkan lowering work.  It never
// invents tensor names, offsets, or executable capabilities.

#include <algorithm>
#include <cstdint>
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
}

int main(int argc, char** argv) {
    std::vector<std::string> manifests;
    std::string out = "qwen4exp_operator_contract.md";
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--manifest" && i + 1 < argc) manifests.emplace_back(argv[++i]);
        else if (a == "--out" && i + 1 < argc) out = argv[++i];
        else { std::cerr << "usage: deep2_reverse_engineer --manifest FILE [--manifest FILE] --out REPORT\n"; return 2; }
    }
    if (manifests.empty()) { std::cerr << "at least one --manifest is required\n"; return 2; }
    try {
        std::vector<Tensor> tensors;
        for (const auto& m : manifests) { auto part = ReadManifest(m); tensors.insert(tensors.end(), part.begin(), part.end()); }
        std::map<std::string, size_t> counts;
        for (const auto& t : tensors) ++counts[Op(t.name)];
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
        report << "| Operator | Tensor count | Contract geometry | Native executable |\n|---|---:|---|---|\n";
        report << "| QSA | " << counts["QSA"] << " | indexer tensors, top-k compressed-key attention | NO |\n";
        report << "| GDN | " << counts["GDN"] << " | selective gated delta state; ssm_a=" << Shape(gdn_a) << " | NO |\n";
        report << "| PLE | " << counts["PLE"] << " | causal conv=" << Shape(ple_conv) << " | NO |\n";
        report << "| HYPERCONNECTION | " << counts["HYPERCONNECTION"] << " | down=" << Shape(hc_down) << ", inject=" << Shape(hc_inject) << ", up=" << Shape(hc_up) << " | NO |\n";
        report << "| SPARSE_MOE | " << counts["SPARSE_MOE"] << " | gate=" << Shape(moe_gate) << ", 512 experts | NO |\n\n";
        report << "Geometry checks: " << (geometry_ok ? "PASS" : "FAIL") << "\n";
        report << "Certification: NOT_CERTIFIED (native Vulkan lowering and parity are still required)\n";
        std::cout << "QWEN4EXP_REVERSE_ENGINEERED=1\nTENSORS=" << tensors.size()
                  << " GEOMETRY=" << (geometry_ok ? "PASS" : "FAIL") << "\nREPORT=" << out << "\n";
        return geometry_ok ? 0 : 3;
    } catch (const std::exception& e) { std::cerr << "REVERSE_ENGINEERING_FAIL: " << e.what() << "\n"; return 1; }
}
