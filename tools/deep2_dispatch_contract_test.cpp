// The per-layer dispatch contract.
//
// The Qwen3.5 prefill failure was a block that the engine lowered to the
// wrong operation. The failure did not appear at the block: it appeared
// several operations later, as a width mismatch at a norm, and the message
// named a norm rather than the mixer that was wrong.
//
// This is the check that would have caught it at the block. It runs the
// engine's own graph builder over a model and compares what it bound, for
// every layer, against what the layer's own tensors say the layer is.
//
// The two are independent witnesses. The graph says what the engine decided
// to do. The shapes say what the file is. When they disagree, the engine
// will execute a layer as something it is not, and the only question is
// where the failure surfaces.
//
// It is a static check. It reads the header, the key-value directory and
// the tensor directory, and it runs no inference and touches no device.
#include "modelgenie/universal_gguf.hpp"

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace {

// ---- the shape reader ------------------------------------------------------
//
// A second, independent reader of the tensor directory. It is deliberately
// not the engine's: the point is to have a witness that does not share a
// code path with the thing being checked.

struct Tensor {
    std::string name;
    std::vector<uint64_t> dims;
    uint64_t in() const { return dims.size() >= 1 ? dims[0] : 0; }
    uint64_t out() const { return dims.size() >= 2 ? dims[1] : (dims.empty() ? 0 : dims[0]); }
};

bool readExact(std::ifstream& f, void* dst, size_t bytes) {
    return static_cast<bool>(f.read(reinterpret_cast<char*>(dst), static_cast<std::streamsize>(bytes)));
}

bool readU32(std::ifstream& f, uint32_t& v) { return readExact(f, &v, sizeof(v)); }
bool readU64(std::ifstream& f, uint64_t& v) { return readExact(f, &v, sizeof(v)); }

bool readString(std::ifstream& f, std::string& out) {
    uint64_t len = 0;
    if (!readU64(f, len)) return false;
    if (len > (1u << 24)) return false;
    out.assign(static_cast<size_t>(len), '\0');
    if (len) return readExact(f, out.data(), len);
    return true;
}

bool skipValue(std::ifstream& f, uint32_t type);

bool skipArray(std::ifstream& f) {
    uint32_t sub = 0;
    uint64_t count = 0;
    if (!readU32(f, sub) || !readU64(f, count)) return false;
    for (uint64_t i = 0; i < count; ++i) {
        if (!skipValue(f, sub)) return false;
    }
    return true;
}

bool skipValue(std::ifstream& f, uint32_t type) {
    switch (type) {
        case 0: case 1: case 7: { uint8_t v = 0; return readExact(f, &v, 1); }
        case 2: case 3: { uint16_t v = 0; return readExact(f, &v, 2); }
        case 4: case 5: { uint32_t v = 0; return readExact(f, &v, 4); }
        case 6: { float v = 0; return readExact(f, &v, 4); }
        case 8: { std::string s; return readString(f, s); }
        case 9: return skipArray(f);
        case 10: case 11: { uint64_t v = 0; return readExact(f, &v, 8); }
        case 12: { double v = 0; return readExact(f, &v, 8); }
        default: return false;
    }
}

bool readTensorDirectory(const std::string& path, std::map<std::string, Tensor>& out) {
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) return false;
    uint32_t magic = 0, version = 0;
    if (!readU32(f, magic) || magic != 0x46554747u) return false;
    if (!readU32(f, version)) return false;
    uint64_t tensorCount = 0, kvCount = 0;
    if (!readU64(f, tensorCount) || !readU64(f, kvCount)) return false;
    for (uint64_t i = 0; i < kvCount; ++i) {
        std::string key;
        if (!readString(f, key)) return false;
        uint32_t type = 0;
        if (!readU32(f, type)) return false;
        if (!skipValue(f, type)) return false;
    }
    for (uint64_t i = 0; i < tensorCount; ++i) {
        Tensor t;
        if (!readString(f, t.name)) return false;
        uint32_t nDims = 0;
        if (!readU32(f, nDims)) return false;
        if (nDims > 8) return false;
        t.dims.resize(nDims);
        for (uint32_t d = 0; d < nDims; ++d) if (!readU64(f, t.dims[d])) return false;
        uint32_t type = 0;
        uint64_t offset = 0;
        if (!readU32(f, type) || !readU64(f, offset)) return false;
        out.emplace(t.name, std::move(t));
    }
    return true;
}

std::string BlockOf(const std::string& name) {
    if (name.rfind("blk.", 0) != 0) return {};
    const size_t dot = name.find('.', 4);
    if (dot == std::string::npos) return {};
    return name.substr(0, dot);
}

std::string PartOf(const std::string& name) {
    if (name.rfind("blk.", 0) != 0) return name;
    const size_t dot = name.find('.', 4);
    if (dot == std::string::npos) return name;
    return name.substr(dot + 1);
}

// The kind of layer the shapes say a block is.
enum class Expected { Unknown, FullAttention, GatedDelta, LatentAttention, SharedExpert };

Expected ExpectedKind(const std::set<std::string>& parts) {
    const bool gate = parts.count("attn_gate.weight") > 0;
    const bool fused = parts.count("attn_qkv.weight") > 0;
    const bool recurrent = parts.count("ssm_a") > 0 || parts.count("ssm_d") > 0 ||
                          parts.count("ssm_alpha.weight") > 0 ||
                          parts.count("ssm_beta.weight") > 0 ||
                          parts.count("ssm_out.weight") > 0;
    const bool latent = parts.count("attn_q_a.weight") > 0 ||
                        parts.count("attn_kv_a_mqa.weight") > 0;
    const bool separate = parts.count("attn_q.weight") > 0;
    if (latent) return Expected::LatentAttention;
    if (fused && gate && recurrent) return Expected::GatedDelta;
    if (separate) return Expected::FullAttention;
    if (parts.count("attn_norm.weight") > 0 && parts.count("ffn_up.weight") > 0) {
        return Expected::SharedExpert;
    }
    return Expected::Unknown;
}

const char* ExpectedName(Expected e) {
    switch (e) {
        case Expected::FullAttention: return "full attention";
        case Expected::GatedDelta: return "gated delta";
        case Expected::LatentAttention: return "latent attention";
        case Expected::SharedExpert: return "shared expert";
        case Expected::Unknown: return "unknown";
    }
    return "?";
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::printf("usage: deep2_dispatch_contract_test <model.gguf>\n");
        return 2;
    }
    const std::string path = argv[1];

    // What the file says.
    std::map<std::string, Tensor> tensors;
    if (!readTensorDirectory(path, tensors)) {
        std::printf("COULD NOT READ THE TENSOR DIRECTORY: %s\n", path.c_str());
        return 2;
    }
    std::map<std::string, std::set<std::string>> blockParts;
    for (const auto& [name, t] : tensors) {
        const std::string block = BlockOf(name);
        if (block.empty()) continue;
        blockParts[block].insert(PartOf(name));
    }
    std::map<std::string, Expected> expected;
    for (const auto& [block, parts] : blockParts) expected[block] = ExpectedKind(parts);

    // What the engine decided.
    const RawrXD::Deep2::Universal::IngestReport& report = RawrXD::Deep2::Universal::Ingest(path, false);
    if (!report.ok) {
        std::printf("THE ENGINE DID NOT INGEST THE MODEL: %s\n", report.error.c_str());
        return 2;
    }

    // What the engine bound, per block.
    struct Bound {
        uint32_t gdn = 0;
        uint32_t attention = 0;
        uint32_t ssmScan = 0;
        uint32_t mla = 0;
        uint32_t unsupported = 0;
        std::vector<std::string> unsupportedReasons;
    };
    std::map<std::string, Bound> bound;
    for (const auto& op : report.graph.ops) {
        if (op.block < 0) continue;
        const std::string block = "blk." + std::to_string(op.block);
        Bound& b = bound[block];
        switch (op.op) {
            case RawrXD::Deep2::Universal::Op::Gdn: ++b.gdn; break;
            case RawrXD::Deep2::Universal::Op::Attention: ++b.attention; break;
            case RawrXD::Deep2::Universal::Op::SsmScan: ++b.ssmScan; break;
            case RawrXD::Deep2::Universal::Op::MlaDecompress: ++b.mla; break;
            case RawrXD::Deep2::Universal::Op::Unsupported:
                ++b.unsupported;
                b.unsupportedReasons.push_back(op.detail);
                break;
            default: break;
        }
    }

    std::printf("=== %s ===\n", path.c_str());
    std::printf("  architecture : %s\n", report.spec.architecture.c_str());
    std::printf("  layers       : %zu\n", blockParts.size());
    std::printf("  graph ops    : %zu (%zu unsupported)\n",
                report.graph.ops.size(), report.graph.unsupported);

    // The contract.
    //
    // A layer is bound to the mixer its shapes say it is, and to exactly
    // one mixer. Two mixers on one layer is the failure that produced the
    // width mismatch, because the second one is executed on the output of
    // the first.
    uint64_t failures = 0;
    uint64_t checked = 0;
    for (const auto& [block, exp] : expected) {
        if (exp == Expected::Unknown) continue;
        auto it = bound.find(block);
        if (it == bound.end()) {
            std::printf("  [FAIL] %s: the shapes say %s and the graph bound no mixer at all\n",
                        block.c_str(), ExpectedName(exp));
            ++failures;
            continue;
        }
        const Bound& b = it->second;
        const uint32_t mixers = b.gdn + b.attention + b.ssmScan + b.mla;
        ++checked;

        uint32_t got = 0;
        const char* gotName = "";
        if (b.gdn) { got = b.gdn; gotName = "gated delta"; }
        else if (b.attention) { got = b.attention; gotName = "attention"; }
        else if (b.ssmScan) { got = b.ssmScan; gotName = "recurrent scan"; }
        else if (b.mla) { got = b.mla; gotName = "latent attention"; }

        const bool rightKind =
            (exp == Expected::GatedDelta && b.gdn == 1 && b.attention == 0 && b.ssmScan == 0) ||
            (exp == Expected::FullAttention && b.attention == 1 && b.gdn == 0 && b.ssmScan == 0) ||
            (exp == Expected::LatentAttention && b.mla >= 1 && b.gdn == 0 && b.attention == 0) ||
            (exp == Expected::SharedExpert && mixers == 0);

        if (!rightKind || mixers > 1) {
            std::printf("  [FAIL] %s: the shapes say %s, the graph bound %u mixer(s) (%s)\n",
                        block.c_str(), ExpectedName(exp), mixers, gotName);
            ++failures;
        }
    }

    std::printf("\n  %llu layer(s) checked, %llu contract failure(s)\n",
                static_cast<unsigned long long>(checked),
                static_cast<unsigned long long>(failures));
    if (failures == 0) {
        std::printf("  every layer is bound to the mixer its shapes say it is, and to exactly one\n");
    }
    return failures ? 3 : 0;
}
