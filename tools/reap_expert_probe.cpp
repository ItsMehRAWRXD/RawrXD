// ============================================================================
// reap_expert_probe.cpp — P2-C expert FFN execution probe.
//
// Reproduces one MoE expert's FFN using the SAME arithmetic the engine uses
// (QuantKernelRegistry GEMV kernels + Deep2_SwiGLU), once from the mapped
// tensor and once from block-aligned file-streamed expert slices, and compares
// the two bitwise.
//
// Tensor semantics are taken from Deep2Engine::computeExpertFFN:
//   gate = gemv(gateW, input, rows=expertDim, cols=hidden)
//   up   = gemv(upW,   input, rows=expertDim, cols=hidden)
//   SwiGLU(gate, up, gate, expertDim)          // in-place, silu(gate)*up
//   out  = gemv(downW, gate,  rows=hidden,    cols=expertDim)
// Buffers are zeroed first because the kernels accumulate.
// ============================================================================
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cmath>
#include <algorithm>
#include <string>
#include <vector>

#include "deep2/GGUFLoader.hpp"
#include "deep2/QuantKernelRegistry.hpp"
#include "ggml.h"

extern "C" void Deep2_SwiGLU(const float* x, const float* y, float* out, size_t n);

namespace {
constexpr uint64_t BK4_0 = 18;

struct TensorView {
    const Deep2::GGUFTensor* t = nullptr;
    uint64_t rows = 0, cols = 0, experts = 0;
    uint64_t blocksPerRow = 0, blocksPerExpert = 0, bytesPerExpert = 0;
};

bool describe(const Deep2::GGUFLoader& ld, const std::string& name, uint32_t expectExperts,
              TensorView& out, std::string& err) {
    const Deep2::GGUFTensor* t = ld.getTensor(name);
    if (!t || !t->data) { err = "missing tensor " + name; return false; }
    if (static_cast<int>(t->type) != 2) { err = name + " is not Q4_0"; return false; }
    if (t->shape.size() != 3) { err = name + " not 3-D"; return false; }
    for (int i = 0; i < 3; ++i) if (t->shape[i] <= 0) { err = name + " bad dim"; return false; }
    const uint64_t c = static_cast<uint64_t>(t->shape[0]);
    const uint64_t r = static_cast<uint64_t>(t->shape[1]);
    const uint64_t e = static_cast<uint64_t>(t->shape[2]);
    if (e != expectExperts) { err = name + " expert count mismatch"; return false; }
    if (c % 32 != 0) { err = name + " cols not block aligned"; return false; }
    const uint64_t bpr = c / 32;
    const uint64_t bpe = r * bpr;
    if (bpe * 18 * e != t->sizeBytes) { err = name + " byte math mismatch"; return false; }
    out.t = t; out.rows = r; out.cols = c; out.experts = e;
    out.blocksPerRow = bpr; out.blocksPerExpert = bpe; out.bytesPerExpert = bpe * 18;
    return true;
}

bool readSlice(FILE* f, const TensorView& v, uint32_t expert, uint32_t tileBlocks,
               std::vector<unsigned char>& dst, uint64_t& tiles, uint64_t& bytes) {
    const uint64_t startByte = v.t->fileOffset + static_cast<uint64_t>(expert) * v.bytesPerExpert;
    const uint64_t totalBlocks = v.blocksPerExpert;
    dst.resize(static_cast<size_t>(v.bytesPerExpert));
    uint64_t written = 0;
    for (uint64_t b0 = 0; b0 < totalBlocks; b0 += tileBlocks) {
        const uint64_t nb = std::min<uint64_t>(tileBlocks, totalBlocks - b0);
        const uint64_t inBytes = nb * BK4_0;
        if (_fseeki64(f, static_cast<__int64>(startByte + b0 * BK4_0), SEEK_SET) != 0) return false;
        if (std::fread(dst.data() + written, 1, static_cast<size_t>(inBytes), f) != inBytes)
            return false;
        written += inBytes;
        ++tiles;
        bytes += inBytes;
    }
    return written == v.bytesPerExpert;
}

struct Routing {
    uint32_t layer = 0, hidden = 0, count = 0;
    uint64_t step = 0;
    std::vector<uint32_t> ids;
    std::vector<float> weights;
    std::vector<float> input;
};

bool loadRouting(const char* path, Routing& r) {
    FILE* f = std::fopen(path, "rb");
    if (!f) return false;
    uint32_t layer = 0, hidden = 0, count = 0;
    uint64_t step = 0;
    if (std::fread(&layer, 4, 1, f) != 1 || std::fread(&step, 8, 1, f) != 1 ||
        std::fread(&hidden, 4, 1, f) != 1 || std::fread(&count, 4, 1, f) != 1) {
        std::fclose(f); return false;
    }
    r.layer = layer; r.step = step; r.hidden = hidden; r.count = count;
    r.ids.resize(count); r.weights.resize(count); r.input.resize(hidden);
    if (count && (std::fread(r.ids.data(), 4, count, f) != count ||
                  std::fread(r.weights.data(), 4, count, f) != count)) {
        std::fclose(f); return false;
    }
    if (std::fread(r.input.data(), 4, hidden, f) != hidden) { std::fclose(f); return false; }
    std::fclose(f);
    return true;
}
// 2-D tensors (shared expert: gate/up [2048,2816], down [2816,2048]).
bool describe2D(const Deep2::GGUFLoader& ld, const std::string& name,
                TensorView& out, std::string& err) {
    const Deep2::GGUFTensor* t = ld.getTensor(name);
    if (!t || !t->data) { err = "missing " + name; return false; }
    if (static_cast<int>(t->type) != 2) { err = name + " is not Q4_0"; return false; }
    if (t->shape.size() != 2) { err = name + " not 2-D"; return false; }
    if (t->shape[0] <= 0 || t->shape[1] <= 0) { err = name + " bad dim"; return false; }
    const uint64_t c = static_cast<uint64_t>(t->shape[0]);
    const uint64_t r = static_cast<uint64_t>(t->shape[1]);
    if (c % 32 != 0) { err = name + " cols not block aligned"; return false; }
    const uint64_t bpr = c / 32;
    const uint64_t bpe = r * bpr;
    if (bpe * 18 != t->sizeBytes) { err = name + " byte math mismatch"; return false; }
    out.t = t; out.rows = r; out.cols = c; out.experts = 1;
    out.blocksPerRow = bpr; out.blocksPerExpert = bpe; out.bytesPerExpert = bpe * 18;
    return true;
}

struct EngineRec {
    uint32_t layer = 0, kind = 0, expert = 0, count = 0;
    uint64_t step = 0;
    float weight = 0.0f;
    std::vector<float> out;
};

// Reads records written by reap-calibrate --dump-expert-outs:
//   [u32 layer][u64 step][u32 kind][u32 expert][f32 weight][u32 count][f32 x count]
bool loadEngineOuts(const char* path, std::vector<EngineRec>& recs) {
    FILE* f = std::fopen(path, "rb");
    if (!f) return false;
    for (;;) {
        EngineRec r{};
        if (std::fread(&r.layer, 4, 1, f) != 1) break;
        if (std::fread(&r.step, 8, 1, f) != 1) break;
        if (std::fread(&r.kind, 4, 1, f) != 1) break;
        if (std::fread(&r.expert, 4, 1, f) != 1) break;
        if (std::fread(&r.weight, 4, 1, f) != 1) break;
        if (std::fread(&r.count, 4, 1, f) != 1) break;
        r.out.resize(r.count);
        if (r.count && std::fread(r.out.data(), 4, r.count, f) != r.count) break;
        recs.push_back(std::move(r));
    }
    std::fclose(f);
    return !recs.empty();
}
} // namespace

int main(int argc, char** argv) {
    std::string model, routingPath, which = "all", engineOutsPath, boundaryPath;
    bool sharedMode = false, zeroShared = false;
    int expert = 0, tileBlocks = 64;
    uint64_t scratchCap = 0;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--model" && i + 1 < argc) model = argv[++i];
        else if (a == "--routing" && i + 1 < argc) routingPath = argv[++i];
        else if (a == "--expert" && i + 1 < argc) { expert = std::atoi(argv[++i]); which = "one"; }
        else if (a == "--all") which = "all";
        else if (a == "--engine-outs" && i + 1 < argc) engineOutsPath = argv[++i];
        else if (a == "--boundary" && i + 1 < argc) boundaryPath = argv[++i];
        else if (a == "--shared") sharedMode = true;
        else if (a == "--zero-shared") zeroShared = true;
        else if (a == "--tile-blocks" && i + 1 < argc) tileBlocks = std::atoi(argv[++i]);
        else if (a == "--scratch-bytes" && i + 1 < argc)
            scratchCap = std::strtoull(argv[++i], nullptr, 10);
        else if (a == "--help" || a == "-h") {
            std::fprintf(stderr, "Usage: %s --model <gguf> --routing <bin> "
                                 "[--expert N | --all] [--tile-blocks N] [--scratch-bytes N]\n",
                         argv[0]);
            return 0;
        }
        else { std::fprintf(stderr, "Unknown argument: %s\n", a.c_str()); return 2; }
    }
    if (model.empty() || routingPath.empty()) { std::fprintf(stderr, "need --model and --routing\n"); return 2; }
    if (tileBlocks <= 0) tileBlocks = 64;

    Routing r{};
    if (!loadRouting(routingPath.c_str(), r)) {
        std::fprintf(stderr, "EXPERT_PROBE_FAIL routing payload unreadable\n");
        return 3;
    }
    std::printf("EXPERT_PROBE routing layer=%u step=%llu hidden=%u selected=%u\n",
                r.layer, (unsigned long long)r.step, r.hidden, r.count);

    std::vector<EngineRec> engineRecs;
    const EngineRec* engineShared = nullptr;
    if (!engineOutsPath.empty()) {
        if (!loadEngineOuts(engineOutsPath.c_str(), engineRecs)) {
            std::fprintf(stderr, "EXPERT_PROBE_FAIL engine-outs unreadable\n");
            return 3;
        }
        for (const auto& r : engineRecs) if (r.kind == 0) engineShared = &r;
        std::printf("EXPERT_PROBE_ENGINE records=%zu shared=%d\n",
                    engineRecs.size(), engineShared ? 1 : 0);
    }

    Deep2::GGUFLoader ld;
    if (!ld.load(model)) { std::fprintf(stderr, "EXPERT_PROBE_FAIL model load\n"); return 3; }

    char gName[128], uName[128], dName[128];
    std::snprintf(gName, sizeof(gName), "blk.%u.ffn_gate_exps.weight", r.layer);
    std::snprintf(uName, sizeof(uName), "blk.%u.ffn_up_exps.weight",   r.layer);
    std::snprintf(dName, sizeof(dName), "blk.%u.ffn_down_exps.weight", r.layer);

    TensorView g{}, u{}, d{};
    std::string err;
    // The expert count comes from the tensor itself (r.count is the number of
    // selected experts, not the expert dimension).
    {
        const Deep2::GGUFTensor* gt = ld.getTensor(gName);
        if (!gt || gt->shape.size() != 3) { std::fprintf(stderr, "EXPERT_PROBE_FAIL gate layout\n"); return 4; }
        const uint32_t nExp = static_cast<uint32_t>(gt->shape[2]);
        if (!describe(ld, gName, nExp, g, err) ||
            !describe(ld, uName, nExp, u, err) ||
            !describe(ld, dName, nExp, d, err)) {
            std::fprintf(stderr, "EXPERT_PROBE_FAIL %s\n", err.c_str());
            return 4;
        }
        std::printf("EXPERT_PROBE tensors experts=%u gate[%llux%llu] up[%llux%llu] down[%llux%llu] "
                    "bytesPerExpert=%llu\n",
                    nExp, (unsigned long long)g.rows, (unsigned long long)g.cols,
                    (unsigned long long)u.rows, (unsigned long long)u.cols,
                    (unsigned long long)d.rows, (unsigned long long)d.cols,
                    (unsigned long long)g.bytesPerExpert);
        if (g.rows != u.rows || g.cols != u.cols ||
            d.cols != g.rows || d.rows != g.cols) {
            std::fprintf(stderr, "EXPERT_PROBE_FAIL projection geometry inconsistent\n");
            return 4;
        }
        if (r.hidden != g.cols) {
            std::fprintf(stderr, "EXPERT_PROBE_FAIL hidden=%u != gate cols=%llu\n",
                         r.hidden, (unsigned long long)g.cols);
            return 4;
        }
    }

    const uint64_t needScratch = 3 * g.bytesPerExpert +
                                 (g.rows + d.rows + r.hidden) * sizeof(float);
    if (scratchCap && needScratch > scratchCap) {
        std::fprintf(stderr, "EXPERT_PROBE_FAIL scratch limit need=%llu cap=%llu\n",
                     (unsigned long long)needScratch, (unsigned long long)scratchCap);
        return 5;
    }

    auto& reg = Deep2::QuantKernelRegistry::Instance();
    reg.Initialize();   // RegisterBuiltins(): Q4_0 -> gemv_q4_0_scalar
    auto gk = reg.GetGEMV(2);
    if (!gk) { std::fprintf(stderr, "EXPERT_PROBE_FAIL no Q4_0 GEMV kernel\n"); return 4; }

    FILE* f = std::fopen(model.c_str(), "rb");
    if (!f) { std::fprintf(stderr, "EXPERT_PROBE_FAIL reopen\n"); return 3; }

    const uint32_t nExp = static_cast<uint32_t>(g.experts);
    const uint32_t first = (which == "one") ? static_cast<uint32_t>(expert) : 0u;
    const uint32_t last  = (which == "one") ? first : (r.count ? r.count - 1 : 0);
    if (first >= nExp) { std::fprintf(stderr, "EXPERT_PROBE_FAIL expert out of range\n"); std::fclose(f); return 4; }

    std::vector<unsigned char> bufG, bufU, bufD;
    std::vector<float> gate(g.rows), up(g.rows), outStreamed(d.rows), outMapped(d.rows);
    std::vector<float> refGate(g.rows), refUp(g.rows);
    // Accumulator mirrors the engine order: shared contribution first, then
    // routed experts in selection order, each scaled by its applied weight.
    std::vector<float> acc(d.rows, 0.0f);
    uint64_t tiles = 0, bytesStreamed = 0;

    // --- Independent shared-expert reconstruction (2-D shexp tensors) ---
    if (sharedMode) {
        TensorView gs{}, us{}, ds{};
        char sg[128], su[128], sd[128];
        std::snprintf(sg, sizeof(sg), "blk.%u.ffn_gate_shexp.weight", r.layer);
        std::snprintf(su, sizeof(su), "blk.%u.ffn_up_shexp.weight",   r.layer);
        std::snprintf(sd, sizeof(sd), "blk.%u.ffn_down_shexp.weight", r.layer);
        if (!describe2D(ld, sg, gs, err) || !describe2D(ld, su, us, err) ||
            !describe2D(ld, sd, ds, err)) {
            std::fprintf(stderr, "EXPERT_PROBE_FAIL shared %s\n", err.c_str());
            std::fclose(f);
            return 4;
        }
        if (gs.rows != us.rows || gs.cols != us.cols ||
            ds.cols != gs.rows || ds.rows != gs.cols || gs.cols != r.hidden) {
            std::fprintf(stderr, "EXPERT_PROBE_FAIL shared geometry inconsistent\n");
            std::fclose(f);
            return 4;
        }
        std::printf("EXPERT_PROBE_SHARED gate[%llux%llu] up[%llux%llu] down[%llux%llu] "
                    "bytes=%llu\n",
                    (unsigned long long)gs.rows, (unsigned long long)gs.cols,
                    (unsigned long long)us.rows, (unsigned long long)us.cols,
                    (unsigned long long)ds.rows, (unsigned long long)ds.cols,
                    (unsigned long long)gs.bytesPerExpert);

        std::vector<unsigned char> bsG, bsU, bsD;
        uint64_t shTiles = 0, shBytes = 0;
        if (!readSlice(f, gs, 0, tileBlocks, bsG, shTiles, shBytes) ||
            !readSlice(f, us, 0, tileBlocks, bsU, shTiles, shBytes) ||
            !readSlice(f, ds, 0, tileBlocks, bsD, shTiles, shBytes)) {
            std::fprintf(stderr, "EXPERT_PROBE_FAIL shared streaming\n");
            std::fclose(f);
            return 6;
        }
        const int shByteEqual =
            (std::memcmp(gs.t->data, bsG.data(), gs.bytesPerExpert) == 0) &&
            (std::memcmp(us.t->data, bsU.data(), us.bytesPerExpert) == 0) &&
            (std::memcmp(ds.t->data, bsD.data(), ds.bytesPerExpert) == 0) ? 1 : 0;

        std::vector<float> shGate(gs.rows), shUp(us.rows), shOut(ds.rows), shAct(gs.rows);
        std::memset(shGate.data(), 0, shGate.size() * sizeof(float));
        std::memset(shUp.data(),   0, shUp.size()   * sizeof(float));
        gk(bsG.data(), r.input.data(), shGate.data(), gs.rows, gs.cols);
        gk(bsU.data(), r.input.data(), shUp.data(),   us.rows, us.cols);
        {
            auto siluS = [](float v) -> float {
                if (v > 20.0f) return v;
                if (v < -20.0f) return 0.0f;
                return v / (1.0f + std::exp(-v));
            };
            for (size_t i = 0; i < shAct.size(); ++i)
                shAct[i] = siluS(shGate[i]) * shUp[i];
        }
        std::memset(shOut.data(), 0, shOut.size() * sizeof(float));
        gk(bsD.data(), shAct.data(), shOut.data(), ds.rows, ds.cols);

        tiles += shTiles;
        bytesStreamed += shBytes;

        int sharedBitwise = -1;
        if (engineShared && engineShared->count == shOut.size()) {
            sharedBitwise = (std::memcmp(engineShared->out.data(), shOut.data(),
                                         shOut.size() * sizeof(float)) == 0) ? 1 : 0;
            double shMax = 0.0;
            for (size_t i = 0; i < shOut.size(); ++i) {
                const double dd = std::fabs(static_cast<double>(engineShared->out[i]) -
                                            static_cast<double>(shOut[i]));
                if (dd > shMax) shMax = dd;
            }
            std::printf("SHARED_PARITY bytes_equal=%d bitwise_vs_engine=%d max_abs=%.9g\n",
                        shByteEqual, sharedBitwise, shMax);
        } else {
            std::printf("SHARED_PARITY bytes_equal=%d bitwise_vs_engine=NO_ENGINE_RECORD\n",
                        shByteEqual);
        }
        acc = shOut;
    } else if (!zeroShared && engineShared && engineShared->count == acc.size()) {
        acc = engineShared->out;
    }

    uint64_t byteMismatches = 0, valueMismatches = 0;
    double maxAbs = 0.0;
    uint64_t nonfinite = 0;

    auto fnvBytes = [](const void* p, size_t n) -> unsigned long long {
        const unsigned char* b = static_cast<const unsigned char*>(p);
        unsigned long long h = 1469598103934665603ull;
        for (size_t i = 0; i < n; ++i) { h ^= b[i]; h *= 1099511628211ull; }
        return h;
    };

    for (uint32_t k = first; k <= last; ++k) {
        const uint32_t e = r.ids[k];
        if (e >= nExp) { std::fprintf(stderr, "EXPERT_PROBE_FAIL id %u out of range\n", e); std::fclose(f); return 4; }

        if (!readSlice(f, g, e, tileBlocks, bufG, tiles, bytesStreamed) ||
            !readSlice(f, u, e, tileBlocks, bufU, tiles, bytesStreamed) ||
            !readSlice(f, d, e, tileBlocks, bufD, tiles, bytesStreamed)) {
            std::fprintf(stderr, "EXPERT_PROBE_FAIL stream expert %u\n", e); std::fclose(f); return 6;
        }

        const unsigned char* mapG = g.t->data + static_cast<uint64_t>(e) * g.bytesPerExpert;        const unsigned char* mapU = u.t->data + static_cast<uint64_t>(e) * u.bytesPerExpert;
        const unsigned char* mapD = d.t->data + static_cast<uint64_t>(e) * d.bytesPerExpert;
        if (std::memcmp(mapG, bufG.data(), g.bytesPerExpert) != 0) ++byteMismatches;
        if (std::memcmp(mapU, bufU.data(), u.bytesPerExpert) != 0) ++byteMismatches;
        if (std::memcmp(mapD, bufD.data(), d.bytesPerExpert) != 0) ++byteMismatches;

        // Fingerprint the GGUF expert slices with the same span and layout the
        // engine reports, so weight identity can be compared directly.
        std::printf("PROBE_SLICE_FNV expert=%u bytes=%llu gate=%016llX up=%016llX down=%016llX\n",
                    e, (unsigned long long)g.bytesPerExpert,
                    fnvBytes(bufG.data(), static_cast<size_t>(g.bytesPerExpert)),
                    fnvBytes(bufU.data(), static_cast<size_t>(u.bytesPerExpert)),
                    fnvBytes(bufD.data(), static_cast<size_t>(d.bytesPerExpert)));

        // Streamed expert FFN
        std::memset(gate.data(), 0, gate.size() * sizeof(float));
        std::memset(up.data(),   0, up.size()   * sizeof(float));
        gk(bufG.data(), r.input.data(), gate.data(), g.rows, g.cols);
        gk(bufU.data(), r.input.data(), up.data(),   u.rows, u.cols);
        // Engine arithmetic (Deep2Engine::SwiGLU): out = silu(gate) * up.
        // Deep2_SwiGLU is the legacy form (x * silu(y)) and applies SiLU to the
        // wrong operand, so it must not be used for parity work.
        {
            auto siluE = [](float v) -> float {
                if (v > 20.0f) return v;
                if (v < -20.0f) return 0.0f;
                return v / (1.0f + std::exp(-v));
            };
            for (size_t i = 0; i < gate.size(); ++i)
                gate[i] = siluE(gate[i]) * up[i];
        }
        std::memset(outStreamed.data(), 0, outStreamed.size() * sizeof(float));
        gk(bufD.data(), gate.data(), outStreamed.data(), d.rows, d.cols);

        // Mapped expert FFN (same kernels, mapped pointers)
        std::memset(refGate.data(), 0, refGate.size() * sizeof(float));
        std::memset(refUp.data(),   0, refUp.size()   * sizeof(float));
        gk(mapG, r.input.data(), refGate.data(), g.rows, g.cols);
        gk(mapU, r.input.data(), refUp.data(),   u.rows, u.cols);
        // Same engine arithmetic for the mapped reference path.
        {
            auto siluE2 = [](float v) -> float {
                if (v > 20.0f) return v;
                if (v < -20.0f) return 0.0f;
                return v / (1.0f + std::exp(-v));
            };
            for (size_t i = 0; i < refGate.size(); ++i)
                refGate[i] = siluE2(refGate[i]) * refUp[i];
        }
        std::memset(outMapped.data(), 0, outMapped.size() * sizeof(float));
        gk(mapD, refGate.data(), outMapped.data(), d.rows, d.cols);

        double localMax = 0.0;
        for (size_t i = 0; i < outStreamed.size(); ++i) {
            const float a = outMapped[i], b = outStreamed[i];
            if (!std::isfinite(a) || !std::isfinite(b)) { ++nonfinite; continue; }
            const double diff = std::fabs(static_cast<double>(a) - static_cast<double>(b));
            if (diff > localMax) localMax = diff;
        }
        if (std::memcmp(outMapped.data(), outStreamed.data(),
                        outMapped.size() * sizeof(float)) != 0) ++valueMismatches;
        if (localMax > maxAbs) maxAbs = localMax;

        std::printf("EXPERT_PROBE expert=%u weight=%f bytes_equal=%d ffn_bitwise=%d max_abs=%.9g\n",
                    e, r.weights[k],
                    (byteMismatches == 0) ? 1 : 0,
                    (std::memcmp(outMapped.data(), outStreamed.data(),
                                 outMapped.size() * sizeof(float)) == 0) ? 1 : 0,
                    localMax);

        // Independent parity: compare the streamed reproduction against the
        // output the ENGINE actually produced for this expert.
        if (!engineRecs.empty()) {
            const EngineRec* match = nullptr;
            for (const auto& rec : engineRecs)
                if (rec.kind == 1 && rec.expert == e) { match = &rec; break; }
            if (!match || match->count != outStreamed.size()) {
                std::fprintf(stderr, "EXPERT_PROBE_FAIL missing/missized engine record for expert %u\n", e);
                std::fclose(f);
                return 8;
            }
            const int engBitwise =
                (std::memcmp(match->out.data(), outStreamed.data(),
                             outStreamed.size() * sizeof(float)) == 0) ? 1 : 0;
            double engMax = 0.0;
            for (size_t i = 0; i < outStreamed.size(); ++i) {
                const double d = std::fabs(static_cast<double>(match->out[i]) -
                                           static_cast<double>(outStreamed[i]));
                if (d > engMax) engMax = d;
            }
            if (!engBitwise) ++valueMismatches;
            std::printf("ENGINE_PARITY expert=%u bitwise=%d max_abs=%.9g\n",
                        e, engBitwise, engMax);
        }

        // Weighted accumulation in engine order. The engine uses
        // _mm256_fmadd_ps(w, expertOut, output), so use an explicitly fused
        // multiply-add here; a plain w*e + acc compiles to mul+add on this
        // target (no /arch:AVX2) and differs by ~1e-7.
        const float w = r.weights[k];
        for (size_t i = 0; i < acc.size(); ++i)
            acc[i] = std::fma(w, outStreamed[i], acc[i]);
    }
    std::fclose(f);

    int boundaryPass = -1;
    if (!boundaryPath.empty()) {
        FILE* bf = std::fopen(boundaryPath.c_str(), "rb");
        if (!bf) { std::fprintf(stderr, "EXPERT_PROBE_FAIL boundary unreadable\n"); return 3; }
        uint32_t blayer = 0, bcount = 0;
        uint64_t bstep = 0;
        if (std::fread(&blayer, 4, 1, bf) != 1 || std::fread(&bstep, 8, 1, bf) != 1 ||
            std::fread(&bcount, 4, 1, bf) != 1) {
            std::fclose(bf);
            std::fprintf(stderr, "EXPERT_PROBE_FAIL boundary header\n");
            return 3;
        }
        std::vector<float> bound(bcount);
        if (bcount && std::fread(bound.data(), 4, bcount, bf) != bcount) {
            std::fclose(bf);
            std::fprintf(stderr, "EXPERT_PROBE_FAIL boundary payload\n");
            return 3;
        }
        std::fclose(bf);
        if (bcount != acc.size()) {
            std::fprintf(stderr, "EXPERT_PROBE_FAIL boundary count=%u != acc=%zu\n",
                         bcount, acc.size());
            return 4;
        }
        // Pre-registered acceptance: |diff| <= 1e-4 absolute; relative <= 1e-5
        // only for |ref| > 1e-3; near-zero elements reported separately.
        double bmax = 0.0;
        uint64_t relViolations = 0, nearZero = 0, bNonfinite = 0;
        for (size_t i = 0; i < acc.size(); ++i) {
            const double rv = bound[i], av = acc[i];
            if (!std::isfinite(rv) || !std::isfinite(av)) { ++bNonfinite; continue; }
            const double d = std::fabs(rv - av);
            if (d > bmax) bmax = d;
            const double mag = std::fabs(rv);
            if (mag > 1e-3) {
                if (d / mag > 1e-5) ++relViolations;
            } else {
                ++nearZero;
            }
        }
        boundaryPass = (bmax <= 1e-4 && relViolations == 0 && bNonfinite == 0) ? 1 : 0;
        std::printf("BOUNDARY_PARITY layer=%u step=%llu count=%u max_abs=%.9g "
                    "rel_violations=%llu near_zero=%llu nonfinite=%llu verdict=%s\n",
                    blayer, (unsigned long long)bstep, bcount, bmax,
                    (unsigned long long)relViolations, (unsigned long long)nearZero,
                    (unsigned long long)bNonfinite, boundaryPass ? "PASS" : "FAIL");
    }

    std::printf("EXPERT_PROBE_RESULT experts=%u tiles=%llu bytes_streamed=%llu "
                "scratch_total=%llu byte_mismatches=%llu value_mismatches=%llu "
                "max_abs=%.9g nonfinite=%llu\n",
                last - first + 1, (unsigned long long)tiles,
                (unsigned long long)bytesStreamed, (unsigned long long)needScratch,
                (unsigned long long)byteMismatches, (unsigned long long)valueMismatches,
                maxAbs, (unsigned long long)nonfinite);

    const bool pass = byteMismatches == 0 && valueMismatches == 0 && nonfinite == 0 &&
                      (boundaryPass != 0);
    std::printf("EXPERT_PROBE_VERDICT=%s\n", pass ? "PASS" : "FAIL");
    return pass ? 0 : 7;
}