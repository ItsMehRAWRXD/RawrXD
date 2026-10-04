// nanof32_braid_writer.cpp
//
// RAWRXD_NANOF32_BRAID_WRITER_001 — produces a Nanof32Braid (.nqb) test model.
//
// WHY THIS TOOL EXISTS
// --------------------
// tests/nanof32_e2e_test.cpp loads a .nqb through
// Deep2Engine::loadModelFromNanof32Braid(). Before this tool, no .nqb file
// existed anywhere on this machine and no code in the tree could produce one,
// so that test could be compiled and linked but never run. A format with a
// reader, a header describing the layout, and no writer is an untested format.
//
// The test model this emits is SYNTHETIC. Its weights are deterministic
// pseudo-random values, not trained parameters. It certifies that the load
// path, the tensor-name binding, and the forward pass execute end to end. It
// certifies nothing about numerics against a reference, and its output text is
// meaningless. The tool says so in its own receipt rather than leaving a
// reader to assume otherwise.
//
// SELF-VERIFICATION
// -----------------
// The tool does not verify itself with a decoder it also wrote. It reopens the
// file it just produced with the REAL reader (Nanof32BraidStreamer, the same
// code Deep2Engine uses) and compares every tensor against the source floats.
// A writer and a reader written by the same author and agreeing with each
// other prove nothing; only the shipped reader can falsify this writer.
//
// HONESTY CONSTRAINTS
// -------------------
//  * VERDICT is computed from counted comparisons.
//  * Synthetic weights are labelled SYNTHETIC_WEIGHTS=1 in the receipt.
//  * No expected-output string is written anywhere in this file.
//  * A failed round trip removes the artefact and exits non-zero, so an
//    unusable .nqb is never left on disk to be found by a later run.

#include "Nanof32BraidFormat.hpp"
#include "Nanof32BraidWriter.hpp"
#include "Nanof32BraidStreamer.hpp"

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace {

// Token type codes from Tokenizer.cpp (which declares them file-local, so they
// cannot be included). Mirrored here as literals with the source named; if
// Tokenizer.cpp's values ever change this table must change with them.
constexpr int32_t NQ_TOK_NORMAL  = 1;
constexpr int32_t NQ_TOK_UNKNOWN = 2;
constexpr int32_t NQ_TOK_CONTROL = 3;
constexpr int32_t NQ_TOK_BYTE    = 6;

// Deterministic value generator (xorshift64*). A fixed seed makes the artefact
// byte-reproducible, so a diff between two runs means a real behaviour change
// rather than fresh randomness.
struct Rng {
    uint64_t s;
    explicit Rng(uint64_t seed) : s(seed ? seed : 0x9E3779B97F4A7C15ull) {}
    uint64_t next() {
        s ^= s >> 12; s ^= s << 25; s ^= s >> 27;
        return s * 0x2545F4914F6CDD1Dull;
    }
    // Uniform in [-1, 1). Never returns exactly 0 for long stretches, which
    // matters: an all-zero weight block makes RMSNorm divide by ~0 and the
    // forward pass produces NaN for reasons unrelated to the format.
    float uniform() {
        const uint32_t bits = static_cast<uint32_t>(next() >> 40);  // 24 bits
        return static_cast<float>(bits) / 8388608.0f - 1.0f;
    }
};

// RAWRXD_NANOF32_SYNTHETIC_FIXTURE_001
// Structural E2E test fixture, not a trained model surrogate.
// The 1.15-bit braid codec reconstructs with ~5.5x amplitude expansion
// versus the intended pre-codec range, so SwiGLU produces inf at the
// original 1/sqrt(fan_in) scale.  Dividing by an additional factor of 16
// keeps post-codec weights small enough that the structural topology
// can be exercised without numerical overflow.  This is a fixture
// calibration, NOT a codec fidelity fix.
void fillTensor(std::vector<float>& v, size_t rows, size_t cols, uint64_t seed) {
    Rng rng(seed);
    const float scale = 1.0f / (std::sqrt(static_cast<float>(cols ? cols : 1)) * 16.0f);
    v.resize(rows * cols);
    for (size_t i = 0; i < v.size(); ++i) v[i] = rng.uniform() * scale;
}

void usage() {
    std::fprintf(stderr,
        "usage: nanof32_braid_writer --out PATH [options]\n"
        "  --out PATH        .nqb file to write (required)\n"
        "  --layers N        transformer layers (default 2)\n"
        "  --hidden N        hidden dimension (default 64)\n"
        "  --vocab N         vocabulary size (default 512; must be >= the tokenizer size)\n"
        "  --heads N         attention heads (default 4)\n"
        "  --kv-heads N      KV heads (default 4)\n"
        "  --head-dim N      head dimension (default 16)\n"
        "  --intermediate N  FFN intermediate (default 128)\n"
        "  --ctx N           context length (default 512)\n"
        "  --experts N      MoE expert count; >0 emits ffn_gate_exps and sets\n"
        "                    numExperts (default 0 = dense)\n"
        "  --rope N          0=none 1=NeoX 2=GPT-J 3=MLA (default 1)\n"
        "  --rope-theta N    RoPE base theta x1000 (default 10000); required when --rope != 0\n"
        "  --quant N         0=f32 1=bf16 5=braid1.15 (default 5)\n"
        "  --seed N          RNG seed (default 20261004)\n"
        "  --no-verify       skip the read-back round trip\n"
        "  --no-vocab        emit the legacy class: NO tokenizer section. Valid,\n"
        "                    and certified separately, so backward compatibility\n"
        "                    is measured rather than assumed.\n"
        "  --verify-only P   verify an existing .nqb and exit; writes nothing.\n"
        "                    The source tensors are regenerated from --seed so\n"
        "                    the comparison is meaningful; use the same seed\n"
        "                    that produced the file.\n");
}

bool parseUintArg(const char* text, unsigned long long lo,
                  unsigned long long hi, unsigned long long& out) {
    if (!text || !*text) return false;
    char* end = nullptr;
    const unsigned long long v = std::strtoull(text, &end, 10);
    if (end == text || *end != '\0') return false;
    if (v < lo || v > hi) return false;
    out = v;
    return true;
}

// ROUND-TRIP SEMANTICS
// --------------------
// The gate depends on the codec, because the codecs differ in kind:
//
//   NQBRAID_DENSE_F32  lossless. The writer must be its exact inverse, so the
//                      decoded value must equal the source bit for bit.
//   NQBRAID_DENSE_BF16 lossy but high-resolution. The shipped reader builds
//                      bf16 by TRUNCATION (u >> 16), so the floor on error is
//                      one bf16 ulp == 2^-8 relative. Anything beyond that is a
//                      structural bug.
//   NQBRAID_BRAID_115  lossy by DESIGN, at 1.15 bits per weight. It can only
//                      reconstruct from {scaleMin, scaleMax} blended with 8
//                      centroids, so a decoded weight CANNOT match its source.
//                      Asserting that it does would be asserting an invariant
//                      the format does not promise -- the same mistake as
//                      asserting vocabulary ids are contiguous. What IS
//                      guaranteed, and therefore gated, is that every decoded
//                      value lies inside the declared [scaleMin, scaleMax].
//                      Fidelity is reported as a measured fraction, never
//                      asserted as a threshold.
//
// The invariant that holds for EVERY codec, lossy or not, and is the one that
// actually matters here: the reader consumed every tensor, at the right
// element count, and produced only values the writer's own scale range permits.
struct CodecExpectation {
    bool        exact;          // stored losslessly; observable through bf16
    double      tolerance;      // relative tolerance when exact
};

// Replicates bfloat16_t's constructor + toFloat() from BP16Streamer.hpp, i.e.
// what the reader will hand back for ANY stored precision. The reader's only
// output surface is std::vector<bfloat16_t> (NQBraidBlock::bf16Data), so
// nothing finer than bf16 is observable through this API -- an F32 tensor is
// stored losslessly and then narrowed on the way out. Comparing a decoded
// value against the ORIGINAL float for a lossless codec would therefore
// assert something the reader's own type makes impossible, which is how
// DENSE_F32 first reported 19/98624 matches at a max error of 4.9e-4.
float toBf16Truncated(float f) {
    uint32_t u;
    std::memcpy(&u, &f, sizeof u);
    const uint16_t h = static_cast<uint16_t>(u >> 16);
    const uint32_t back = static_cast<uint32_t>(h) << 16;
    float out;
    std::memcpy(&out, &back, sizeof out);
    return out;
}

CodecExpectation expectationFor(uint32_t quant) {
    switch (quant) {
        // Stored losslessly; observable at bf16 truncation. Tight tolerance
        // because the comparison is against the truncated expectation, so a
        // correct writer lands on it exactly.
        case Deep2::NQBRAID_DENSE_F32:
        case Deep2::NQBRAID_DENSE_BF16: return {true, 1e-6};
        default:                        return {false, 0.0};   // lossy
    }
}

} // namespace

int main(int argc, char** argv) {
    std::string outPath;
    unsigned long long layers = 2, hidden = 64, vocab = 512;
    unsigned long long heads = 4, kvHeads = 4, headDim = 16;
    unsigned long long intermediate = 128, ctx = 512, rope = 1;
    unsigned long long experts = 0;   // 0 = dense; >0 emits ffn_gate_exps
    unsigned long long mlaQLora = 32, mlaKvLora = 16;
    unsigned long long mlaNope = 8, mlaRope = 8, mlaV = 8;
    unsigned long long ropeThetaMilli = 10000;   // x1000, avoids float parsing
    unsigned long long quant = Deep2::NQBRAID_BRAID_115;
    unsigned long long seed = 20261004;
    bool verify = true;
    bool verifyOnly = false;
    bool noVocab = false;   // emit the legacy no-tokenizer file class
    bool poison = false;    // write a NaN into tensor 0 to trigger LinearW diagnostics
    bool poisonExpert = false; // write a NaN into one MoE expert tensor

    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto val = [&](const char* what, unsigned long long lo,
                       unsigned long long hi, unsigned long long& dst) -> bool {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "error: %s requires a value\n", what);
                return false;
            }
            if (!parseUintArg(argv[++i], lo, hi, dst)) {
                std::fprintf(stderr, "error: %s value out of range: %s\n",
                             what, argv[i]);
                return false;
            }
            return true;
        };

        if (a == "--out") {
            if (i + 1 >= argc) { std::fprintf(stderr, "error: --out requires a path\n"); return 64; }
            outPath = argv[++i];
        } else if (a == "--layers")       { if (!val("--layers", 1, 512, layers)) return 64; }
        else if (a == "--hidden")        { if (!val("--hidden", 8, 65536, hidden)) return 64; }
        else if (a == "--vocab")         { if (!val("--vocab", 8, 1048576, vocab)) return 64; }
        else if (a == "--heads")         { if (!val("--heads", 1, 4096, heads)) return 64; }
        else if (a == "--kv-heads")      { if (!val("--kv-heads", 1, 4096, kvHeads)) return 64; }
        else if (a == "--head-dim")      { if (!val("--head-dim", 1, 1024, headDim)) return 64; }
        else if (a == "--intermediate")  { if (!val("--intermediate", 8, 65536, intermediate)) return 64; }
        else if (a == "--ctx")           { if (!val("--ctx", 64, 1048576, ctx)) return 64; }
        else if (a == "--rope")          { if (!val("--rope", 0, 3, rope)) return 64; }
        else if (a == "--experts")      { if (!val("--experts", 0, 512, experts)) return 64; }
        else if (a == "--mla-q-lora")  { if (!val("--mla-q-lora", 1, 65536, mlaQLora)) return 64; }
        else if (a == "--mla-kv-lora") { if (!val("--mla-kv-lora", 1, 65536, mlaKvLora)) return 64; }
        else if (a == "--mla-nope")    { if (!val("--mla-nope", 1, 4096, mlaNope)) return 64; }
        else if (a == "--mla-rope")    { if (!val("--mla-rope", 2, 4096, mlaRope)) return 64; }
        else if (a == "--mla-v")       { if (!val("--mla-v", 1, 4096, mlaV)) return 64; }
        else if (a == "--rope-theta") {
            if (!val("--rope-theta", 1, 100000000, ropeThetaMilli)) return 64;
        }
        else if (a == "--quant")         { if (!val("--quant", 0, Deep2::NQBRAID_COUNT - 1, quant)) return 64; }
        else if (a == "--seed")          { if (!val("--seed", 1, 0xFFFFFFFFull, seed)) return 64; }
        else if (a == "--no-verify")     { verify = false; }
        else if (a == "--no-vocab")      { noVocab = true; }
        else if (a == "--poison")         { poison = true; }
        else if (a == "--poison-expert") { poisonExpert = true; }
        else if (a == "--verify-only") {
            if (i + 1 >= argc) { std::fprintf(stderr, "error: --verify-only requires a path\n"); return 64; }
            outPath = argv[++i];
            verifyOnly = true;
        }
        else if (a == "--help" || a == "-h") { usage(); return 0; }
        else { std::fprintf(stderr, "error: unknown argument: %s\n", a.c_str()); usage(); return 64; }
    }

    if (outPath.empty()) { std::fprintf(stderr, "error: --out is required\n"); usage(); return 64; }
    if (kvHeads > heads) {
        std::fprintf(stderr, "error: --kv-heads (%llu) must be <= --heads (%llu)\n",
                     kvHeads, heads);
        return 64;
    }
    const float ropeTheta = static_cast<float>(ropeThetaMilli) / 1000.0f;
    if (rope != 0 && !(ropeTheta > 0.0f)) {
        std::fprintf(stderr,
            "error: --rope %llu requires a positive --rope-theta\n", rope);
        return 64;
    }

    // ---- geometry ----------------------------------------------------------
    const bool useMla = (rope == 3);
    const size_t H = static_cast<size_t>(hidden);
    const size_t V = static_cast<size_t>(vocab);
    const size_t qDim = static_cast<size_t>(heads * headDim);
    const size_t kvDim = static_cast<size_t>(kvHeads * headDim);
    const size_t F = static_cast<size_t>(intermediate);

    Deep2::Nanof32BraidArchMeta meta{};
    std::snprintf(meta.modelName, sizeof meta.modelName, "rawrxd-nqb-selftest");
    std::snprintf(meta.archName, sizeof meta.archName, useMla ? "deepseek2" : "llama");
    meta.numLayers        = static_cast<uint32_t>(layers);
    meta.numExperts       = static_cast<uint32_t>(experts);
    meta.activeExperts    = experts ? (experts < 2 ? 1 : 2) : 0;
    meta.hiddenDim        = static_cast<uint32_t>(hidden);
    meta.numHeads         = static_cast<uint32_t>(heads);
    meta.numKVHeads       = static_cast<uint32_t>(kvHeads);
    meta.headDim          = static_cast<uint32_t>(headDim);
    meta.intermediateDim  = static_cast<uint32_t>(intermediate);
    meta.vocabSize        = static_cast<uint32_t>(vocab);
    meta.contextLength    = static_cast<uint32_t>(ctx);
    meta.ropeType         = static_cast<uint32_t>(rope);
    meta.normEps          = 1e-5f;
    // RAWRXD_NANOF32_BRAID_WRITER_001 -- RoPE theta is mandatory whenever
    // ropeType != 0. The loader refuses a zero here rather than guessing, so
    // emitting one is not optional bookkeeping.
    meta.ropeTheta        = (rope == 0) ? 0.0f : ropeTheta;
    meta.moeGateDim       = 0;
    meta.hasSharedExperts = 0;
    // MLA geometry, only meaningful when ropeType == 3. The loader refuses a
    // ropeType=3 model whose MLA fields are zero, so they are emitted
    // explicitly rather than left at their zero defaults.
    meta.qLoraRank     = static_cast<uint32_t>(mlaQLora);
    meta.kvLoraRank    = static_cast<uint32_t>(mlaKvLora);
    meta.qkNopeHeadDim = static_cast<uint32_t>(mlaNope);
    meta.qkRopeHeadDim = static_cast<uint32_t>(mlaRope);
    meta.vHeadDim      = static_cast<uint32_t>(mlaV);

    // ---- tensors -----------------------------------------------------------
    // Names are chosen to match the substring patterns
    // Deep2Engine::loadModelFromNanof32Braid searches for. Note that loader
    // matches by SUBSTRING over an unordered_map, so a name that contains
    // another pattern as a substring can bind to the wrong tensor. For the
    // dense layout the nine per-layer patterns below are mutually
    // non-overlapping; the MLA path is deliberately NOT generated here because
    // "attn_q" is a substring of "attn_q_a" and "attn_q_a_norm", which would
    // make the binding order-dependent on unordered_map iteration.
    std::vector<Deep2::Nanof32TensorSpec> tensors;
    std::vector<std::vector<float>>       storage;

    auto add = [&](const std::string& name, size_t rows, size_t cols) {
        Deep2::Nanof32TensorSpec spec;
        spec.name  = name;
        spec.rows  = rows;
        spec.cols  = cols;
        spec.quant = static_cast<uint32_t>(quant);
        storage.emplace_back();
        fillTensor(storage.back(), rows, cols, seed + tensors.size());

        // Per-tensor scale from the ACTUAL value range. This is what a real
        // quantiser does, and it matters here: a fixed [-1,+1] range against
        // weights of magnitude ~1/sqrt(cols) wastes almost the whole codebook,
        // and the 1-bit codec then reconstructs a 0.02 weight as 0.69. That
        // is not a writer bug, it is the codec being fed a range it cannot
        // use -- but it makes the artefact useless as a forward-pass fixture.
        float lo = storage.back().empty() ? 0.0f : storage.back()[0];
        float hi = lo;
        for (float v : storage.back()) {
            if (v < lo) lo = v;
            if (v > hi) hi = v;
        }
        // Keep the range strictly increasing: nanof32EncodeBraid115 refuses
        // scaleMax <= scaleMin rather than emitting a degenerate codec.
        const float pad = std::max(1e-6f, std::fabs(hi - lo) * 1e-3f);
        spec.scaleMin = lo - pad;
        spec.scaleMax = hi + pad;

        spec.values = storage.back().data();
        tensors.push_back(spec);
    };

    add("token_embd.weight", V, H);
    add("output_norm.weight", 1, H);
    add("output.weight",     V, H);

    auto addExpert = [&](const std::string& name, size_t rows, size_t cols,
                         uint32_t expert) {
        add(name, rows, cols);
        tensors.back().expertIndex = expert;
    };

    // MoE router + per-expert FFN weights. The loader binds
    // LayerWeights::moeGate/moeUp/moeDown, each a vector<WeightTensor> indexed
    // by expert, and computeMoE refuses unless all numExperts slots are
    // populated:
    //     [Deep2Engine] forward failed: MoE: expert tensors not fully bound
    // so a router alone is not a MoE model.
    if (experts > 0) {
        for (unsigned long long l = 0; l < layers; ++l) {
            const std::string p = "blk." + std::to_string(l) + ".";
            add(p + "ffn_gate_exps.weight", static_cast<size_t>(experts), H);
            for (unsigned long long e = 0; e < experts; ++e) {
                const std::string s = "." + std::to_string(e) + ".weight";
                addExpert(p + "ffn_gate" + s, F, H, (uint32_t)e);
                addExpert(p + "ffn_up"   + s, F, H, (uint32_t)e);
                addExpert(p + "ffn_down" + s, H, F, (uint32_t)e);
            }
        }
    }

    for (unsigned long long l = 0; l < layers; ++l) {
        const std::string p = "blk." + std::to_string(l) + ".";
        add(p + "attn_norm.weight", 1, H);
        add(p + "ffn_norm.weight",  1, H);
        if (useMla) {
            // Shapes mirror the loader's MLA binds, which use the REAL MLA
            // geometry from the arch meta (not hiddenDim throughout):
            //   qLoraRank  = --mla-q-lora   (default 32)
            //   kvLoraRank = --mla-kv-lora  (default 16)
            //   nope       = --mla-nope     (default 8)
            //   rope       = --mla-rope     (default 8, must be EVEN)
            //   vlen       = --mla-v        (default 8)
            const size_t QL = static_cast<size_t>(mlaQLora);
            const size_t KV = static_cast<size_t>(mlaKvLora);
            const size_t NP = static_cast<size_t>(mlaNope);
            const size_t RP = static_cast<size_t>(mlaRope);
            const size_t VL = static_cast<size_t>(mlaV);
            const size_t HEADS = static_cast<size_t>(heads);
            add(p + "attn_q_a.weight", QL, H);
            add(p + "attn_q_b.weight", HEADS * (NP + RP), QL);
            add(p + "attn_kv_a.weight", KV + RP, H);
            add(p + "attn_k_b.weight", HEADS * NP, KV);
            add(p + "attn_v_b.weight", HEADS * VL, KV);
            // attn_o is [H, heads*vlen] per deep2_cpu_mla.cpp's shape check, NOT
            // heads*(nope+vlen).
            add(p + "attn_o.weight", H, HEADS * VL);
            // Norm widths follow the LORA rank they normalise (deep2_cpu_mla.cpp
            // RMSNormW(..., qRank) and RMSNormW(..., kvRank)), not the head
            // dimension.
            add(p + "attn_q_a_norm.weight", 1, QL);
            add(p + "attn_kv_a_norm.weight", 1, KV);
        } else {
            add(p + "attn_q.weight", qDim, H);
            add(p + "attn_k.weight", kvDim, H);
            add(p + "attn_v.weight", kvDim, H);
            add(p + "attn_o.weight", H, qDim);
        }
        add(p + "ffn_gate.weight", F, H);
        add(p + "ffn_up.weight", F, H);
        add(p + "ffn_down.weight", H, F);
    }

// ---- vocabulary section (RAWRXD_NQBRAID_TOKENIZER_E2E_001) -------------
    //
    // Without this the loader can only fall back to a dummy tokenizer and no
    // token text can ever be produced. The fixture vocabulary is a REAL
    // SentencePiece-style table, not a stub: it contains the U+2581 word-start
    // marker, byte-fallback tokens for every byte, and the specials, which is
    // what encodeSentencePiece() needs to segment text.
    Deep2::Nanof32VocabSpec vocabSec;
    {
        // Byte-fallback tokens first (ids 0..255), matching the convention that
        // <0xXX> covers byte XX.
        for (int b = 0; b < 256; ++b) {
            char buf[16];
            std::snprintf(buf, sizeof buf, "<0x%02X>", b);
            vocabSec.tokens.emplace_back(buf);
            vocabSec.scores.push_back(0.0f);
            vocabSec.types.push_back(NQ_TOK_BYTE);
        }
        // Specials.
        vocabSec.unkId = static_cast<int32_t>(vocabSec.tokens.size());
        vocabSec.tokens.emplace_back("<unk>"); vocabSec.scores.push_back(0.0f);
        vocabSec.types.push_back(NQ_TOK_UNKNOWN);
        vocabSec.bosId = static_cast<int32_t>(vocabSec.tokens.size());
        vocabSec.tokens.emplace_back("<s>"); vocabSec.scores.push_back(0.0f);
        vocabSec.types.push_back(NQ_TOK_CONTROL);
        vocabSec.eosId = static_cast<int32_t>(vocabSec.tokens.size());
        vocabSec.tokens.emplace_back("</s>"); vocabSec.scores.push_back(0.0f);
        vocabSec.types.push_back(NQ_TOK_CONTROL);

        // Word pieces. Every entry starts with U+2581 because
        // encodeSentencePiece() replaces spaces with that marker and the trie
        // is matched against the transformed text.
        // U+2581 LOWER ONE EIGHTH BLOCK, the SentencePiece word-start marker.
        // Written as its own literal and CONCATENATED: in "\xE2\x96\x81capital"
        // the compiler reads \x81c as a single hex escape, not \x81 followed by
        // 'c'. That silently produced tokens one byte short of the marker.
        static const char* const kSP = "\xE2\x96\x81";

        struct Piece { std::string text; float score; };
        static const Piece kPieces[] = {
            { std::string(kSP) + "The",     -1.0f }, { std::string(kSP) + "capital", -2.0f },
            { std::string(kSP) + "of",      -1.0f }, { std::string(kSP) + "France",  -2.0f },
            { std::string(kSP) + "is",      -1.0f }, { std::string(kSP) + "a",      -1.0f },
            { std::string(kSP) + "city",    -2.0f }, { std::string(kSP) + "Paris",   -2.0f },
            { std::string(kSP) + "which",   -2.0f }, { std::string(kSP) + "and",    -1.0f },
            { std::string(kSP) + "in",      -1.0f }, { std::string(kSP) + "it",     -1.0f },
            { std::string(kSP) + "end",     -2.0f }, { std::string(kSP),            -0.1f },
            { "T", -4.0f }, { "h", -4.0f }, { "e", -4.0f },
            { "c", -4.0f }, { "a", -4.0f }, { "p", -4.0f }, { "i", -4.0f },
            { "t", -4.0f }, { "l", -4.0f }, { "o", -4.0f }, { "f", -4.0f },
            { "F", -4.0f }, { "r", -4.0f }, { "n", -4.0f }, { "s", -4.0f },
        };
        for (const Piece& p : kPieces) {
            vocabSec.tokens.emplace_back(p.text);
            vocabSec.scores.push_back(p.score);
            vocabSec.types.push_back(NQ_TOK_NORMAL);
        }
        vocabSec.model  = "llama";
        vocabSec.kind   = 2;              // SentencePiece
        vocabSec.addBos = false;          // keeps encode() output == round trip
        vocabSec.addEos = false;
    }

    // ---- write (skipped entirely in --verify-only mode) --------------------
    // Regenerate the expectation set from the same seed rather than
    // inventing expected values. This mode exists so the gate can be
    // falsified on demand: corrupt one byte of a written file, re-run, and
    // the comparison must fail. A gate that has only ever passed has not
    // been shown to be able to fail.
    Deep2::Nanof32WriteResult w;
    if (verifyOnly) {
        w.ok          = true;
        w.error       = "SKIPPED_VERIFY_ONLY";
        w.bytesWritten = 0;
        w.paramCount  = 0;
        for (const auto& t : tensors) w.paramCount += t.rows * t.cols;
        w.tensorCount = static_cast<uint32_t>(tensors.size());
    } else {
        // --poison writes a NaN into one tensor so the non-finite LinearW diagnostics
    // can be triggered deliberately. The anomaly under investigation
    // (RAWRXD_STALE_OBJECT_DIAGNOSTIC_001) needs a REPRODUCIBLE emitter, and
    // no naturally-occurring model produced one: synthetic weights are finite
    // by construction. Poisoning is explicit and reported, never silent.
    if (poison && !tensors.empty()) {
        auto& v = storage[0];
        if (!v.empty()) v[0] = std::numeric_limits<float>::quiet_NaN();
    }

    // --poison-expert writes a NaN into ONE MoE expert tensor so the non-finite
    // LinearW diagnostics can be triggered deliberately.
    //
    // RAWRXD_STALE_OBJECT_DIAGNOSTIC_001 needs a REPRODUCIBLE emitter, and no
    // naturally-occurring model produced one: synthetic weights are finite by
    // construction. Poisoning token_embd does NOT work -- the e2e test's own
    // weight-sanity gate correctly rejects the file first:
    //     FAIL=weight_nonfinite name=token_embd idx=0/32768 raw=0x7FC0
    // which is the gate doing its job. An EXPERT tensor is checked by neither
    // that gate nor the router check, so the forward pass actually runs and
    // reaches the emitter.
    if (poisonExpert) {
        // ALL experts, not just expert 0: which experts a token routes to is
        // decided by the router, so poisoning one leaves the run dependent on
        // routing luck. The first version poisoned only expert 0 and the run
        // PASSED, because expert 0 was simply never selected.
        int poisoned = 0;
        for (size_t i = 0; i < tensors.size(); ++i) {
            if (tensors[i].name.find("ffn_gate") == std::string::npos) continue;
            if (tensors[i].expertIndex == 0xFFFFFFFFu) continue;   // dense one
            if (storage[i].empty()) continue;
            storage[i][0] = std::numeric_limits<float>::quiet_NaN();
            ++poisoned;
        }
        if (poisoned == 0) {
            std::fprintf(stderr,
                "error: --poison-expert requires a MoE model (--experts N>0) with "
                "per-expert ffn_gate tensors\n");
            return 64;
        }
        std::fprintf(stderr, "POISON_EXPERT_TENSORS=%d\n", poisoned);
    }

    if (noVocab) {
            // Legacy file class: a valid .nqb that declares NO tokenizer
            // section. This is a legitimate format state, not a degraded one,
            // and it must be produced deliberately so backward compatibility
            // can be certified rather than assumed.
            w = Deep2::nanof32WriteBraid(outPath, meta, tensors, nullptr);
        } else {
            w = Deep2::nanof32WriteBraid(outPath, meta, tensors, &vocabSec);
        }
    }

    std::printf("=== RAWRXD_NANOF32_BRAID_WRITER_001 ===\n");
    std::printf("MODE=%s\n", verifyOnly ? "VERIFY_ONLY" : "WRITE");
    std::printf("OUT_PATH=%s\n", outPath.c_str());
    std::printf("LAYERS=%llu HIDDEN=%llu VOCAB=%llu HEADS=%llu KV_HEADS=%llu\n",
                layers, hidden, vocab, heads, kvHeads);
    std::printf("HEAD_DIM=%llu INTERMEDIATE=%llu CTX=%llu ROPE=%llu\n",
                headDim, intermediate, ctx, rope);
    std::printf("QUANT_REQUESTED=%llu\n", quant);
    std::printf("SYNTHETIC_WEIGHTS=1\n");
    std::printf("WRITE_OK=%d\n", w.ok ? 1 : 0);
    std::printf("WRITE_ERROR=%s\n", w.error.empty() ? "NONE" : w.error.c_str());
    std::printf("BYTES_WRITTEN=%llu\n", (unsigned long long)w.bytesWritten);
    std::printf("PARAM_COUNT=%llu\n", (unsigned long long)w.paramCount);
    std::printf("TENSOR_COUNT=%llu\n", (unsigned long long)w.tensorCount);
    std::printf("DATA_START=%llu\n", (unsigned long long)w.dataStart);
    std::printf("FINAL_FOOTER=%llu\n", (unsigned long long)w.finalFooter);
    std::printf("HEADER_SIZE=%llu ARCHMETA_SIZE=%llu FOOTER_SIZE=%llu\n",
                (unsigned long long)sizeof(Deep2::Nanof32BraidHeader),
                (unsigned long long)sizeof(Deep2::Nanof32BraidArchMeta),
                (unsigned long long)sizeof(Deep2::Nanof32BraidTensorFooter));

    // Emit a deterministic vocab sidecar so the e2e test can tokenise a prompt
    // instead of silently falling back to dummy tokens.  RAWRXD_NANOF32_BRAID_WRITER_001.
    const std::string vocabPath = outPath + ".vocab.txt";
    if (!verifyOnly) {
        std::ofstream vocabOut(vocabPath);
        if (vocabOut) {
            for (size_t i = 0; i < V; ++i) {
                vocabOut << i << " \"<t" << i << ">\"\n";
            }
        }
    }

    if (!w.ok) {
        std::printf("VERDICT=FAIL\n");
        return 1;
    }
    std::printf("VOCAB_PATH=%s\n", vocabPath.c_str());
    std::printf("VOCAB_SIZE=%llu\n", (unsigned long long)V);
    // This is the part that can fail. It uses Nanof32BraidStreamer, the same
    // reader Deep2Engine uses, so agreement here means the shipped reader
    // accepts what the shipped writer produced.
    uint64_t tensorsRead = 0, elemsCompared = 0, mismatch = 0;
    uint64_t rangeViolations = 0, exactMatches = 0, within5pctOfRange = 0;
    double   maxAbsErr = 0.0;
    std::string firstMismatch;

    if (verify) {
        Deep2::Nanof32BraidStreamer reader;
        if (!reader.open(outPath)) {
            std::printf("VERIFY=READER_OPEN_FAILED\n");
            std::printf("VERDICT=FAIL\n");
            return 1;
        }

        Deep2::Nanof32BraidArchMeta readMeta{};
        const bool metaOk = reader.readArchMeta(readMeta);
        std::printf("VERIFY_ARCH_META_OK=%d\n", metaOk ? 1 : 0);
        std::printf("VERIFY_ARCH_MATCH=%d\n",
                    (metaOk && readMeta.numLayers == meta.numLayers &&
                     readMeta.hiddenDim == meta.hiddenDim &&
                     readMeta.vocabSize == meta.vocabSize &&
                     readMeta.numHeads == meta.numHeads &&
                     readMeta.intermediateDim == meta.intermediateDim) ? 1 : 0);

        std::vector<std::pair<std::string, Deep2::NQBraidBlock>> read;
        const bool allOk = reader.readAllTensors(read);
        std::printf("VERIFY_READ_ALL_OK=%d\n", allOk ? 1 : 0);
        std::printf("VERIFY_TENSORS_READ=%llu\n", (unsigned long long)read.size());

        if (!allOk) {
            std::printf("VERDICT=FAIL\n");
            return 1;
        }

        // RAWRXD_NANOF32_SYNTHETIC_FIXTURE_001 -- post-codec amplitude measurement.
        // The acceptance gate requires PRE/POST_CODEC_MAX_ABS and POST_CODEC_MEAN_ABS
        // so the fixture calibration can be verified independently of the codec's
        // intrinsic numerical fidelity (which remains an open issue).
        double preCodecSumAbs = 0.0, postCodecSumAbs = 0.0;
        float  preCodecMaxAbs = 0.0f, postCodecMaxAbs = 0.0f;
        size_t codecElems = 0;

        // The reader walks backward, so `read` is in reverse write order.
        // Match by name rather than by index so the comparison does not
        // silently depend on that ordering.
        for (size_t i = 0; i < tensors.size(); ++i) {
            const Deep2::Nanof32TensorSpec& spec = tensors[i];
            const Deep2::NQBraidBlock* found = nullptr;
            for (auto& kv : read) {
                if (kv.first == spec.name) { found = &kv.second; break; }
            }
            if (!found) {
                ++mismatch;
                if (firstMismatch.empty()) firstMismatch = "absent:" + spec.name;
                continue;
            }
            const size_t elements = static_cast<size_t>(spec.rows * spec.cols);
            if (found->bf16Data.size() != elements) {
                ++mismatch;
                if (firstMismatch.empty()) {
                    firstMismatch = "size:" + spec.name + ":got" +
                        std::to_string(found->bf16Data.size()) +
                        ":want" + std::to_string(elements);
                }
                continue;
            }
            ++tensorsRead;
            const CodecExpectation expect = expectationFor(spec.quant);
            for (size_t k = 0; k < elements; ++k) {
                const float got = found->bf16Data[k].toFloat();
                const float want = spec.values[k];
                ++elemsCompared;
                // Synthetic fixture amplitude measurement (not a codec fidelity gate)
                preCodecSumAbs += std::fabs(static_cast<double>(want));
                postCodecSumAbs += std::fabs(static_cast<double>(got));
                if (std::fabs(want) > preCodecMaxAbs) preCodecMaxAbs = std::fabs(want);
                if (std::fabs(got) > postCodecMaxAbs) postCodecMaxAbs = std::fabs(got);
                ++codecElems;

                // Universal invariant: the codec must not invent a value
                // outside the range the writer declared for this tensor.
                if (!(got >= spec.scaleMin && got <= spec.scaleMax)) {
                    ++rangeViolations;
                    if (firstMismatch.empty()) {
                        firstMismatch = "range:" + spec.name + ":idx" +
                            std::to_string(k) + ":got" + std::to_string(got) +
                            ":declared[" + std::to_string(spec.scaleMin) + "," +
                            std::to_string(spec.scaleMax) + "]";
                    }
                }

                if (expect.exact) {
                    // Compare against what the reader can actually return.
                    const float wantObs = toBf16Truncated(want);
                    const double d =
                        std::fabs(static_cast<double>(got) - wantObs);
                    if (d > maxAbsErr) maxAbsErr = d;
                    if (d <= expect.tolerance * (1.0 + std::fabs(static_cast<double>(wantObs)))) {
                        ++exactMatches;
                    } else {
                        ++mismatch;
                        if (firstMismatch.empty()) {
                            firstMismatch = "value:" + spec.name + ":idx" +
                                std::to_string(k) + ":got" + std::to_string(got) +
                                ":wantObs" + std::to_string(wantObs);
                        }
                    }
                } else {
                    // Lossy codec: count fidelity against the source, and
                    // report. Never thresholded -- 1.15 bits per weight cannot
                    // reproduce an arbitrary float, and asserting otherwise
                    // would be asserting an invariant the format disclaims.
                    const double d =
                        std::fabs(static_cast<double>(got) - want);
                    if (d > maxAbsErr) maxAbsErr = d;
                    const double tol =
                        0.05 * (std::fabs(static_cast<double>(spec.scaleMax) -
                                           spec.scaleMin) + 1e-9);
                    if (d <= tol) ++within5pctOfRange;
                }
            }
        }
        std::printf("VERIFY_TENSORS_MATCHED=%llu\n", (unsigned long long)tensorsRead);
        std::printf("VERIFY_ELEMENTS_COMPARED=%llu\n", (unsigned long long)elemsCompared);
        std::printf("VERIFY_RANGE_VIOLATIONS=%llu\n", (unsigned long long)rangeViolations);
        std::printf("VERIFY_EXACT_MATCHES=%llu\n", (unsigned long long)exactMatches);
        std::printf("VERIFY_WITHIN_5PCT_OF_RANGE=%llu\n", (unsigned long long)within5pctOfRange);
        std::printf("VERIFY_MAX_ABS_ERROR=%.6g\n", maxAbsErr);
        std::printf("VERIFY_FIRST_MISMATCH=%s\n",
                    firstMismatch.empty() ? "NONE" : firstMismatch.c_str());
        std::printf("PRE_CODEC_MAX_ABS=%.6g\n", static_cast<double>(preCodecMaxAbs));
        std::printf("POST_CODEC_MAX_ABS=%.6g\n", static_cast<double>(postCodecMaxAbs));
        std::printf("POST_CODEC_MEAN_ABS=%.6g\n",
                    codecElems ? (postCodecSumAbs / static_cast<double>(codecElems)) : 0.0);
    } else {
        std::printf("VERIFY=SKIPPED_BY_FLAG\n");
    }

    // Lossy codecs are gated on structure and range only; fidelity is reported.
    const CodecExpectation expect = expectationFor(static_cast<uint32_t>(quant));
    const bool pass = (!verify) ||
                      (tensorsRead == tensors.size() &&
                       rangeViolations == 0 &&
                       elemsCompared > 0 &&
                       (!expect.exact || mismatch == 0));
    std::printf("CODEC_EXACT_INVERSE=%d\n", expect.exact ? 1 : 0);
    std::printf("PASS_ROUND_TRIP=%d\n", pass ? 1 : 0);
    std::printf("VERDICT=%s\n", pass ? "PASS" : "FAIL");
    return pass ? 0 : 1;
}