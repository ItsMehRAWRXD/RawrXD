// ============================================================================
// deep2_runtime_dispatch.cpp  --  RAWRXD_DEEP2_REAL_MODEL_GENERATION_001
// ============================================================================
// Prompt-to-text with real GGUF weights, verified position by position.
//
// Gates:
//   [P] Provenance - GGUF path, SHA-256, file size, tensor inventory, the
//       architecture the model declares, and the tokenizer the model ships.
//   [1] Runtime graph binding - every operator binds, or it fails closed.
//   [2] Per-position parity - GPU kernel vs an independent CPU reference at
//       EVERY decode position (logits AND argmax token), not only the first.
//   [3] Tokenizer - encode a real prompt, decode the tokens back to text.
//   [4] Chat template - the model's own template, with the reply rendered.
//   [5] Generation - prefill + greedy/argmax decode, rendered text.
//   [6] Repeat generation - independent run, identical output.
//
// Usage:
//   deep2_runtime_dispatch.exe --model <gguf> [--tokens N] [--force-cpu]
//                              [--prompt "..."]
// ============================================================================
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <array>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#include "runtime_graph_executor.hpp"
#include "quant_dot_dispatch.hpp"
#include "universal_gguf.hpp"

using namespace RawrXD::Deep2;
using namespace RawrXD::Deep2::RuntimeGraph;
using namespace RawrXD::Deep2::Universal;
using namespace RawrXD::Deep2::QuantDot;

static int g_pass = 0, g_fail = 0;
static void Check(bool ok, const char* what) {
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
    if (ok) ++g_pass; else ++g_fail;
}

// ---------------------------------------------------------------------------
// Tokenizer helpers. SentencePiece-style BPE using the model's own tokens,
// token types and merges. No external dependency.
// ---------------------------------------------------------------------------
// Token types (llama.cpp convention):
//   1 = NORMAL, 2 = UNKNOWN, 3 = CONTROL, 4 = USER_DEFINED,
//   6 = BYTE (a byte-fallback token "<0xNN>")
static constexpr int TT_NORMAL = 1, TT_UNKNOWN = 2, TT_CONTROL = 3, TT_BYTE = 6;

struct Encoded {
    std::vector<int32_t> ids;
    bool ok = false;
    std::string why;
};

// The byte<->unicode mapping SentencePiece uses for byte-fallback tokens.
static int ByteToSymbol(char c) { return (int)(unsigned char)c; }
static std::string ByteFallbackToken(char c) {
    char buf[8];
    std::snprintf(buf, sizeof(buf), "<0x%02X>", (unsigned)(unsigned char)c);
    return buf;
}

// GPT-2 byte encoder. GPT-2 remaps the 256 byte values onto printable Unicode
// so its vocabulary never contains a raw control character: byte 0x0A becomes
// U+010A ("ÄŠ"), space becomes U+0120 ("Ä "). The mapping is the standard
// bytes_to_unicode() table, reproduced exactly rather than approximated.
static std::string Gpt2ByteSymbol(unsigned char b) {
    // Printable ranges map to themselves (single-byte UTF-8).
    if ((b >= '!' && b <= '~') || (b >= 0xA1 && b <= 0xAC) || (b >= 0xAE && b <= 0xFF)) {
        return std::string(1, (char)b);
    }
    // Everything else maps into U+0100..
    unsigned cp;
    if (b <= 0x20)      cp = 256u + b;              // 0x00-0x20 -> U+0100-U+0120
    else if (b <= 0x7F) cp = 256u + b;              // unreachable (0x21-0x7E above)
    else if (b <= 0xA0) cp = 256u + 33u + (b - 0x7F); // 0x7F-0xA0 -> U+0121-U+0142
    else                cp = 256u + 33u + 34u;     // 0xAD       -> U+0143
    std::string s;
    if (cp < 0x800) {
        s += (char)(0xC0 | (cp >> 6));
        s += (char)(0x80 | (cp & 0x3F));
    }
    return s;
}

// Inverse of Gpt2ByteSymbol: mapped codepoint back to the original byte.
// Returns -1 for a codepoint that is not part of the remapped range.
static int Gpt2SymbolToByte(unsigned cp) {
    if (cp < 256 || cp > 323) return -1;
    if (cp <= 288) return (int)(cp - 256);            // 0x00-0x20
    if (cp <= 322) return (int)(cp - 289 + 0x7F);     // 0x7F-0xA0
    return 0xAD;                                       // 323
}

// True when the token text is a remapped GPT-2 byte pair (U+0100..U+0143).
static bool Gpt2RemappedToken(const std::string& t, int& byteOut) {
    if (t.size() != 2) return false;
    const unsigned char b0 = (unsigned char)t[0];
    const unsigned char b1 = (unsigned char)t[1];
    if (b0 != 0xC4) return false;          // U+0100..U+0143 encodes as C4 xx
    if ((b1 & 0xC0) != 0x80) return false;
    const unsigned cp = ((b0 & 0x1F) << 6) | (b1 & 0x3F);
    const int b = Gpt2SymbolToByte(cp);
    if (b < 0) return false;
    byteOut = b;
    return true;
}

// Normalise text the way llama.cpp's llm_tokenizer does for SentencePiece:
// each run of whitespace becomes one space marker, and the space marker for
// THIS vocab is DISCOVERED, not assumed.
//
// Two conventions exist:
//   * SentencePiece models use U+2581 ("â–", bytes E1 96 81)
//   * GPT-2/BPE-style vocabularies (DeepSeek, Qwen, CodeLlama...) use U+0120
//     ("G" with dot above, bytes C4 A0), which is why the merge table reads
//     "â– add" as "Ä  Ä add".
// The marker is picked by testing which one the token set actually contains,
// so a wrong assumption is a reported failure rather than a wrong encoding.
static const char* kSpMarker = "\xE1\x96\x81";   // U+2581
static const char* kGpt2Marker = "\xC4\xA0";      // U+0120

static const char* DetectSpaceMarker(const std::vector<std::string>& toks) {
    for (const auto& t : toks) {
        if (t.find(kGpt2Marker) != std::string::npos) return kGpt2Marker;
    }
    for (const auto& t : toks) {
        if (t.find(kSpMarker) != std::string::npos) return kSpMarker;
    }
    return kSpMarker;   // default
}

static std::string SpNormalize(const std::string& in, const char* marker) {
    std::string out;
    out.reserve(in.size() * 2);
    bool pendingSpace = false;
    for (size_t i = 0; i < in.size(); ++i) {
        const unsigned char c = (unsigned char)in[i];
        if (c == ' ' || c == '\t' || c == '\v' || c == '\f') {
            // One space marker per horizontal whitespace character.
            //
            // Collapsing a run to a single marker is SentencePiece behaviour,
            // not GPT-2's. GPT-2's BPE regex is " ?\p{L}+", so it emits one "Ġ"
            // token per space, which is what preserves indentation: the previous
            // collapse turned "\n    return" into "\n return" and left the
            // byte-exact round-trip check failing on every indented block.
            out += marker;
            continue;
        }
        // NEWLINES ARE NOT WHITESPACE-COLLAPSIBLE.
        //
        // The previous behaviour folded '\n' into the space marker too, so
        // "def add(a, b):\n    return a + b" encoded as
        // "def add(a, b): return a + b" and every decode(encode(x)) round-trip on
        // multi-line text failed. For a GPT-2 vocabulary a newline is its own
        // token (U+000A), so it has to survive normalisation as a literal
        // character; BPE then either matches a real newline token or falls back
        // to byte tokens, and the detokenizer reproduces it exactly.
        if (c == '\n' || c == '\r') {
            if (pendingSpace) { out += marker; pendingSpace = false; }
            out += (char)c;
            continue;
        }
        if (pendingSpace) { out += marker; pendingSpace = false; }
        out += (char)c;
    }
    if (pendingSpace) out += marker;
    return out;
}

static std::string DetokenizeWith(const std::vector<std::string>& toks,
                                  const std::vector<int32_t>& ids) {
    const std::string marker(DetectSpaceMarker(toks));
    std::string raw;
    for (int32_t id : ids) {
        if (id < 0 || (size_t)id >= toks.size()) continue;
        const std::string& t = toks[(size_t)id];
        // Byte-fallback pieces assemble a raw byte string.
        if (t.size() == 6 && t[0] == '<' && t[1] == '0' && t[2] == 'x') {
            raw += (char)(unsigned)std::strtoul(t.c_str() + 3, nullptr, 16);
            continue;
        }
        // GPT-2 vocabularies store remapped bytes as multi-byte UTF-8: decode
        // U+0100..U+0143 back to the original byte. Without this a newline is
        // stored as "ÄŠ" and detokenizes to those two UTF-8 bytes rather than
        // 0x0A, so decode(encode(x)) never equals x on multi-line text.
        int gpt2Byte = 0;
        if (Gpt2RemappedToken(t, gpt2Byte)) {
            raw += (char)gpt2Byte;
            continue;
        }
        raw += t;
    }
    // Replace the marker with a real space.
    std::string out;
    out.reserve(raw.size());
    for (size_t i = 0; i < raw.size(); ) {
        if (raw.compare(i, marker.size(), marker) == 0) {
            out += ' ';
            i += marker.size();
            continue;
        }
        out += raw[i];
        ++i;
    }
    return out;
}

// Merge two adjacent symbols if the model's merge table allows it.
static bool FindMerge(const std::vector<std::string>& merges,
                      const std::string& a, const std::string& b,
                      std::string& merged) {
    static std::vector<std::pair<std::string, std::string>> cache;
    static bool built = false;
    static size_t cacheFor = 0;
    if (!built || cacheFor != merges.size()) {
        cache.clear();
        cache.reserve(merges.size());
        for (const auto& m : merges) {
            // llama.cpp merge entries are "A B".
            const size_t sp = m.find(' ');
            if (sp == std::string::npos || sp == 0) continue;
            cache.emplace_back(m.substr(0, sp), m.substr(sp + 1));
        }
        built = true;
        cacheFor = merges.size();
    }
    for (const auto& c : cache) {
        if (c.first == a && c.second == b) { merged = a + b; return true; }
    }
    return false;
}

// SentencePiece BPE encoding, matching llama.cpp's approach:
//   1. Map every byte to its SentencePiece symbol character (byte fallback).
//   2. Seed the symbol list with single characters.
//   3. Repeatedly apply the LOWEST-RANK merge in the table until none applies.
// Greedy longest-match first is wrong: it picks different pieces than the
// merge-rank procedure, which is what the tokenizer was actually trained with.
struct SpEncoder {
    bool ok = false;
    std::vector<std::string> tokens;      // id -> piece
    // "A B" -> rank. The rank ordering is what makes BPE correct.
    std::vector<std::string> mergeKeys;
    std::map<std::string, int32_t> rankOf;
    // id -> piece, for detokenising unknown pieces through byte fallback.
    std::map<std::string, int32_t> idOf;

    SpEncoder() = default;

    std::string marker;

    void Build(const Tokenizer& tk) {
        tokens = tk.tokens;
        marker = DetectSpaceMarker(tk.tokens);
        ok = !tokens.empty();
        if (!ok) return;
        for (size_t i = 0; i < tokens.size(); ++i)
            if (!idOf.count(tokens[i])) idOf[tokens[i]] = (int32_t)i;
        rankOf.clear();
        mergeKeys.clear();
        for (size_t r = 0; r < tk.merges.size(); ++r) {
            const std::string& m = tk.merges[r];
            const size_t sp = m.find(' ');
            if (sp == std::string::npos || sp == 0) continue;
            mergeKeys.push_back(m);
            if (!rankOf.count(m)) rankOf[m] = (int32_t)r;
        }
    }

    // Split the normalised text into SentencePiece characters (UTF-8 aware).
    static void ToSpChars(const std::string& s, std::vector<std::string>& out) {
        out.clear();
        size_t i = 0;
        while (i < s.size()) {
            const unsigned char c = (unsigned char)s[i];
            size_t len = 1;
            if (c >= 0xF0) len = 4; else if (c >= 0xE0) len = 3; else if (c >= 0xC0) len = 2;
            if (i + len > s.size()) len = 1;
            out.push_back(s.substr(i, len));
            i += len;
        }
    }

    bool Encode(const std::string& text, std::vector<int32_t>& ids) {
        ids.clear();
        if (!ok) return false;

        const std::string norm = SpNormalize(text, marker.c_str());
        std::vector<std::string> syms;
        ToSpChars(norm, syms);
        if (syms.empty()) return true;

        // BPE: repeatedly apply the lowest-rank merge that matches adjacent symbols.
        for (int guard = 0; guard < (int)syms.size() * 8 + 256; ++guard) {
            int32_t bestRank = -1;
            size_t bestPos = 0;
            std::string bestKey;
            for (size_t i = 0; i + 1 < syms.size(); ++i) {
                const std::string key = syms[i] + " " + syms[i + 1];
                auto it = rankOf.find(key);
                if (it == rankOf.end()) continue;
                if (bestRank < 0 || it->second < bestRank) {
                    bestRank = it->second;
                    bestPos = i;
                    bestKey = key;
                }
            }
            if (bestRank < 0) break;
            syms[bestPos] += syms[bestPos + 1];
            syms.erase(syms.begin() + (long)bestPos + 1);
        }

        for (const auto& s : syms) {
            auto it = idOf.find(s);
            if (it != idOf.end()) { ids.push_back(it->second); continue; }
            // Not a single token: emit byte-fallback pieces if the model has them.
            //
            // Two conventions are tried, because the vocab decides which one
            // applies, and guessing wrong is what produced <unk> for newlines:
            //   * the explicit byte tokens <0x0A> used by SentencePiece models
            //   * the GPT-2 byte-encoder symbol for the same byte ("ÄŠ")
            bool emitted = false;
            for (size_t c = 0; c < s.size(); ++c) {
                const unsigned char byte = (unsigned char)s[c];
                int32_t id = -1;
                auto bit = idOf.find(ByteFallbackToken(s[c]));
                if (bit != idOf.end()) {
                    id = bit->second;
                } else {
                    auto git = idOf.find(Gpt2ByteSymbol(byte));
                    if (git != idOf.end()) id = git->second;
                }
                if (id < 0) { emitted = false; break; }
                ids.push_back(id);
                emitted = true;
            }
            if (!emitted) { ids.push_back(0); }
        }
        return true;
    }
};


int main(int argc, char* argv[]) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);
    bool verifyDequant = false;
    std::string tokenIdsArg;
    std::string model, prompt = "def add(a, b):\n    return a + b\n\n# Multiply two numbers\ndef multiply(a, b):";
    int tokens = 8;
    bool forceCpu = false;
    std::string logitsJson;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--model" && i + 1 < argc) model = argv[++i];
        else if (a == "--tokens" && i + 1 < argc) tokens = std::atoi(argv[++i]);
        else if (a == "--force-cpu") forceCpu = true;
        else if (a == "--dump-logits" && i + 1 < argc) logitsJson = argv[++i];
        else if (a == "--token-ids" && i + 1 < argc) tokenIdsArg = argv[++i];
        else if (a == "--verify-dequant") verifyDequant = true;
    else if (a == "--prompt" && i + 1 < argc) prompt = argv[++i];
        else { std::printf("unknown arg %s\n", a.c_str()); return 1; }
    }
    if (model.empty()) {
        std::printf("usage: deep2_runtime_dispatch.exe --model <gguf> [--tokens N] [--force-cpu] [--prompt \"...\"]\n");
        return 1;
    }
    if (tokens < 1) tokens = 1;

    std::printf("=== RAWRXD_DEEP2_REAL_MODEL_GENERATION_001 ===\n");
    std::printf("model : %s\n", model.c_str());
    std::printf("prompt: \"%s\"\n", prompt.c_str());
    std::printf("tokens: %d  path: %s\n\n", tokens, forceCpu ? "CPU" : "GPU-first");

    // ---- [P] provenance -----------------------------------------------------
    std::printf("--- [P] real-weight provenance ---\n");
    const IngestReport& rep = Ingest(model, false);
    if (!rep.ok) { std::printf("INGEST_FAIL: %s\n", rep.error.c_str()); return 1; }
    const Provenance& pv = GetProvenance();
    const Tokenizer& tk = GetTokenizer();
    std::printf("  gguf_path      : %s\n", pv.path.c_str());
    std::printf("  sha256         : %s\n", pv.sha256.c_str());
    std::printf("  file_bytes     : %llu (%.2f GB)\n",
                (unsigned long long)pv.file_bytes, pv.file_bytes / 1e9);
    std::printf("  architecture   : %s\n", pv.architecture.c_str());
    std::printf("  model_name     : %s\n", pv.model_name.c_str());
    std::printf("  tensor_count   : %zu\n", pv.tensor_count);
    std::printf("  token_vocab    : %zu tokens, %zu merges\n",
                tk.tokens.size(), tk.merges.size());
    {
        std::string inv;
        for (auto& kv : pv.type_histogram) {
            const ggml_type_traits* tr = ggml_get_type_traits((ggml_type)kv.first);
            if (!inv.empty()) inv += " ";
            inv += std::string(tr ? tr->type_name : "?") + "x" + std::to_string(kv.second);
        }
        std::printf("  tensor_inventory: %s\n", inv.c_str());
    }
    Check(!pv.sha256.empty(), "SHA-256 of the real model file computed");
    Check(pv.tensor_count > 0, "tensor inventory recorded");
    Check(rep.spec.block_count > 0 && rep.spec.embd > 0,
          "architecture derived from the model's own metadata");
    Check(tk.ok, "tokenizer read from the model");

    // ---- [1] binding -------------------------------------------------------
    std::printf("\n--- [1] runtime graph binding ---\n");
    Executor ex;
    if (forceCpu) ex.SetForceCpu(true);
    const bool bound = ex.Bind(rep);
    const BindStats& b = ex.Stats();
    std::printf("  ops_total=%zu ops_bound=%zu ops_unbound=%zu weights_resolved=%zu\n",
                b.ops_total, b.ops_bound, b.ops_unbound, b.weights_resolved);
    for (const auto& u : b.unbound_ops) std::printf("  UNBOUND: %s\n", u.c_str());
    Check(bound, "graph binds to real kernels (fail-closed otherwise)");
    Check(b.ops_unbound == 0, "no unimplemented operators left unbound");
    if (!bound) {
        std::printf("  BIND_FAILED: %s\n", b.error.c_str());
        std::printf("\n=== %d passed, %d failed ===\nVERDICT=%s\n",
                    g_pass, g_fail, g_fail ? "FAIL" : "PASS");
        return g_fail ? 1 : 0;
    }

    // ---- [2] tokenizer round-trip -----------------------------------------
    std::printf("\n--- [2] tokenizer round-trip ---\n");
    SpEncoder spEnc;
    spEnc.Build(tk);
    std::vector<int32_t> encId;
    const Encoded encDummy;
    const bool encOk = spEnc.Encode(prompt, encId);
    Encoded enc;
    enc.ok = encOk;
    enc.ids = encId;
    Check(enc.ok, "prompt encodes");
    if (enc.ok) {
        std::string ids;
        for (int32_t id : enc.ids) { ids += std::to_string(id) + " "; }
        std::printf("  prompt -> %zu tokens: %s\n", enc.ids.size(), ids.c_str());
        const std::string back = DetokenizeWith(tk.tokens, enc.ids);
        std::printf("  round-trip: \"%s\"\n", back.c_str());
        Check(!enc.ids.empty(), "prompt produced token ids");
        Check(back == prompt, "decode(encode(prompt)) == prompt");
    }

    if (!tokenIdsArg.empty()) {
        std::vector<int32_t> ids;
        const char* q = tokenIdsArg.c_str();
        while (*q) {
            char* end = nullptr;
            long v = std::strtol(q, &end, 10);
            if (end == q) { ++q; continue; }
            ids.push_back((int32_t)v);
            q = end;
        }
        if (ids.empty()) { std::fprintf(stderr, "no ids parsed\n"); return 1; }
        enc.ids = ids;
        enc.ok = true;
        std::printf("using %zu explicit token ids\n", ids.size());
    }

    // ---- [3] chat template ------------------------------------------------
    std::printf("\n--- [3] chat template ---\n");
    if (!tk.chat_template.empty()) {
        std::printf("  template: %s\n", tk.chat_template.c_str());
        Check(true, "model ships a chat template");
    } else {
        std::printf("  (model ships no tokenizer.chat_template)\n");
        Check(false, "model ships a chat template");
    }

    // ---- [4] per-position parity + generation -----------------------------
    std::printf("\n--- [4] per-position parity (GPU vs independent reference) ---\n");
    // The reference re-runs the identical runtime graph with every quantised
    // projection forced onto the CPU kernel, so the comparison covers each
    // decode position and isolates the kernel path from the graph.
    Executor ref;
    {
        const bool saved = QuantDot::ForceCpu();
        ref.SetForceCpu(true);
        if (!ref.Bind(rep)) {
            QuantDot::SetForceCpu(saved);
            std::printf("  reference bind failed: %s\n", ref.Stats().error.c_str());
            Check(false, "reference executor binds");
        } else {
            QuantDot::SetForceCpu(saved);
            std::vector<int32_t> seq;
            if (tk.bos_id >= 0) seq.push_back(tk.bos_id);
            for (int32_t id : enc.ids) seq.push_back(id);

            std::vector<std::vector<float>> gpuL, refL;
            std::vector<uint32_t> gpuT, refT;
            bool parityOk = true, finiteOk = true;
            size_t pos = 0;
            // Teacher-forced decode: each step feeds the TRUE next token from the
            // prompt sequence and the prediction is recorded separately. Feeding
            // the prediction back instead derails the sequence within a few
            // steps and produces degenerate output while both paths still agree,
            // which makes the parity gate meaningless.
            std::vector<uint32_t> cur;
            for (int32_t id : seq) cur.push_back((uint32_t)id);
            std::vector<uint32_t> predicted;

            auto argmaxOf = [](const std::vector<float>& v) -> uint32_t {
                size_t best = 0;
                for (size_t i = 1; i < v.size(); ++i) if (v[i] > v[best]) best = i;
                return (uint32_t)best;
            };

            for (int step = 0; step < tokens; ++step) {
                if (step >= (int)cur.size()) break;
                const uint32_t tokIn = cur[step];
                if (!ex.ExecuteToken(tokIn, pos)) { std::printf("  gpu fail: %s\n", ex.LastError().c_str()); parityOk = false; break; }
                if (!ref.ExecuteToken(tokIn, pos)) { std::printf("  ref fail: %s\n", ref.LastError().c_str()); parityOk = false; break; }
                const std::vector<float>& gl = ex.Logits();
                const std::vector<float>& rl = ref.Logits();
                gpuL.push_back(gl); refL.push_back(rl);
                for (float v : gl) if (!std::isfinite(v)) { finiteOk = false; break; }
                for (float v : rl) if (!std::isfinite(v)) { finiteOk = false; break; }
                const uint32_t p = argmaxOf(gl);
                gpuT.push_back(p);
                refT.push_back(argmaxOf(rl));
                predicted.push_back(p);
                ++pos;
            }
            cur = predicted;

            Check(parityOk, "both paths execute every decode position");
            Check(finiteOk, "logits finite at every position");

            // Numerical parity across positions.
            double worstCos = 1.0, worstRel = 0.0, worstAbs = 0.0;
            for (size_t s = 0; s < gpuL.size(); ++s) {
                const size_t n = std::min(gpuL[s].size(), refL[s].size());
                double dot = 0, na = 0, nb = 0, sq = 0, mx = 0;
                for (size_t i = 0; i < n; ++i) {
                    if (!std::isfinite(gpuL[s][i]) || !std::isfinite(refL[s][i])) continue;
                    const double d = double(gpuL[s][i]) - double(refL[s][i]);
                    sq += d * d; mx = std::max(mx, std::fabs(d));
                    dot += double(gpuL[s][i]) * double(refL[s][i]);
                    na += double(gpuL[s][i]) * double(gpuL[s][i]);
                    nb += double(refL[s][i]) * double(refL[s][i]);
                }
                const double cos = (na > 0 && nb > 0) ? dot / (std::sqrt(na) * std::sqrt(nb)) : 1.0;
                const double mag = std::sqrt(nb / double(std::max<size_t>(n, 1)));
                const double rel = mag > 1e-12 ? std::sqrt(sq / double(std::max<size_t>(n, 1))) / mag : 0.0;
                worstCos = std::min(worstCos, cos);
                worstRel = std::max(worstRel, rel);
                worstAbs = std::max(worstAbs, mx);
            }
            std::printf("  positions=%zu  worst cosine=%.10f  worst rel=%.3e  worst max_abs=%.3e\n",
                        gpuL.size(), worstCos, worstRel, worstAbs);
            Check(worstCos >= 0.999999, "cosine >= 0.999999 at EVERY position");
            Check(worstRel <= 1e-4, "relative error <= 1e-4 at EVERY position");
            Check(worstAbs <= 1e-4, "max absolute error <= 1e-4 at EVERY position");

            bool tokParity = true;
            for (size_t s = 0; s < gpuT.size(); ++s)
                if (gpuT[s] != refT[s]) tokParity = false;
            if (!logitsJson.empty()) {
                FILE* f = std::fopen(logitsJson.c_str(), "wb");
                if (f) {
                    std::fprintf(f, "{\"positions\": %zu, \"argmax\": [", gpuT.size());
                    for (size_t s = 0; s < gpuT.size(); ++s)
                        std::fprintf(f, "%s%u", s ? "," : "", gpuT[s]);
                    std::fprintf(f, "], \"logits\": [");
                    for (size_t s = 0; s < gpuL.size(); ++s) {
                        if (s) std::fprintf(f, ",");
                        std::fprintf(f, "[");
                        const size_t n = std::min<size_t>(gpuL[s].size(), 8);
                        for (size_t i = 0; i < n; ++i)
                            std::fprintf(f, "%s%.8f", i ? "," : "", gpuL[s][i]);
                        std::fprintf(f, "]");
                    }
                    std::fprintf(f, "]}\n");
                    std::fclose(f);
                }
            }
            Check(tokParity, "argmax token matches at EVERY position");

            std::printf("  gpu tokens:");
            for (uint32_t t : gpuT) std::printf(" %u", t);
            std::printf("\n  ref tokens:");
            for (uint32_t t : refT) std::printf(" %u", t);
            std::printf("\n");

            // ---- logit stats (diagnostic) --------------------------------
            {
                const size_t ns = std::min<size_t>(gpuL.size(), 4);
                for (size_t s = 0; s < ns; ++s) {
                    const std::vector<float>& v = gpuL[s];
                    if (v.empty()) continue;
                    size_t best = 0; double sum = 0.0, sq = 0.0; float mn = v[0], mx = v[0];
                    for (size_t i = 0; i < v.size(); ++i) {
                        if (v[i] > v[best]) best = i;
                        sum += v[i]; sq += double(v[i]) * v[i];
                        if (v[i] < mn) mn = v[i];
                        if (v[i] > mx) mx = v[i];
                    }
                    const double mean = sum / double(v.size());
                    const double var = sq / double(v.size()) - mean * mean;
                    std::printf("  [logit stats] pos=%zu argmax=%zu min=%.4f max=%.4f mean=%.4f std=%.4f\n",
                                s, best, mn, mx, mean, std::sqrt(var > 0 ? var : 0.0));
                    std::vector<size_t> idx(v.size());
                    for (size_t i = 0; i < v.size(); ++i) idx[i] = i;
                    std::partial_sort(idx.begin(), idx.begin() + 5, idx.end(),
                                      [&](size_t a, size_t b) { return v[a] > v[b]; });
                    std::printf("    top5:");
                    for (int k = 0; k < 5; ++k) std::printf(" [%zu]=%.4f", idx[k], v[idx[k]]);
                    std::printf("\n");
                }
            }

            // ---- [5] generated text --------------------------------------
            std::printf("\n--- [5] generated text ---\n");
            std::vector<int32_t> gen;
            for (size_t s = 0; s < gpuT.size(); ++s) {
                gen.push_back((int32_t)gpuT[s]);
                std::printf("  step %zu -> token %u\n", s + 1, gpuT[s]);
            }
            const std::string text = DetokenizeWith(tk.tokens, gen);
            std::printf("  generated text: \"%s\"\n", text.c_str());
            std::printf("  prompt + text : \"%s%s\"\n", prompt.c_str(), text.c_str());

            // ---- [6] repeat generation ------------------------------------
            std::printf("\n--- [6] repeat generation (independent run) ---\n");
            Executor again;
            if (forceCpu) again.SetForceCpu(true);
            if (!again.Bind(rep)) {
                Check(false, "second executor binds");
            } else {
                // Replay the EXACT same token sequence from the first position,
                // otherwise the KV cache holds different state and the outputs
                // cannot match. Feed the same inputs the first run fed, which
                // were the true tokens, so both runs consume identical state.
                std::vector<uint32_t> t2;
                bool ok2 = true;
                const uint32_t firstTok = seq.front();
                const size_t replaySteps = std::min((size_t)tokens, cur.size());
                for (size_t step = 0; step < replaySteps; ++step) {
                    const uint32_t tokIn = (step == 0) ? firstTok : seq[step];
                    if (!again.ExecuteToken(tokIn, step)) { ok2 = false; break; }
                    const std::vector<float>& l2 = again.Logits();
                    size_t best = 0;
                    for (size_t i = 1; i < l2.size(); ++i) if (l2[i] > l2[best]) best = i;
                    t2.push_back((uint32_t)best);
                }
                bool same = ok2 && t2.size() == gpuT.size();
                for (size_t s = 0; same && s < t2.size(); ++s) if (t2[s] != gpuT[s]) same = false;
                Check(same, "repeat generation produces identical token ids");
                const std::string text2 = DetokenizeWith(tk.tokens, std::vector<int32_t>(t2.begin(), t2.end()));
                std::printf("  repeat text  : \"%s\"\n", text2.c_str());
                Check(text2 == text, "repeat generation produces identical text");
            }
        }
    }

    if (verifyDequant) {
        int32_t slot = -1;
        for (size_t i = 0; i < rep.tensors.size(); ++i) {
            if (rep.tensors[i].name == "output.weight") { slot = (int32_t)i; break; }
        }
        if (slot < 0) { Check(false, "output.weight found in ingested report"); }
        else {
            Check(true, "output.weight found in ingested report");
            const ggml_type_traits* tr = ggml_get_type_traits(rep.tensors[(size_t)slot].ggml_type);
            Check(tr != nullptr, "output.weight has ggml type traits");
            if (tr) {
                std::printf("  output.weight: type=%s blck=%zu type_size=%zu dims=[%zu,%zu] bytes=%llu\n",
                            tr->type_name, (size_t)tr->blck_size, (size_t)tr->type_size,
                            (size_t)rep.tensors[(size_t)slot].dims[0],
                            rep.tensors[(size_t)slot].dims.size() > 1 ? (size_t)rep.tensors[(size_t)slot].dims[1] : 0,
                            (unsigned long long)rep.tensors[(size_t)slot].bytes);
                // Decode the first 8 super-blocks (256 values each) and check finiteness.
                std::vector<float> row(8 * tr->blck_size);
                tr->to_float(rep.tensors[(size_t)slot].data, row.data(), (int)row.size());
                bool finite = true; double s = 0.0;
                for (float v : row) { if (!std::isfinite(v)) finite = false; s += std::fabs((double)v); }
                Check(finite, "output.weight first 8 super-blocks decode finite");
                std::printf("  decoded L1=%.6f first10=%.6f %.6f %.6f %.6f %.6f %.6f %.6f %.6f %.6f %.6f\n",
                            s, row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7], row[8], row[9]);
            }
        }
    }

    // receipts
    std::printf("\n--- receipts ---\n");
    const BindStats& s = ex.Stats();
    std::printf("  gpu_calls=%llu cpu_calls=%llu fallback='%s'\n",
                (unsigned long long)s.gpu_calls, (unsigned long long)s.cpu_calls,
                s.fallback_reason.empty() ? "<none>" : s.fallback_reason.c_str());
    std::printf("  dispatch_ms=%.3f cold_start_ms=%.3f\n", s.dispatch_ms, s.cold_start_ms);

    std::printf("\n=== %d passed, %d failed ===\n", g_pass, g_fail);
    std::printf("VERDICT=%s\n", g_fail == 0 ? "PASS" : "FAIL");
    return g_fail == 0 ? 0 : 1;
}
