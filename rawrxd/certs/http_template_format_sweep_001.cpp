// ============================================================================
// http_template_format_sweep_001.cpp
// RAWRXD_HTTP_TEMPLATE_FORMAT_SWEEP_001
//
// The previous entry (RAWRXD_HTTP_TEMPLATE_ROOT_CAUSE_002) concluded that the
// template "asks for a role vocabulary the tokenizer does not have", and that
// this was therefore the fault. That conclusion was WRONG, and the error came
// from trusting the local GGUF detection without checking what the model was
// actually trained on.
//
// The upstream TinyLlama-1.1B-Chat-v1.0 tokenizer_config.json declares
// added_tokens_decoder with exactly three entries -- <unk>=0, <s>=1, </s>=2 --
// and a chat_template whose role markers ARE "<|user|>", "<|system|>",
// "<|assistant|>". So:
//
//   * the markers are the model's REAL training format, not a misdetection
//   * they were deliberately NOT added as special tokens
//   * the model therefore SAW them during training as ordinary text pieces
//
// The probe measured EXACT_VOCAB_ENTRY=0 and concluded "incompatible". The
// correct reading is "this is how the model was trained". A gate that treats
// absence-from-vocab as evidence of a defect will condemn correct behavior.
//
// The remaining suspect is therefore WHITESPACE. The upstream Jinja template
// is ambiguous about the newlines around its block tags, and different Jinja
// configurations (trim_blocks, lstrip_blocks) legitimately produce different
// byte sequences. formatPhi3 emits:
//
//     <|user|>\n{content}</s><|assistant|>
//
// which has NO newline after </s> and none after <|assistant|>. Whether that
// matches training is an empirical question, not an arguable one.
//
// This sweep measures every plausible byte-level variant of the SAME model on
// the SAME engine with the SAME seed and reports which recovers semantics.
// It changes no product code and asserts no winner: it prints a table.
// ============================================================================

#include "deep2/Deep2Engine.h"
#include "deep2/Tokenizer.hpp"
#include "deep2/GGUFLoader.hpp"
#include "deep2/ChatTemplate.hpp"

#include <cstdio>
#include <cctype>
#include <string>
#include <vector>

namespace {

struct Oracle { const char* name; const char* prompt; const char* expected; };

const std::vector<Oracle>& oracles() {
    static const std::vector<Oracle> v = {
        {"capital_of_france", "The capital of France is",        "paris"},
        {"opposite_of_hot",    "The opposite of hot is",          "cold"},
        {"first_letter",       "The first letter of the alphabet is", "a"},
    };
    return v;
}

// Candidate renderings. All are the SAME Zephyr role vocabulary; they differ
// only in whitespace, which is exactly the dimension under test.
struct Variant {
    const char* name;
    std::string (*render)(const std::string&);
};

// RAWRXD_SWEEP_002: the shipped template path. Five variants below are
// hand-rolled guesses using hardcoded Zephyr role markers; this one is not.
// Deep2::ChatTemplate::initFromGGUF reads tokenizer.chat_template from the model
// and detects the family from that string, so this variant is model-derived by
// construction and exercises the code the OpenAI server actually calls.
const Deep2::ChatTemplate* g_productTemplate = nullptr;

std::string productTemplateRender(const std::string& u) {
    if (g_productTemplate) return g_productTemplate->formatSingle(u);
    return u;
}

std::string rawRender(const std::string& u) { return u; }

// formatPhi3 as implemented in ChatTemplate.cpp today.
std::string phi3Current(const std::string& u) {
    return "<|user|>\n" + u + "</s><|assistant|>";
}

// Zephyr as commonly transcribed: newline after </s>, newline after the
// generation marker.
std::string zephyrNewlines(const std::string& u) {
    return "<|user|>\n" + u + "</s>\n<|assistant|>\n";
}

// Same, without the trailing newline after the generation marker.
std::string zephyrNoTrail(const std::string& u) {
    return "<|user|>\n" + u + "</s>\n<|assistant|>";
}

// Jinja with trim_blocks=false leaves a newline per loop iteration.
std::string jinjaLoopNewline(const std::string& u) {
    return "\n<|user|>\n" + u + "</s>\n<|assistant|>\n";
}

// The trailing space variant seen in some Zephyr conversions.
std::string zephyrSpace(const std::string& u) {
    return "<|user|>\n" + u + "</s>\n<|assistant|> ";
}

std::string lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

bool wholeWordMatch(const std::string& hay, const std::string& needle) {
    if (needle.empty()) return false;
    size_t pos = 0;
    auto isWord = [](unsigned char c) { return std::isalnum(c) != 0 || c == '_'; };
    while ((pos = hay.find(needle, pos)) != std::string::npos) {
        const bool l = pos == 0 || !isWord(static_cast<unsigned char>(hay[pos - 1]));
        const size_t e = pos + needle.size();
        const bool r = e >= hay.size() || !isWord(static_cast<unsigned char>(hay[e]));
        if (l && r) return true;
        pos = e;
    }
    return false;
}

std::string escapeForPrint(const std::string& s) {
    std::string o;
    for (unsigned char c : s) {
        if (c == '\n') { o += "\\n"; }
        else if (c == '\r') { o += "\\r"; }
        else if (c == '\t') { o += "\\t"; }
        else if (c < 0x20) { char b[8]; std::snprintf(b, sizeof b, "\\x%02X", c); o += b; }
        else o.push_back(static_cast<char>(c));
    }
    return o;
}

// Fragment leak: any bar-delimited role word in the output.
bool fragLeak(const std::string& t) {
    static const char* roles[] = {"user", "system", "assistant"};
    for (const char* r : roles) {
        size_t q = 0;
        while ((q = t.find(r, q)) != std::string::npos) {
            const bool l = q > 0 && t[q - 1] == '|';
            const size_t e = q + std::char_traits<char>::length(r);
            const bool rr = e < t.size() && t[e] == '|';
            if (l || rr) return true;
            q = e;
        }
    }
    return false;
}

} // namespace

int main(int argc, char** argv) {
    std::string model;
    for (int i = 1; i < argc; ++i)
        if (std::string(argv[i]) == "--model" && i + 1 < argc) model = argv[++i];
    if (model.empty()) {
        std::fprintf(stderr, "usage: http_template_format_sweep_001 --model <gguf>\n");
        return 2;
    }

    // Upstream-added token census, printed so the sweep's premise is checkable
    // rather than assumed.
    {
        Deep2::GGUFLoader ld;
        if (ld.load(model)) {
            std::vector<std::string> toks;
            if (ld.getMetaStringArray("tokenizer.ggml.tokens", toks)) {
                std::printf("VOCAB_SIZE=%zu\n", toks.size());
                int control = 0, userDefined = 0;
                std::vector<int32_t> types;
                if (ld.getMetaInt32Array("tokenizer.ggml.token_type", types) &&
                    types.size() == toks.size()) {
                    for (int32_t t : types) {
                        if (t == 3) ++control;
                        if (t == 4) ++userDefined;
                    }
                }
                std::printf("TOKEN_TYPE_CONTROL=%d\n", control);
                std::printf("TOKEN_TYPE_USER_DEFINED=%d\n", userDefined);
                std::printf("ADDED_TOKENS_IN_VOCAB=%d\n", control + userDefined);
                std::printf("PREMISE_MODEL_HAS_NO_ADDED_ROLE_TOKENS=%d\n",
                            (control + userDefined) <= 3 ? 1 : 0);

                // RAWRXD_SWEEP_002_ROLE_VOCAB
                // The header comment says this census exists so "the sweep's
                // premise is checkable rather than assumed". It did not actually
                // check the one thing the sweep depends on: the five Zephyr
                // variants below hardcode <|user|>, <|system|>, <|assistant|>,
                // <|end|> and </s>. On a model whose control tokens are something
                // else those strings tokenize as ordinary text, every template
                // variant fails identically, and the resulting table is a
                // vocabulary-mismatch result wearing a numerics result's clothes.
                // PREMISE_MODEL_HAS_NO_ADDED_ROLE_TOKENS is a TinyLlama-specific
                // threshold (<=3) and is NOT a general claim about the model; it
                // must not be read as one.
                {
                    static const char* kMarkers[] = {
                        "<|system|>", "<|user|>", "<|assistant|>", "<|end|>", "</s>"
                    };
                    std::string haystack;
                    haystack.reserve(toks.size() * 8);
                    for (const std::string& t : toks) {
                        haystack += '\n';
                        haystack += t;
                    }
                    int present = 0;
                    for (const char* m : kMarkers) {
                        const bool in = haystack.find(m) != std::string::npos;
                        std::printf("ROLE_MARKER=%-14s PRESENT_IN_VOCAB=%d\n", m, in ? 1 : 0);
                        if (in) ++present;
                    }
                    const int kTotal = static_cast<int>(sizeof(kMarkers) / sizeof(kMarkers[0]));
                    std::printf("ROLE_MARKERS_PRESENT=%d/%d\n", present, kTotal);
                    std::printf("HARDCODED_ZEPHYR_VARIANTS_USABLE=%d\n",
                                present == kTotal ? 1 : 0);
                }

                // Layer-0 tensor census. Printed because the FFN layout is the
                // thing being decided here: a gated model that ships a FUSED
                // gate+up tensor cannot simply be admitted, because the CPU
                // forward path treats a missing wGate as "simple MLP" and would
                // then compute silu(up) instead of silu(gate)*up -- wrong
                // numbers that look entirely plausible. The split point is
                // derived from the measured row count, not assumed.
                std::printf("\n-- LAYER0_TENSORS --\n");
                for (const char* nm : {"token_embd", "output_norm",
                                       "blk.0.attn_norm", "blk.0.attn_qkv",
                                       "blk.0.attn_q", "blk.0.attn_k", "blk.0.attn_v",
                                       "blk.0.attn_output",
                                       "blk.0.ffn_norm",
                                       "blk.0.ffn_gate", "blk.0.ffn_up", "blk.0.ffn_down"}) {
                    // GGUF weight dims are stored [in, out] -- shape[0] is the INPUT width and
                // shape[1] is the OUTPUT row count. Reading shape[0] as the row
                // count produced FFN_FUSED_GATE_UP_SUSPECTED=0 for a tensor that
                // is in fact exactly 2x fused, which is the axis mistake this
                // project keeps paying for.
                const std::string key = std::string(nm) + ".weight";
                    if (const auto* t = ld.getTensor(key)) {
                        const uint32_t in  = t->shape.size() > 0 ? static_cast<uint32_t>(t->shape[0]) : 0;
                        const uint32_t out = t->shape.size() > 1 ? static_cast<uint32_t>(t->shape[1]) : 0;
                        std::printf("TENSOR name=%s in=%u out=%u bytes=%llu\n",
                                    nm, in, out,
                                    static_cast<unsigned long long>(t->sizeBytes));
                    } else {
                        std::printf("TENSOR name=%s ABSENT\n", nm);
                    }
                }
                // A gated model ships ONE tensor holding gate rows followed by up
                // rows. ffn_down consumes the intermediate dim, so the fused
                // tensor's out dim must be exactly 2x that.
                if (const auto* up = ld.getTensor("blk.0.ffn_up.weight")) {
                    if (const auto* dn = ld.getTensor("blk.0.ffn_down.weight")) {
                        const uint32_t upOut = static_cast<uint32_t>(up->shape[1]);
                        const uint32_t dnIn  = static_cast<uint32_t>(dn->shape[0]);
                        std::printf("FFN_FUSED_GATE_UP_SUSPECTED=%d\n",
                                    upOut == dnIn * 2 ? 1 : 0);
                        std::printf("FFN_UP_OUT=%u FFN_DOWN_IN=%u IMPLIED_INTERMEDIATE=%u EXPECTED_FUSED_OUT=%u\n",
                                    upOut, dnIn, dnIn, dnIn * 2);
                    }
                } else if (const auto* gate = ld.getTensor("blk.0.ffn_gate.weight")) {
                    std::printf("FFN_FUSED_GATE_UP_SUSPECTED=0 SPLIT_GATE_OUT=%u\n",
                                static_cast<uint32_t>(gate->shape[1]));
                }
                std::printf("\n");
            }
        }
    }

    Deep2::Deep2Engine eng;
    Deep2::ModelLoadDiag diag;
    if (!eng.loadModel(model, &diag)) {
        std::fprintf(stderr, "MODEL_LOAD=0 %s\n", diag.message.c_str());
        return 3;
    }

    // RAWRXD_SWEEP_002: initialise the shipped template path for this same model
    // and print exactly what it renders for the first oracle, so the table can
    // show the real prompt bytes rather than only their downstream effect.
    {
        Deep2::ChatTemplate tmpl;
        const bool ok = tmpl.initFromGGUF(model);
        g_productTemplate = ok ? &tmpl : nullptr;
        std::printf("\n-- PRODUCT_TEMPLATE --\n");
        std::printf("PRODUCT_TEMPLATE_INIT=%d\n", ok ? 1 : 0);
        std::printf("PRODUCT_TEMPLATE_TYPE=%s\n", ok ? tmpl.getTypeName() : "(none)");
        if (ok) {
            const Deep2::ChatTemplateConfig& cfg = tmpl.getConfig();
            std::printf("PRODUCT_TEMPLATE_BOS=%s EOS=%s ADD_BOS=%d\n",
                        cfg.bosToken.c_str(), cfg.eosToken.c_str(),
                        cfg.addBos ? 1 : 0);
            std::printf("PRODUCT_TEMPLATE_RENDER=%s\n",
                        escapeForPrint(tmpl.formatSingle(oracles()[0].prompt)).c_str());
        }
    }

    Deep2::GenerationOptions base;
    base.maxTokens = 24;
    base.temperature = 0.0f;
    base.topK = 1;
    base.topP = 1.0f;
    base.seed = 1234;

    // --quick: one variant, one oracle, few tokens. The full 6x3 sweep is ~40
    // minutes on CPU at 0.30 tok/s, which is far too slow to iterate on while
    // deciding a single question. The diagnostic is a CONTRAST between runs,
    // not the absolute quality, so a short generation is sufficient to see
    // whether the fused path is consumed and whether the halves are ordered
    // the way the split assumes.
    // Scan every argument rather than a fixed index: `--model <path> --quick`
    // puts the flag at argv[3], and checking one index silently ran the full
    // 6x3 sweep instead of the probe. A flag that can be ignored without any
    // error is the same class of defect as a gate that cannot fail.
    bool quick = false;
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--quick") quick = true;
    }
    if (quick) {
        base.maxTokens = 8;
        const char* o = std::getenv("RAWRXD_FUSED_GATE_UP_ORDER");
        std::printf("QUICK=1 MAX_TOKENS=%d FUSED_GATE_UP_ORDER=%s\n",
                    base.maxTokens, o ? o : "gate_up(default)");
    }

    const std::vector<Variant> variants = {
        {"raw_no_template",      rawRender},
        {"product_chattemplate", productTemplateRender},
        {"phi3_current",         phi3Current},
        {"zephyr_newlines",      zephyrNewlines},
        {"zephyr_no_trailing",   zephyrNoTrail},
        {"jinja_loop_newline",   jinjaLoopNewline},
        {"zephyr_trailing_sp",   zephyrSpace},
    };

    std::printf("\nVARIANTS=%zu\n", quick ? 1u : variants.size());
    std::printf("ORACLES=%zu\n", quick ? 1u : oracles().size());
    // RAWRXD_SWEEP_002: --quick breaks out of the loop after the FIRST variant,
    // so its sample comes from raw_no_template -- a prompt with no chat template
    // at all. That was silently unreadable, and a raw-prompt continuation was
    // mistaken for evidence about chat formatting. Name the variant explicitly.
    if (quick) {
        std::printf("QUICK_VARIANT=%s\n", variants[0].name);
        std::printf("QUICK_COVERS_TEMPLATE_VARIANTS=0"
                    "  (run without --quick for the full sweep)\n");
    }
    std::printf("\n%-22s %-8s %-8s %-8s %-8s\n",
                "VARIANT", "SEMANTIC", "CONTAM", "GEN_TOKS", "SAMPLE");

    std::string firstSample;
    for (const Variant& v : variants) {
        int pass = 0, contam = 0;
        const size_t nOracles = quick ? 1u : oracles().size();
        for (size_t oi = 0; oi < nOracles; ++oi) {
            const Oracle& o = oracles()[oi];
            const std::string prompt = v.render(o.prompt);
            std::string text;
            eng.reset();
            auto r = eng.generateStream(prompt, base,
                [&](int32_t, const std::string& piece) { text += piece; return true; });
            if (wholeWordMatch(lower(text), lower(o.expected))) ++pass;
            if (fragLeak(text)) ++contam;
            if (firstSample.empty()) firstSample = text;
        }
        if (quick) break;
        std::printf("%-22s %d/%-6zu %d/%-6zu %-8s %s\n",
                    v.name, pass, nOracles, contam, nOracles,
                    "greedy", escapeForPrint(firstSample).c_str());
    }

    if (quick) {
        std::printf("QUICK_SAMPLE=%s\n", escapeForPrint(firstSample).c_str());
    } else {
        std::printf("\nNOTE=no winner is asserted; the table is the result\n");
    }
    return 0;
}