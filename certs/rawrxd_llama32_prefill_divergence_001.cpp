// certs/rawrxd_llama32_prefill_divergence_001.cpp — U08 P1/P2 (1-token only)
#include "../src/deep2/SemanticSafe.hpp"
#include "../src/deep2/RawrRunSession.hpp"
#include "../src/deep2/RawrModelAlias.hpp"
#include "../src/deep2/DecodeFeedbackProbe.hpp"
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#endif
using namespace Deep2;
using namespace Deep2::rawr_run;

static const char* kEvid =
    "G:\\~dev\\rawrxd\\evidence\\RAWRXD_LLAMA32_PREFILL_DIVERGENCE_001";

#ifdef _WIN32
struct Quiet {
    int s = -1;
    Quiet() {
        fflush(stdout);
        s = _dup(1);
        if (s >= 0) _dup2(2, 1);
    }
    ~Quiet() {
        if (s >= 0) {
            fflush(stdout);
            _dup2(s, 1);
            _close(s);
        }
    }
};
#endif

static void Gate(FILE* g, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    if (g) {
        vfprintf(g, fmt, ap);
        fflush(g);
    }
    va_end(ap);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    fflush(stderr);
    va_end(ap);
}

struct PrefillSnap {
    int ok = 0;
    int argmax = -1;
    float logitMax = 0.f;
    float logitMin = 0.f;
    uint64_t logitsFnv = 0;
    uint64_t embedFnv = 0;
    uint64_t tokenIdsFnv = 0;
    int nTok = 0;
    int top5[5]{};
    int top5n = 0;
    std::string piece;
};

static uint64_t FnvIds(const std::vector<int>& ids) {
    uint64_t h = 14695981039346656037ull;
    for (int id : ids) {
        h ^= (uint32_t)id;
        h *= 1099511628211ull;
    }
    return h;
}

static uint64_t EmbedFnv(Deep2Engine& e, const std::vector<int>& ids) {
    const size_t dim = e.getConfig().hiddenDim;
    if (dim == 0 || ids.empty()) return 0;
    std::vector<float> buf(dim);
    uint64_t h = 14695981039346656037ull;
    const size_t n = ids.size() < 8 ? ids.size() : 8;
    for (size_t i = 0; i < n; ++i) {
        if (!e.embedToken(ids[i], buf.data())) continue;
        for (size_t d = 0; d < dim; d += (dim > 64 ? dim / 64 : 1)) {
            uint32_t bits = 0;
            std::memcpy(&bits, &buf[d], 4);
            h ^= bits;
            h *= 1099511628211ull;
        }
        h ^= (uint32_t)ids[i];
        h *= 1099511628211ull;
    }
    return h;
}

static PrefillSnap OneToken(Deep2Engine& e, const std::vector<int>& ids) {
    PrefillSnap s{};
    if (ids.empty()) return s;
    s.nTok = (int)ids.size();
    s.tokenIdsFnv = FnvIds(ids);
    s.embedFnv = EmbedFnv(e, ids);
    DecodeFeedbackReset();
    std::vector<int> out(1, 0);
    InferenceStats st{};
#ifdef _WIN32
    Quiet q;
#endif
    size_t n = e.generate(ids.data(), ids.size(), out.data(), 1, &st, nullptr);
    auto& df = DecodeFeedback();
    if (n == 0 || df.stepCount < 1) return s;
    s.ok = 1;
    s.argmax = df.steps[0].argmax;
    s.logitMax = df.steps[0].logitMax;
    s.logitMin = df.steps[0].logitMin;
    s.logitsFnv = df.logitsFnv0;
    s.top5n = df.top5Count;
    for (int i = 0; i < s.top5n; ++i) s.top5[i] = df.top5Ids[i];
    s.piece = df.firstTokenText;
    return s;
}

static void DumpSnap(FILE* g, const char* tag, const PrefillSnap& s) {
    Gate(g, "%s_OK=%d\n", tag, s.ok);
    Gate(g, "%s_NTOK=%d\n", tag, s.nTok);
    Gate(g, "%s_TOKEN_IDS_FNV=%016llx\n", tag, (unsigned long long)s.tokenIdsFnv);
    Gate(g, "%s_EMBED_FNV=%016llx\n", tag, (unsigned long long)s.embedFnv);
    Gate(g, "%s_LOGITS_FNV=%016llx\n", tag, (unsigned long long)s.logitsFnv);
    Gate(g, "%s_ARGMAX=%d\n", tag, s.argmax);
    Gate(g, "%s_LOGIT_MAX=%.6f\n", tag, s.logitMax);
    Gate(g, "%s_LOGIT_MIN=%.6f\n", tag, s.logitMin);
    Gate(g, "%s_PIECE=[%s]\n", tag, s.piece.c_str());
    Gate(g, "%s_TOP5=", tag);
    for (int i = 0; i < s.top5n; ++i) {
        if (i) Gate(g, ",");
        Gate(g, "%d", s.top5[i]);
    }
    Gate(g, "\n");
}

int main() {
#ifdef _WIN32
    _putenv_s("RAWRXD_DECODE_FEEDBACK", "1");
    _putenv_s("RAWRXD_GREEDY", "1");
    _putenv_s("RAWRXD_EMBED_DIAG", "0");
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence", nullptr);
    CreateDirectoryA(kEvid, nullptr);
#endif
    SemanticSafeApply();

    FILE* g = fopen((std::string(kEvid) + "\\GATE_STATUS.txt").c_str(), "w");
    Gate(g, "GATE=RAWRXD_LLAMA32_PREFILL_DIVERGENCE_001\n");
    Gate(g, "MODE=P1_PROMPT_SENSITIVITY+P2_TEMPLATE_BYPASS\n");
    Gate(g, "MAX_TOKENS=1\n");

    AliasResolve ar{};
    if (!ResolveModelAlias("llama32", ar) || !ar.resolved) {
        Gate(g, "MODEL_RESOLVED=0\n");
        Gate(g, "RAWRXD_LLAMA32_PREFILL_DIVERGENCE_001=FAIL\n");
        if (g) fclose(g);
        return 1;
    }
    Gate(g, "MODEL_PATH=%s\n", ar.path.c_str());

    Deep2Engine e;
    RunWitness w{};
    {
#ifdef _WIN32
        Quiet q;
#endif
        if (!OpenSession(e, "llama32", w)) {
            Gate(g, "LOAD=0\n");
            Gate(g, "RAWRXD_LLAMA32_PREFILL_DIVERGENCE_001=FAIL\n");
            if (g) fclose(g);
            return 1;
        }
    }
    Gate(g, "LOAD=1\n");

    const char* promptA = "The capital of France is";
    const char* promptB = "Write a haiku about volcanic ash and copper wire.";
    Gate(g, "PROMPT_A=%s\n", promptA);
    Gate(g, "PROMPT_B=%s\n", promptB);

    // P1: chat-templated A vs B
    std::string fmtA = FormatChatPrompt(e, promptA, &w);
    std::string fmtB = FormatChatPrompt(e, promptB, &w);
    auto idsA = e.tokenize(fmtA);
    auto idsB = e.tokenize(fmtB);
    PrefillSnap a = OneToken(e, idsA);
    PrefillSnap b = OneToken(e, idsB);
    DumpSnap(g, "A", a);
    DumpSnap(g, "B", b);

    const int tokenIdsDiffer = (a.tokenIdsFnv != b.tokenIdsFnv) ? 1 : 0;
    const int embedDiffer = (a.embedFnv != b.embedFnv) ? 1 : 0;
    const int logitsDiffer = (a.logitsFnv != b.logitsFnv) ? 1 : 0;
    const int argmaxDiffer = (a.argmax != b.argmax) ? 1 : 0;
    Gate(g, "P1_TOKEN_IDS_DIFFER=%d\n", tokenIdsDiffer);
    Gate(g, "P1_EMBED_FINGERPRINT_DIFFER=%d\n", embedDiffer);
    Gate(g, "P1_FINAL_LOGITS_DIFFER=%d\n", logitsDiffer);
    Gate(g, "P1_ARGMAX_DIFFER=%d\n", argmaxDiffer);
    Gate(g, "ARGMAX_A=%d\n", a.argmax);
    Gate(g, "ARGMAX_B=%d\n", b.argmax);

    // P2: bare vs template for prompt A
    auto bareIds = e.tokenize(promptA);
    PrefillSnap bare = OneToken(e, bareIds);
    DumpSnap(g, "BARE", bare);
    const int p2Tok = (bare.tokenIdsFnv != a.tokenIdsFnv) ? 1 : 0;
    const int p2Emb = (bare.embedFnv != a.embedFnv) ? 1 : 0;
    const int p2Log = (bare.logitsFnv != a.logitsFnv) ? 1 : 0;
    const int p2Arg = (bare.argmax != a.argmax) ? 1 : 0;
    Gate(g, "P2_TOKEN_IDS_DIFFER=%d\n", p2Tok);
    Gate(g, "P2_EMBED_DIFFER=%d\n", p2Emb);
    Gate(g, "P2_LOGITS_DIFFER=%d\n", p2Log);
    Gate(g, "P2_ARGMAX_DIFFER=%d\n", p2Arg);
    Gate(g, "ARGMAX_BARE=%d\n", bare.argmax);

    // Interpretation
    const char* owner = "UNKNOWN";
    if (!tokenIdsDiffer)
        owner = "TOKENIZE_IDENTICAL"; // unexpected
    else if (!embedDiffer)
        owner = "EMBED_COLLAPSE";
    else if (!logitsDiffer)
        owner = "PREFILL_MATH_COLLAPSE"; // embeds differ, logits same → attn/ffn/rope/gqa
    else if (!argmaxDiffer)
        owner = "LOGITS_DIFF_ARGMAX_SAME"; // soft collapse
    else
        owner = "PROMPT_SENSITIVE_OK"; // P1 healthy; quality issue elsewhere

    if (owner[0] == 'P' && p2Log == 0 && p2Tok == 1)
        owner = "TEMPLATE_COLLAPSE"; // templated logits ignore vs bare? rare
    if (embedDiffer && !logitsDiffer)
        owner = "PREFILL_MATH_COLLAPSE";
    if (p2Tok && p2Log && !argmaxDiffer && a.argmax == 44061)
        owner = "PREFILL_MATH_COLLAPSE"; // still ussen lock across paths

    Gate(g, "FAIL_OWNER=%s\n", owner);
    Gate(g, "FIRST_COLLAPSE_LAYER=?\n");
    Gate(g, "FIRST_COLLAPSE_STAGE=%s\n",
         !embedDiffer ? "EMBED"
                      : (!logitsDiffer ? "PREFILL_FORWARD_OR_LOGITS"
                                       : (argmaxDiffer ? "NONE" : "ARGMAX_TIE")));

    // Cert "PASS" means divergence probe ran and localized — not U08 quality PASS.
    const bool probeOk = a.ok && b.ok && bare.ok && tokenIdsDiffer;
    Gate(g, "RAWRXD_LLAMA32_PREFILL_DIVERGENCE_001=%s\n",
         probeOk ? "PASS" : "FAIL");
    e.unloadModel();
    if (g) fclose(g);
    puts(probeOk ? "RAWRXD_LLAMA32_PREFILL_DIVERGENCE_001=PASS"
                 : "RAWRXD_LLAMA32_PREFILL_DIVERGENCE_001=FAIL");
    return probeOk ? 0 : 1;
}
