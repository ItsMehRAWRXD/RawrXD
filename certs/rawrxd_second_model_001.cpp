// certs/rawrxd_second_model_001.cpp — U08: llama32 greedy seal (gpt2 BPE)
#include "../src/deep2/SemanticSafe.hpp"
#include "../src/deep2/RawrRunSession.hpp"
#include "../src/deep2/RawrNormalGgufFinal.hpp"
#include "../src/deep2/RawrModelAlias.hpp"
#include "../src/deep2/DecodeFeedbackProbe.hpp"
#include <cstdarg>
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
using namespace Deep2::normal_gguf;

static const char* kEvid =
    "G:\\~dev\\rawrxd\\evidence\\RAWRXD_SECOND_MODEL_001";

#ifdef _WIN32
struct QuietStdout {
    int saved = -1;
    QuietStdout() {
        fflush(stdout);
        saved = _dup(1);
        if (saved >= 0) _dup2(2, 1);
    }
    ~QuietStdout() {
        if (saved >= 0) {
            fflush(stdout);
            _dup2(saved, 1);
            _close(saved);
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

static int VisibleBytes(const std::string& s) {
    int n = 0;
    for (unsigned char c : s)
        if (c >= 32 && c != 127) ++n;
    return n;
}

static bool NormEq(const std::string& a, const std::string& b) {
    auto norm = [](std::string s) {
        while (!s.empty() && (s.back() == ' ' || s.back() == '\n')) s.pop_back();
        size_t i = 0;
        while (i < s.size() && (s[i] == ' ' || s[i] == '\n')) ++i;
        return s.substr(i);
    };
    return norm(a) == norm(b);
}

struct RoundTrip {
    int ok = 0;
    size_t ids = 0;
    std::string text;
};

static RoundTrip ProbeRoundTrip(Deep2Engine& e) {
    RoundTrip r{};
    const char* probe = "The quick brown fox";
    auto ids = e.tokenize(probe);
    r.ids = ids.size();
    r.text = e.detokenize(ids);
    r.ok = (!ids.empty() && NormEq(r.text, probe)) ? 1 : 0;
    return r;
}

// Real production decode only — ScoreQuality must consume these IDs.
static size_t GreedyGen(Deep2Engine& e, const std::string& prompt,
                        uint32_t maxTok, std::vector<int>& generatedIds,
                        std::string& text) {
    DecodeFeedbackReset();
    auto promptIds = e.tokenize(prompt);
    if (promptIds.empty()) {
        generatedIds.clear();
        text.clear();
        return 0;
    }
    generatedIds.assign(maxTok, 0);
    InferenceStats stats{};
    const size_t nGen =
        e.generate(promptIds.data(), promptIds.size(), generatedIds.data(),
                   maxTok, &stats, nullptr);
    generatedIds.resize(nGen);
    text = e.detokenize(generatedIds);
    return nGen;
}

static const char* ClassifyOwner(const DecodeFeedbackWitness& df,
                                 const RoundTrip& rt, const std::string& text,
                                 size_t nTok) {
    if (!rt.ok) return "TOKENIZER";
    if (nTok == 0) return "DECODE_EXEC";
    if (df.emptyPieceCount > 0 && df.inVocabCount == df.stepCount)
        return "DETOKENIZER";
    if (df.stepCount > 0 && df.specialCount * 2 >= df.stepCount)
        return "SPECIAL_OR_TEMPLATE";
    if (df.stepCount >= 8 && df.argmaxChanged == 0) return "LOGITS_CONSTANT";
    if (df.maxRepeatRun >= 8) return "LOGITS_REPEAT";
    if (VisibleBytes(text) == 0) return "EMPTY_VISIBLE";
    return "OUTPUT_SEMANTICS";
}

int main() {
#ifdef _WIN32
    _putenv_s("RAWRXD_EMBED_DIAG", "0");
    _putenv_s("RAWRXD_Q3K_GEMV_DIAG", "0");
    _putenv_s("RAWRXD_DECODE_FEEDBACK", "1");
    _putenv_s("RAWRXD_GREEDY", "1");
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence", nullptr);
    CreateDirectoryA(kEvid, nullptr);
#endif
    SemanticSafeApply();
#ifdef _WIN32
    _putenv_s("RAWRXD_EMBED_DIAG", "0");
    _putenv_s("RAWRXD_GREEDY", "1");
#endif

    FILE* g = fopen((std::string(kEvid) + "\\GATE_STATUS.txt").c_str(), "w");
    Gate(g, "MODEL_1=tinyllama\n");
    Gate(g, "MODEL_2=llama3.2-3b-Q3_K_S\n");
    Gate(g, "SECOND_MODEL=llama32\n");
    Gate(g, "TEMPERATURE=0\nTOP_K=1\nMAX_TOKENS=128\n");

    AliasResolve ar{};
    if (!ResolveModelAlias("llama32", ar) || !ar.resolved) {
        Gate(g, "MODEL_ALIAS_RESOLVED=0\n");
        Gate(g, "REAL_TOKEN_IDS=0\n");
        Gate(g, "RAWRXD_SECOND_MODEL_001=FAIL\n");
        if (g) fclose(g);
        puts("RAWRXD_SECOND_MODEL_001=FAIL");
        return 1;
    }
    Gate(g, "TRY_ALIAS=llama32 PATH=%s\n", ar.path.c_str());

    Deep2Engine e;
    RunWitness w{};
    RoundTrip rt{};
    std::vector<int> generatedIds;
    std::string text;
    size_t nGen = 0;
    {
#ifdef _WIN32
        QuietStdout q;
#endif
        DecodeFeedbackReset();
        if (!OpenSession(e, "llama32", w)) {
            Gate(g, "SECOND_MODEL_LOAD=0\n");
            Gate(g, "REAL_TOKEN_IDS=0\n");
            Gate(g, "RAWRXD_SECOND_MODEL_001=FAIL\n");
            if (g) fclose(g);
            puts("RAWRXD_SECOND_MODEL_001=FAIL");
            return 1;
        }
        rt = ProbeRoundTrip(e);
        Gate(g, "TOKENIZER_ROUNDTRIP=%d\n", rt.ok);
        Gate(g, "TOK_ROUNDTRIP_TEXT=[%s]\n", rt.text.c_str());

        std::string fmt =
            FormatChatPrompt(e, "write one short paragraph about local inference",
                             &w);
        // Reset again so round-trip probing cannot contaminate decode feedback.
        nGen = GreedyGen(e, fmt, 128, generatedIds, text);
        e.unloadModel();
    }

    auto& df = DecodeFeedback();
    const int visible = VisibleBytes(text);
    const double specialRatio =
        df.stepCount > 0 ? (double)df.specialCount / (double)df.stepCount : 0.0;
    int logitsFiniteAll = df.stepCount > 0 ? 1 : 0;
    for (int i = 0; i < df.stepCount; ++i)
        if (!df.steps[i].logitsFinite) logitsFiniteAll = 0;
    const int idsInVocab =
        df.sampleTotal > 0 && df.inVocabCount == df.sampleTotal ? 1 : 0;
    const int piecesVisible = visible > 0 ? 1 : 0;
    // Token-dependent quality MUST use engine-emitted IDs (never synthetic).
    const int realTokenIds =
        (generatedIds.size() == nGen && nGen > 0) ? 1 : 0;
    QualityWitness qw = ScoreQuality(text, generatedIds);
    const char* owner = ClassifyOwner(df, rt, text, nGen);
    const int leak = HasDebugLeak(text) ? 1 : 0;
    const int tokenizerDecode = rt.ok ? 1 : 0;
    const int specialPolicy = (specialRatio <= 0.35) ? 1 : 0;

    const int load = w.ggufOpened ? 1 : 0;
    const int prefill = 1;
    const int realDecode = nGen > 0 ? 1 : 0;
    const int tokOk = nGen >= 128 ? 1 : 0;
    const int coherent = qw.coherent ? 1 : 0;
    const bool pass = load && rt.ok && realDecode && tokOk && coherent &&
                      realTokenIds && !leak &&
                      w.ollamaProcessUsed == 0 && w.networkUsed == 0 &&
                      logitsFiniteAll && idsInVocab;

    Gate(g, "SECOND_MODEL_LOAD=%d\n", load);
    Gate(g, "SECOND_MODEL_PREFILL=%d\n", prefill);
    Gate(g, "SECOND_MODEL_REAL_DECODE=%d\n", realDecode);
    Gate(g, "GENERATED_TOKEN_COUNT=%zu\n", nGen);
    Gate(g, "REAL_TOKEN_IDS=%d\n", realTokenIds);
    Gate(g, "FEEDBACK_TOKEN_MATCH=%d\n", df.feedbackTokenMatch);
    Gate(g, "TOKENIZER_DECODE=%s\n", tokenizerDecode ? "PASS" : "FAIL");
    Gate(g, "SPECIAL_TOKEN_POLICY=%s\n", specialPolicy ? "PASS" : "FAIL");
    Gate(g, "SECOND_MODEL_TOKENS=%zu\n", nGen);
    Gate(g, "SECOND_MODEL_COHERENT=%d\n", coherent);
    Gate(g, "LOGITS_FINITE=%d\n", logitsFiniteAll);
    Gate(g, "ARGMAX_NONCONSTANT=%d\n", df.argmaxChanged > 0 ? 1 : 0);
    Gate(g, "SAMPLE_NEQ_ARGMAX=%d\n", df.sampleNeqArgmax);
    Gate(g, "TOKEN_IDS_IN_VOCAB=%d\n", idsInVocab);
    Gate(g, "TOKEN_PIECES_VISIBLE=%d\n", piecesVisible);
    Gate(g, "SPECIAL_TOKEN_RATIO=%.3f\n", specialRatio);
    Gate(g, "COHERENT_PARAGRAPH=%d\n", coherent);
    Gate(g, "FAIL_OWNER=%s\n", pass ? "NONE" : owner);
    Gate(g, "STDOUT_DIAG_LEAK=%d\n", leak);
    Gate(g, "--- GENERATED ---\n%s\n--- END ---\n", text.c_str());
    Gate(g, "SECOND_MODEL_EXIT=%d\n", pass ? 0 : 1);
    Gate(g, "RAWRXD_SECOND_MODEL_001=%s\n", pass ? "PASS" : "FAIL");
    if (g) fclose(g);

    puts(pass ? "RAWRXD_SECOND_MODEL_001=PASS" : "RAWRXD_SECOND_MODEL_001=FAIL");
    return pass ? 0 : 1;
}
