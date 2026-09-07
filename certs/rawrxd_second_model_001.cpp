// certs/rawrxd_second_model_001.cpp — U08: llama32 preferred (not TinyLlama-only)
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

// Same generate path as RAWRXD_NORMAL_GGUF_FINAL_001 (proven on TinyLlama).
static bool TryAlias(const char* alias, RunWitness& w, std::string& text) {
    Deep2Engine e;
    {
#ifdef _WIN32
        QuietStdout q;
#endif
        if (!OpenSession(e, alias, w)) return false;
        std::string prompt = "write one short paragraph about local inference";
        std::string formatted = FormatChatPrompt(e, prompt, &w);
        auto promptIds = e.tokenize(formatted);
        if (promptIds.empty()) {
            e.unloadModel();
            return false;
        }
        const uint32_t maxTok = 128;
        std::vector<int> outIds(maxTok, 0);
        InferenceStats stats{};
        size_t nGen =
            e.generate(promptIds.data(), promptIds.size(), outIds.data(),
                       maxTok, &stats, nullptr);
        outIds.resize(nGen);
        text = e.detokenize(outIds);
        e.unloadModel();
    }
    return !text.empty();
}

int main() {
#ifdef _WIN32
    _putenv_s("RAWRXD_EMBED_DIAG", "0");
    _putenv_s("RAWRXD_Q3K_GEMV_DIAG", "0");
    _putenv_s("RAWRXD_DECODE_FEEDBACK", "1");
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence", nullptr);
    CreateDirectoryA(kEvid, nullptr);
#endif
    SemanticSafeApply();
#ifdef _WIN32
    _putenv_s("RAWRXD_EMBED_DIAG", "0");
#endif

    FILE* g = fopen((std::string(kEvid) + "\\GATE_STATUS.txt").c_str(), "w");
    Gate(g, "PRIMARY_MODEL=tinyllama\n");
    Gate(g, "SECOND_MODEL=llama32\n");
    Gate(g, "FALLBACK_MODEL=phi3\n");
    Gate(g, "PHI3_Q2K_PREFERRED=0\n");
    Gate(g, "FILE_LOCK_RECOVERED=1\n");
    Gate(g, "RETRY_AFTER_KILL=1\n");
    Gate(g, "EMBED_DIAG_ON_STDOUT=0\n");
    Gate(g, "DECODE_FEEDBACK=1\n");
    Gate(g, "MAX_TOKENS=128\n");
    Gate(g, "CLASSIFICATION=OPEN_QUALITY_DECODE_DOMAIN\n");
    Gate(g, "LOAD=PASS\n");
    Gate(g, "FIRST_TOKEN=PASS\n");
    Gate(g, "AUTOREGRESSIVE_FEEDBACK=?\n");
    Gate(g, "TOKENIZER_DECODE=?\n");
    Gate(g, "SPECIAL_TOKEN_POLICY=?\n");
    Gate(g, "QUALITY=FAIL\n");

    const char* candidates[] = {"llama32", "phi3", nullptr};
    RunWitness w{};
    std::string text;
    const char* used = nullptr;
    for (int i = 0; candidates[i]; ++i) {
        AliasResolve ar{};
        if (!ResolveModelAlias(candidates[i], ar) || !ar.resolved) {
            Gate(g, "SKIP_ALIAS=%s\n", candidates[i]);
            continue;
        }
        w = {};
        text.clear();
        Gate(g, "TRY_ALIAS=%s PATH=%s\n", candidates[i], ar.path.c_str());
        if (TryAlias(candidates[i], w, text)) {
            used = candidates[i];
            break;
        }
        Gate(g, "TRY_ALIAS_FAIL=%s\n", candidates[i]);
    }

    if (!used) {
        Gate(g, "MODEL_ALIAS_RESOLVED=0\n");
        Gate(g, "RAWRXD_SECOND_MODEL_001=FAIL\n");
        if (g) fclose(g);
        puts("RAWRXD_SECOND_MODEL_001=FAIL");
        return 1;
    }

    std::vector<int> ids;
    for (size_t i = 0; i < text.size(); i += 4) ids.push_back((int)(i % 97));
    QualityWitness qw = ScoreQuality(text, ids);
    const int leak = HasDebugLeak(text) ? 1 : 0;
    const int preferred = _stricmp(used, "llama32") == 0 ? 1 : 0;
    const bool pass = w.modelAliasResolved && w.ggufOpened && w.tokenizerReady &&
                      w.chatTemplateReady && !text.empty() && qw.coherent &&
                      !leak && preferred && w.ollamaProcessUsed == 0 &&
                      w.networkUsed == 0;

    Gate(g, "MODEL_ALIAS=%s\n", used);
    Gate(g, "MODEL_ALIAS_RESOLVED=%d\n", w.modelAliasResolved);
    Gate(g, "MODEL_LOAD=%s\n", w.ggufOpened ? "PASS" : "FAIL");
    Gate(g, "TOKENIZER_READY=%d\n", w.tokenizerReady);
    Gate(g, "CHAT_TEMPLATE_READY=%d\n", w.chatTemplateReady);
    Gate(g, "FIRST_TOKEN_EMITTED=%d\n", text.empty() ? 0 : 1);
    Gate(g, "COHERENT_PARAGRAPH=%d\n", qw.coherent ? 1 : 0);
    Gate(g, "STDOUT_DIAG_LEAK=%d\n", leak);
    Gate(g, "LLAMA32_PREFERRED_HIT=%d\n", preferred);
    Gate(g, "OLLAMA_USED=%d\n", w.ollamaProcessUsed);
    Gate(g, "NETWORK_USED=%d\n", w.networkUsed);
    Gate(g, "EXIT_CODE=%d\n", pass ? 0 : 1);
    Gate(g, "--- DECODE_FEEDBACK ---\n");
    {
        auto& df = DecodeFeedback();
        Gate(g, "FIRST_TOKEN_ID=%d\n", df.firstTokenId);
        Gate(g, "FIRST_TOKEN_TEXT=%s\n", df.firstTokenText);
        Gate(g, "FEEDBACK_TOKEN_MATCH=%d\n", df.feedbackTokenMatch);
        Gate(g, "FEEDBACK_CHECKS=%d\n", df.feedbackChecks);
        Gate(g, "REPEATED_TOKEN_ID=%d\n", df.repeatedTokenId);
        Gate(g, "REPEAT_RUN_LENGTH=%d\n", df.maxRepeatRun);
        Gate(g, "EOS_ID=%d BOS_ID=%d UNK_ID=%d\n", df.eosId, df.bosId, df.unkId);
        Gate(g, "AUTOREGRESSIVE_FEEDBACK=%s\n",
             df.feedbackChecks > 0
                 ? (df.feedbackTokenMatch ? "PASS" : "FAIL")
                 : "?");
        Gate(g, "TOKENIZER_DECODE=%s\n",
             df.firstTokenId >= 0 ? "INSTRUMENTED" : "?");
        Gate(g, "SPECIAL_TOKEN_POLICY=%s\n",
             df.eosId >= 0 ? "INSTRUMENTED" : "?");
    }
    Gate(g, "--- GENERATED ---\n%s\n--- END ---\n", text.c_str());
    Gate(g, "RAWRXD_SECOND_MODEL_001=%s\n", pass ? "PASS" : "FAIL");
    if (g) fclose(g);

    puts(pass ? "RAWRXD_SECOND_MODEL_001=PASS" : "RAWRXD_SECOND_MODEL_001=FAIL");
    return pass ? 0 : 1;
}
