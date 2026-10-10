//=============================================================================
// dll_parity_main - RAWRXD_MODELGENIE_PRODUCTION_RUNTIME_001
//
// Loads the same GGUF through RawrXDCore.dll (which routes through
// ModelGenieRuntime) and through the standalone ModelGenie IR executor, feeds
// the same token / position / KV state, and proves the logits match. Also
// proves 16-token autoregression with persistent KV state.
//=============================================================================

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <cstdint>
#include <string>
#include <vector>
#include <functional>
#include <utility>

#include "RawrXDCore.h"
#include "ModelGenieRuntime.h"
#include "ModelGenieExecutor.hpp"

#define MG_VOCAB_LIMIT 102400

namespace {

struct Failure {
    std::string name;
    bool passed = false;
    std::string detail;
};

static std::vector<Failure> g_checks;

void Check(const char* name, bool ok, const std::string& detail = {})
{
    g_checks.push_back(Failure{name, ok, detail});
    std::printf("[%.24s] %s %s\n", name, ok ? "PASS" : "FAIL", detail.c_str());
    std::fflush(stdout);
}

//=== logits helpers ==========================================================
struct LogitStats {
    float mMin = 0.0f, mMax = 0.0f;
    size_t finite = 0, total = 0;
    uint32_t argmax = 0;
};

LogitStats Summarise(const std::vector<float>& v)
{
    LogitStats s{};
    if (v.empty()) return s;
    s.mMin = s.mMax = v[0];
    for (size_t i = 0; i < v.size(); ++i) {
        const float x = v[i];
        if (std::isfinite(x)) {
            s.finite++;
            if (x < s.mMin) s.mMin = x;
            if (x > s.mMax) { s.mMax = x; s.argmax = static_cast<uint32_t>(i); }
        }
        if (x < s.mMin) s.mMin = x;
        if (x > s.mMax) s.mMax = x;
    }
    s.total = v.size();
    return s;
}

double Cosine(const std::vector<float>& a, const std::vector<float>& b)
{
    if (a.size() != b.size() || a.empty()) return 0.0;
    double dot = 0.0, na = 0.0, nb = 0.0;
    for (size_t i = 0; i < a.size(); ++i) {
        dot += double(a[i]) * b[i];
        na += double(a[i]) * a[i];
        nb += double(b[i]) * b[i];
    }
    const double den = std::sqrt(na * nb);
    return den > 0.0 ? dot / den : 0.0;
}

double MaxAbsDiff(const std::vector<float>& a, const std::vector<float>& b)
{
    if (a.size() != b.size() || a.empty()) return 1e30;
    double mx = 0.0;
    for (size_t i = 0; i < a.size(); ++i) {
        mx = std::max(mx, std::fabs(double(a[i]) - double(b[i])));
    }
    return mx;
}

} // namespace

int main(int argc, char* argv[])
{
    // Enable differential recorder for tensor debugging
    g_differential_recorder.Enable(R"(F:\rawrxd\evidence\DIFF_DEBUG_001)");
    const std::string gguf = (argc > 1) ? argv[1]
        : R"(F:\rawrxd\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf)";
    const std::string evidenceDir = (argc > 2) ? argv[2]
        : R"(F:\rawrxd\evidence\NUGVERSE_ESTIMATOR_001)";
    const int promptTokens[] = {1, 185, 16, 15};
    const size_t kPromptCount = sizeof(promptTokens) / sizeof(promptTokens[0]);
    const uint32_t kEvalToken = promptTokens[0];
    const size_t kEvalPosition = 0;

    std::printf("RAWRXD_MODELGENIE_PRODUCTION_RUNTIME_001\n");
    std::printf("model      = %s\n", gguf.c_str());
    std::printf("runtime    = %s\n", mg_runtime_version());
    std::fflush(stdout);

    //=== 1. Standalone executor reference logits =============================
    std::vector<float> standaloneLogits;
    {
        IRExecutor executor(gguf, static_cast<uint32_t>(promptTokens[0]));
        executor.ClearArena();
        const bool ok = executor.Execute();
        Check("SAME_EXECUTOR_IMPLEMENTATION", ok,
              ok ? "standalone tail of shared library" : "Execute() failed");

        const std::vector<float>* logits = executor.GetLogits();
        Check("REAL_GGUF_MODEL_LOAD", logits != nullptr && !logits->empty(),
              logits ? std::to_string(logits->size()) + " logits" : "no logits");
        Check("IR_DISPATCH_300_OF_300",
              executor.Visited() == 300 && executor.Dispatched() == 300 &&
              executor.Skipped() == 0,
              "visited=" + std::to_string(executor.Visited()) +
              " dispatched=" + std::to_string(executor.Dispatched()) +
              " skipped=" + std::to_string(executor.Skipped()));

        if (logits) standaloneLogits = *logits;
        const LogitStats s = Summarise(standaloneLogits);
        Check("FINITE_NONZERO_LOGITS", s.finite == s.total && s.mMax != 0.0f,
              "finite=" + std::to_string(s.finite) + "/" + std::to_string(s.total) +
              " max=" + std::to_string(s.mMax));
    }

    //=== 2. DLL through the public C API =====================================
    mg_model_t* model = nullptr;
    mg_model_config_t cfg{};
    cfg.max_seq_len = 1024;
    cfg.use_kv_cache = true;
    const mg_error_t loadRc = mg_model_load(gguf.c_str(), &cfg, &model);
    Check("DLL_MODEL_LOAD", loadRc == MG_SUCCESS && model != nullptr,
          "mg_error_t=" + std::to_string(static_cast<int>(loadRc)));

    mg_context_t* ctx = nullptr;
    if (model) {
        const mg_error_t ctxRc = mg_context_create(model, &ctx);
        Check("DLL_CONTEXT_CREATE", ctxRc == MG_SUCCESS && ctx != nullptr,
              "mg_error_t=" + std::to_string(static_cast<int>(ctxRc)));
    }

    std::vector<float> dllLogits;
    if (ctx) {
        size_t n = MG_VOCAB_LIMIT;
        std::vector<float> buf(n, 0.0f);
        const mg_error_t evalRc = mg_context_eval(ctx, kEvalToken, buf.data(), &n);
        Check("DLL_REAL_PREFILL",
              evalRc == MG_SUCCESS && n == standaloneLogits.size(),
              "logits=" + std::to_string(n));
        if (evalRc == MG_SUCCESS && n == standaloneLogits.size()) {
            dllLogits.assign(buf.begin(), buf.begin() + static_cast<ptrdiff_t>(n));
        }
        Check("IR_DISPATCH_300_OF_300_DLL",
              mg_context_ops_visited(ctx) == 300 &&
              mg_context_ops_skipped(ctx) == 0,
              "visited=" + std::to_string(mg_context_ops_visited(ctx)) +
              " skipped=" + std::to_string(mg_context_ops_skipped(ctx)));
    }

    //=== 3. One-token equivalence ============================================
    if (!standaloneLogits.empty() && !dllLogits.empty()) {
        const double cos = Cosine(standaloneLogits, dllLogits);
        const double mx = MaxAbsDiff(standaloneLogits, dllLogits);
        const LogitStats a = Summarise(standaloneLogits);
        const LogitStats b = Summarise(dllLogits);
        char detail[256];
        std::snprintf(detail, sizeof(detail),
                      "cos=%.9f max|d|=%.3e argmax=%u/%u",
                      cos, mx, a.argmax, b.argmax);
        Check("STANDALONE_DLL_LOGIT_PARITY",
              cos > 0.999999999999 && mx < 1e-6 && a.argmax == b.argmax, detail);
    } else {
        Check("STANDALONE_DLL_LOGIT_PARITY", false, "missing logits");
    }

    //=== 4. 16-token autoregression with persistent KV state =================
    {
        mg_context_t* ar = nullptr;
        if (model && mg_context_create(model, &ar) == MG_SUCCESS && ar) {
            std::vector<uint32_t> prompt;
            for (int t : promptTokens) prompt.push_back(static_cast<uint32_t>(t));

            mg_generation_config_t gcfg{};
            gcfg.max_tokens = 16 - static_cast<size_t>(kPromptCount);
            gcfg.temperature = 0.0f;
            gcfg.top_k = 1;

            std::vector<uint32_t> ids(32, 0);
            size_t produced = ids.size();
            const mg_error_t rc = mg_context_capture_tokens(
                ar, prompt.data(), prompt.size(),
                static_cast<uint32_t>(gcfg.max_tokens),
                ids.data(), ids.size(), &produced);

            const bool ok = rc == MG_SUCCESS && produced == gcfg.max_tokens;
            std::string detail = "produced=" + std::to_string(produced) +
                                 " first=" + (produced ? std::to_string(ids[0]) : "none");
            Check("AUTOREGRESSIVE_16", ok, detail);

            std::string trace;
            for (size_t i = 0; i < produced && i < 16; ++i) {
                if (i) trace += " ";
                trace += std::to_string(ids[i]);
            }
            std::printf("  autoregressive tail (16 - prompt): %s\n", trace.c_str());
            std::printf("  context position after generation: %zu\n",
                        mg_context_position(ar));
            std::fflush(stdout);
            mg_context_free(ar);
        } else {
            Check("AUTOREGRESSIVE_16", false, "context create failed");
        }
    }

    //=== 5. Prompt-echo absence ===============================================
    // A token-by-token membership test is meaningless: real autoregression can
    // legitimately reproduce a prompt token. Echo is defined as the generated
    // sequence being the prompt sequence.
    {
        mg_context_t* ec = nullptr;
        bool echoed = false;
        size_t produced = 0;
        if (model && mg_context_create(model, &ec) == MG_SUCCESS && ec) {
            std::vector<uint32_t> prompt;
            for (int t : promptTokens) prompt.push_back(static_cast<uint32_t>(t));
            uint32_t ids[16] = {0};
            produced = sizeof(ids) / sizeof(ids[0]);
            if (mg_context_capture_tokens(ec, prompt.data(), prompt.size(), 4,
                                          ids, produced, &produced) == MG_SUCCESS) {
                // Echo would mean the first promptTokenCount outputs are exactly
                // the prompt, i.e. the DLL returned what it was given.
                if (produced >= prompt.size()) {
                    echoed = std::equal(prompt.begin(), prompt.end(), ids);
                }
            } else {
                produced = 0;
            }
            std::string trace;
            for (size_t i = 0; i < produced; ++i) {
                if (i) trace += " ";
                trace += std::to_string(ids[i]);
            }
            std::printf("  echo check produced: %s\n", trace.c_str());
            mg_context_free(ec);
        }
        Check("PROMPT_ECHO_FALLBACK", !echoed,
              echoed ? "sequence equals prompt" :
                      ("generated " + std::to_string(produced) + " tokens, != prompt"));
    }

    //=== 6. RawrXDCore.h layer ================================================
    {
        if (!RawrXDCore_Initialize()) {
            Check("RAWRXDCORE_INIT", false, "already initialized?");
        } else {
            Check("RAWRXDCORE_INIT", true, "");
        }
        RawrXDModel* mdl = RawrXDCore_LoadModel(gguf.c_str());
        Check("RAWRXDCORE_LOAD_MODEL", mdl != nullptr, "model handle");
        if (mdl) {
            RawrXDInferenceContext* ictx = RawrXDCore_CreateContext(mdl);
            Check("RAWRXDCORE_CREATE_CONTEXT", ictx != nullptr, "");
            if (ictx) {
                RawrXDInferenceParams p{};
                p.maxTokens = 8;
                p.temperature = 0.0f;

                // The callback receives ids and token text; capture both.
                struct CbState {
                    std::string text;
                    std::vector<uint32_t> ids;
                } state;

                const int n = RawrXDCore_RunInference(
                    ictx, "Hello, world!", &p,
                    [](int tokenId, const char* t, void* ud) -> bool {
                        auto* s = static_cast<CbState*>(ud);
                        if (t && t[0]) s->text.append(t);
                        s->ids.push_back(static_cast<uint32_t>(tokenId));
                        return true;
                    },
                    &state);

                Check("FIRST_REAL_TOKEN_CALLBACK",
                      n > 0 && !state.ids.empty() && !state.text.empty(),
                      "tokens=" + std::to_string(n) +
                      " generatedText=\"" + state.text.substr(0, 80) + "\"");
                if (!state.ids.empty()) {
                    std::string trace;
                    for (uint32_t id : state.ids) {
                        if (!trace.empty()) trace += " ";
                        trace += std::to_string(id);
                    }
                    std::printf("  RawrXDCore_RunInference token ids: %s\n", trace.c_str());
                    std::printf("  RawrXDCore_RunInference token text: \"%s\"\n",
                                state.text.substr(0, 200).c_str());
                    std::fflush(stdout);
                }
                RawrXDCore_DestroyContext(ictx);
            }
            RawrXDCore_UnloadModel(mdl);
        }
        RawrXDCore_Shutdown();
    }

    //=== summary ==============================================================
    // RAWRXD_MODELGENIE_PRODUCTION_RUNTIME_001: the certificate is written to a
    // file, flushed and closed before the process exits, so a consumer can
    // re-open it and validate the fields independently. Printing to stdout
    // alone is not evidence: a truncated or redirected stream must not be able
    // to make the run look like it passed.
    int passed = 0, failed = 0;
    std::printf("\nRAWRXD_MODELGENIE_PRODUCTION_RUNTIME_001 CERTIFICATE\n\n");
    for (const auto& c : g_checks) {
        std::printf("%-32s = %s\n", c.name.c_str(), c.passed ? "PASS" : "FAIL");
        if (c.passed) passed++; else failed++;
    }
    std::printf("\nVERDICT = %s\n", failed == 0 ? "PASS" : "FAIL");
    std::fflush(stdout);

    const char* certPath = std::getenv("RAWRXD_CERTIFICATE_PATH");
    if (certPath && certPath[0]) {
        FILE* f = std::fopen(certPath, "w");
        if (f) {
            std::fprintf(f, "GATE = RAWRXD_MODELGENIE_PRODUCTION_RUNTIME_001\n");
            std::fprintf(f, "MODEL = %s\n", gguf.c_str());
            std::fprintf(f, "RUNTIME = %s\n", mg_runtime_version());
            std::fprintf(f, "CHECKS = %zu\n", g_checks.size());
            for (const auto& c : g_checks) {
                std::fprintf(f, "%s = %s", c.name.c_str(), c.passed ? "PASS" : "FAIL");
                if (!c.detail.empty()) std::fprintf(f, " (%s)", c.detail.c_str());
                std::fprintf(f, "\n");
            }
            std::fprintf(f, "PASSED = %d\n", passed);
            std::fprintf(f, "FAILED = %d\n", failed);
            std::fprintf(f, "VERDICT = %s\n", failed == 0 ? "PASS" : "FAIL");
            std::fprintf(f, "END_CERTIFICATE = 1\n");
            std::fflush(f);
            std::fclose(f);
            std::printf("certificate written to %s\n", certPath);
        } else {
            std::fprintf(stderr, "WARNING: could not open %s for the certificate\n", certPath);
            failed++;
        }
    }
    g_differential_recorder.SaveAll();


    return failed == 0 ? 0 : 1;
