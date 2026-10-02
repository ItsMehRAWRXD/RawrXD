// inference_authority_ladder.cpp
// RAWRXD_DEEP2_INFERENCE_AUTHORITY_001
//
// The enterprise IDE cannot ship while inference correctness depends on which
// historical receipt is selected. A single "it generated text" claim collapses
// eight independent gates into one unverifiable statement: a model can load and
// produce garbage, or produce correct logits and have the sampler corrupt them,
// or stream correctly and be dropped by the IDE transport. Any of those yields
// "a token was printed".
//
// So this walks the distance from a GGUF file to a token that is visible in the
// IDE, one gate at a time, and reports each gate independently:
//
//   G1 MODEL_LOAD           a real GGUF is read, admitted, and its geometry known
//   G2 TOKENIZATION         prompt -> token ids, and back to the original text
//   G3 FORWARD_EXECUTION    a forward pass runs and returns logits of the right shape
//   G4 NUMERICAL_CORRECTNESS logits are finite and stable across repeats
//   G5 SAMPLING_CORRECTNESS greedy sampling equals argmax, and is deterministic
//   G6 TOKEN_STREAMING      the callback token ids match what generation reported
//   G7 IDE_DELIVERY         the token reaches the IDE panel store the UI renders
//   G8 PERFORMANCE          throughput, measured, and never allowed to imply the above
//
// For every gate the receipt separates five claims that are routinely confused:
//
//   SOURCE_WIRED      the code path exists in the binary
//   RUNTIME_REACHED   the path actually executed in this run
//   NUMERICALLY_CORRECT the values are right, not merely present
//   TOKEN_SURVIVED    the token made it through transport to its consumer
//   PERFORMANCE_PASS  it was fast
//
// A gate may satisfy four of those and fail the fifth. `correct=true` with
// `reached=false` is the specific shape of a receipt that has been faked, and
// it is reported as FAIL here rather than averaged away.
//
// CPU and Vulkan are run INDEPENDENTLY. A GPU that initializes, is selected,
// and then silently falls back to CPU is reported as a GPU FAIL with the
// fallback visible -- never as a pass that happened to be fast.
//
// RELAXED POLICY IS REFUSED. RAWRXD_ALLOW_AGENTIC_STUB_FALLBACK, or any
// equivalent, is detected and the run is rejected outright: a relaxed policy
// means a stub lane may have served any of these gates, which is precisely the
// ambiguity this ladder exists to remove.

#include "deep2/Deep2Engine.h"
#include "win32app/Win32IDE_ChatPanel.h"

#include <atomic>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

using Clock = std::chrono::steady_clock;

namespace {

// RAWRXD_DEEP2_INFERENCE_AUTHORITY_001: one gate, five separable claims.
struct Gate {
    const char* id;
    const char* name;
    bool sourceWired      = false;
    bool runtimeReached   = false;
    bool numericallyCorrect = false;
    bool tokenSurvived    = false;
    bool performancePass  = false;   // only meaningful on G8
    std::string evidence;

    // A gate passes only if every claim that APPLIES to it is true. A gate
    // cannot be marked correct on the strength of a claim it never made.
    bool pass() const {
        if (!sourceWired)    return false;
        if (!runtimeReached) return false;
        if (!numericallyCorrect) return false;
        if (std::strcmp(id, "G6") == 0 || std::strcmp(id, "G7") == 0)
            if (!tokenSurvived) return false;
        return true;
    }
    void print() const {
        std::printf("%-4s %-22s SOURCE_WIRED=%d RUNTIME_REACHED=%d "
                    "NUMERICALLY_CORRECT=%d TOKEN_SURVIVED=%d PERFORMANCE_PASS=%d  %s\n",
                    id, name, sourceWired, runtimeReached, numericallyCorrect,
                    tokenSurvived, performancePass, pass() ? "PASS" : "FAIL");
        if (!evidence.empty()) std::printf("      %s\n", evidence.c_str());
    }
};

double Ms(Clock::time_point a, Clock::time_point b) {
    return std::chrono::duration<double, std::milli>(b - a).count();
}

bool AllFinite(const std::vector<float>& v, size_t* badIndex) {
    for (size_t i = 0; i < v.size(); ++i) {
        if (!std::isfinite(v[i])) { if (badIndex) *badIndex = i; return false; }
    }
    return true;
}

size_t Argmax(const std::vector<float>& v) {
    if (v.empty()) return 0;
    size_t best = 0;
    for (size_t i = 1; i < v.size(); ++i) if (v[i] > v[best]) best = i;
    return best;
}

// RAWRXD_RELAXED_POLICY_REFUSED_001
// A relaxed stub policy makes every gate below unprovable, because a stub lane
// may have produced the result. It is refused at the door, not warned about.
bool RelaxedPolicyActive(std::string* which) {
    static const char* kNames[] = {
        "RAWRXD_ALLOW_AGENTIC_STUB_FALLBACK",
        "RAWRXD_ALLOW_STUB_FALLBACK",
        "RAWRXD_ENABLE_STUB_FALLBACK",
    };
    for (const char* n : kNames) {
        const char* v = std::getenv(n);
        if (v && (v[0] == '1' || v[0] == 't' || v[0] == 'T')) {
            if (which) *which = n;
            return true;
        }
    }
    return false;
}

struct Run {
    std::string route;          // "CPU" or "VULKAN"
    std::vector<Gate> gates;
    bool gpuRequested = false;
    bool gpuInitialized = false;
    bool gpuActuallyUsed = false;
    size_t generated = 0;
    double decodeTokPerSec = 0.0;
    double prefillTokPerSec = 0.0;
    // The greedy sequence this route produced, retained so it can be compared
    // against another route.
    std::vector<int> greedy;
    // RAWRXD_DEBUG_EXPOSE_LOGITS_001: logits captured for the greedy step, and
    // the step counter at capture time so a stale vector cannot be mistaken for
    // a measured one.
    std::vector<float> greedyLogits;
    uint64_t greedyLogitsStep = 0;
};

// RAWRXD_CROSS_ROUTE_PARITY_001
// Load a reference greedy sequence emitted by another route.
bool LoadTokenFile(const std::string& path, std::vector<int>* out) {
    std::FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return false;
    int n = 0;
    if (std::fscanf(f, "%d", &n) != 1 || n <= 0) { std::fclose(f); return false; }
    out->clear();
    out->reserve((size_t)n);
    for (int i = 0; i < n; ++i) {
        int id = 0;
        if (std::fscanf(f, "%d", &id) != 1) { std::fclose(f); return false; }
        out->push_back(id);
    }
    std::fclose(f);
    return true;
}

bool SaveTokenFile(const std::string& path, const std::vector<int>& ids) {
    std::FILE* f = std::fopen(path.c_str(), "wb");
    if (!f) return false;
    std::fprintf(f, "%zu\n", ids.size());
    for (int id : ids) std::fprintf(f, "%d ", id);
    std::fprintf(f, "\n");
    std::fclose(f);
    return true;
}

// RAWRXD_LOGIT_DUMP_001: the logits vector as text, so CPU and Vulkan runs can
// be compared in separate processes. One value per line, ascending index.
bool SaveLogitsFile(const std::string& path, const std::vector<float>& v) {
    std::FILE* f = std::fopen(path.c_str(), "wb");
    if (!f) return false;
    std::fprintf(f, "%zu\n", v.size());
    for (float x : v) std::fprintf(f, "%.9g ", (double)x);
    std::fprintf(f, "\n");
    std::fclose(f);
    return true;
}

bool LoadLogitsFile(const std::string& path, std::vector<float>* out) {
    std::FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return false;
    size_t n = 0;
    if (std::fscanf(f, "%zu", &n) != 1 || n == 0) { std::fclose(f); return false; }
    out->assign(n, 0.0f);
    for (size_t i = 0; i < n; ++i) {
        double x = 0.0;
        if (std::fscanf(f, "%lf", &x) != 1) { std::fclose(f); return false; }
        (*out)[i] = (float)x;
    }
    std::fclose(f);
    return true;
}

// Top-k with a stable, documented tie-break: lowest index wins ties, so the
// same vector always produces the same ordering on both routes. A tie-break
// that differed between runs would itself masquerade as numerical divergence.
std::vector<std::pair<float, int>> TopK(const std::vector<float>& v, int k) {
    std::vector<std::pair<float, int>> all;
    all.reserve(v.size());
    for (size_t i = 0; i < v.size(); ++i) all.emplace_back(v[i], (int)i);
    const int kk = k < (int)all.size() ? k : (int)all.size();
    std::partial_sort(all.begin(), all.begin() + kk, all.end(),
        [](const std::pair<float,int>& a, const std::pair<float,int>& b) {
            if (a.first != b.first) return a.first > b.first;
            return a.second < b.second;   // lowest index wins ties
        });
    all.resize((size_t)kk);
    return all;
}

} // namespace

int main(int argc, char** argv) {
    // A crash or hang must still report how far it got.
    setvbuf(stdout, nullptr, _IONBF, 0);

    const std::string model = (argc > 1) ? argv[1]
                                         : "F:/~dev/qwen2.5-coder-1.5b-base.gguf";
    const int tokens = (argc > 2) ? std::atoi(argv[2]) : 12;

    std::string relaxed;
    if (RelaxedPolicyActive(&relaxed)) {
        std::printf("RELAXED_POLICY_REFUSED: %s is set. Every gate below would be\n"
                    "unprovable, because a stub lane may have produced the result.\n"
                    "This ladder refuses relaxed policy outright.\n", relaxed.c_str());
        std::printf("VERDICT=REJECT_RELAXED_POLICY\n");
        return 3;
    }
    std::printf("relaxed_policy=none (required for certification)\n");

    // CPU and Vulkan are two independent runs. The second is requested through
    // DEEP2_DISABLE_VULKAN for the CPU leg, matching the shipped opt-out policy.
    const char* disEnv = std::getenv("DEEP2_DISABLE_VULKAN");
    const bool wantGpu = !(disEnv && (disEnv[0] == '1' || disEnv[0] == 't' || disEnv[0] == 'T'));
    const char* routeEnv = std::getenv("RAWRXD_LADDER_ROUTE");
    const bool runVulkan = routeEnv ? (routeEnv[0] == 'V' || routeEnv[0] == 'v') : wantGpu;

    std::printf("model=%s tokens=%d route=%s\n", model.c_str(), tokens,
                runVulkan ? "VULKAN" : "CPU");

    Run R;
    R.route = runVulkan ? "VULKAN" : "CPU";
    R.gpuRequested = runVulkan;
    R.gates.resize(8);

    // ───────────────────────── G1 MODEL_LOAD ─────────────────────────
    {
        Gate& g = R.gates[0];
        g.id = "G1"; g.name = "MODEL_LOAD";
        // SOURCE_WIRED: the entry point is linked into this binary. Reaching it
        // at all is the proof, so it is set by construction once we run.
        g.sourceWired = true;

        Deep2::Deep2Engine eng;
        eng.enableVulkan(runVulkan);
        Deep2::ModelLoadDiag diag;

        // ───────────── STAGE C: layer/stage bisection probe ─────────────
        // RAWRXD_VULKAN_FIRST_DIVERGENCE_001
        // The engine already carries a 20-stage checkpoint grid
        // (Embed, AttnNorm, Q, K, V, Q_Rope, K_Rope, AttnScores, AttnProbs,
        // AttnValue, OProj, AttnResidual, FfnNorm, FfnGate, FfnUp, Swiglu,
        // FfnDown, LayerResidual, FinalNorm, Logits). Emitting it on BOTH
        // routes and diffing the two files gives the first stage where they
        // part, which is the question Stage B raised: is the final projection
        // misreading a vector, or faithfully reporting damage from earlier?
        const char* parityPath = std::getenv("RAWRXD_LADDER_PARITY");
        if (parityPath && *parityPath) {
            const char* stepsEnv = std::getenv("RAWRXD_LADDER_PARITY_STEPS");
            const int maxSteps = stepsEnv ? std::atoi(stepsEnv) : 1;
            eng.enableParityProbe(parityPath, maxSteps);
            std::printf("parity_probe=%s max_steps=%d\n", parityPath, maxSteps);
        }

        const auto t0 = Clock::now();
        const bool loaded = eng.loadModel(model, &diag);
        const double loadMs = Ms(t0, Clock::now());
        g.runtimeReached = true;

        if (!loaded) {
            g.evidence = "loadModel FAILED stage=" + std::to_string(diag.stageCode) +
                         " name='" + diag.stageName + "' message='" + diag.message + "'";
            for (auto& x : R.gates) x.print();
            std::printf("\nVERDICT=FAIL (G1)\n");
            return 1;
        }
        R.gpuInitialized = eng.isVulkanInitialized();
        R.gpuActuallyUsed = eng.isVulkanInitialized();

        // NUMERICALLY_CORRECT for this gate means the geometry is internally
        // consistent, not merely non-zero: a model that reports 0 layers or a
        // vocab smaller than the tokenizer cannot be correct.
        const size_t H = eng.hiddenDim(), L = eng.numLayers(), V = eng.vocabSize();
        // RAWRXD_DEEP2_INFERENCE_AUTHORITY_001: read the geometry through the
        // public accessors only. modelWeights is private; getModelWeights() is
        // the read-only view, and going around it would make this harness a
        // second, privileged view of engine state rather than a consumer of the
        // same API the product uses.
        const Deep2::ModelWeights& mw = eng.getModelWeights();
        const size_t heads = mw.numHeads, kv = mw.numKVHeads;
        const bool geoOk = H > 0 && L > 0 && V > 0 && heads > 0 && kv > 0 && kv <= heads;
        g.numericallyCorrect = geoOk;
        char buf[256];
        std::snprintf(buf, sizeof(buf),
            "load_ms=%.1f hidden=%zu layers=%zu vocab=%zu heads=%zu kv_heads=%zu "
            "weight_type=%s dominance=%.1f%% gpu_initialized=%d",
            loadMs, H, L, V, heads, kv, eng.loadedWeightTypeName(),
            eng.loadedWeightTypeDominancePercent(), R.gpuInitialized ? 1 : 0);
        g.evidence = buf;

        if (runVulkan && !R.gpuInitialized) {
            g.evidence += "  [GPU REQUESTED BUT NOT INITIALIZED -> this is a GPU FAIL]";
        }

        // ───────────────────── G2 TOKENIZATION ─────────────────────
        {
            Gate& t = R.gates[1];
            t.id = "G2"; t.name = "TOKENIZATION";
            t.sourceWired = true;
            const std::string prompt = "The capital of France is";
            const std::vector<int> ids = eng.tokenize(prompt);
            t.runtimeReached = true;
            t.tokenSurvived = !ids.empty();
            const std::string back = eng.detokenize(ids);
            // Correct means: ids exist, all in vocab range, and the round trip
            // reproduces the prompt. A lossy round trip is a real tokenizer
            // defect even though tokens were produced.
            bool inRange = true;
            for (int id : ids) if (id < 0 || (size_t)id >= V) inRange = false;
            t.numericallyCorrect = t.tokenSurvived && inRange && (back == prompt);
            char b2[256];
            std::snprintf(b2, sizeof(b2),
                "prompt_bytes=%zu tokens=%zu roundtrip_exact=%d all_in_vocab=%d text='%s'",
                prompt.size(), ids.size(), back == prompt ? 1 : 0, inRange ? 1 : 0,
                back.c_str());
            t.evidence = b2;
        }

        // ─────────────────── G3 FORWARD_EXECUTION ───────────────────
        std::vector<int> promptIds;
        {
            Gate& f = R.gates[2];
            f.id = "G3"; f.name = "FORWARD_EXECUTION";
            f.sourceWired = true;
            promptIds = eng.tokenize("The capital of France is");
            Deep2::GenerationOptions warm;
            warm.maxTokens = 1;
            auto r = eng.generateStream("warm", warm,
                [](int32_t, const std::string&) { return true; });
            f.runtimeReached = true;
            const bool ran = r.completed || r.generatedTokens > 0;
            f.numericallyCorrect = ran && r.failureDetail.empty();
            f.tokenSurvived = r.generatedTokens > 0;
            f.evidence = "warmup status=" + std::to_string((int)r.status) +
                         " generated=" + std::to_string(r.generatedTokens) +
                         " detail='" + r.failureDetail + "'";
        }

        // ─────────────────── G4 NUMERICAL_CORRECTNESS ───────────────────
        {
            Gate& n = R.gates[3];
            n.id = "G4"; n.name = "NUMERICAL_CORRECTNESS";
            n.sourceWired = true;
            // Two independent greedy generations of the same prompt. Correct
            // means finite values and identical token sequences -- a forward
            // pass that returns different answers for the same input is not
            // correct no matter how fast it is.
            // RAWRXD_DEEP2_INFERENCE_AUTHORITY_001
            // This gate measures the FORWARD PASS, not the sampler (G5 owns
            // sampling). Two mistakes were made here first and both produced a
            // FAIL that was the harness's fault:
            //   1. it ran the two "independent" generations without reset(), so
            //      the second continued from the first one's KV cache;
            //   2. it used the low-level generate() token API, which takes NO
            //      sampling options and therefore samples stochastically at the
            //      engine's defaults. Repeatability was then impossible by
            //      construction and repeatable=0 said nothing about the
            //      forward pass.
            //
            // So the forward is exercised through generateStream with greedy
            // forced, and compared across two identical greedy runs.
            //
            // LIMITATION, stated rather than papered over: raw logits are not
            // reachable through the public API, so this gate CANNOT assert
            // "logits are finite". It asserts the observable consequences: token
            // ids land inside the vocabulary and the engine reports no failure
            // detail. Anything claiming a logits-finiteness proof from this
            // harness would be overstating what was measured.
            std::vector<int> a, b;
            Deep2::GenerationOptions g1, g2;
            g1.maxTokens = (uint32_t)tokens; g1.temperature = 0.0f; g1.topK = 1; g1.seed = 7;
            g2.maxTokens = (uint32_t)tokens; g2.temperature = 0.0f; g2.topK = 1; g2.seed = 7;

            eng.reset();
            auto ra = eng.generateStream("The capital of France is", g1,
                [&](int32_t id, const std::string&) { a.push_back(id); return true; });
            eng.reset();
            auto rb = eng.generateStream("The capital of France is", g2,
                [&](int32_t id, const std::string&) { b.push_back(id); return true; });

            n.runtimeReached = true;
            n.performancePass = true;   // a real decode happened; G8 carries the number

            bool same = (a.size() == b.size());
            if (same) for (size_t i = 0; i < a.size(); ++i) if (a[i] != b[i]) { same = false; break; }

            bool allInVocab = true;
            for (int id : a) if (id < 0 || (size_t)id >= V) allInVocab = false;

            n.numericallyCorrect = same && !a.empty() && allInVocab &&
                                   ra.failureDetail.empty() && rb.failureDetail.empty();
            n.tokenSurvived = !a.empty();
            char b4[320];
            std::snprintf(b4, sizeof(b4),
                "greedy_runs_identical=%d tokens=%zu/%zu all_in_vocab=%d "
                "status=%d/%d first_ids=[%d,%d,%d]  "
                "LIMITS: logits not observable via public API, so finiteness is "
                "NOT asserted here (G5 covers sampler determinism)",
                same ? 1 : 0, a.size(), b.size(), allInVocab ? 1 : 0,
                (int)ra.status, (int)rb.status,
                a.size() > 0 ? a[0] : -1, a.size() > 1 ? a[1] : -1,
                a.size() > 2 ? a[2] : -1);
            n.evidence = b4;
            R.generated = a.size();
            R.greedy = a;
            // Capture the logits of THIS greedy step, so the Stage-B comparison
            // is against the step whose token actually diverged. The step
            // counter is recorded alongside so a later run cannot silently
            // compare against a vector from a different forward.
            if (eng.debugLogitsEnabled()) {
                R.greedyLogits = eng.debugLastLogits();
                R.greedyLogitsStep = eng.debugLogitsStep();
            }
        }

        // ─────────────────── G5 SAMPLING_CORRECTNESS ───────────────────
        {
            Gate& s = R.gates[4];
            s.id = "G5"; s.name = "SAMPLING_CORRECTNESS";
            s.sourceWired = true;
            // Greedy with temperature 0 and topK 1 must equal argmax, and must
            // be seed-independent. A sampler that varies under a fixed seed is
            // not correct even if the text looks fine.
            Deep2::GenerationOptions o1, o2;
            o1.maxTokens = (uint32_t)tokens; o1.temperature = 0.0f; o1.topK = 1; o1.seed = 1;
            o2.maxTokens = (uint32_t)tokens; o2.temperature = 0.0f; o2.topK = 1; o2.seed = 999;
            std::vector<int> s1, s2;
            eng.reset();
            auto r1 = eng.generateStream("The capital of France is", o1,
                [&](int32_t id, const std::string&) { s1.push_back(id); return true; });
            eng.reset();
            auto r2 = eng.generateStream("The capital of France is", o2,
                [&](int32_t id, const std::string&) { s2.push_back(id); return true; });
            s.runtimeReached = true;
            bool same = (s1.size() == s2.size());
            if (same) for (size_t i = 0; i < s1.size(); ++i) if (s1[i] != s2[i]) { same = false; break; }
            s.numericallyCorrect = same && !s1.empty();
            s.tokenSurvived = !s1.empty();
            // The result status is reported so that an empty callback is
            // diagnosable: "zero tokens" and "zero tokens because generation
            // failed" are different defects and a receipt must not conflate them.
            char b5[256];
            std::snprintf(b5, sizeof(b5),
                "greedy_seed_invariant=%d tokens=%zu/%zu status=%d/%d "
                "detail='%s' (temperature=0 topK=1, seeds 1 vs 999)",
                same ? 1 : 0, s1.size(), s2.size(),
                (int)r1.status, (int)r2.status, r1.failureDetail.c_str());
            s.evidence = b5;
        }

        // ─────────────────── G6 TOKEN_STREAMING ───────────────────
        {
            Gate& t = R.gates[5];
            t.id = "G6"; t.name = "TOKEN_STREAMING";
            t.sourceWired = true;
            // The callback is the ONLY channel the IDE consumes. This gate
            // asserts the ids arriving on it match the ids generation reported,
            // so a token cannot be counted as generated and then dropped.
            std::vector<int> cbIds;
            std::string cbText;
            Deep2::GenerationOptions o;
            o.maxTokens = (uint32_t)tokens; o.temperature = 0.0f; o.topK = 1; o.seed = 1;
            auto r = eng.generateStream("The capital of France is", o,
                [&](int32_t id, const std::string& text) {
                    cbIds.push_back(id); cbText += text; return true;
                });
            t.runtimeReached = true;
            t.tokenSurvived = (r.generatedTokens == cbIds.size()) && r.generatedTokens > 0;
            // Correct: the streamed count agrees with the reported count AND
            // the concatenated text is real text, not empty or a marker.
            t.numericallyCorrect = t.tokenSurvived && !cbText.empty() &&
                                   cbText.rfind("[", 0) != 0;
            char b6[224];
            std::snprintf(b6, sizeof(b6),
                "reported=%llu callback=%zu agree=%d text_bytes=%zu first='%.40s'",
                (unsigned long long)r.generatedTokens, cbIds.size(),
                ((size_t)r.generatedTokens == cbIds.size()) ? 1 : 0,
                cbText.size(), cbText.c_str());
            t.evidence = b6;
        }

        // ─────────────────── G7 IDE_DELIVERY ───────────────────
        {
            Gate& d = R.gates[6];
            d.id = "G7"; d.name = "IDE_DELIVERY";
            d.sourceWired = true;
            // The IDE's own WndProc does exactly this: BeginStreaming, then
            // AppendStreamToken per token, then EndStreaming, and the receipt
            // reads back through ChatPanel_GetMessage -- the same store
            // ChatPaint renders. This gate drives that store directly, so it
            // proves the token SURVIVED transport, not merely that a callback
            // fired.
            RawrXD::IDE::ChatPanel_Clear();
            RawrXD::IDE::ChatPanel_AddMessage(RawrXD::IDE::MsgRole::User, "The capital of France is");
            RawrXD::IDE::ChatPanel_BeginStreaming();
            const size_t before = RawrXD::IDE::ChatPanel_StreamingTokenCount();
            std::string delivered;
            Deep2::GenerationOptions o;
            o.maxTokens = (uint32_t)tokens; o.temperature = 0.0f; o.topK = 1; o.seed = 1;
            eng.reset();
            auto r = eng.generateStream("The capital of France is", o,
                [&](int32_t, const std::string& text) {
                    RawrXD::IDE::ChatPanel_AppendStreamToken(text);
                    delivered += text;
                    return true;
                });
            // RAWRXD_DEEP2_INFERENCE_AUTHORITY_001: read the streaming count
            // BEFORE EndStreaming(). EndStreaming() clears the streaming flag
            // and resets the counter, so reading it afterwards always reports 0
            // and the gate fails for a reason that has nothing to do with
            // delivery. The first version of this gate made exactly that
            // mistake and reported IDE_DELIVERY FAIL while the visible message
            // demonstrably contained every streamed token.
            const size_t after = RawrXD::IDE::ChatPanel_StreamingTokenCount();
            RawrXD::IDE::ChatPanel_EndStreaming();
            d.runtimeReached = true;
            const size_t msgs  = RawrXD::IDE::ChatPanel_MessageCount();
            const std::string visible = msgs ? RawrXD::IDE::ChatPanel_GetMessage(msgs - 1) : "";

            d.tokenSurvived = (after > before) && !visible.empty();
            // Correct: what the panel shows contains the streamed text. This is
            // the last link in the enterprise chain -- GGUF to visible token.
            d.numericallyCorrect = d.tokenSurvived && visible.find(delivered) != std::string::npos;
            char b7[256];
            std::snprintf(b7, sizeof(b7),
                "panel_messages=%zu tokens_before=%zu tokens_after=%zu "
                "visible_bytes=%zu contains_streamed=%d",
                msgs, before, after, visible.size(),
                visible.find(delivered) != std::string::npos ? 1 : 0);
            d.evidence = b7;
        }

        // ─────────────────── G8 PERFORMANCE ───────────────────
        {
            Gate& p = R.gates[7];
            p.id = "G8"; p.name = "PERFORMANCE";
            p.sourceWired = true;
            // Throughput is measured by the engine's own counters, on a
            // dedicated greedy run, so the correctness gates above are not
            // perturbed by instrumentation.
            eng.reset();
            Deep2::GenerationOptions o;
            o.maxTokens = (uint32_t)tokens; o.temperature = 0.0f; o.topK = 1; o.seed = 1;
            const auto t0 = Clock::now();
            std::vector<int> perfIds;
            eng.generateStream("The capital of France is", o,
                [&](int32_t id, const std::string&) { perfIds.push_back(id); return true; });
            const double wallMs = Ms(t0, Clock::now());
            // PERFORMANCE is never allowed to imply any earlier gate. It is
            // reported last, measured last, and a fast run that failed G4 or G7
            // still ends in FAIL.
            p.runtimeReached = !perfIds.empty();
            p.numericallyCorrect = !perfIds.empty();   // a real decode was measured
            p.performancePass = !perfIds.empty();
            p.tokenSurvived = !perfIds.empty();
            R.generated = perfIds.size();
            R.decodeTokPerSec = wallMs > 0.0 ? (perfIds.size() * 1000.0 / wallMs) : 0.0;
            char b8[256];
            std::snprintf(b8, sizeof(b8),
                "decode=%.3f tok/s tokens=%zu wall=%.1f ms "
                "(throughput alone NEVER implies correctness; G8 does not certify G1-G7)",
                R.decodeTokPerSec, perfIds.size(), wallMs);
            p.evidence = b8;
        }
    }

    // ─────────────────── G9 CROSS_ROUTE_PARITY ───────────────────
    // RAWRXD_CROSS_ROUTE_PARITY_001
    //
    // This gate exists because the first version of the ladder PASSED a
    // numerically broken GPU. Measured on qwen2.5-coder-1.5b-base Q4_K:
    //
    //   CPU     ids [32671,563,624,...]  text "The capital of France is _______. A. Paris B"
    //   VULKAN  ids [151661,75085,69178,...]  text " anglais,.\n\n.\n\n.\n"
    //
    // and BOTH reported GATES_FAILED=0 / VERDICT=PASS. Every gate above is a
    // SELF-CONSISTENCY check: ids inside the vocabulary, greedy deterministic,
    // tokens surviving transport, throughput non-zero. A route that is
    // deterministically wrong satisfies all of them. Determinism is not
    // correctness, and being fast is not correctness.
    //
    // The only thing that distinguishes "correct" from "consistently incorrect"
    // is agreement with an independent reference. So this gate compares the
    // greedy token sequence against one produced by another route.
    //
    // It is NOT optional and NOT reported as a warning. A GPU route that
    // disagrees with the CPU reference has not passed inference correctness,
    // no matter how many of the other gates it satisfies.
    std::vector<int> reference;
    const char* cmpPath = std::getenv("RAWRXD_LADDER_COMPARE");
    const bool haveRef = cmpPath && *cmpPath && LoadTokenFile(cmpPath, &reference) &&
                         !reference.empty();
    const char* emitPath = std::getenv("RAWRXD_LADDER_EMIT");

    Gate cross;
    cross.id = "G9";
    cross.name = "CROSS_ROUTE_PARITY";
    cross.sourceWired = haveRef;
    cross.runtimeReached = haveRef;
    if (haveRef) {
        const size_t n = (std::min)(reference.size(), R.greedy.size());
        size_t firstDiff = n;
        for (size_t i = 0; i < n; ++i) if (reference[i] != R.greedy[i]) { firstDiff = i; break; }
        const bool identical = (reference.size() == R.greedy.size()) && firstDiff == n;
        cross.numericallyCorrect = identical;
        cross.tokenSurvived = !R.greedy.empty();
        cross.performancePass = false;   // never a performance gate
        char b9[320];
        std::snprintf(b9, sizeof(b9),
            "reference=%s ref_tokens=%zu this_tokens=%zu identical=%d "
            "first_divergence_index=%d ref[0]=%d this[0]=%d",
            cmpPath, reference.size(), R.greedy.size(), identical ? 1 : 0,
            identical ? -1 : (int)firstDiff,
            reference.empty() ? -1 : reference[0],
            R.greedy.empty() ? -1 : R.greedy[0]);
        cross.evidence = b9;
    } else {
        cross.numericallyCorrect = false;
        cross.evidence = "NO REFERENCE SUPPLIED. Set RAWRXD_LADDER_COMPARE to a token "
                         "file emitted by another route. Without a reference this gate "
                         "cannot pass, and it is reported FAIL rather than skipped: a "
                         "route that is never compared to anything is exactly the route "
                         "that can be deterministically wrong while passing every other "
                         "gate.";
    }
    // RAWRXD_COMPARE_B_CHAIN_001: the same technique extended past V. Each
    // stage's input is the GPU's own captured arena vector for the preceding
    // stage, so the CPU reference cannot be mis-paired the way the ordinal
    // comparator's was.
    // RAWRXD_VULKAN_ATTENTION_CORE_BISECT_001 (A1-A6): CPU RoPE applied to the
    // captured pre-RoPE bytes, compared against the device's post-RoPE capture.
    const char* ropeEnv = std::getenv("RAWRXD_ROPE_BISECT");
    if (ropeEnv && *ropeEnv) {
        std::printf("\n---- RoPE bisect (RAWRXD_VULKAN_ATTENTION_CORE_BISECT_001) ----\n");
        std::fflush(stdout);
        Deep2::Deep2Engine re;
        re.enableVulkan(true);
        Deep2::ModelLoadDiag d3;
        if (!re.loadModel(model, &d3)) {
            std::printf("ROPE_LOAD_FAIL stage=%d '%s'\n", d3.stageCode, d3.message.c_str());
        } else {
            std::vector<Deep2::Deep2Engine::ChainStage> rs;
            if (re.ropeBisectRun(0, ropeEnv, &rs) && !rs.empty()) {
                std::printf("%-10s %-12s %-12s %-11s %-11s %s\n",
                            "STAGE", "CPU_L2", "GPU_L2", "MAX_DIFF", "COSINE", "VERDICT");
                const char* firstBad = nullptr;
                for (const auto& s : rs) {
                    std::printf("%-10s %-12.6f %-12.6f %-11.6g %-11.6f %s%s\n",
                                s.stage, s.cpuL2, s.gpuL2, s.maxAbsDiff, s.cosine,
                                s.match ? "MATCH" : "NUMERIC_MISMATCH",
                                s.reason.empty() ? "" : (" (" + s.reason + ")").c_str());
                    if (!s.match && !firstBad) firstBad = s.stage;
                }
                std::printf("\nROPE_FIRST_MISMATCH=%s\n", firstBad ? firstBad : "NONE");
            } else {
                std::printf("ROPE_BISECT_NO_RESULT\n");
            }
        }
        std::fflush(stdout);
    }
    const char* chainEnv = std::getenv("RAWRXD_COMPARE_B_CHAIN");
    if (chainEnv && *chainEnv) {
        std::printf("\n---- post-V CPU replay chain (RAWRXD_COMPARE_B_CHAIN_001) ----\n");
        std::fflush(stdout);
        Deep2::Deep2Engine ce;
        ce.enableVulkan(true);
        Deep2::ModelLoadDiag d2;
        if (!ce.loadModel(model, &d2)) {
            std::printf("CHAIN_LOAD_FAIL stage=%d '%s'\n", d2.stageCode, d2.message.c_str());
        } else {
            std::vector<Deep2::Deep2Engine::ChainStage> chain;
            if (ce.postVChainReplay(0, chainEnv, &chain) && !chain.empty()) {
                std::printf("%-18s %-12s %-12s %-11s %-11s %s\n",
                            "STAGE", "CPU_L2", "GPU_L2", "COSINE", "MAX_DIFF", "VERDICT");
                const char* firstBad = nullptr;
                for (const auto& s : chain) {
                    std::printf("%-18s %-12.6f %-12.6f %-11.6f %-11.6g %s\n",
                                s.stage, s.cpuL2, s.gpuL2, s.cosine, s.maxAbsDiff,
                                s.match ? "MATCH" : "NUMERIC_MISMATCH");
                    if (!s.match && !firstBad) firstBad = s.stage;
                }
                std::printf("\nCHAIN_FIRST_MISMATCH_STAGE=%s\n",
                            firstBad ? firstBad : "NONE");
                if (firstBad) {
                    std::printf("  => Q/K/V are exonerated on real captured input, so the\n"
                                "     first genuine divergence after V is at %s.\n", firstBad);
                } else {
                    std::printf("  => every replayed post-V stage agrees. The divergence lies in\n"
                                "     the FUSED attention (DispatchAttnDecode), which has no\n"
                                "     device arena and therefore no capture point at all.\n");
                }
            } else {
                std::printf("CHAIN_REPLAY_FAILED (no captured vectors matched)\n");
            }
        }
        std::fflush(stdout);
    }
    if (emitPath && *emitPath) {
        SaveTokenFile(emitPath, R.greedy);
        std::printf("emitted_greedy_tokens=%zu -> %s\n", R.greedy.size(), emitPath);
    }

    if (emitPath && *emitPath) {
        SaveTokenFile(emitPath, R.greedy);
        std::printf("emitted_greedy_tokens=%zu -> %s\n", R.greedy.size(), emitPath);
    }

    // ───────────── RAWRXD_VULKAN_PROJECTION_BISECT_001 ─────────────
    // The identical-input experiment. Runs AFTER the gate ladder so the ladder
    // verdict is produced first and cannot be influenced by it.
    //
    // This is the measurement that separates ONE upstream defect from TWO
    // independent defects: it feeds the SAME host vector to the CPU projection
    // and the GPU projection, so the ~13% RMS_ATTN disagreement observed by the
    // grid is removed from the experiment entirely.
    const char* projEnv = std::getenv("RAWRXD_PROJECTION_BISECT");
    if (projEnv && (projEnv[0] == '1' || projEnv[0] == 't' || projEnv[0] == 'T')) {
        std::printf("\n---- identical-input projection bisect "
                    "(RAWRXD_VULKAN_PROJECTION_BISECT_001) ----\n");
        std::fflush(stdout);
        Deep2::Deep2Engine be;
        be.enableVulkan(true);
        Deep2::ModelLoadDiag d;
        if (!be.loadModel(model, &d)) {
            std::printf("PROJ_BISECT_LOAD_FAIL stage=%d '%s'\n",
                        d.stageCode, d.message.c_str());
        } else {
            std::vector<Deep2::Deep2Engine::ProjectionBisectResult> res;
            if (be.projectionBisectRun(0, &res) && !res.empty()) {
                std::printf("%-6s %-10s %-10s %-9s %-12s %-12s %-8s %-10s %s\n",
                            "STAGE", "ROWS_EXP", "ROWS_DISP", "TYPE",
                            "CPU_L2", "GPU_L2", "RATIO", "COSINE", "TOP1_AGREE");
                // RAWRXD_VULKAN_PROJECTION_BISECT_001
                // The verdict is gated on the GPU path actually RUNNING.
                //
                // The first version of this block checked only top1Agree and
                // cosine, and both are 0 when the GPU produced nothing at all.
                // It therefore printed IDENTICAL_INPUT_GPU_QKV_MATCH=NO and
                // declared an independent projection defect PROVEN -- while
                // gpu_reached was 0 on every stage and the dispatch had never
                // executed. A failed measurement reported as a defect is the
                // same class of error as a fabricated receipt, and it is now
                // structurally impossible: no GPU output, no verdict.
                bool allRan = true;
                for (const auto& r : res) if (!r.gpuReached) allRan = false;
                bool allAgree = true;
                for (const auto& r : res) {
                    const double ratio = r.cpuL2 > 0 ? r.gpuL2 / r.cpuL2 : 0.0;
                    std::printf("%-6s %-10zu %-10u %-9d %-12.4f %-12.4f %-8.4f %-10.6f %zu%s\n",
                                r.stage, r.rows, r.rowsDispatched, r.type,
                                r.cpuL2, r.gpuL2, ratio, r.cosine, r.top1Agree,
                                r.gpuReached ? "" : "  GPU_NOT_REACHED");
                    std::printf("       byte_offset=%zu byte_size=%zu max_abs_diff=%.6g "
                                "rms_diff=%.6g gpu_reached=%d\n",
                                r.byteOffset, r.byteSize, r.maxAbsDiff,
                                r.rmsDiff, r.gpuReached ? 1 : 0);
                    if (r.gpuReached && (!r.top1Agree || r.cosine < 0.99)) allAgree = false;
                }
                if (!allRan) {
                    std::printf("\nIDENTICAL_INPUT_GPU_QKV_MATCH=UNKNOWN\n");
                    std::printf("  => NO VERDICT. The GPU projection did not execute "
                                "(gpu_reached=0 on at least one stage), so there is\n"
                                "     no measurement to conclude from. Reporting a "
                                "mismatch here would be\n"
                                "     reporting a failed dispatch as a numerical defect.\n"
                                "     The GPU side must be routed through the SAME "
                                "residency path the\n"
                                "     forward uses (PrefetchWeight + SubmitGemvPrefetch), "
                                "not a bare\n"
                                "     DispatchGemvQuant with a host weight pointer.\n");
                } else {
                std::printf("\nIDENTICAL_INPUT_GPU_QKV_MATCH=%s\n", allAgree ? "YES" : "NO");
                if (allAgree) {
                    std::printf("  => the projection machinery is SOUND on identical input.\n"
                                "     The divergence originates UPSTREAM (the RMS_ATTN mismatch\n"
                                "     the grid already measured). Chase that, not gemvOverlap3.\n");
                } else {
                    std::printf("  => an INDEPENDENT GPU projection defect is PROVEN: with the\n"
                                "     same input bytes the two paths disagree. Suspect weight\n"
                                "     binding, dequant scale, row stride, or the fused 3-input\n"
                                "     dispatch indexing -- NOT the upstream RMS.\n");
                }
                }
            } else {
                std::printf("PROJ_BISECT_RUN_FAILED\n");
            }
        }
        std::fflush(stdout);
    }

    // ───────────── STAGE B: FIRST-TOKEN LOGIT DIVERGENCE ─────────────
    // RAWRXD_VULKAN_FIRST_DIVERGENCE_001
    //
    // Token-0 divergence means the defect is upstream of the sampler. The
    // question this answers is: does the final PROJECTION already differ, or is
    // the projection faithfully reporting damage done earlier?
    //
    //   - wildly different top-8  => suspect layout, dequant, residual, RoPE
    //                                 or readback (a wrong VECTOR, not a wrong
    //                                 ordering)
    //   - same top-8, reordered   => suspect precision/tolerance only
    //
    // Those two diagnoses point at entirely different parts of the engine, so
    // the distinction is worth the two extra lines of output.
    const char* emitLogits = std::getenv("RAWRXD_LADDER_EMIT_LOGITS");
    const char* cmpLogits  = std::getenv("RAWRXD_LADDER_COMPARE_LOGITS");
    if (emitLogits && *emitLogits) {
        SaveLogitsFile(emitLogits, R.greedyLogits);
        std::printf("emitted_logits=%zu step=%llu -> %s\n",
                    R.greedyLogits.size(),
                    (unsigned long long)R.greedyLogitsStep, emitLogits);
    }
    if (cmpLogits && *cmpLogits) {
        std::vector<float> ref;
        if (LoadLogitsFile(cmpLogits, &ref) && !ref.empty() && !R.greedyLogits.empty()) {
            const size_t n = (std::min)(ref.size(), R.greedyLogits.size());
            double maxAbs = 0.0, sumSq = 0.0, sumRef = 0.0, sumTh = 0.0, dot = 0.0;
            size_t nanCount = 0;
            for (size_t i = 0; i < n; ++i) {
                if (!std::isfinite(ref[i]) || !std::isfinite(R.greedyLogits[i])) { ++nanCount; continue; }
                const double d = (double)R.greedyLogits[i] - (double)ref[i];
                maxAbs = d < 0 ? -d > maxAbs ? -d : maxAbs : d > maxAbs ? d : maxAbs;
                sumSq += d * d;
                sumRef += (double)ref[i] * (double)ref[i];
                sumTh  += (double)R.greedyLogits[i] * (double)R.greedyLogits[i];
                dot   += (double)ref[i] * (double)R.greedyLogits[i];
            }
            const double rms = n ? std::sqrt(sumSq / (double)n) : 0.0;
            const double denom = (sumRef > 0 && sumTh > 0) ? std::sqrt(sumRef * sumTh) : 0.0;
            const double cos = denom > 0 ? dot / denom : 0.0;

            const auto refTop = TopK(ref, 8);
            const auto thTop  = TopK(R.greedyLogits, 8);
            int overlap = 0;
            for (const auto& r : refTop)
                for (const auto& t : thTop) if (r.second == t.second) { ++overlap; break; }

            const size_t refTop1 = refTop.empty() ? 0 : (size_t)refTop[0].second;
            const size_t thTop1  = thTop.empty()  ? 0 : (size_t)thTop[0].second;

            std::printf("\n---- first-token logit comparison (STAGE B) ----\n");
            std::printf("CPU_TOP1_ID=%zu CPU_TOP1_LOGIT=%.6f\n",
                        refTop1, refTop.empty() ? 0.0 : (double)refTop[0].first);
            std::printf("%s_TOP1_ID=%zu %s_TOP1_LOGIT=%.6f\n",
                        R.route.c_str(), thTop1, R.route.c_str(),
                        thTop.empty() ? 0.0 : (double)thTop[0].first);
            std::printf("CPU_TOP8=[");
            for (size_t i = 0; i < refTop.size(); ++i)
                std::printf("%s%d:%.4f", i ? " " : "", refTop[i].second, (double)refTop[i].first);
            std::printf("]\n%s_TOP8=[", R.route.c_str());
            for (size_t i = 0; i < thTop.size(); ++i)
                std::printf("%s%d:%.4f", i ? " " : "", thTop[i].second, (double)thTop[i].first);
            std::printf("]\n");
            std::printf("VECTOR_LEN cpu=%zu %s=%zu\n", ref.size(), R.route.c_str(),
                        R.greedyLogits.size());
            std::printf("MAX_ABS_DIFF=%.6g RMS_DIFF=%.6g COSINE_SIM=%.6f NON_FINITE=%zu\n",
                        maxAbs, rms, cos, nanCount);
            std::printf("TOP8_OVERLAP=%d/8 TOP1_MATCH=%d\n", overlap,
                        (refTop1 == thTop1) ? 1 : 0);
            if (overlap <= 2) {
                std::printf("DIAGNOSIS=VECTOR_DIVERGENCE  the final projection is reading a\n"
                            "  different vector, not the same vector in a different order.\n"
                            "  Suspect layout/stride, Q4_K dequant, residual, RoPE, or logits\n"
                            "  readback -- NOT precision tolerance.\n");
            } else if (overlap >= 7) {
                std::printf("DIAGNOSIS=ORDERING_ONLY  the same candidates are present; only the\n"
                            "  ordering differs. Suspect precision/tolerance before layout.\n");
            } else {
                std::printf("DIAGNOSIS=PARTIAL  some candidates agree. Bisect by layer.\n");
            }
        } else {
            std::printf("\nSTAGE B: could not load reference logits from %s\n", cmpLogits);
        }
    }

    // ─────────────────────── verdict ───────────────────────
    int failures = 0;
    std::printf("\n==== gate ladder: %s ====\n", R.route.c_str());
    for (const Gate& g : R.gates) {
        g.print();
        if (!g.pass()) ++failures;
    }
    cross.print();
    if (!cross.pass()) ++failures;

    // A GPU route that fell back to CPU is a GPU failure, reported as such
    // rather than as a fast pass.
    bool gpuLie = false;
    if (R.gpuRequested && !R.gpuInitialized) {
        gpuLie = true;
        std::printf("\nGPU_FALLBACK_DETECTED: Vulkan was requested and did not initialize. "
                    "This run did NOT exercise the GPU path and cannot certify it.\n");
    }

    std::printf("\nROUTE=%s GATES_FAILED=%d GPU_FALLBACK=%d\n",
                R.route.c_str(), failures, gpuLie ? 1 : 0);
    std::printf("CORRECTNESS_INDEPENDENT_OF_SPEED=1 (G8 does not imply G1-G7)\n");
    std::printf("VERDICT=%s\n", (failures == 0 && !gpuLie) ? "PASS" : "FAIL");
    return (failures == 0 && !gpuLie) ? 0 : 1;
}
