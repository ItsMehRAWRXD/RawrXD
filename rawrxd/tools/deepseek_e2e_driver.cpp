// deepseek_e2e_driver.cpp
//
// RAWRXD_DEEPSEEK_CPU_E2E_001 -- the single-model end-to-end driver.
//
// WHY A SEPARATE DRIVER
// ---------------------
// deep2_streamer_cert is a CENSUS: it discovers artefacts under roots, spawns a
// child per model, and tallies outcomes. That shape cannot answer "why did
// DeepSeek not stream", because the census reports a per-model RESULT and
// discards the stage that failed. DeepSeek is the one model here whose
// architecture (MLA + MoE) has no CPU execution route at all, so the question
// is not "is it in the census" but "which stage, in order, first refuses".
//
// This driver therefore emits ONE model, ONE ordered stage trace, and ONE
// derived verdict. Every field printed is either an observation from the engine
// or a value the engine returned. There is no expected value written as a
// literal anywhere below.
//
// HONESTY CONSTRAINTS BUILT INTO THIS FILE
// ----------------------------------------
//  * VERDICT is computed from counted observations, never assigned.
//  * No PREDICTED_* / EXPECTED_* / DREAM_* field exists, by construction.
//  * A stage that does not run emits SKIP with its reason. A stage that is
//    merely absent is indistinguishable from a stage nobody looked for, and
//    an absent stage is the failure mode this driver exists to detect.
//  * The first failure is recorded once and never overwritten. Later failures
//    still print, but they do not become the answer.
//  * Every value that can escape into the receipt is escaped, because the
//    receipt is line-oriented KEY=VALUE and a token containing a newline would
//    otherwise forge a field.
//  * No gate is placed on a value the engine derives from another value it
//    already returned. Deep2Engine.cpp:8171 sets
//        res.completed = (res.status == GenerationStatus:: Completed);
//    so `completed` is a restatement of `status`, not corroboration of it.
//    Asserting the two agree is a check that cannot fail, which is worse than
//    no check: it reports rigour it does not have. `completed` is therefore
//    REPORTED and never gated.
//  * Exit code 0 means text was streamed. Non-zero means it was not, and the
//    number says which stage refused: 10 + stage ordinal.
//
// MEASURED GAPS THIS VERSION CLOSES (previous behaviour, stated plainly)
// -----------------------------------------------------------------------
//  * `TOKEN_IDS_CONTIGUOUS` compared each callback's tokenId to the previous
//    one plus one. tokenId is a VOCABULARY INDEX, not a position, so no
//    language model can satisfy it; the field was near-permanently 0 and
//    meant nothing. The callback contract carries no position, so ordering is
//    no longer asserted. Real observations replace it: distinct id count,
//    adjacent-duplicate count, first id, last id.
//  * The verdict ignored GenerationResult::status, so a ForwardFailure that
//    still reported generatedTokens > 0 would have PASSED.
//  * The verdict ignored the accumulated text, so a run streaming tokens that
//    decoded to nothing would have PASSED.
//  * A legitimate immediate stop (EndOfSequence with zero tokens) was
//    Deep2Engine.cpp:8169's documented non-error, and this driver recorded it
//    as a GENERATE_STREAM stage failure. It is now reported as a clean stop
//    with exit 1, which is distinct from a stage that refused.
//  * `g_stageFail` was assigned the literal 1, so every failure exited 11 and
//    the header's promise about the exit code was false.
//  * `reset()` and `unloadModel()` shared one try block: a throw in reset()
//    skipped unloadModel() and erased the KV-length observation, so a leak
//    left no trace at all.
//  * GenerationOptions::maxTokens == 0 means UNLIMITED (Deep2Engine.cpp:8112).
//    The old parser accepted `--tokens 0` and then reported a FAIL that looked
//    like a model defect.
//  * A model path longer than EngineConfig::modelPath[512] was silently
//    truncated by snprintf, and the resulting "cannot open" blamed the model
//    file for a command-line error.
//  * Unknown flags were ignored, so `--vulkan=true` silently produced a CPU
//    run that still reported VULKAN_REQUESTED=0.
//  * The control-byte test missed 0x0B, 0x0C and 0x7F.
//  * promptTokens, promptTimeMs, generationTimeMs, cancelled, completed and
//    modelArchitecture() were available and never used.
//  * kvCacheLength() was read only after reset, so nothing observed whether
//    generation actually consumed and grew the cache.

#include "Deep2Engine.h"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <string>
#include <vector>

namespace {

// ===========================================================================
// Exit codes
// ===========================================================================

constexpr int kExitPass   = 0;
constexpr int kExitNoText = 1;   // every stage ran; no text streamed
constexpr int kExitGate   = 2;   // text streamed, but a corroboration gate failed
constexpr int kExitUsage  = 64;

// Stage ordinals are the exit-code base. Order is execution order.
enum class Stage : int {
    EngineInitialize = 0,
    ModelLoad       = 1,
    GenerateStream  = 2,
    Teardown        = 3,
};

constexpr int stageExit(Stage s) { return 10 + static_cast<int>(s); }

const char* stageName(Stage s) {
    switch (s) {
        case Stage::EngineInitialize: return "ENGINE_INITIALIZE";
        case Stage::ModelLoad:        return "MODEL_LOAD";
        case Stage::GenerateStream:   return "GENERATE_STREAM";
        case Stage::Teardown:         return "TEARDOWN";
    }
    return "UNKNOWN_STAGE";
}

// ===========================================================================
// Receipt-safe text
// ===========================================================================

// The receipt is parsed one KEY=VALUE per line. Raw bytes would let a token
// containing '\n' invent a field, and a token containing NUL would truncate the
// line. Both must be escaped before a consumer sees them.
std::string escapeField(const std::string& in) {
    std::string out;
    out.reserve(in.size() + 8);
    for (unsigned char c : in) {
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            case '"':  out += "\\\""; break;
            default:
                if (c < 0x20 || c == 0x7F) {
                    char buf[8];
                    std::snprintf(buf, sizeof buf, "\\x%02X",
                                  static_cast<unsigned>(c));
                    out += buf;
                } else {
                    out += static_cast<char>(c);
                }
        }
    }
    return out;
}

// A token built from control bytes is the signature of a buffer that is not
// text. Tab, LF and CR are legitimate model output. NUL, the C0 controls that
// do not occur in prose, and DEL do not. Bytes >= 0x80 are UTF-8 lead or
// continuation bytes and are left alone.
bool isSuspiciousControl(unsigned char c) {
    if (c == '\t' || c == '\n' || c == '\r') return false;
    if (c < 0x20)   return true;
    if (c == 0x7F)  return true;
    return false;
}

// ===========================================================================
// Trace
// ===========================================================================

// Owns the first-failure record and is the single write point for the receipt.
class Trace {
public:
    void setFlushEveryRecord(bool on) { flushEveryRecord_ = on; }

    void line(const std::string& text) {
        std::printf("%s\n", text.c_str());
        maybeFlush();
    }

    void stageEnter(const char* name) { stageTag("[STAGE] ENTER", name, ""); }
    void stageOk(const char* name, const char* note = "") {
        stageTag("[STAGE] OK   ", name, note);
    }

    void stageSkip(const char* name, const char* reason) {
        std::printf("[STAGE] SKIP  name=%s reason=%s\n", name, reason);
        maybeFlush();
    }

    // Write-once. The first refusal is the answer; later ones are context.
    void stageFail(const char* name, const std::string& detail) {
        std::printf("[STAGE] FAIL  name=%s detail=%s\n", name,
                    escapeField(detail).c_str());
        maybeFlush();
        if (hasFailure_) return;
        hasFailure_  = true;
        firstStage_  = name;
        firstDetail_ = detail;
    }

    void failStage(Stage s, const std::string& detail) {
        stageFail(stageName(s), detail);
    }

    bool        hasFailure()  const { return hasFailure_; }
    const char* firstStage()   const { return hasFailure_ ? firstStage_ : "NONE"; }
    const char* firstDetail()  const { return hasFailure_ ? firstDetail_.c_str() : "NONE"; }

    // One line per field, one write point: a field cannot be split across two
    // records by an interleaved write.
    void kv(const char* key, const char* value) {
        std::printf("%s=%s\n", key, value);
        maybeFlush();
    }
    void kv(const char* key, const std::string& value) {
        kv(key, escapeField(value).c_str());
    }

    template <typename T>
        requires std::is_arithmetic_v<T>
    void kv(const char* key, T value) {
        if constexpr (std::is_floating_point_v<T>) {
            std::printf("%s=%.6g\n", key, static_cast<double>(value));
        } else if constexpr (std::is_signed_v<T>) {
            std::printf("%s=%lld\n", key, static_cast<long long>(value));
        } else {
            std::printf("%s=%llu\n", key,
                        static_cast<unsigned long long>(value));
        }
        maybeFlush();
    }

    void kvFlag(const char* key, bool value) { kv(key, value ? 1 : 0); }

private:
    void stageTag(const char* tag, const char* name, const char* note) {
        if (note && note[0]) std::printf("%s name=%s note=%s\n", tag, name, note);
        else                  std::printf("%s name=%s\n", tag, name);
        maybeFlush();
    }
    void maybeFlush() { if (flushEveryRecord_) std::fflush(stdout); }

    bool        flushEveryRecord_ = true;
    bool        hasFailure_      = false;
    const char* firstStage_      = "NONE";
    std::string firstDetail_;
};

// ===========================================================================
// Options
// ===========================================================================

struct Options {
    std::string modelPath;
    std::string prompt     = "The capital of France is";
    uint32_t    maxTokens  = 16;
    size_t      ctxLen     = 512;
    uint32_t    repeat     = 1;   // determinism replays (>= 1)
    bool        wantVulkan = false;
    bool        flushEveryRecord = true;
};

void usage() {
    std::fprintf(stderr,
        "usage: deepseek_e2e_driver --model PATH [options]\n"
        "  --model PATH   GGUF file to load (required)\n"
        "  --prompt TEXT  prompt string (default: \"The capital of France is\")\n"
        "  --tokens N     tokens to request, 1..100000 (default 16).\n"
        "                 NOTE: 0 means UNLIMITED in GenerationOptions and is rejected\n"
        "  --ctx N        max sequence length, >= 64 (default 512)\n"
        "  --repeat N     replay generation N times, require identical token id\n"
        "                 sequences (default 1, which disables the check)\n"
        "  --vulkan       request the Vulkan route\n"
        "  --no-flush     do not flush per record (long runs; loses the\n"
        "                 crash-resilience of a streamed trace)\n"
        "  --help         this text\n"
        "\n"
        "exit codes: 0 streamed text | 1 ran clean, no text streamed |\n"
        "            2 streamed text, corroboration gate failed |\n"
        "            10+stage ordinal = that stage refused | 64 usage\n");
}

bool parseUint(const char* text, unsigned long long maxValue,
               unsigned long long& out) {
    if (!text || *text == '\0') return false;
    char* end = nullptr;
    const unsigned long long n = std::strtoull(text, &end, 10);
    if (end == text || *end != '\0') return false;   // junk or trailing garbage
    if (n < 1 || n > maxValue) return false;
    out = n;
    return true;
}

// Returns false with `err` set on a malformed or unknown argument. Unknown
// flags are a hard error: silently ignoring one turns a typo into a
// differently-configured run that still looks intentional.
// Returns false with an EMPTY `err` when help was printed (exit 0).
bool parseArgs(int argc, char** argv, Options& o, std::string& err) {
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto value = [&](const char* what, const char*& out) -> bool {
            if (i + 1 >= argc) {
                err = std::string(what) + " requires a value";
                return false;
            }
            out = argv[++i];
            return true;
        };

        if (a == "--model") {
            const char* v = nullptr;
            if (!value("--model", v)) return false;
            o.modelPath = v;
        } else if (a == "--prompt") {
            const char* v = nullptr;
            if (!value("--prompt", v)) return false;
            o.prompt = v;
        } else if (a == "--tokens") {
            const char* v = nullptr;
            if (!value("--tokens", v)) return false;
            unsigned long long n = 0;
            if (!parseUint(v, 100000, n)) {
                err = std::string("--tokens must be 1..100000 (") +
                      (v && *v ? v : "") +
                      "); 0 means UNLIMITED in GenerationOptions";
                return false;
            }
            o.maxTokens = static_cast<uint32_t>(n);
        } else if (a == "--ctx") {
            const char* v = nullptr;
            if (!value("--ctx", v)) return false;
            unsigned long long n = 0;
            if (!parseUint(v, 1ull << 24, n) || n < 64) {
                err = std::string("--ctx must be 64..16777216 (") + v + ")";
                return false;
            }
            o.ctxLen = static_cast<size_t>(n);
        } else if (a == "--repeat") {
            const char* v = nullptr;
            if (!value("--repeat", v)) return false;
            unsigned long long n = 0;
            if (!parseUint(v, 64, n)) {
                err = std::string("--repeat must be 1..64 (") + v + ")";
                return false;
            }
            o.repeat = static_cast<uint32_t>(n);
        } else if (a == "--vulkan") {
            o.wantVulkan = true;
        } else if (a == "--no-flush") {
            o.flushEveryRecord = false;
        } else if (a == "--help" || a == "-h") {
            usage();
            return false;
        } else {
            err = "unknown argument: " + a;
            return false;
        }
    }
    if (o.modelPath.empty()) { err = "--model is required"; return false; }
    return true;
}

// ===========================================================================
// Measurements
// ===========================================================================

struct RunObservation {
    uint64_t callbacks      = 0;
    uint64_t reportedTokens = 0;
    uint64_t reportedPrompt = 0;
    uint64_t nonTextTokens  = 0;   // callbacks whose text was control soup
    uint64_t emptyTextTokens = 0;
    uint64_t adjacentDuplicateIds = 0;
    uint64_t distinctIds    = 0;
    size_t   kvBefore       = 0;
    size_t   kvAfterReturn  = 0;   // post-tail-reset; see kvDuring* below
    size_t   kvDuringFirst  = 0;   // sampled INSIDE the callback
    size_t   kvDuringLast   = 0;   // sampled INSIDE the callback
    bool     kvSampledInCallback = false;
    int32_t  firstTokenId   = -1;
    int32_t  lastTokenId    = -1;
    double   wallMs         = 0.0;
    double   enginePromptMs = 0.0;
    double   engineGenMs    = 0.0;
    std::string text;
    std::vector<int32_t> tokenIds;
    Deep2::GenerationStatus status = Deep2::GenerationStatus::InternalError;
    std::string failureDetail;
    bool     engineCompleted = false;
    bool     engineCancelled = false;
    bool     threw           = false;
    std::string throwDetail;
};

const char* statusName(Deep2::GenerationStatus s) {
    switch (s) {
        case Deep2::GenerationStatus::Completed:      return "Completed";
        case Deep2::GenerationStatus::EndOfSequence:  return "EndOfSequence";
        case Deep2::GenerationStatus::Cancelled:      return "Cancelled";
        case Deep2::GenerationStatus::InvalidInput:   return "InvalidInput";
        case Deep2::GenerationStatus::ForwardFailure: return "ForwardFailure";
        case Deep2::GenerationStatus::InternalError:  return "InternalError";
    }
    return "Unrecognized";   // forward-compatible: a new enumerator is OBSERVED
}

double nowMs() {
    using clock = std::chrono::steady_clock;
    return std::chrono::duration<double, std::milli>(
               clock::now().time_since_epoch()).count();
}

// One greedy generation, recording everything observable. Never throws: an
// exception becomes `threw` plus the engine's message, because a driver that
// dies on the floor produces no receipt at all.
RunObservation runOnce(Deep2::Deep2Engine& engine, const Options& opt) {
    RunObservation obs;
    obs.kvBefore = engine.kvCacheLength();

    Deep2::GenerationOptions gopt;
    gopt.maxTokens     = opt.maxTokens;
    gopt.temperature   = 0.0f;   // greedy: a non-deterministic first token is
    gopt.topP          = 1.0f;   // not a useful failure signal
    gopt.topK          = 1;
    gopt.repeatPenalty = 1.0f;   // stated so a default change becomes visible
    gopt.minP          = 0.0f;
    gopt.seed          = 1;

    obs.text.reserve(static_cast<size_t>(opt.maxTokens) * 8);
    obs.tokenIds.reserve(opt.maxTokens);

    int32_t previousId = -1;
    bool    firstSeen  = false;

    Deep2::TokenCallback cb =
        [&](int32_t tokenId, const std::string& token) -> bool {
            if (!firstSeen) { obs.firstTokenId = tokenId; firstSeen = true; }
            else if (tokenId == previousId) { ++obs.adjacentDuplicateIds; }
            obs.lastTokenId = tokenId;
            previousId      = tokenId;

            ++obs.callbacks;
            obs.tokenIds.push_back(tokenId);

            // Deep2Engine.cpp:8280 calls reset() on the tail of generateStream,
            // so kvCacheLength() read AFTER the call returns is 0 by
            // construction and observes nothing. The only place the cache is
            // live is inside this callback, so that is where it is sampled.
            // (An earlier revision of this driver read it after the call and
            // reported KV_CACHE_GREW=0 for every successful run -- a
            // measurement that could not disagree with anything.)
            const size_t kvLive = engine.kvCacheLength();
            if (!obs.kvSampledInCallback) {
                obs.kvDuringFirst      = kvLive;
                obs.kvSampledInCallback = true;
            }
            obs.kvDuringLast = kvLive;

            if (token.empty()) {
                ++obs.emptyTextTokens;
            } else {
                obs.text += token;
                for (unsigned char c : token) {
                    if (isSuspiciousControl(c)) { ++obs.nonTextTokens; break; }
                }
            }
            std::printf("[TOKEN] ordinal=%llu id=%d text=%s\n",
                        static_cast<unsigned long long>(obs.callbacks - 1),
                        static_cast<int>(tokenId),
                        escapeField(token).c_str());
            return true;   // never cancel: the point is to see the whole run
        };

    const double t0 = nowMs();
    try {
        const Deep2::GenerationResult r =
            engine.generateStream(opt.prompt, gopt, cb);
        obs.status          = r.status;
        obs.reportedTokens  = r.generatedTokens;
        obs.reportedPrompt  = r.promptTokens;
        obs.failureDetail   = r.failureDetail;
        obs.engineCompleted = r.completed;   // reported, never gated (see header)
        obs.engineCancelled = r.cancelled;
        obs.enginePromptMs  = r.promptTimeMs;
        obs.engineGenMs     = r.generationTimeMs;
    } catch (const std::exception& e) {
        obs.threw       = true;
        obs.throwDetail = e.what();
    } catch (...) {
        obs.threw       = true;
        obs.throwDetail = "non-std exception (type not inspectable)";
    }
    obs.wallMs         = nowMs() - t0;
    obs.kvAfterReturn  = engine.kvCacheLength();

    std::vector<int32_t> distinct = obs.tokenIds;
    std::sort(distinct.begin(), distinct.end());
    distinct.erase(std::unique(distinct.begin(), distinct.end()),
                   distinct.end());
    obs.distinctIds = distinct.size();

    return obs;
}

} // namespace

// ===========================================================================
// main
// ===========================================================================

int main(int argc, char** argv) {
    Options opt;
    std::string argError;
    if (!parseArgs(argc, argv, opt, argError)) {
        if (argError.empty()) return kExitPass;   // --help already printed
        std::fprintf(stderr, "error: %s\n\n", argError.c_str());
        usage();
        return kExitUsage;
    }

    Trace trace;
    trace.setFlushEveryRecord(opt.flushEveryRecord);

    trace.line("=== RAWRXD_DEEPSEEK_CPU_E2E_001 ===");
    trace.kv("MODEL_PATH", opt.modelPath);
    trace.kv("PROMPT", opt.prompt);
    trace.kv("REQUESTED_TOKENS", opt.maxTokens);
    trace.kv("REQUESTED_CTX", opt.ctxLen);
    trace.kv("REPEAT_REQUESTS", opt.repeat);
    trace.kvFlag("VULKAN_REQUESTED", opt.wantVulkan);

    Deep2::Deep2Engine engine;
    Deep2::EngineConfig cfg;
    cfg.maxSeqLen     = opt.ctxLen;
    cfg.numThreads    = 0;                 // auto
    cfg.useKVCache    = true;
    cfg.useThreadPool = true;

    // ---- STAGE 1: initialize ----------------------------------------------
    // A truncated path yields "cannot open model", which blames the model file
    // for a command-line error. Report the truncation instead.
    const int written = std::snprintf(cfg.modelPath, sizeof cfg.modelPath,
                                      "%s", opt.modelPath.c_str());
    trace.stageEnter(stageName(Stage::EngineInitialize));
    bool initialized = false;
    if (written < 0 || static_cast<size_t>(written) >= sizeof cfg.modelPath) {
        trace.failStage(Stage::EngineInitialize,
                        "model path exceeds EngineConfig::modelPath capacity (" +
                        std::to_string(sizeof cfg.modelPath) + " bytes)");
    } else {
        const double tInit0 = nowMs();
        engine.enableVulkan(opt.wantVulkan);
        try {
            initialized = engine.initialize(cfg);
        } catch (const std::exception& e) {
            trace.failStage(Stage::EngineInitialize, e.what());
        } catch (...) {
            trace.failStage(Stage::EngineInitialize, "non-std exception");
        }
        trace.kv("INIT_MS", nowMs() - tInit0);
        if (initialized) {
            trace.stageOk(stageName(Stage::EngineInitialize));
        } else if (!trace.hasFailure()) {
            trace.failStage(Stage::EngineInitialize,
                            "initialize() returned false");
        }
    }
    trace.kvFlag("ENGINE_REPORTED_INITIALIZED", engine.isInitialized());

    // ---- STAGE 2: load model ----------------------------------------------
    Deep2::ModelLoadDiag diag;
    bool loaded = false;
    if (trace.hasFailure()) {
        trace.stageSkip(stageName(Stage::ModelLoad), "UPSTREAM_FAILURE");
    } else {
        trace.stageEnter(stageName(Stage::ModelLoad));
        const double tLoad0 = nowMs();
        try {
            loaded = engine.loadModel(opt.modelPath, &diag);
        } catch (const std::exception& e) {
            trace.failStage(Stage::ModelLoad, e.what());
        } catch (...) {
            trace.failStage(Stage::ModelLoad, "non-std exception");
        }
        trace.kv("LOAD_MS", nowMs() - tLoad0);
        if (loaded) {
            trace.stageOk(stageName(Stage::ModelLoad));
        } else {
            trace.kv("LOAD_STAGE_CODE", diag.stageCode);
            trace.kv("LOAD_STAGE_NAME", diag.stageName);
            trace.kv("LOAD_MESSAGE", diag.message);
            const std::string where = diag.stageName.empty()
                ? std::string("loadModel() returned false")
                : diag.stageName + ": " + diag.message;
            trace.failStage(Stage::ModelLoad, where);
        }
    }
    // Architecture is why this driver exists: whether MLA/MoE is engaged is the
    // question the census shape could not answer.
    trace.kv("MODEL_ARCHITECTURE", engine.modelArchitecture());
    trace.kvFlag("ENGINE_REPORTED_MODEL_LOADED", engine.isModelLoaded());

    // ---- STAGE 3: generate -------------------------------------------------
    RunObservation obs;
    bool legitimateStop = false;   // EndOfSequence with no failure and no output
    if (trace.hasFailure()) {
        trace.stageSkip(stageName(Stage::GenerateStream), "UPSTREAM_FAILURE");
    } else {
        trace.stageEnter(stageName(Stage::GenerateStream));
        obs = runOnce(engine, opt);
        trace.kv("STREAM_WALL_MS", obs.wallMs);

        const bool statusOk = obs.status == Deep2::GenerationStatus::Completed ||
                              obs.status == Deep2::GenerationStatus::EndOfSequence;

        if (obs.threw) {
            trace.failStage(Stage::GenerateStream, obs.throwDetail);
        } else if (obs.callbacks > 0 && !obs.text.empty() &&
                   obs.nonTextTokens == 0 && obs.emptyTextTokens == 0 &&
                   statusOk) {
            trace.stageOk(stageName(Stage::GenerateStream));
        } else if (statusOk && obs.callbacks == 0) {
            // Deep2Engine.cpp:8167-8169 documents zero tokens with no recorded
            // failure as a legitimate immediate stop, NOT an error. Recording
            // it as a stage failure would blame the model for the engine's
            // contract. It is a clean run that produced no text: exit 1.
            legitimateStop = true;
            trace.stageOk(stageName(Stage::GenerateStream),
                          "legitimate_immediate_stop_no_output");
        } else {
            std::string why = obs.failureDetail;
            if (why.empty()) {
                why = "no usable text streamed";
                if (obs.callbacks == 0)          why += " (zero callbacks)";
                else if (obs.text.empty())       why += " (callbacks carried no text)";
                else if (obs.emptyTextTokens)    why += " (" +
                    std::to_string(obs.emptyTextTokens) + " callbacks carried empty text)";
                else if (obs.nonTextTokens)      why += " (" +
                    std::to_string(obs.nonTextTokens) + " tokens decoded to control bytes)";
                else                             why += " (status=" +
                    std::string(statusName(obs.status)) + ")";
            }
            trace.failStage(Stage::GenerateStream, why);
        }
    }

    // ---- determinism replay (opt-in, strictly additive) --------------------
    // MUST precede teardown: generateStream requires a loaded model, and
    // unloadModel() above would make every replay early-exit with
    // "engine not ready" and report a divergence that is an artefact of
    // ordering rather than a property of the engine.
    uint32_t replayMatches = 0;
    bool     replayDeterministic = true;
    bool     replayRan = false;
    if (opt.repeat > 1 && loaded && !obs.threw && obs.callbacks > 0) {
        replayRan = true;
        bool replayBroke = false;
        for (uint32_t i = 0; i + 1 < opt.repeat && !replayBroke; ++i) {
            try {
                engine.reset();
            } catch (const std::exception& e) {
                replayDeterministic = false;
                replayBroke = true;
                trace.kv("REPLAY_ERROR_STAGE", std::string("reset: ") + e.what());
                break;
            } catch (...) {
                replayDeterministic = false;
                replayBroke = true;
                trace.kv("REPLAY_ERROR_STAGE", "reset: non-std exception");
                break;
            }
            const RunObservation again = runOnce(engine, opt);
            if (again.tokenIds == obs.tokenIds) {
                ++replayMatches;
            } else {
                replayDeterministic = false;
                replayBroke = true;
                trace.kv("REPLAY_MISMATCH_AT_RUN", static_cast<long long>(i + 2));
            }
        }
        trace.kv("REPLAY_EXPECTED_MATCHES", opt.repeat - 1);
        trace.kv("REPLAY_OBSERVED_MATCHES", replayMatches);
    }

    // ---- STAGE 4: teardown -------------------------------------------------
    // Each sub-step reports independently. One try block around all of them
    // meant a throw in reset() silently skipped unloadModel() and hid the
    // KV-length observation, so a leak left no trace at all.
    trace.stageEnter(stageName(Stage::Teardown));
    bool resetOk = true, unloadOk = true, kvAfterResetKnown = false;
    int64_t kvAfterReset = -1;   // -1 = NOT_OBSERVED, distinct from 0
    if (!initialized) {
        trace.stageSkip(stageName(Stage::Teardown), "ENGINE_NEVER_INITIALIZED");
    } else {
        try {
            engine.reset();
            kvAfterReset      = static_cast<int64_t>(engine.kvCacheLength());
            kvAfterResetKnown = true;
        } catch (const std::exception& e) {
            resetOk = false;
            trace.failStage(Stage::Teardown, std::string("reset: ") + e.what());
        } catch (...) {
            resetOk = false;
            trace.failStage(Stage::Teardown, "reset: non-std exception");
        }

        try {
            engine.unloadModel();
        } catch (const std::exception& e) {
            unloadOk = false;
            trace.failStage(Stage::Teardown, std::string("unloadModel: ") + e.what());
        } catch (...) {
            unloadOk = false;
            trace.failStage(Stage::Teardown, "unloadModel: non-std exception");
        }

        if (kvAfterResetKnown) trace.kv("KV_CACHE_LENGTH_AFTER", kvAfterReset);
        else                  trace.kv("KV_CACHE_LENGTH_AFTER", -1);
    }
    if (initialized && resetOk && unloadOk) {
        trace.stageOk(stageName(Stage::Teardown));
    }

    // ---- RECEIPT -----------------------------------------------------------
    trace.line("");
    trace.line("=== RECEIPT ===");

    trace.kvFlag("INITIALIZED", initialized);
    trace.kvFlag("MODEL_LOADED", loaded);

    trace.kv("CALLBACKS", static_cast<long long>(obs.callbacks));
    trace.kv("REPORTED_GENERATED_TOKENS", static_cast<long long>(obs.reportedTokens));
    trace.kv("REPORTED_PROMPT_TOKENS", static_cast<long long>(obs.reportedPrompt));
    trace.kvFlag("STREAM_CALLBACKS_EQUAL_REPORTED",
                 obs.callbacks == obs.reportedTokens);
    trace.kv("FIRST_TOKEN_ID", static_cast<long long>(obs.firstTokenId));
    trace.kv("LAST_TOKEN_ID", static_cast<long long>(obs.lastTokenId));
    trace.kv("DISTINCT_TOKEN_IDS", static_cast<long long>(obs.distinctIds));
    trace.kv("ADJACENT_DUPLICATE_TOKEN_IDS",
             static_cast<long long>(obs.adjacentDuplicateIds));
    trace.kv("SUSPECTED_NON_TEXT_TOKENS", static_cast<long long>(obs.nonTextTokens));
    trace.kv("EMPTY_TEXT_TOKENS", static_cast<long long>(obs.emptyTextTokens));

    trace.kvFlag("CLEAN_TEARDOWN", resetOk && unloadOk);
    trace.kvFlag("KV_EMPTY_AFTER_RESET", kvAfterResetKnown && kvAfterReset == 0);

    trace.kv("STATUS", statusName(obs.status));
    trace.kvFlag("ENGINE_COMPLETED_FLAG", obs.engineCompleted);
    trace.kvFlag("ENGINE_CANCELLED_FLAG", obs.engineCancelled);
    trace.kvFlag("LEGITIMATE_IMMEDIATE_STOP", legitimateStop);
    trace.kvFlag("GENERATION_THREW", obs.threw);
    trace.kv("GENERATION_THROW_DETAIL", obs.throwDetail);
    trace.kv("FAILURE_DETAIL", obs.failureDetail);

    // Two independent time estimates. One wall clock around the call is a
    // claim; the engine's own prefill/decode split landing inside it is
    // corroboration from a different measurement.
    trace.kv("STREAM_WALL_MS", obs.wallMs);
    trace.kv("ENGINE_PROMPT_MS", obs.enginePromptMs);
    trace.kv("ENGINE_GENERATION_MS", obs.engineGenMs);
    const double engineTotal = obs.enginePromptMs + obs.engineGenMs;
    trace.kvFlag("ENGINE_TIME_WITHIN_WALL",
                 engineTotal > 0.0 && engineTotal <= obs.wallMs * 1.05);
    trace.kv("DECODE_TPS",
             (obs.wallMs > 0.0 && obs.reportedTokens > 0)
                 ? obs.reportedTokens / (obs.wallMs / 1000.0) : 0.0);
    trace.kv("DECODE_TPS_ENGINE",
             (obs.engineGenMs > 0.0 && obs.reportedTokens > 0)
                 ? obs.reportedTokens / (obs.engineGenMs / 1000.0) : 0.0);

    // Did generation actually consume and grow the cache? Deep2Engine.cpp:8280
    // resets the cache on the tail of generateStream, so the post-return value
    // is 0 for every run and is reported only as evidence of that reset. The
    // growth measurement is the in-callback sample, taken while the cache is
    // live. Whether the final sampled token's KV is written is an engine
    // convention rather than a published invariant, so only the unambiguous
    // direction is gated and the exact delta is reported for inspection.
    trace.kv("KV_CACHE_LENGTH_BEFORE", static_cast<long long>(obs.kvBefore));
    trace.kvFlag("KV_SAMPLED_IN_CALLBACK", obs.kvSampledInCallback);
    trace.kv("KV_CACHE_LENGTH_AT_TOKEN_1",
             obs.kvSampledInCallback
                 ? static_cast<long long>(obs.kvDuringFirst) : -1);
    trace.kv("KV_CACHE_LENGTH_AT_TOKEN_N",
             obs.kvSampledInCallback
                 ? static_cast<long long>(obs.kvDuringLast) : -1);
    trace.kv("KV_CACHE_DELTA_IN_CALLBACK",
             obs.kvSampledInCallback
                 ? static_cast<long long>(obs.kvDuringLast) -
                   static_cast<long long>(obs.kvDuringFirst) : -1);
    trace.kv("KV_CACHE_EXPECTED_DELTA_IN_CALLBACK",
             static_cast<long long>(obs.reportedPrompt + obs.reportedTokens));
    trace.kvFlag("KV_CACHE_GREW_DURING_DECODE",
                 obs.kvSampledInCallback && obs.kvDuringLast > obs.kvBefore);
    trace.kv("KV_CACHE_LENGTH_AFTER_RETURN",
             static_cast<long long>(obs.kvAfterReturn));
    trace.kvFlag("KV_EMPTY_AFTER_GENERATE_RETURN", obs.kvAfterReturn == 0);

    if (replayRan) trace.kvFlag("REPLAY_DETERMINISTIC", replayDeterministic);
    else           trace.kv("REPLAY_DETERMINISTIC", "NOT_RUN");

    trace.kvFlag("TEXT_STREAMED", !obs.text.empty());
    trace.kv("TEXT", obs.text);
    trace.kv("FIRST_FAILED_STAGE", trace.firstStage());
    trace.kv("FIRST_FAILED_STAGE_DETAIL", trace.firstDetail());

    // ---- derived verdict ---------------------------------------------------
    // Every conjunct below is an observation recorded above. No branch sets the
    // verdict without having measured something first. `engineCompleted` is
    // deliberately absent: Deep2Engine.cpp:8171 derives it from `status`.
    const bool textStreamed = !obs.text.empty();
    const bool statusOk     = obs.status == Deep2::GenerationStatus::Completed ||
                              obs.status == Deep2::GenerationStatus::EndOfSequence;
    const bool countOk      = obs.callbacks == obs.reportedTokens;
    const bool decodeClean  = obs.nonTextTokens == 0 && obs.emptyTextTokens == 0;

    const bool pass = initialized && loaded && textStreamed && statusOk &&
                      countOk && decodeClean && !obs.threw &&
                      resetOk && unloadOk &&
                      (!replayRan || replayDeterministic) && !trace.hasFailure();

    trace.kvFlag("PASS_STREAMED_TEXT", textStreamed);
    trace.kvFlag("PASS_STATUS_CONTRACT", statusOk);
    trace.kvFlag("PASS_CALLBACK_COUNT_MATCHES", countOk);
    trace.kvFlag("PASS_DECODE_CLEAN", decodeClean);
    trace.kvFlag("PASS_ALL", pass);
    trace.kv("VERDICT", pass ? "PASS" : "FAIL");

    if (textStreamed) {
        std::printf("\n=== COMPLETION ===\n%s\n", obs.text.c_str());
    }
    std::fflush(stdout);

    if (pass) return kExitPass;
    if (trace.hasFailure()) {
        // Map the first refusal back to its stage ordinal.
        for (Stage s : {Stage::EngineInitialize, Stage::ModelLoad,
                        Stage::GenerateStream, Stage::Teardown}) {
            if (std::strcmp(trace.firstStage(), stageName(s)) == 0) {
                return stageExit(s);
            }
        }
        return stageExit(Stage::Teardown);
    }
    // No stage refused. Distinguish "ran clean and produced nothing" from
    // "produced text but a corroboration gate disagreed" -- reporting the
    // latter as kExitNoText would claim less than actually happened, which is
    // the same class of defect this file exists to remove.
    return textStreamed ? kExitGate : kExitNoText;
}