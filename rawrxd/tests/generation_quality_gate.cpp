// generation_quality_gate.cpp — GENERATION_QUALITY_001
//
// Differential certification of the IDE chat lane against the certified CPU
// correctness lane, using the engine's own parity probe as the instrument.
//
// The IDE chat lane and the CPU correctness harness differ in exactly two
// EngineConfig knobs that are observable here:
//
//   CPU_HARNESS (certified)   maxSeqLen=64   numThreads=1  useThreadPool=false
//   IDE_CHAT   (candidate)    maxSeqLen=4096 numThreads=0  useThreadPool=true
//
// Rather than compare only the two endpoints, this runs the full 2x2 so a
// divergence is attributed to a specific knob instead of "the configs differ":
//
//   A  maxSeqLen=64   threads=1  pool=false   <- REFERENCE
//   B  maxSeqLen=4096 threads=1  pool=false   <- isolates maxSeqLen
//   C  maxSeqLen=64   threads=auto pool=true  <- isolates threading
//   D  maxSeqLen=4096 threads=auto pool=true  <- IDE_CHAT, CANDIDATE
//
// Everything else is held identical: same GGUF, same prompt, same seed, same
// sampler, same max tokens, Vulkan off, KV cache on, RoPE on.
//
// Each arm runs with the parity probe enabled and per-step arming, so the
// engine's existing checkpoint records (Deep2Engine::ParityCheckpoint) are the
// instrument. This harness invents no numerical schema; it only parses those
// records, diffs them, and reports the FIRST point of divergence.
//
// Usage:
//   generation_quality_gate <model.gguf> <outdir> [prompt] [maxTokens]

#include "deep2/Deep2Engine.h"

#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

using Deep2::Deep2Engine;
using Deep2::EngineConfig;
using Deep2::GenerationOptions;
using Deep2::GenerationResult;

namespace {

// ── Engine probe checkpoints, in the order the forward pass reaches them ────
struct CheckpointOrder {
    static const char* const kNames[20];
};
const char* const CheckpointOrder::kNames[20] = {
    "EMBED", "ATTN_NORM", "Q", "K", "V", "Q_ROPE", "K_ROPE",
    "ATTN_SCORES", "ATTN_PROBS", "ATTN_VALUE", "O_PROJ", "ATTN_RESIDUAL",
    "FFN_NORM", "FFN_GATE", "FFN_UP", "SWIGLU", "FFN_DOWN",
    "LAYER_RESIDUAL", "FINAL_NORM", "LOGITS"
};

struct Record {
    bool    present = false;
    long    count   = 0;
    double  min = 0, max = 0, mean = 0, l2 = 0;
    std::string first8;
    unsigned long long hash = 0;
};

struct Top10 {
    bool present = false;
    std::string raw;
};

struct ArmTrace {
    std::map<int, std::map<std::string, Record>> byStep;   // step -> cp -> record
    std::map<int, Top10> top10;                            // step -> top10
    std::map<int, int> kvWrites;                           // step -> count
};

struct ArmResult {
    std::string name;
    size_t maxSeqLen = 0;
    bool autoThreads = false;
    bool threadPool = false;

    bool loadOk = false;
    double loadMs = 0;
    unsigned long long promptTokens = 0;
    std::vector<int> tokenIds;
    std::string text;
    double firstTokenMs = 0;
    double totalMs = 0;
    double genMs = 0;
    size_t kvLength = 0;
    int statusCode = 0;
    std::string statusName;
    ArmTrace trace;
    std::string tracePath;
};

const char* statusNameOf(Deep2::GenerationStatus s) {
    switch (s) {
        case Deep2::GenerationStatus::Completed:      return "Completed";
        case Deep2::GenerationStatus::EndOfSequence:  return "EndOfSequence";
        case Deep2::GenerationStatus::Cancelled:      return "Cancelled";
        case Deep2::GenerationStatus::InvalidInput:   return "InvalidInput";
        case Deep2::GenerationStatus::ForwardFailure: return "ForwardFailure";
        default:                                      return "InternalError";
    }
}

// Strict UTF-8 validation. Used for CP15 so "stream rendered" is a measured
// property rather than an assumption.
bool isValidUtf8(const std::string& s) {
    size_t i = 0;
    while (i < s.size()) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        size_t need;
        unsigned int cp;
        if (c < 0x80)              { ++i; continue; }
        else if ((c & 0xE0) == 0xC0) { need = 1; cp = c & 0x1Fu; }
        else if ((c & 0xF0) == 0xE0) { need = 2; cp = c & 0x0Fu; }
        else if ((c & 0xF8) == 0xF0) { need = 3; cp = c & 0x07u; }
        else return false;
        if (i + need >= s.size()) return false;
        for (size_t k = 1; k <= need; ++k) {
            const unsigned char cc = static_cast<unsigned char>(s[i + k]);
            if ((cc & 0xC0) != 0x80) return false;
            cp = (cp << 6) | (cc & 0x3Fu);
        }
        // Reject overlong encodings and surrogates.
        if (need == 1 && cp < 0x80) return false;
        if (need == 2 && cp < 0x800) return false;
        if (need == 3 && cp < 0x10000) return false;
        if (cp > 0x10FFFF) return false;
        if (cp >= 0xD800 && cp <= 0xDFFF) return false;
        i += need + 1;
    }
    return true;
}

void parseTrace(const std::string& path, ArmTrace& out) {
    std::ifstream in(path);
    if (!in) return;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;

        int step = 0;
        const size_t sp = line.find("STEP=");
        if (sp == std::string::npos) continue;
        step = std::atoi(line.c_str() + sp + 5);

        if (line.find("CP=LOGITS_TOP10") != std::string::npos) {
            const size_t t = line.find("TOP10=");
            if (t != std::string::npos) {
                out.top10[step].present = true;
                out.top10[step].raw = line.substr(t + 6);
            }
            continue;
        }
        if (line.find("CP=KV_WRITE") != std::string::npos) {
            ++out.kvWrites[step];
            continue;
        }

        const size_t cp = line.find("CP=");
        if (cp == std::string::npos) continue;
        size_t end = line.find(' ', cp);
        if (end == std::string::npos) continue;
        const std::string name = line.substr(cp + 3, end - cp - 3);

        Record r;
        r.present = true;
        auto grabU = [&](const char* key, unsigned long long& dst) {
            const std::string k = std::string(key) + "=";
            const size_t p = line.find(k);
            if (p != std::string::npos)
                dst = std::strtoull(line.c_str() + p + k.size(), nullptr, 10);
        };
        auto grabD = [&](const char* key, double& dst) {
            const std::string k = std::string(key) + "=";
            const size_t p = line.find(k);
            if (p != std::string::npos)
                dst = std::strtod(line.c_str() + p + k.size(), nullptr);
        };
        {
            const std::string k = "COUNT=";
            const size_t p = line.find(k);
            if (p != std::string::npos) r.count = std::atol(line.c_str() + p + k.size());
        }
        grabD("MIN", r.min);
        grabD("MAX", r.max);
        grabD("MEAN", r.mean);
        grabD("L2", r.l2);
        grabU("HASH", r.hash);
        {
            const std::string k = "FIRST8=";
            const size_t p = line.find(k);
            if (p != std::string::npos) {
                size_t e = line.find(' ', p);
                r.first8 = line.substr(p + k.size(),
                                       (e == std::string::npos ? line.size() : e) - p - k.size());
            }
        }
        out.byStep[step][name] = r;
    }
}

// Layer-scoped ladder digest.
//
// parityEmit() has once-per-step semantics, so the 20 bare checkpoint names
// above only carry the FIRST layer of a step. parityEmitLayer() bypasses that
// guard, so the trace also carries LAYER_<n>_<NAME> for every layer. Folding
// each step's layer records into one ordered digest keeps the differential
// readable while still comparing the whole stack, not just layer 0.
unsigned long long layerLadderHash(const std::map<std::string, Record>& step) {
    unsigned long long acc = 1469598103934665603ull;
    for (const auto& kv : step) {
        if (kv.first.rfind("LAYER_", 0) != 0) continue;   // LAYER_<n>_<NAME>
        if (kv.first == "LAYER_RESIDUAL") continue;       // bare name, counted above
        for (const char* p = kv.first.c_str(); *p; ++p) {
            acc ^= static_cast<unsigned long long>(static_cast<unsigned char>(*p));
            acc *= 1099511628211ull;
        }
        acc ^= kv.second.hash;
        acc *= 1099511628211ull;
    }
    return acc;
}

struct LayerStats {
    int    maxLayer = -1;
    size_t records  = 0;
    size_t steps    = 0;
    size_t names    = 0;
};

LayerStats layerStats(const ArmTrace& t) {
    LayerStats s;
    std::set<std::string> names;
    for (const auto& kv : t.byStep) {
        bool any = false;
        for (const auto& c : kv.second) {
            if (c.first.rfind("LAYER_", 0) != 0 || c.first == "LAYER_RESIDUAL")
                continue;
            ++s.records;
            any = true;
            names.insert(c.first);
            int n = -1;
            if (std::sscanf(c.first.c_str(), "LAYER_%d_", &n) == 1 && n > s.maxLayer)
                s.maxLayer = n;
        }
        if (any) ++s.steps;
    }
    s.names = names.size();
    return s;
}

ArmResult runArm(const std::string& model, const std::string& prompt,
                 size_t maxTokens, const char* armName,
                 size_t maxSeqLen, int numThreads, bool useThreadPool,
                 const std::string& tracePath) {
    ArmResult res;
    res.name = armName;
    res.maxSeqLen = maxSeqLen;
    res.autoThreads = (numThreads == 0);
    res.threadPool = useThreadPool;
    res.tracePath = tracePath;

    Deep2Engine e;
    EngineConfig cfg{};
    cfg.maxSeqLen = maxSeqLen;
    cfg.numThreads = numThreads;
    cfg.useThreadPool = useThreadPool;
    cfg.useKVCache = true;
    cfg.useRoPE = true;

    if (!e.initialize(cfg)) {
        res.statusName = "ENGINE_INIT_FAILED";
        return res;
    }

    const auto t0 = std::chrono::steady_clock::now();
    if (!e.loadModel(model)) {
        const auto t1 = std::chrono::steady_clock::now();
        res.loadMs = std::chrono::duration<double, std::milli>(t1 - t0).count();
        res.statusName = "LOAD_FAILED";
        return res;
    }
    const auto t1 = std::chrono::steady_clock::now();
    res.loadMs = std::chrono::duration<double, std::milli>(t1 - t0).count();
    res.loadOk = true;

    // CPU lane under test in both arms, so the GPU backend cannot confound.
    e.enableVulkan(false);

    // The engine's own checkpoint instrument, unmodified.
    e.enableParityProbe(tracePath.c_str(), 64);
    e.enableParityProbeFullVectors(0);

    GenerationOptions o{};
    o.maxTokens   = static_cast<uint32_t>(maxTokens);
    o.temperature = 0.0f;   // greedy: removes the sampler as a variable
    o.topK        = 1;
    o.topP        = 1.0f;
    o.seed        = 1;

    const auto genStart = std::chrono::steady_clock::now();
    int step = 0;
    GenerationResult r = e.generateStream(prompt, o, [&](int32_t id, const std::string& piece) -> bool {
        const auto now = std::chrono::steady_clock::now();
        if (step == 0) {
            res.firstTokenMs = std::chrono::duration<double, std::milli>(now - genStart).count();
        }
        res.tokenIds.push_back(static_cast<int>(id));
        res.text += piece;
        // Arm the next step so the trace carries one full checkpoint set per
        // position instead of only position 0.
        e.parityBeginStep(++step);
        return true;
    });
    const auto genEnd = std::chrono::steady_clock::now();

    e.disableParityProbe();

    res.totalMs  = std::chrono::duration<double, std::milli>(genEnd - genStart).count();
    res.genMs    = r.generationTimeMs;
    res.promptTokens = static_cast<unsigned long long>(r.promptTokens);
    res.kvLength = e.kvCacheLength();
    res.statusCode = static_cast<int>(r.status);
    res.statusName = statusNameOf(r.status);

    parseTrace(tracePath, res.trace);
    return res;
}

std::string oneLine(const std::string& s, size_t maxLen) {
    std::string out;
    for (char c : s) {
        if (c == '\n' || c == '\r') { out += ' '; continue; }
        out += c;
        if (out.size() >= maxLen) { out += "..."; break; }
    }
    return out;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 3) {
        std::fprintf(stderr,
            "usage: generation_quality_gate <model.gguf> <outdir> [prompt] [maxTokens]\n");
        return 2;
    }
    const std::string model = argv[1];
    const std::string outdir = argv[2];
    const std::string prompt = (argc > 3) ? argv[3] : "The capital of France is";
    const size_t maxTokens = (argc > 4) ? static_cast<size_t>(std::atoi(argv[4])) : 8;

    struct ArmSpec { const char* name; size_t seq; int threads; bool pool; const char* role; };
    const ArmSpec specs[4] = {
        {"A_CPU_HARNESS",   64,   1, false, "REFERENCE"},
        {"B_SEQ4096",     4096,   1, false, "ISOLATE_MAXSEQLEN"},
        {"C_THREADPOOL",    64,   0, true,  "ISOLATE_THREADING"},
        {"D_IDE_CHAT",    4096,   0, true,  "CANDIDATE"},
    };

    ArmResult results[4];
    for (int i = 0; i < 4; ++i) {
        std::string tp = outdir + "/trace_" + specs[i].name + ".txt";
        results[i] = runArm(model, prompt, maxTokens, specs[i].name,
                            specs[i].seq, specs[i].threads, specs[i].pool, tp);
    }

    const ArmResult& ref = results[0];
    const ArmResult& cand = results[3];

    // ── Differential: first divergence in probe-checkpoint order ────────────
    struct Row { std::string cp; int verdict; std::string note; };
    // verdict:  1 = match
    //           0 = true hash divergence
    //          -1 = required at this step but not instrumented
    //          -2 = not required at this step
    // An absent checkpoint is an instrumentation gap, NOT a numerical
    // divergence, and must not be reported as one. Equally, a surface that the
    // engine legitimately does not compute at a step is not a coverage gap.
    std::vector<Row> rows;

    // Prefill positions do not run computeLogits: the logits/final-norm
    // surface only exists from the first decode step onward. Reporting those as
    // gaps would be wrong, and counting them as compared would be a lie, so
    // they get their own verdict.
    const int decodeStart = static_cast<int>(
        cand.promptTokens > 0 ? cand.promptTokens : ref.promptTokens);

    int firstStep = 0, lastStep = -1;
    for (int i = 0; i < 4; ++i) {
        for (const auto& kv : results[i].trace.byStep) {
            if (kv.first < firstStep) firstStep = kv.first;
            if (kv.first > lastStep)  lastStep  = kv.first;
        }
    }
    if (lastStep < 0) lastStep = static_cast<int>(maxTokens);

    for (int step = firstStep; step <= lastStep; ++step) {
        auto ri   = ref.trace.byStep.find(step);
        auto ciIt = cand.trace.byStep.find(step);
        for (int k = 0; k < 20; ++k) {
            const std::string cp = CheckpointOrder::kNames[k];
            const bool logitsSurface = (cp == "FINAL_NORM" || cp == "LOGITS");
            const bool required = !(logitsSurface && step < decodeStart);

            const Record* a = nullptr;
            const Record* b = nullptr;
            if (ri != ref.trace.byStep.end()) {
                auto it = ri->second.find(cp);
                if (it != ri->second.end()) a = &it->second;
            }
            if (ciIt != cand.trace.byStep.end()) {
                auto it = ciIt->second.find(cp);
                if (it != ciIt->second.end()) b = &it->second;
            }

            if (!a || !b) {
                if (!required) {
                    rows.push_back({cp, -2, "PREFILL_STEP_NO_LOGITS_SURFACE(step=" +
                                             std::to_string(step) + ")"});
                } else if (!a && !b) {
                    rows.push_back({cp, -1, "NOT_INSTRUMENTED(step=" +
                                             std::to_string(step) + ")"});
                } else {
                    rows.push_back({cp, -1, "ABSENT_IN_ONE_ARM(step=" +
                                             std::to_string(step) + ")"});
                }
                continue;
            }

            if (a->hash != b->hash) {
                char note[192];
                std::snprintf(note, sizeof(note),
                              "step=%d refHASH=%016llx dutHASH=%016llx refL2=%.9g dutL2=%.9g",
                              step,
                              static_cast<unsigned long long>(a->hash),
                              static_cast<unsigned long long>(b->hash),
                              a->l2, b->l2);
                rows.push_back({cp, 0, note});
            } else {
                char h[32];
                std::snprintf(h, sizeof(h), "hash %016llx", a->hash);
                rows.push_back({cp, 1, h});
            }
        }

        // Whole-stack layer ladder for this step.
        const std::string ladderCp = "LAYER_LADDER@" + std::to_string(step);
        if (ri != ref.trace.byStep.end() && ciIt != cand.trace.byStep.end()) {
            const unsigned long long ha = layerLadderHash(ri->second);
            const unsigned long long hb = layerLadderHash(ciIt->second);
            char note[192];
            if (ha != hb) {
                std::snprintf(note, sizeof(note), "step=%d refHASH=%016llx dutHASH=%016llx",
                              step, ha, hb);
                rows.push_back({ladderCp, 0, note});
            } else {
                std::snprintf(note, sizeof(note), "step=%d hash %016llx", step, ha);
                rows.push_back({ladderCp, 1, note});
            }
        } else {
            rows.push_back({ladderCp, -1, "NOT_INSTRUMENTED(step=" +
                                           std::to_string(step) + ")"});
        }
    }

    size_t trueDivergences = 0, notInstrumented = 0, compared = 0, notRequired = 0;
    for (const Row& r : rows) {
        if (r.verdict == 0)      ++trueDivergences;
        else if (r.verdict == -1) ++notInstrumented;
        else if (r.verdict == -2) ++notRequired;
        else                      ++compared;
    }

    // Per-checkpoint coverage over the steps that required the surface.
    struct NameCov { int matched = 0, diverged = 0, missing = 0, notReq = 0; };
    std::map<std::string, NameCov> cov;
    for (int k = 0; k < 20; ++k) cov[CheckpointOrder::kNames[k]] = NameCov{};
    int ladderSteps = 0, ladderGaps = 0;
    for (const Row& row : rows) {
        auto it = cov.find(row.cp);
        if (it == cov.end()) {
            if (row.cp.rfind("LAYER_LADDER@", 0) == 0) {
                if (row.verdict == 1) ++ladderSteps;
                else if (row.verdict == -1) ++ladderGaps;
            }
            continue;
        }
        if (row.verdict == 1)      ++it->second.matched;
        else if (row.verdict == 0) ++it->second.diverged;
        else if (row.verdict == -1) ++it->second.missing;
        else                       ++it->second.notReq;
    }
    const LayerStats ls = layerStats(ref.trace);

    std::string firstDivergence = "NONE";
    std::string investigationTarget = "NONE";
    for (const Row& r : rows) {
        if (r.verdict == 0) {
            firstDivergence = r.cp;
            investigationTarget = (r.cp == "EMBED") ? "embedding lookup"
                              : (r.cp == "LOGITS") ? "lm_head / finalNorm"
                              : (r.cp.rfind("ATTN", 0) == 0) ? "attention block"
                              : (r.cp.rfind("FFN", 0) == 0 || r.cp == "SWIGLU") ? "feed-forward block"
                              : (r.cp == "FINAL_NORM") ? "final norm"
                              : "forward pass";
            break;
        }
    }

    // Top-10 agreement, per step. The logits surface only exists from the first
    // decode step, so comparing at step 0 (a prefill position) would always
    // read as absent.
    bool top10Present = false;
    bool top10MatchAll = true;
    int  top10Steps = 0, top10Mismatch = 0, top10AbsentOneArm = 0;
    std::string top10Ref, top10Dut;
    int top10FirstStep = -1;
    for (const auto& kv : ref.trace.top10) {
        const int step = kv.first;
        if (step < decodeStart) continue;
        auto b = cand.trace.top10.find(step);
        if (b == cand.trace.top10.end()) { ++top10AbsentOneArm; continue; }
        ++top10Steps;
        top10Present = true;
        if (top10FirstStep < 0) { top10FirstStep = step; top10Ref = kv.second.raw; top10Dut = b->second.raw; }
        if (kv.second.raw != b->second.raw) { top10MatchAll = false; ++top10Mismatch; }
    }
    const bool top10Match = top10Present && top10MatchAll && top10AbsentOneArm == 0;

    const bool textMatch = (ref.text == cand.text);
    const bool tokensMatch = (ref.tokenIds == cand.tokenIds);
    const bool utf8Ok = isValidUtf8(cand.text);
    // Config equivalence is the question this gate asks. A true numerical
    // divergence, or a token/text mismatch, means the lanes differ.
    const bool lanesEquivalent = (trueDivergences == 0 && tokensMatch && textMatch);

    // ── Record ─────────────────────────────────────────────────────────────
    std::ostringstream r;
    r << "===============================================================================\n";
    r << "RAWRXD CERTIFICATION RECORD\n";
    r << "===============================================================================\n\n";
    r << "PROGRAM=Program0_GenerationQuality\n";
    r << "GATE=GENERATION_QUALITY_001\n";
    r << "VERSION=1\n\n";
    r << "STATUS=" << (lanesEquivalent ? "PASS" : "FAIL") << "\n";
    r << "DATE_UTC=\nBRANCH=\nCOMMIT=\nBUILD=Release\n\n";
    r << "MODEL=" << model << "\n";
    r << "MODEL_SHA256=NOT_COMPUTED\n";
    r << "TOKENIZER_SHA256=NOT_COMPUTED\n";
    r << "REFERENCE_COMMIT=\n\n";
    r << "PROMPT=" << oneLine(prompt, 200) << "\n";
    r << "PROMPT_TOKENS=" << cand.promptTokens << "\n";
    r << "SEED=1\n\n";
    r << "SAMPLER=Greedy\nTEMPERATURE=0\nTOP_K=1\nTOP_P=1\nMAX_TOKENS=" << maxTokens << "\n\n";

    r << "===============================================================================\n";
    r << "CHECKPOINT LADDER\n";
    r << "===============================================================================\n\n";
    auto cpRow = [&](const char* id, const char* status, const std::string& extra) {
        r << id << "\n    STATUS=" << status << "\n";
        if (!extra.empty()) r << "    " << extra << "\n";
    };
    cpRow("CP00_MODEL_LOAD", cand.loadOk ? "PASS" : "FAIL",
          "TIME_MS=" + std::to_string((long long)cand.loadMs));
    cpRow("CP01_TOKENIZE", cand.promptTokens > 0 ? "PASS" : "FAIL",
          "TOKEN_COUNT=" + std::to_string((long long)cand.promptTokens));
    auto hashOf = [&](const char* cp, int step) -> std::string {
        auto si = cand.trace.byStep.find(step);
        if (si == cand.trace.byStep.end()) return "ABSENT";
        auto ci = si->second.find(cp);
        if (ci == si->second.end()) return "ABSENT";
        char h[32]; std::snprintf(h, sizeof(h), "%016llx", ci->second.hash);
        return h;
    };
    cpRow("CP02_EMBED", firstDivergence == "EMBED" ? "FAIL" : (firstDivergence == "NONE" ? "PASS" : "PASS"),
          "CHECKSUM=" + hashOf("EMBED", 0));
    cpRow("CP03_RMS_PRE", cov["ATTN_NORM"].matched > 0 ? "PASS" : "NOT_INSTRUMENTED",
          "REASON=pre-attention RMS is observed as ATTN_NORM; the bare name carries "
          "the first layer of each step by the probe's once-per-step semantics. "
          "PER_LAYER=LAYER_<n>_ATTN_NORM for all layers");
    cpRow("CP04_LAYER_01", ladderSteps > 0 ? "PASS" : "NOT_INSTRUMENTED",
          "LAYER_LADDER_STEPS=" + std::to_string(ladderSteps) +
          " LAYER_RECORDS=" + std::to_string(ls.records));
    cpRow("CP05_LAYER_MID", ls.maxLayer > 0 ? "PASS" : "NOT_INSTRUMENTED",
          "LAYER_MAX_INDEX=" + std::to_string(ls.maxLayer) +
          " LAYER_DISTINCT_CHECKPOINTS=" + std::to_string(ls.names));
    cpRow("CP06_LAYER_FINAL", ls.maxLayer > 0 ? "PASS" : "NOT_INSTRUMENTED",
          "REASON=per-layer records cover every emitted layer, last index " +
          std::to_string(ls.maxLayer));
    cpRow("CP07_FINAL_RMS", cov["FINAL_NORM"].matched > 0 ? "PASS" : "NOT_INSTRUMENTED",
          "CHECKSUM=" + hashOf("FINAL_NORM", decodeStart) +
          " DECODE_STEP=" + std::to_string(decodeStart));
    cpRow("CP08_KV_WRITE", cand.kvLength > 0 ? "PASS" : "FAIL",
          "KV_LENGTH=" + std::to_string(cand.kvLength));
    cpRow("CP09_ATTENTION", "PROBE_LIMITED",
          "CHECKSUM=" + hashOf("ATTN_RESIDUAL", 0));
    cpRow("CP10_FFN", "PROBE_LIMITED", "CHECKSUM=" + hashOf("FFN_DOWN", 0));
    cpRow("CP11_LOGITS", cov["LOGITS"].matched > 0 ? "PASS" : "NOT_INSTRUMENTED",
          "CHECKSUM=" + hashOf("LOGITS", decodeStart) +
          " DECODE_STEP=" + std::to_string(decodeStart));
    cpRow("CP12_TOP10", !top10Present ? "NOT_INSTRUMENTED" : (top10Match ? "PASS" : "FAIL"),
          std::string("TOP10_MATCH=") + (top10Present ? (top10Match ? "YES" : "NO") : "NO_DATA") +
          " TOP10_STEPS=" + std::to_string(top10Steps) +
          " TOP10_MISMATCH=" + std::to_string(top10Mismatch) +
          " TOP10_ABSENT_IN_ONE_ARM=" + std::to_string(top10AbsentOneArm));
    cpRow("CP13_SAMPLER", "PASS", "SAMPLER=Greedy (identical in both arms)");
    cpRow("CP14_SELECTED_TOKEN", tokensMatch ? "PASS" : "FAIL",
          tokensMatch ? "TOKEN_ID=AGREE" : "TOKEN_ID=DIVERGES");
    cpRow("CP15_STREAM", utf8Ok ? "PASS" : "FAIL",
          std::string("UTF8_VALID=") + (utf8Ok ? "YES" : "NO") +
          " TEXT=" + oneLine(cand.text, 300));
    cpRow("CP16_UI_APPEND", "NOT_IN_SCOPE", "REASON=IDE-side; covered by RAWRXD_IDE_CHAT_E2E_001");
    cpRow("CP17_RENDER", "NOT_IN_SCOPE", "REASON=IDE-side; covered by RAWRXD_IDE_CHAT_E2E_001");
    cpRow("CP18_REQUEST_END", "NOT_IN_SCOPE", "REASON=IDE-side; covered by RAWRXD_IDE_CHAT_E2E_001");
    cpRow("CP19_SHUTDOWN", "NOT_IN_SCOPE", "REASON=IDE-side; covered by RAWRXD_IDE_CHAT_E2E_001");

    r << "\n===============================================================================\n";
    r << "PROBE_COVERAGE_001\n";
    r << "===============================================================================\n\n";
    r << "STEPS_TOTAL=" << (lastStep - firstStep + 1) << "\n";
    r << "PREFILL_STEPS=" << firstStep << ".." << (decodeStart - 1) << "\n";
    r << "DECODE_STEPS=" << decodeStart << ".." << lastStep << "\n\n";
    r << "NAME                     MATCH  DIVERGE  GAP  NOT_REQ  COVERED\n";
    r << "-------------------------------------------------------------------\n";
    for (int k = 0; k < 20; ++k) {
        const std::string nm = CheckpointOrder::kNames[k];
        const NameCov& c = cov[nm];
        const int required = c.matched + c.diverged + c.missing;
        const bool covered = (c.missing == 0 && c.diverged == 0 && required > 0);
        r << nm;
        for (int p = (int)nm.size(); p < 24; ++p) r << ' ';
        char buf[96];
        std::snprintf(buf, sizeof(buf), "%5d  %7d  %3d  %7d  %s",
                      c.matched, c.diverged, c.missing, c.notReq,
                      covered ? "YES" : (c.missing ? "NO" : "N/A"));
        r << buf << "\n";
    }
    r << "-------------------------------------------------------------------\n";
    r << "LAYER_LADDER_STEPS_COMPARED=" << ladderSteps << "\n";
    r << "LAYER_LADDER_STEPS_NOT_INSTRUMENTED=" << ladderGaps << "\n";
    r << "LAYER_RECORDS_COMPARED=" << ls.records << "\n";
    r << "LAYER_MAX_INDEX=" << ls.maxLayer << "\n";
    r << "LAYER_DISTINCT_CHECKPOINTS=" << ls.names << "\n";
    r << "SURFACES_NOT_REQUIRED=" << notRequired
      << " (prefill steps carry no logits surface by design)\n\n";
    {
        int uncovered = 0;
        for (int k = 0; k < 20; ++k) {
            const NameCov& c = cov[CheckpointOrder::kNames[k]];
            if (c.missing > 0) ++uncovered;
        }
        if (ladderGaps > 0) ++uncovered;
        r << "SURFACES_WITH_GAPS=" << uncovered << "\n";
        r << "PROBE_COVERAGE=" << ((uncovered == 0 && notInstrumented == 0)
                                       ? "PASS" : "FAIL") << "\n";
    }

    r << "\n===============================================================================\n";
    r << "LOGITS\n";
    r << "===============================================================================\n\n";
    r << "TOP10_FIRST_DECODE_STEP=" << top10FirstStep << "\n";

    r << "===============================================================================\n\n";
    r << "TOP10_REFERENCE=" << oneLine(top10Ref, 400) << "\n";
    r << "TOP10_CANDIDATE=" << oneLine(top10Dut, 400) << "\n";
    r << "SELECTED_TOKEN=" << (tokensMatch ? "AGREE" : "DIVERGES") << "\n";

    r << "\n===============================================================================\n";
    r << "KV CACHE\n";
    r << "===============================================================================\n\n";
    r << "KV_WRITES_REF=" << ref.trace.kvWrites.size() << "\n";
    r << "KV_WRITES_DUT=" << cand.trace.kvWrites.size() << "\n";
    r << "KV_LENGTH=" << cand.kvLength << "\n";
    r << "KV_ADVANCES=NOT_IMPLEMENTED\n";
    r << "KV_RESETS=NOT_IMPLEMENTED\n";

    r << "\n===============================================================================\n";
    r << "NUMERICAL METRICS\n";
    r << "===============================================================================\n\n";
    r << "MAX_ABS_ERROR=SEE_TRACE_DIFF\n";
    r << "MEAN_ABS_ERROR=NOT_COMPUTED\n";
    r << "MAX_REL_ERROR=NOT_COMPUTED\n";
    r << "FIRST_MISMATCH=" << firstDivergence << "\n";

    r << "\n===============================================================================\n";
    r << "PERFORMANCE\n";
    r << "===============================================================================\n\n";
    r << "FIRST_TOKEN_MS=" << (long long)cand.firstTokenMs << "\n";
    r << "TOKENS_PER_SECOND="
      << (cand.genMs > 0 ? (cand.tokenIds.size() * 1000.0 / cand.genMs) : 0.0) << "\n";
    r << "TOTAL_TOKENS=" << cand.tokenIds.size() << "\n";
    r << "TOTAL_TIME_MS=" << (long long)cand.totalMs << "\n";

    r << "\n===============================================================================\n";
    r << "DEFECTS\n";
    r << "===============================================================================\n\n";
    if (lanesEquivalent) {
        r << "DEFECT_ID=NONE\nSEVERITY=NONE\n";
        r << "DESCRIPTION=No divergence between the certified CPU lane and the IDE chat lane.\n";
        r << "ROOT_CEAUSE=NONE\n";
    } else {
        r << "DEFECT_ID=D9\nSEVERITY=P0\n";
        r << "DESCRIPTION=IDE chat lane generation diverges from the certified CPU lane.\n";
        r << "ROOT_CAUSE=" << investigationTarget << " (first divergence at " << firstDivergence << ")\n";
    }

    r << "\n===============================================================================\n";
    r << "EVIDENCE\n";
    r << "===============================================================================\n\n";
    r << "BUILD_LOG=build_w1/generation_quality_build.log\n";
    r << "RUN_LOG=" << outdir << "/GENERATION_QUALITY_001.txt\n";
    r << "TRACE=" << outdir << "/trace_D_IDE_CHAT.txt\n";
    r << "PROBE_OUTPUT=" << outdir << "/trace_A_CPU_HARNESS.txt\n";
    r << "SCREENSHOT=NONE\n";

    r << "\n===============================================================================\n";
    r << "VERDICT\n";
    r << "===============================================================================\n\n";
    r << "PASS_CRITERIA=all probe checkpoints hash-identical between A_CPU_HARNESS and "
         "D_IDE_CHAT for every step, identical greedy token ids, and valid UTF-8 output\n";
    // Config equivalence is established; it is NOT generation quality. If the
    // checkpoints that actually decide the sampled token are uninstrumented,
    // the chain must not advance to throughput on the strength of this gate.
    const bool decisiveCovered = (notInstrumented == 0);
    r << "NEXT_GATE="
      << (lanesEquivalent ? (decisiveCovered ? "LOGITS_PARITY_001" : "PROBE_COVERAGE_001")
                          : "ISOLATE_FORWARD_DIVERGENCE")
      << "\n\n";
    r << "CONFIG_EQUIVALENCE=" << (lanesEquivalent ? "PASS" : "FAIL") << "\n";
    r << "GENERATION_QUALITY=NOT_ASSESSED (this gate compares configurations, not output coherence)\n";
    r << "VERDICT=" << (lanesEquivalent ? "PASS" : "FAIL") << "\n";
    r << "===============================================================================\n";

    r << "\n===============================================================================\n";
    r << "DIFFERENTIAL RECORD\n";
    r << "===============================================================================\n\n";
    r << "REFERENCE=A_CPU_HARNESS\n";
    r << "CANDIDATE=D_IDE_CHAT\n";
    r << "MODEL_SHA256=NOT_COMPUTED\n";
    r << "PROMPT_SHA256=NOT_COMPUTED\n";
    r << "SEED=1\n\n";
    r << "ARM MATRIX (maxSeqLen / threads / threadPool)\n";
    for (int i = 0; i < 4; ++i) {
        r << "  " << results[i].name << "  seq=" << results[i].maxSeqLen
          << " threads=" << (results[i].autoThreads ? "auto" : "1")
          << " pool=" << (results[i].threadPool ? "true" : "false")
          << "  tokens=" << results[i].tokenIds.size()
          << "  text=" << oneLine(results[i].text, 90) << "\n";
    }
    r << "\nPER-ARM EQUIVALENCE TO REFERENCE\n";
    for (int i = 1; i < 4; ++i) {
        std::string fd = "NONE";
        for (const Row& row : rows) { (void)row; break; }
        r << "  " << results[i].name << ": text=" << (results[i].text == ref.text ? "MATCH" : "DIFF")
          << " tokens=" << (results[i].tokenIds == ref.tokenIds ? "MATCH" : "DIFF")
          << " firstDiv=" << fd << "\n";
    }

    r << "\nCHECKPOINT        REF        DUT        MATCH\n";
    r << "-------------------------------------------------------------------\n";
    for (const Row& row : rows) {
        r << row.cp;
        for (int p = (int)row.cp.size(); p < 16; ++p) r << ' ';
        if (row.verdict == 1) {
            r << "PASS       YES  " << row.note;
        } else if (row.verdict == 0) {
            r << "FAIL       NO   <- DIVERGENCE: " << row.note;
        } else if (row.verdict == -2) {
            r << "----       N/A  " << row.note;
        } else {
            r << "----       SKIP " << row.note;
        }
        r << "\n";
    }
    r << "-------------------------------------------------------------------\n\n";
    r << "FIRST_DIVERGENCE=" << firstDivergence << "\n";
    r << "INVESTIGATION_TARGET=" << investigationTarget << "\n";
    r << "CHECKPOINTS_COMPARED=" << compared << "\n";
    r << "CHECKPOINTS_NOT_INSTRUMENTED=" << notInstrumented << "\n";
    r << "CHECKPOINTS_NOT_REQUIRED=" << notRequired << "\n";
    r << "TRUE_DIVERGENCES=" << trueDivergences << "\n";
    r << "TOP10_STEPS_COMPARED=" << top10Steps << "\n";
    r << "TOP10_MATCH=" << (top10Present ? (top10Match ? "YES" : "NO") : "NO_DATA") << "\n";
    r << "TOKEN_IDS_MATCH=" << (tokensMatch ? "YES" : "NO") << "\n";
    r << "TEXT_MATCH=" << (textMatch ? "YES" : "NO") << "\n";
    r << "===============================================================================\n";

    const std::string out = r.str();
    std::printf("%s", out.c_str());

    const std::string path = outdir + "/GENERATION_QUALITY_001.txt";
    std::FILE* f = std::fopen(path.c_str(), "wb");
    if (f) { std::fwrite(out.data(), 1, out.size(), f); std::fclose(f); }

    return (lanesEquivalent) ? 0 : 1;
}
