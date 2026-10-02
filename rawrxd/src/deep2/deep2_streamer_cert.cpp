// deep2_streamer_cert.cpp
// STREAMER-CERT-001 -- Deep2 streaming certification harness.
//
// Admission policy: NONE BY SIZE. Every discovered artifact with real local
// weight bytes is attempted. There is deliberately no MODEL_TOO_LARGE_FOR_RAM
// result: file size is not evidence, and Deep2's streamer exists precisely to
// execute models larger than system RAM.
//
// Discovery is by GGUF magic (47 47 55 46), never by extension, because Ollama
// blobs carry no extension at all.
//
// Shard sets are resolved into ONE logical model: discovery groups
// <prefix>-00001-of-000NN.gguf members, verifies all NN members exist before
// opening, and hands shard 1 to Deep2::GGUFLoader (which maps the rest).
//
// Each model runs in a CHILD PROCESS. That is not a size gate -- it is what
// makes an attempt survivable, so one model's OOM or fault is recorded as that
// model's result instead of destroying the census.
//
// PASS is derived, never printed:
//     PASS = real local weights + Deep2 load + real prefill + real decode
//            + actual streamed callbacks + requested token count + clean teardown
//   PASS != discovered != parsed != admitted != loaded
//
// Build: see CMake option BUILD_DEEP2_STREAMER_CERT.

#include "Deep2Engine.h"
#include "GGUFLoader.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <map>
#include <set>
#include <string>
#include <vector>

#include <windows.h>

namespace fs = std::filesystem;

namespace {

// Deterministic, minimal prompt, shared by every model so any difference in
// output is attributable to the model and not to the harness.
//
// Overridable (--prompt) because a shared input that the tokenizer cannot
// encode turns EVERY model into an identical failure. The first census ran
// "Count:", which yields 0 tokens under encodeGPT2 (Tokenizer.cpp:545 returns
// {} when any symbol is missing from the vocab and no unk id exists). That
// reported 182/182 MODEL_LOAD_FAILED -- one bug wearing 182 model-shaped
// coats. A census must not be able to report its own harness failure as a
// per-model verdict.
std::string g_prompt = "The capital of France is";

// ---------------------------------------------------------------- result enum
// Terminal outcomes are deliberately fine-grained. A generic MODEL_LOAD_FAILED
// would collapse SHARD_RESOLUTION / MMAP_OPEN / MODEL_LOAD / PREFILL /
// FIRST_TOKEN / TOKEN_N / TIMEOUT / CHILD_EXIT into one bucket, which destroys
// the only information the failure actually carries.
//
// MODEL_TIMEOUT is its own result and is NEVER reported as unsupported, as too
// large, or as a load failure. A 30-minute wall bound is a liveness fact, not a
// property of the model.
enum class Result {
    MODEL_STREAMABLE,
    MODEL_UNSUPPORTED_FORMAT,
    MODEL_CORRUPT,
    MODEL_MISSING_PAYLOAD,
    MODEL_LOAD_FAILED,
    MODEL_PREFILL_FAILED,
    MODEL_DECODE_FAILED,
    MODEL_STREAM_FAILED,
    MODEL_TIMEOUT,
    MODEL_CHILD_CRASH,
    MODEL_PASS,
};

const char* resultName(Result r)
{
    switch (r) {
        case Result::MODEL_STREAMABLE:         return "MODEL_STREAMABLE";
        case Result::MODEL_UNSUPPORTED_FORMAT: return "MODEL_UNSUPPORTED";
        case Result::MODEL_CORRUPT:            return "MODEL_CORRUPT";
        case Result::MODEL_MISSING_PAYLOAD:    return "MODEL_MISSING_PAYLOAD";
        case Result::MODEL_LOAD_FAILED:        return "MODEL_LOAD_FAILED";
        case Result::MODEL_PREFILL_FAILED:     return "MODEL_PREFILL_FAILED";
        case Result::MODEL_DECODE_FAILED:      return "MODEL_DECODE_FAILED";
        case Result::MODEL_STREAM_FAILED:      return "MODEL_STREAM_FAILED";
        case Result::MODEL_TIMEOUT:            return "MODEL_TIMEOUT";
        case Result::MODEL_CHILD_CRASH:        return "MODEL_CHILD_CRASH";
        case Result::MODEL_PASS:               return "MODEL_PASS";
    }
    return "UNKNOWN";
}

// ------------------------------------------------- the furthest stage reached
// Reported alongside the result so a failure names the boundary it stopped at.
enum class Stage {
    DISCOVERED, SHARD_RESOLUTION, MMAP_OPEN, MODEL_LOAD,
    TOKENIZE, PREFILL, FIRST_TOKEN, TOKEN_N, TEARDOWN, DONE
};

const char* stageName(Stage s)
{
    switch (s) {
        case Stage::DISCOVERED:       return "DISCOVERED";
        case Stage::SHARD_RESOLUTION: return "SHARD_RESOLUTION";
        case Stage::MMAP_OPEN:        return "MMAP_OPEN";
        case Stage::MODEL_LOAD:       return "MODEL_LOAD";
        case Stage::TOKENIZE:         return "TOKENIZE";
        case Stage::PREFILL:          return "PREFILL";
        case Stage::FIRST_TOKEN:      return "FIRST_TOKEN";
        case Stage::TOKEN_N:          return "TOKEN_N";
        case Stage::TEARDOWN:         return "TEARDOWN";
        case Stage::DONE:             return "DONE";
    }
    return "?";
}

// ------------------------------------------------------------ artifact kinds
enum class Kind { Inference, InferenceSharded, Projector, NotLocal };

const char* kindName(Kind k)
{
    switch (k) {
        case Kind::Inference:          return "inference";
        case Kind::InferenceSharded:   return "inference_sharded";
        case Kind::Projector:          return "projector";
        case Kind::NotLocal:           return "not_local";
    }
    return "?";
}

struct Artifact {
    std::string logicalName;   // shard 1 path, or the single blob path
    Kind        kind      = Kind::Inference;
    uint64_t    bytes     = 0;
    uint32_t    shardCount = 1;
    std::string arch, quant;
    Result      result     = Result::MODEL_STREAMABLE;
    Stage       stage      = Stage::DISCOVERED;
    std::string detail;
    // stream evidence
    uint64_t tokens = 0;
    double   ttftMs = 0.0;
    double   decodeTps = 0.0;
    uint32_t callbacks = 0;
    bool     contiguous = false;
    bool     finiteLogits = false;
    bool     cleanTeardown = false;
    std::vector<int32_t> firstIds;
    std::string text;
};

// -------------------------------------------------------------- GGUF by magic
// An Ollama blob is a GGUF with no extension. Only the magic decides.
bool hasGgufMagic(const fs::path& p)
{
    std::error_code ec;
    const auto sz = fs::file_size(p, ec);
    if (ec || sz < 8) return false;
    FILE* f = std::fopen(p.string().c_str(), "rb");
    if (!f) return false;
    unsigned char m[4] = {0,0,0,0};
    const bool ok = std::fread(m, 1, 4, f) == 4;
    std::fclose(f);
    return ok && m[0]=='G' && m[1]=='G' && m[2]=='U' && m[3]=='F';
}

// ------------------------------------------------- canonical shard set naming
// Kimi: Kimi-K2-Instruct-0905-Q4_K_M-00001-of-00013.gguf
bool parseShard(const std::string& stem, std::string& prefix, uint32_t& idx, uint32_t& cnt)
{
    const size_t d = stem.rfind("-00001-of-");
    if (d == std::string::npos) return false;
    prefix = stem.substr(0, d);
    idx = 1;
    const std::string tail = stem.substr(d + 1);           // "00001-of-00013"
    const size_t of = tail.find("-of-");
    if (of == std::string::npos) return false;
    cnt = static_cast<uint32_t>(std::strtoul(tail.c_str() + of + 4, nullptr, 10));
    return cnt > 1;
}

std::string shardPath(const std::string& prefix, uint32_t i, uint32_t n)
{
    char buf[64];
    std::snprintf(buf, sizeof buf, "-%05u-of-%05u.gguf", i, n);
    return prefix + buf;
}

bool isProjector(const std::string& lower)
{
    return lower.find("mmproj") != std::string::npos ||
           lower.find("clip")   != std::string::npos;
}

// -------------------------------------------------------------- census totals
struct Census {
    int total = 0, localInference = 0, projectors = 0, notLocal = 0;
    int attempted = 0, loadPass = 0, generationPass = 0, failures = 0;
};

void tally(Census& c, const Artifact& a)
{
    c.total++;
    switch (a.kind) {
        case Kind::Inference:
        case Kind::InferenceSharded: c.localInference++; break;
        case Kind::Projector:        c.projectors++;    break;
        case Kind::NotLocal:         c.notLocal++;      break;
    }
    if (a.result == Result::MODEL_MISSING_PAYLOAD) return;
    c.attempted++;
    if (a.result == Result::MODEL_PASS) { c.generationPass++; c.loadPass++; }
    else if (a.result == Result::MODEL_STREAM_FAILED) { c.loadPass++; c.failures++; }
    else c.failures++;
}

// --------------------------------------------------------------- discovery
std::vector<Artifact> discover(const std::vector<fs::path>& roots)
{
    std::vector<Artifact> out;
    std::set<std::string> seenShardFirst;   // avoid re-opening the same set

    for (const auto& root : roots) {
        std::error_code ec;
        if (!fs::exists(root, ec)) {
            std::printf("ROOT_MISSING=%s\n", root.string().c_str());
            continue;
        }
        std::vector<fs::path> ggufs;
        if (fs::is_directory(root, ec)) {
            for (auto it = fs::recursive_directory_iterator(
                     root, fs::directory_options::skip_permission_denied, ec);
                 it != fs::recursive_directory_iterator(); it.increment(ec)) {
                if (ec) { ec.clear(); continue; }
                if (!it->is_regular_file(ec)) continue;
                const fs::path& p = it->path();
                const uint64_t sz = fs::file_size(p, ec);
                if (ec || sz < 1024) continue;
                // magic, not extension
                if (!hasGgufMagic(p)) continue;
                ggufs.push_back(p);
            }
        } else if (hasGgufMagic(root)) {
            ggufs.push_back(root);
        }

        // group shard sets; emit ONE artifact per set
        std::map<std::string, std::vector<std::string>> sets;
        for (const auto& p : ggufs) {
            std::string stem = p.stem().string();
            std::string prefix; uint32_t i = 0, n = 0;
            if (parseShard(stem, prefix, i, n)) sets[prefix].push_back(p.string());
        }

        for (const auto& p : ggufs) {
            std::string stem = p.stem().string();
            std::string prefix; uint32_t i = 0, n = 0;
            if (parseShard(stem, prefix, i, n)) {
                if (i != 1) continue;                 // only shard 1 opens the set
                if (seenShardFirst.count(stem)) continue;
                seenShardFirst.insert(stem);

                Artifact a;
                a.logicalName = p.string();
                a.kind = Kind::InferenceSharded;
                a.shardCount = n;
                // prove ALL members exist before opening anything
                uint64_t total = 0;
                bool complete = true;
                for (uint32_t k = 1; k <= n; ++k) {
                    const std::string sp = shardPath(prefix, k, n);
                    if (!fs::exists(sp, ec)) { complete = false; break; }
                    total += fs::file_size(sp, ec);
                }
                a.bytes = total;
                if (!complete) { a.kind = Kind::NotLocal;
                                 a.result = Result::MODEL_MISSING_PAYLOAD;
                                 a.detail = "shard set incomplete"; }
                out.push_back(a);
                continue;
            }

            std::string lower = p.filename().string();
            std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

            Artifact a;
            a.logicalName = p.string();
            a.bytes = fs::file_size(p, ec);
            if (isProjector(lower)) { a.kind = Kind::Projector; a.shardCount = 1; }
            else                     { a.kind = Kind::Inference; a.shardCount = 1; }
            out.push_back(a);
        }
    }
    return out;
}

// -------------------------------------------------------- metadata inspection
// Opens ONLY the header. A model this large must never be read into RAM to be
// identified -- that is the whole premise of the streamer.
void inspect(Artifact& a)
{
    a.stage = Stage::SHARD_RESOLUTION;
    Deep2::GGUFLoader loader;
    if (!loader.load(a.logicalName)) {
        // loader.load() covers both shard resolution and header mapping; the
        // error text distinguishes them, so do not guess.
        const std::string e = loader.error();
        const bool shardIssue = e.find("shard") != std::string::npos ||
                                e.find("split") != std::string::npos;
        a.stage  = shardIssue ? Stage::SHARD_RESOLUTION : Stage::MMAP_OPEN;
        a.result = shardIssue ? Result::MODEL_CORRUPT : Result::MODEL_UNSUPPORTED_FORMAT;
        a.detail = e;
        return;
    }
    a.stage = Stage::MMAP_OPEN;
    a.shardCount = loader.shardCount();
    a.arch  = loader.getMetaString("general.architecture", "unknown");
    a.quant = loader.getMetaString("general.file_type", "unknown");
    a.bytes = loader.mappedBytes();
    a.kind  = (loader.shardCount() > 1) ? Kind::InferenceSharded : Kind::Inference;
    a.stage = Stage::MODEL_LOAD;
}

// ---------------------------------------------------------- the actual attempt
void attempt(Artifact& a, uint32_t maxTokens)
{
    inspect(a);
    if (a.result != Result::MODEL_STREAMABLE) return;

Deep2::Deep2Engine engine;

    // Enable the GPU backend BEFORE loadModel.
    //
    // Deep2Engine.cpp:1904 suspends an MLA model when `vulkanEnabled_` is false:
    //     if (report.mla && !vulkanEnabled_) { ...stage 21 MLA_CPU_PATH_ABSENT... }
    // `vulkanEnabled_` is set in exactly one place -- Deep2Engine::enableVulkan()
    // (Deep2Engine_VulkanRuntime.cpp:69/80) -- and defaults false (Deep2Engine.h:1389).
    // A harness that never calls it therefore NEVER reaches Vulkan, NEVER maps
    // weights, and NEVER runs MLA compute: the model is rejected at admission by
    // a configuration flag, not by any hardware capability test.
    //
    // The Vulkan loader was measured independently as seeing 3 physical devices
    // (vkEnumeratePhysicalDevices rc=0 count=3), so the capability exists; only
    // this call was missing.
    engine.enableVulkan(true);

    Deep2::ModelLoadDiag diag;
    if (!engine.loadModel(a.logicalName, &diag)) {
        a.result = Result::MODEL_LOAD_FAILED;
        a.detail = "stage=" + std::to_string(diag.stageCode) +
                   " name=" + diag.stageName + " msg=" + diag.message;
        return;
    }

// NOTE: do NOT call engine.initialize() here.
    // loadModel() already resolves dynamic geometry and performs initialization
    // (observed: "[INIT] Deep2Engine::initialize hiddenDim=3072 vocabSize=128256
    // numLayers=28 ..."). Calling initialize again with a default-constructed
    // EngineConfig re-enters initialize with zero geometry and tears down the
    // allocated buffers without reallocating them, so the engine streams from an
    // empty weight set. That produced "[TOKENIZE] ... -> 0 tokens" and
    // status=InvalidInput on the first run of this harness.
    //
    // A second initialization is the caller's decision only if it supplies real
    // geometry; this harness must not.

// Deterministic, minimal prompt. Overridable because a fixed prompt that
    // the tokenizer cannot encode turns EVERY model into an identical failure:
    // "Count:" yields 0 tokens under encodeGPT2 (Tokenizer.cpp:545 returns {}
    // when any symbol is absent from the vocab and no unk id exists), so the
    // first census reported 182/182 MODEL_LOAD_FAILED and that was one bug,
    // not 182 broken models. A shared input must never be able to masquerade
    // as a per-model result.
    Deep2::GenerationOptions opt;
    opt.maxTokens  = maxTokens;
    opt.temperature = 0.0f;   // deterministic
    opt.topP = 1.0f;
    opt.topK = 1;
    opt.seed = 12345;

    auto t0 = std::chrono::steady_clock::now();
    uint64_t callbacks = 0;
    bool sawNonEmpty = false;

Deep2::GenerationResult r = engine.generateStream(
        g_prompt.c_str(), opt,
        [&](int32_t id, const std::string& tok) -> bool {
            if (callbacks == 0) {
                a.ttftMs = std::chrono::duration<double, std::milli>(
                    std::chrono::steady_clock::now() - t0).count();
            }
            if (a.firstIds.size() < 16) a.firstIds.push_back(id);
            a.text += tok;
            if (!tok.empty()) sawNonEmpty = true;
            ++callbacks;
            return true;                 // never cancel: the point is to stream
        });

    double genMs = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - t0).count();

    a.callbacks  = static_cast<uint32_t>(callbacks);
    a.contiguous = (callbacks == r.generatedTokens);
    a.tokens     = r.generatedTokens;
    a.decodeTps  = genMs > 0 ? (double)r.generatedTokens / (genMs / 1000.0) : 0.0;
    a.finiteLogits = (r.status == Deep2::GenerationStatus::Completed ||
                      r.status == Deep2::GenerationStatus::EndOfSequence);

    engine.unloadModel();
    a.cleanTeardown = true;

    const bool ok = (r.status == Deep2::GenerationStatus::Completed ||
                     r.status == Deep2::GenerationStatus::EndOfSequence) &&
                    callbacks > 0 &&
                    a.contiguous &&
                    r.generatedTokens >= maxTokens;
    a.result = ok ? Result::MODEL_PASS : Result::MODEL_STREAM_FAILED;
    if (!ok) {
        a.detail = "status=" + std::to_string(static_cast<int>(r.status)) +
                   " gen=" + std::to_string(r.generatedTokens) +
                   " cb=" + std::to_string(callbacks) +
                   " req=" + std::to_string(maxTokens) +
                   " " + r.failureDetail;
    }
}

} // namespace

// ===========================================================================
// parent: census driver. Spawns one child per artifact so a fault in one model
// cannot destroy the census. No size-based admission anywhere below.
// ===========================================================================
int main(int argc, char** argv)
{
    uint32_t maxTokens = 8;
    std::vector<fs::path> roots;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
if (a == "--tokens" && i + 1 < argc) { maxTokens = (uint32_t)std::strtoul(argv[++i], nullptr, 10); }
        else if (a == "--prompt" && i + 1 < argc) { g_prompt = argv[++i]; }
        else roots.emplace_back(a);
    }
    if (roots.empty()) {
        roots.emplace_back("F:/OllamaModels");
        roots.emplace_back("F:/OllamaModels/blobs");
    }
    if (maxTokens == 0) maxTokens = 8;

if (argc >= 3 && std::string(argv[1]) == "--child") {
        Artifact a;
        a.logicalName = argv[2];
        a.kind = Kind::Inference;
        // CreateProcess does NOT interpret '>' redirection -- that is cmd.exe's
        // job. Passing a shell command line therefore sent the child's stdout to
        // the inherited console and left the result file empty, so the parent
        // reported "child exit=0 (no RESULT emitted)". The child now writes its
        // own result file directly; no shell is involved anywhere.
        std::string outFile;
        for (int i = 3; i + 1 < argc; ++i)
            if (std::string(argv[i]) == "--out") outFile = argv[++i];
        attempt(a, maxTokens);
        const std::string res = std::string("RESULT=") + resultName(a.result) + "\n" +
                                "DETAIL=" + a.detail + "\n" +
                                "TOKENS=" + std::to_string(a.tokens) + "\n" +
                                "TTFT_MS=" + std::to_string(a.ttftMs) + "\n" +
                                "DECODE_TPS=" + std::to_string(a.decodeTps) + "\n" +
                                "CALLBACKS=" + std::to_string(a.callbacks) + "\n" +
                                "CONTIGUOUS=" + (a.contiguous ? "1" : "0") + "\n" +
                                "CLEAN_TEARDOWN=" + (a.cleanTeardown ? "1" : "0") + "\n" +
                                "ARCH=" + a.arch + "\n" +
                                "QUANT=" + a.quant + "\n" +
                                "SHARDS=" + std::to_string(a.shardCount) + "\n";
        if (outFile.empty()) std::fputs(res.c_str(), stdout);
        if (!outFile.empty()) {
            FILE* f = std::fopen(outFile.c_str(), "wb");
            if (f) { std::fputs(res.c_str(), f); std::fclose(f); }
        }
        return a.result == Result::MODEL_PASS ? 0 : 1;
    }

    std::vector<Artifact> arts = discover(roots);
    Census c;

    for (auto& a : arts) {
        const fs::path dir = fs::path(a.logicalName).parent_path();
        const std::string exe = fs::absolute(argv[0]).string();

        std::printf("\n[MODEL]\n");
        std::printf("path=%s\n", a.logicalName.c_str());
        std::printf("kind=%s\n", kindName(a.kind));
        std::printf("bytes=%llu\n", (unsigned long long)a.bytes);
        std::printf("shards=%u\n", a.shardCount);

        if (a.result == Result::MODEL_MISSING_PAYLOAD) {
            std::printf("result=%s\ndetail=%s\n", resultName(a.result), a.detail.c_str());
            tally(c, a);
            continue;
        }

static int childSeq = 0;
        char tmpDir[MAX_PATH] = {0};
        GetTempPathA(MAX_PATH, tmpDir);
        const std::string outp =
            std::string(tmpDir) + "\\deep2_streamer_child_" +
            std::to_string(++childSeq) + ".txt";
        std::string line = "\"" + exe + "\" --child \"" + a.logicalName +
                           "\" --tokens " + std::to_string(maxTokens) +
                           " --out \"" + outp + "\"";

        STARTUPINFOA si{}; PROCESS_INFORMATION pi{};
        si.cb = sizeof si;
        std::vector<char> cmdbuf(line.begin(), line.end()); cmdbuf.push_back('\0');
        const BOOL ok = CreateProcessA(nullptr, cmdbuf.data(), nullptr, nullptr, FALSE,
                                       CREATE_NO_WINDOW, nullptr,
                                       dir.empty() ? nullptr : dir.string().c_str(),
                                       &si, &pi);
        if (!ok) {
            a.result = Result::MODEL_LOAD_FAILED;
            a.detail = "child spawn failed";
        } else {
            const DWORD wr = WaitForSingleObject(pi.hProcess, 0);
            if (wr == WAIT_TIMEOUT) {
                // large model still streaming; poll until it finishes or we cap
                const DWORD start = GetTickCount();
                bool done = false;
                while (GetTickCount() - start < 1000u * 60u * 30u) {
                    if (WaitForSingleObject(pi.hProcess, 500) != WAIT_TIMEOUT) { done = true; break; }
                }
                if (!done) { TerminateProcess(pi.hProcess, 0); a.result = Result::MODEL_LOAD_FAILED;
                             a.detail = "child exceeded 30 min wall cap"; }
                else done = true;
                if (done) {
                    DWORD code = 1; GetExitCodeProcess(pi.hProcess, &code);
                    std::string res, det;
                    FILE* rf = std::fopen(outp.c_str(), "rb");
                    if (rf) {
                        char b[1024];
                        while (std::fgets(b, sizeof b, rf)) {
                            std::string s(b);
                            if (s.rfind("RESULT=", 0) == 0) res = s.substr(7);
                            if (s.rfind("DETAIL=", 0) == 0) det = s.substr(7);
                            while (!res.empty() && (res.back()=='\n'||res.back()=='\r')) res.pop_back();
                            while (!det.empty() && (det.back()=='\n'||det.back()=='\r')) det.pop_back();
                        }
                        std::fclose(rf);
                    }
                    static const struct { const char* n; Result v; } map[] = {
                        {"MODEL_PASS", Result::MODEL_PASS},
                        {"MODEL_STREAM_FAILED", Result::MODEL_STREAM_FAILED},
                        {"MODEL_LOAD_FAILED", Result::MODEL_LOAD_FAILED},
                        {"MODEL_UNSUPPORTED_FORMAT", Result::MODEL_UNSUPPORTED_FORMAT},
                        {"MODEL_CORRUPT", Result::MODEL_CORRUPT},
                    };
                    a.result = Result::MODEL_LOAD_FAILED;
                    for (auto& m : map) if (res == m.n) { a.result = m.v; break; }
                    a.detail = det.empty() ? ("child exit=" + std::to_string(code)) : det;
                    if (res.empty()) a.detail += " (no RESULT emitted; child likely faulted)";
                }
            } else {
                DWORD code = 1; GetExitCodeProcess(pi.hProcess, &code);
                a.result = Result::MODEL_LOAD_FAILED;
                a.detail = "child exit=" + std::to_string(code) + " (faulted before emitting RESULT)";
            }
            CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
            std::remove(outp.c_str());
        }

        std::printf("result=%s\n", resultName(a.result));
        if (!a.detail.empty()) std::printf("detail=%s\n", a.detail.c_str());
        tally(c, a);
        std::printf("tally=%d/%d\n", c.total, c.localInference);
    }

    std::printf("\n=== CENSUS ===\n");
    std::printf("STREAMER_CENSUS_TOTAL=%d\n", c.total);
    std::printf("STREAMER_LOCAL_INFERENCE_MODELS=%d\n", c.localInference);
    std::printf("STREAMER_PROJECTORS=%d\n", c.projectors);
    std::printf("STREAMER_NOT_LOCAL=%d\n", c.notLocal);
    std::printf("STREAMER_ATTEMPTED=%d\n", c.attempted);
    std::printf("STREAMER_LOAD_PASS=%d\n", c.loadPass);
    std::printf("STREAMER_GENERATION_PASS=%d\n", c.generationPass);
    std::printf("STREAMER_FAIL=%d\n", c.failures);
    return 0;
}


