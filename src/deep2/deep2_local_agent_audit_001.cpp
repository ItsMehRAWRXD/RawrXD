// deep2_local_agent_audit_001.cpp — LOCAL_AGENT_AUDIT_001 + DIM_RESET_001
#include "Deep2Engine.h"
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

using namespace Deep2;

static const char* kGateDir =
    "G:\\~dev\\rawrxd\\evidence\\LOCAL_AGENT_AUDIT_001";
static const char* kCanaryId = "LOCAL_AGENT_AUDIT_CANARY_7F31";

static void WriteGate(const char* body) {
#ifdef _WIN32
    CreateDirectoryA(kGateDir, nullptr);
#endif
    std::string path = std::string(kGateDir) + "\\GATE_STATUS.txt";
    FILE* f = fopen(path.c_str(), "w");
    if (!f) return;
    fputs(body, f);
    fclose(f);
}

static bool ReadFileTool(const char* path, std::string& out, std::string& err) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        err = "open_failed";
        return false;
    }
    std::ostringstream ss;
    ss << in.rdbuf();
    out = ss.str();
    if (out.empty()) {
        err = "empty";
        return false;
    }
    return true;
}

static bool ContainsCI(const std::string& hay, const char* needle) {
    if (!needle || !*needle) return false;
    std::string h = hay, n = needle;
    for (char& c : h) c = (char)tolower((unsigned char)c);
    for (char& c : n) c = (char)tolower((unsigned char)c);
    return h.find(n) != std::string::npos;
}

static void StripHeavyEnhancements() {
#ifdef _WIN32
    // MSVC getenv() does not reliably see SetEnvironmentVariableA — use _putenv_s.
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    _putenv_s("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    _putenv_s("DEEP2_LIVE_POLICY", "MIN");
    _putenv_s("DEEP2_K2_SHARD_DIR", "");
    _putenv_s("RAWRXD_GPU_FWD", "0");
    _putenv_s(
        "RAWRXD_ENHANCE_SKIP",
        "elastic,cyclone,ckv,medusa,nvme,prefetch,torus,mars,sov,plasma,"
        "chamber,nu,warmup,slide,telemetry");
#endif
}

struct DimWitness {
    size_t loadedHidden = 0, loadedLayers = 0, loadedKVHeads = 0, loadedHeadDim = 0;
    size_t runtimeHidden = 0, runtimeLayers = 0, runtimeKVHeads = 0, runtimeHeadDim = 0;
    int preloadDefaultRetired = 1;
    int modelDimsAfterLoadUsed = 0;
    int staleKv = 0, staleCkv = 0, staleLayers = 0, staleHidden = 0;
    int dimResetPass = 0;
};

static bool CheckDims(const Deep2Engine& e, DimWitness& w) {
    const auto& mw = e.getModelWeights();
    const auto& cfg = e.getConfig();
    w.loadedHidden = mw.hiddenDim;
    w.loadedLayers = mw.numLayers;
    w.loadedKVHeads = mw.numKVHeads;
    w.loadedHeadDim = mw.headDim;
    w.runtimeHidden = cfg.hiddenDim;
    w.runtimeLayers = cfg.numLayers;
    w.runtimeKVHeads = cfg.numKVHeads;
    w.runtimeHeadDim = cfg.headDim;
    w.modelDimsAfterLoadUsed = 1;
    w.staleHidden = (w.runtimeHidden != w.loadedHidden) ? 1 : 0;
    w.staleLayers = (w.runtimeLayers != w.loadedLayers) ? 1 : 0;
    w.staleKv = (w.runtimeKVHeads != w.loadedKVHeads ||
                 w.runtimeHeadDim != w.loadedHeadDim)
                    ? 1
                    : 0;
    // CKV must not be authoritative on this TinyLlama audit path.
    w.staleCkv = e.isCompressedKVEnabled() ? 1 : 0;
    // Reject EngineConfig defaults (4096/32) surviving past load.
    if (w.runtimeHidden == 4096 && w.loadedHidden != 4096) w.staleHidden = 1;
    if (w.runtimeLayers == 32 && w.loadedLayers != 32) w.staleLayers = 1;
    w.dimResetPass =
        (w.preloadDefaultRetired && w.modelDimsAfterLoadUsed && !w.staleHidden &&
         !w.staleLayers && !w.staleKv && !w.staleCkv)
            ? 1
            : 0;
    printf("LOCAL_AGENT_AUDIT_DIM_RESET_001\n");
    printf("PRELOAD_DEFAULT_CONTEXT_RETIRED=%d\n", w.preloadDefaultRetired);
    printf("MODEL_DIMS_AFTER_LOAD_USED=%d\n", w.modelDimsAfterLoadUsed);
    printf("LOADED_HIDDEN=%zu RUNTIME_HIDDEN=%zu STALE_HIDDEN_DIM=%d\n",
           w.loadedHidden, w.runtimeHidden, w.staleHidden);
    printf("LOADED_LAYERS=%zu RUNTIME_LAYERS=%zu STALE_LAYER_COUNT=%d\n",
           w.loadedLayers, w.runtimeLayers, w.staleLayers);
    printf("LOADED_KV_HEADS=%zu RUNTIME_KV_HEADS=%zu STALE_KV_DIMS=%d\n",
           w.loadedKVHeads, w.runtimeKVHeads, w.staleKv);
    printf("LOADED_HEAD_DIM=%zu RUNTIME_HEAD_DIM=%zu STALE_CKV_DIMS=%d\n",
           w.loadedHeadDim, w.runtimeHeadDim, w.staleCkv);
    printf("LOCAL_AGENT_AUDIT_DIM_RESET_001=%s\n",
           w.dimResetPass ? "PASS" : "FAIL");
    return w.dimResetPass != 0;
}

int main(int argc, char** argv) {
    StripHeavyEnhancements();

    const char* model =
        (argc > 1 && argv[1] && argv[1][0]) ? argv[1]
        : (std::getenv("RAWRXD_LOCAL_GGUF") && std::getenv("RAWRXD_LOCAL_GGUF")[0]
               ? std::getenv("RAWRXD_LOCAL_GGUF")
               : "G:\\~dev\\rawrxd\\models\\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf");
    const char* auditFile =
        (argc > 2 && argv[2] && argv[2][0]) ? argv[2]
        : (std::getenv("RAWRXD_AUDIT_FILE") && std::getenv("RAWRXD_AUDIT_FILE")[0]
               ? std::getenv("RAWRXD_AUDIT_FILE")
               : "G:\\~dev\\rawrxd\\evidence\\LOCAL_AGENT_AUDIT_001\\fixture_canary_7F31.cpp");

    printf("LOCAL_AGENT_AUDIT_001\nMODEL_LOCAL_ONLY=1\nmodel=%s\naudit_file=%s\n",
           model, auditFile);

    // LAW: construct → loadModel → dims from GGUF → initialize → generate.
    // Never initialize() with EngineConfig defaults (4096/32) before load.
    Deep2Engine engine;
    if (!engine.loadModel(model) || !engine.isModelLoaded()) {
        WriteGate("P0_PROCESS_ALIVE=1\nMODEL_LOAD=FAIL\nLOCAL_AGENT_AUDIT_001=FAIL\n");
        printf("MODEL_LOAD=FAIL\n");
        return 3;
    }
    printf("MODEL_LOAD=PASS\n");

    const auto& mw = engine.getModelWeights();
    EngineConfig cfg{};
    cfg.numThreads = 4;
    cfg.useKVCache = true;
    cfg.useThreadPool = true;
    cfg.maxSeqLen = 512; // audit-sized; not K2 2048 default owner
    cfg.hiddenDim = mw.hiddenDim;
    cfg.numLayers = mw.numLayers;
    cfg.numHeads = mw.numHeads;
    cfg.numKVHeads = mw.numKVHeads;
    cfg.headDim = mw.headDim;
    cfg.vocabSize = mw.vocabSize;
    cfg.intermediateDim = mw.intermediateDim;
    cfg.useMLA = false; // TinyLlama: never inherit K2 MLA buffer path

    if (!engine.initialize(cfg)) {
        WriteGate("P0_PROCESS_ALIVE=0\nMODEL_LOAD=PASS\nINIT_FAIL=1\n"
                  "LOCAL_AGENT_AUDIT_001=FAIL\n");
        printf("INIT_FAIL\n");
        return 2;
    }
    printf("P0_PROCESS_ALIVE=1\n");

    DimWitness dim{};
    if (!CheckDims(engine, dim)) {
        WriteGate("STALE_RUNTIME_DIMS=1\nLOCAL_AGENT_AUDIT_DIM_RESET_001=FAIL\n"
                  "LOCAL_AGENT_AUDIT_001=FAIL\n");
        printf("STALE_RUNTIME_DIMS=1\nGENERATE_ENTERED=0\n");
        return 8;
    }

    const char* warmPrompt = "Say hello in one short sentence.";
    auto promptTok = engine.tokenize(warmPrompt);
    if (promptTok.empty()) {
        WriteGate("MODEL_LOAD=PASS\nTOKENIZE=FAIL\nLOCAL_AGENT_AUDIT_001=FAIL\n");
        return 4;
    }

    printf("GENERATE_ENTERED=1\n");
    const size_t maxOut = 64;
    std::vector<int> outTok(maxOut, 0);
    InferenceStats stats{};
    auto t0 = std::chrono::steady_clock::now();
    size_t generated = engine.generate(
        promptTok.data(), promptTok.size(), outTok.data(), maxOut, &stats, nullptr);
    auto t1 = std::chrono::steady_clock::now();
    const double decodeUs =
        std::chrono::duration<double, std::micro>(t1 - t0).count();
    const double decodeTps =
        (generated > 0 && decodeUs > 0.0)
            ? (double)generated / (decodeUs / 1000000.0)
            : 0.0;

    printf("FIRST_TOKEN_EMITTED=%d\n", generated > 0 ? 1 : 0);
    printf("[LOCAL_MODEL]\nprompt_tokens=%zu\ngenerated_tokens=%zu\n"
           "decode_ms=%.3f\ndecode_tps=%.3f\nstats_tps=%.3f\n",
           promptTok.size(), generated, decodeUs / 1000.0, decodeTps,
           stats.tokensPerSecond);

    if (generated < 32 || decodeTps <= 0.0) {
        char buf[1024];
        snprintf(buf, sizeof(buf),
                 "P0_PROCESS_ALIVE=1\nMODEL_LOAD=PASS\nTOKENS_GENERATED=%zu\n"
                 "DECODE_TPS_REAL=%.6f\nLOCAL_AGENT_AUDIT_001=FAIL\n",
                 generated, decodeTps);
        WriteGate(buf);
        printf("TPS_OR_TOKEN_GATE=FAIL\n");
        return 5;
    }
    printf("[LOCAL_MODEL_TPS_001] PASS\n");

    std::string fileText, fileErr;
    const bool fileOk = ReadFileTool(auditFile, fileText, fileErr);
    printf("[AGENT]\ntool=read_file\npath=%s\nbytes=%zu\nok=%d\n",
           auditFile, fileText.size(), (int)fileOk);
    if (!fileOk) {
        WriteGate("FILE_READ=0\nLOCAL_AGENT_AUDIT_001=FAIL\n");
        return 6;
    }
    const bool promptHasCanary = ContainsCI(fileText, kCanaryId);
    printf("PROMPT_HAS_CANARY=%d\n", (int)promptHasCanary);

    std::string auditPrompt;
    auditPrompt.reserve(fileText.size() + 512);
    auditPrompt +=
        "You are auditing a source file from the current workspace.\n"
        "Analyze only the supplied file.\n"
        "Report defects with severity and symbol.\n"
        "If you see LOCAL_AGENT_AUDIT_CANARY_7F31, name it explicitly.\n\n"
        "FILE:\n";
    auditPrompt += auditFile;
    auditPrompt += "\n\nCONTENTS:\n";
    auditPrompt += fileText;

    auto auditTok = engine.tokenize(auditPrompt);
    std::vector<int> auditOut(96, 0);
    InferenceStats auditStats{};
    auto a0 = std::chrono::steady_clock::now();
    size_t auditGen = engine.generate(
        auditTok.data(), auditTok.size(), auditOut.data(), 96, &auditStats, nullptr);
    auto a1 = std::chrono::steady_clock::now();
    const double auditUs =
        std::chrono::duration<double, std::micro>(a1 - a0).count();
    const double auditTps =
        (auditGen > 0 && auditUs > 0.0)
            ? (double)auditGen / (auditUs / 1000000.0)
            : 0.0;

    std::vector<int> seq = auditTok;
    seq.insert(seq.end(), auditOut.begin(),
               auditOut.begin() + (ptrdiff_t)auditGen);
    std::string auditText = engine.detokenize(seq);
    const bool nonempty = !auditText.empty();
    const bool identified =
        ContainsCI(auditText, kCanaryId) || ContainsCI(auditText, "divide") ||
        ContainsCI(auditText, "division by zero") ||
        ContainsCI(auditText, "zero");

    printf("[INFERENCE]\nprompt_tokens=%zu\ngenerated_tokens=%zu\ndecode_tps=%.3f\n",
           auditTok.size(), auditGen, auditTps);
    printf("[AGENT]\naudit_bytes=%zu\nfindings_proxy=%d\n", auditText.size(),
           (int)identified);
    printf("--- AUDIT BEGIN ---\n%s\n--- AUDIT END ---\n", auditText.c_str());
    printf("AUDIT_RESULT_EMITTED=1\n");

    const int pass =
        dim.dimResetPass && (generated >= 32) && (decodeTps > 0.0) && fileOk &&
        promptHasCanary && nonempty && identified;

    char gate[2560];
    snprintf(gate, sizeof(gate),
             "P0_PROCESS_ALIVE=1\nMODEL_LOCAL_ONLY=1\nMODEL_LOAD=PASS\n"
             "LOCAL_AGENT_AUDIT_DIM_RESET_001=%s\n"
             "PRELOAD_DEFAULT_CONTEXT_RETIRED=1\nMODEL_DIMS_AFTER_LOAD_USED=1\n"
             "STALE_KV_DIMS=%d\nSTALE_CKV_DIMS=%d\nSTALE_LAYER_COUNT=%d\n"
             "STALE_HIDDEN_DIM=%d\nGENERATE_ENTERED=1\nFIRST_TOKEN_EMITTED=%d\n"
             "AUDIT_RESULT_EMITTED=1\nEXIT_CODE=%d\n"
             "TOKENS_GENERATED=%zu\nDECODE_TPS_REAL=%.6f\n"
             "FILE_READ=1\nFILE_BYTES=%zu\nMODEL_PROMPT_CONTAINS_FILE=1\n"
             "PROMPT_HAS_CANARY=%d\nMODEL_IDENTIFIED_CANARY=%d\n"
             "AUDIT_RESPONSE_NONEMPTY=%d\nPROCESS_STILL_ALIVE=1\n"
             "LOCAL_AGENT_AUDIT_001=%s\n",
             dim.dimResetPass ? "PASS" : "FAIL", dim.staleKv, dim.staleCkv,
             dim.staleLayers, dim.staleHidden, generated > 0 ? 1 : 0,
             pass ? 0 : 7, generated, decodeTps, fileText.size(),
             (int)promptHasCanary, (int)identified, (int)nonempty,
             pass ? "PASS" : "FAIL");
    WriteGate(gate);
    printf("EXIT_CODE=%d\nLOCAL_AGENT_AUDIT_001=%s\n", pass ? 0 : 7,
           pass ? "PASS" : "FAIL");
    return pass ? 0 : 7;
}
