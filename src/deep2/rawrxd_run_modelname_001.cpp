// rawrxd_run_modelname_001.cpp — RAWRXD_RUN_MODELNAME_001 (Ollama-style front door)
#include "RawrRunSession.hpp"
#include <cstdio>
#include <cstdlib>
#include <string>
using namespace Deep2;
using namespace Deep2::rawr_run;

static int Fail(const char* w, int c) {
    printf("RAWRXD_RUN_MODELNAME_001=FAIL %s\n", w);
    return c;
}

int main(int argc, char** argv) {
    printf("RAWRXD_RUN_MODELNAME_001\n");
    printf("LAW=rawr run <alias> → Deep2 stream; OLLAMA_PROCESS_USED=0 NETWORK_USED=0\n");

    const char* alias = (argc > 1 && argv[1][0]) ? argv[1] : "tinyllama";
    const char* prompt =
        (argc > 2 && argv[2][0]) ? argv[2] : "write one short paragraph about local inference";

    Deep2Engine engine;
    RunWitness w{};
    if (!OpenSession(engine, alias, w))
        return Fail("open_session", 2);

    // Run 1: emit >=64 tokens (or cancel path proven separately).
    uint32_t n1 = StreamTokens(engine, prompt, 96, 0, &w);
    if (n1 < 64) return Fail("tokens_lt_64", 3);

    // Cancel proof: second stream stops early via requestCancel.
    RunWitness wCancel = w;
    wCancel.nTokensEmitted = 0;
    wCancel.firstTokenEmitted = 0;
    wCancel.ctrlCCancel = 0;
    uint32_t nCancel = StreamTokens(engine, prompt, 96, 8, &wCancel);
    if (!wCancel.ctrlCCancel || nCancel == 0 || nCancel >= 96)
        return Fail("ctrl_c_cancel", 4);
    w.ctrlCCancel = 1;

    // Unload → reload → second run without process restart.
    std::string path = w.modelPath;
    engine.unloadModel();
    if (engine.isModelLoaded()) return Fail("unload", 5);
    if (!InitFromPath(engine, path)) return Fail("reload", 6);
    RunWitness w2{};
    uint32_t n2 = StreamTokens(engine, "hi", 16, 0, &w2);
    if (n2 == 0) return Fail("second_run", 7);
    w.unloadReload = 1;
    w.secondRunPass = 1;
    w.processAliveAfterRun = 1;
    w.nTokensEmitted = n1;

    printf("RUN_MODELNAME=1\n");
    printf("MODEL_NAME=%s\n", w.modelName.c_str());
    printf("MODEL_PATH=%s\n", w.modelPath.c_str());
    printf("MODEL_ALIAS_RESOLVED=%d\n", w.modelAliasResolved);
    printf("OLLAMA_PROCESS_USED=%d\n", w.ollamaProcessUsed);
    printf("NETWORK_USED=%d\n", w.networkUsed);
    printf("GGUF_OPENED=%d\n", w.ggufOpened);
    printf("SHARDS_DISCOVERED=%d\n", w.shardsDiscovered);
    printf("TOKENIZER_READY=%d\n", w.tokenizerReady);
    printf("CHAT_TEMPLATE_READY=%d\n", w.chatTemplateReady);
    printf("DEEP2_GENERATE_STREAM=%d\n", w.deep2GenerateStream);
    printf("DEEP2_USED=%d\n", w.deep2Used);
    printf("FIRST_TOKEN_EMITTED=%d\n", w.firstTokenEmitted);
    printf("N_TOKENS_EMITTED=%u\n", w.nTokensEmitted);
    printf("STREAM_FIRST_TOKEN=%d\n", w.firstTokenEmitted);
    printf("TOKENS_OUT=%u\n", w.nTokensEmitted);
    printf("CTRL_C_CANCEL=%d\n", w.ctrlCCancel);
    printf("UNLOAD_RELOAD=%d\n", w.unloadReload);
    printf("SECOND_RUN_PASS=%d\n", w.secondRunPass);
    printf("PROCESS_ALIVE_AFTER_RUN=%d\n", w.processAliveAfterRun);
    printf("PROCESS_ALIVE=%d\n", w.processAliveAfterRun);
    printf("OLLAMA_USED=%d\n", w.ollamaProcessUsed);
    printf("VWA_USED=%d\n", w.vwaUsed);
    printf("ELASTIC_USED=%d\n", w.elasticUsed);

    const bool pass =
        w.modelAliasResolved && !w.ollamaProcessUsed && !w.networkUsed &&
        w.ggufOpened && w.shardsDiscovered && w.tokenizerReady &&
        w.chatTemplateReady && w.deep2GenerateStream && w.firstTokenEmitted &&
        w.nTokensEmitted >= 64 && w.ctrlCCancel && w.unloadReload &&
        w.secondRunPass && w.processAliveAfterRun;
    printf("RAWRXD_RUN_MODELNAME_001=%s\n", pass ? "PASS" : "FAIL");
    return pass ? 0 : 8;
}
