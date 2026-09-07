// rkc_deep2_model_authority_cert.cpp — RKC_DEEP2_MODEL_AUTHORITY_001
#include "rkc/RKCDeep2Authority.hpp"
#include "rkc/RKCModelInventory.hpp"
#include "rkc/RKCWorld.hpp"
#include "agentic/LocalOnlyPolicy.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

using namespace RawrXD::RKC;
namespace fs = std::filesystem;

int main() {
#ifdef _WIN32
    CreateDirectoryA(
        "G:\\~dev\\rawrxd\\evidence\\RKC_DEEP2_MODEL_AUTHORITY_001", nullptr);
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
#endif
    const char* rootEnv = std::getenv("DEEP2_MODEL_ROOT");
    std::string root =
        rootEnv && rootEnv[0] ? rootEnv : "F:\\OllamaModels";
    printf("RKC_DEEP2_MODEL_AUTHORITY_001\nMODEL_ROOT=%s\n", root.c_str());
    if (!fs::is_directory(root)) {
        printf("RKC_DEEP2_MODEL_AUTHORITY_001=SKIP\n"); return 0;
    }

    World world;
    world.clearSession();
    auto inv = ObserveModelInventory(world, root);

    // 1) Manifest must never be load authority
    std::string manId;
    for (const auto& kv : world.atoms()) {
        if (kv.first.rfind("inventory.ollama_manifest.", 0) != 0) continue;
        if (kv.first.size() < 8 ||
            kv.first.compare(kv.first.size() - 7, 7, ".source") != 0)
            continue;
        manId = kv.first.substr(std::strlen("inventory.ollama_manifest."));
        manId.resize(manId.size() - 7);
        break;
    }
    auto reject = SelectDeep2Authority(world, manId);
    const bool manifestRejected =
        !manId.empty() && !reject.ok &&
        std::strcmp(reject.reason, "ollama_manifest_not_authority") == 0;

    // 2) RAW Kimi selection
    const char* kimiId = "Kimi-K2-Instruct-0905-GGUF.Q4_K_M";
    auto sel = SelectDeep2AuthorityPreferred(world, kimiId, "Kimi-K2");
    const bool rawOk =
        sel.ok && sel.source == std::string("RAW_GGUF") &&
        sel.shardCount >= 13 && !sel.path.empty();

    // 3) Local-only policy: :11434 never authorized for inference
    const bool localPolicy =
        RawrXD::LocalOnly::isForbiddenOllamaPort(11434) &&
        !RawrXD::LocalOnly::allowOllamaHttpClient() &&
        RawrXD::LocalOnly::sanitizeBaseUrl("http://127.0.0.1:11434").empty();

    printf("INV raw=%u man=%u\n", inv.rawCount, inv.manifestCount);
    printf("MANIFEST_REJECTED=%d RAW_OK=%d LOCAL_POLICY=%d\n",
           manifestRejected ? 1 : 0, rawOk ? 1 : 0, localPolicy ? 1 : 0);
    if (rawOk)
        printf("SELECTED id=%s path=%s shards=%u\n", sel.id.c_str(),
               sel.path.c_str(), sel.shardCount);

    // 4) Deep2 open + short generate (authoritative path)
    auto run = AuthorizeDeep2Generate(sel, 4, 2,
                                      "Write one short paragraph on local decode.");
    printf("OPENED=%d GENERATED=%d OLLAMA_REQUIRED=%d LOCAL_PROVEN=%d "
           "TPS=%.3f reason=%s\n",
           run.opened ? 1 : 0, run.generated ? 1 : 0, run.ollamaRequired ? 1 : 0,
           run.localProven ? 1 : 0, run.tps, run.reason ? run.reason : "");

    const bool pass = manifestRejected && rawOk && localPolicy &&
                      run.selected && run.opened && run.generated &&
                      !run.ollamaRequired && run.localProven;
    printf("RKC_DEEP2_MODEL_AUTHORITY_001=%s\n", pass ? "PASS" : "FAIL");
    FILE* f = fopen(
        "G:\\~dev\\rawrxd\\evidence\\RKC_DEEP2_MODEL_AUTHORITY_001\\GATE_STATUS.txt",
        "w");
    if (f) {
        fprintf(f, "manifest_rejected=%d raw_ok=%d opened=%d generated=%d "
                "ollama_required=%d\n",
                manifestRejected ? 1 : 0, rawOk ? 1 : 0, run.opened ? 1 : 0,
                run.generated ? 1 : 0, run.ollamaRequired ? 1 : 0);
        fprintf(f, "RKC_DEEP2_MODEL_AUTHORITY_001=%s\n", pass ? "PASS" : "FAIL");
        fclose(f);
    }
    fflush(stdout);
    _exit(pass ? 0 : 2);
}
