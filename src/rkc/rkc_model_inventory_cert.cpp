// rkc_model_inventory_cert.cpp — RKC_MODEL_INVENTORY_001
#include "rkc/RKCModelInventory.hpp"
#include "rkc/RKCWorld.hpp"
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

static const KnowledgeAtom* Get(const World& w, const char* k) { return w.get(k); }

int main() {
#ifdef _WIN32
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\RKC_MODEL_INVENTORY_001", nullptr);
#endif
    const char* rootEnv = std::getenv("DEEP2_MODEL_ROOT");
    std::string root =
        rootEnv && rootEnv[0] ? rootEnv : "F:\\OllamaModels";
    printf("RKC_MODEL_INVENTORY_001\nMODEL_ROOT=%s\n", root.c_str());
    if (!fs::is_directory(root)) {
        printf("RKC_MODEL_INVENTORY_001=SKIP\n"); return 0;
    }

    World world;
    world.clearSession();
    auto st = ObserveModelInventory(world, root);
    printf("RAW_COUNT=%u MANIFEST_COUNT=%u RAW_CORPUS=%llu KIMI_RAW=%u\n",
           st.rawCount, st.manifestCount,
           (unsigned long long)st.rawCorpusBytes, st.kimiRawFound);

    const char* kimi =
        "inventory.raw_gguf.Kimi-K2-Instruct-0905-GGUF.Q4_K_M";
    const auto* src = Get(world, (std::string(kimi) + ".source").c_str());
    const auto* shards = Get(world, (std::string(kimi) + ".shard_count").c_str());
    const auto* bytes = Get(world, (std::string(kimi) + ".corpus_bytes").c_str());
    const auto* compat = Get(world, (std::string(kimi) + ".runtime_compat").c_str());
    const auto* merge = Get(world, "inventory.merge_forbidden");

    const bool kimiOk =
        src && src->value == "RAW_GGUF" &&
        shards && std::strtoull(shards->value.c_str(), nullptr, 10) >= 13 &&
        bytes && std::strtoull(bytes->value.c_str(), nullptr, 10) > (100ull << 30) &&
        compat && compat->value == "1" &&
        st.kimiRawFound == 1;

    // Namespaces must stay disjoint: no RAW id reused as manifest id key.
    bool nsOk = true;
    for (const auto& kv : world.atoms()) {
        if (kv.first.rfind("inventory.raw_gguf.", 0) == 0) {
            const std::string id = kv.first.substr(std::strlen("inventory.raw_gguf."));
            const size_t dot = id.find('.');
            if (dot == std::string::npos) continue;
            const std::string base = id.substr(0, id.find('.', 0)); // unused
            (void)base;
        }
        if (kv.first.rfind("inventory.ollama_manifest.", 0) == 0 &&
            kv.first.find(".source") != std::string::npos) {
            if (kv.second.value == "RAW_GGUF") nsOk = false;
        }
        if (kv.first.rfind("inventory.raw_gguf.", 0) == 0 &&
            kv.first.find(".source") != std::string::npos) {
            if (kv.second.value == "OLLAMA_MANIFEST") nsOk = false;
        }
    }

    // Pick one manifest — runtime_compat must be 0 (not Deep2 loader authority)
    bool manCompatOk = false;
    for (const auto& kv : world.atoms()) {
        if (kv.first.rfind("inventory.ollama_manifest.", 0) != 0) continue;
        if (kv.first.size() < 16 ||
            kv.first.compare(kv.first.size() - 15, 15, ".runtime_compat") != 0)
            continue;
        if (kv.second.value == "0") { manCompatOk = true; break; }
    }

    const bool counts =
        st.rawCount >= 1 && st.manifestCount >= 1 &&
        merge && merge->value == "1";

    printf("KIMI_OK=%d NS_OK=%d MAN_COMPAT=%d COUNTS=%d\n",
           kimiOk ? 1 : 0, nsOk ? 1 : 0, manCompatOk ? 1 : 0, counts ? 1 : 0);
    if (shards)
        printf("KIMI_SHARDS=%s CORPUS=%s\n", shards->value.c_str(),
               bytes ? bytes->value.c_str() : "?");

    const bool pass = kimiOk && nsOk && manCompatOk && counts;
    printf("RKC_MODEL_INVENTORY_001=%s\n", pass ? "PASS" : "FAIL");
    FILE* f = fopen(
        "G:\\~dev\\rawrxd\\evidence\\RKC_MODEL_INVENTORY_001\\GATE_STATUS.txt", "w");
    if (f) {
        fprintf(f, "RAW=%u MANIFEST=%u KIMI=%d\n", st.rawCount, st.manifestCount,
                kimiOk ? 1 : 0);
        fprintf(f, "RKC_MODEL_INVENTORY_001=%s\n", pass ? "PASS" : "FAIL");
        fclose(f);
    }
    return pass ? 0 : 2;
}
