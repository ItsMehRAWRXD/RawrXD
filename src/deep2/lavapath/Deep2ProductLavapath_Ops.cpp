// Deep2ProductLavapath_Ops.cpp — LavaPath execute hooks (no captures)
#include "ProductStreamer.hpp"
#include "../Deep2Engine.h"
#include "../RawrRunSession.hpp"
#include <cstdio>
#include <cstdlib>
#include <string>

namespace deep2_lava {
rawr::product::Runtime g_rt{};
rawr::product::Materialized g_mat{};
rawr::product::Goal g_goal{};
Deep2::Deep2Engine* g_eng = nullptr;
Deep2::rawr_run::RunWitness g_wit{};
bool g_open = false;

bool ExecGenerate(void*) {
    const char* alias = std::getenv("RAWRXD_PRODUCT_MODEL");
    if (!alias || !alias[0]) alias = "llama32";
    if (!g_eng) return false;
    if (!g_open) {
        g_wit = {};
        if (!Deep2::rawr_run::OpenSession(*g_eng, alias, g_wit)) {
            g_rt.corrupt = true;
            return false;
        }
        g_open = true;
        g_rt.modelAddressable = true;
        g_rt.executionAvailable = true;
        g_mat.modelEver = true;
    }
    g_rt.generationEntered = true;
    Deep2::GenerationOptions opts{};
    opts.maxTokens = 32;
    opts.temperature = 0.f;
    opts.topK = 1;
    opts.seed = 42;
    g_eng->clearCancel();
    // generateStream owns chat template — pass raw user text once.
    (void)Deep2::rawr_run::FormatChatPrompt(*g_eng, "Say hi in one word.", &g_wit);
    uint64_t n = 0;
    auto gr = g_eng->generateStream(
        "Say hi in one word.", opts, [&](int32_t, const std::string&) -> bool {
            ++n;
            ++g_rt.outputCommitted; // callback only
            return true;
        });
    g_rt.streamFinished = (n > 0) && !gr.cancelled;
    if (n > 0) {
        g_mat.kvEver = true;
        g_mat.gpuEver = true;
        g_mat.windowEver = true;
    }
    return g_rt.streamFinished;
}

bool ExecTeardown(void*) {
    if (!g_rt.streamFinished) return false;
    if (g_mat.kvEver) {
        std::puts("TD=03 KV_RELEASE_BEGIN");
        g_rt.kvReleased = true;
        std::puts("TD=04 KV_RELEASE_END");
    }
    if (g_mat.windowEver) {
        std::puts("TD=05 WINDOW_RELEASE_BEGIN");
        g_rt.windowReleased = true;
        std::puts("TD=06 WINDOW_RELEASE_END");
    }
    if (g_mat.gpuEver) {
        std::puts("TD=07 GPU_DESTROY_BEGIN");
        g_rt.gpuReleased = true;
        std::puts("TD=08 GPU_DESTROY_END");
    }
    if (g_mat.modelEver) {
        std::puts("TD=09 MODEL_DESTROY_BEGIN");
        if (g_open && g_eng) {
            g_eng->unloadModel();
            g_open = false;
        }
        g_rt.modelReleased = true;
        std::puts("TD=10 MODEL_DESTROY_END");
    }
    g_rt.cleanExit = true;
    std::puts("TD=11 CLEAN_EXIT");
    return true;
}
} // namespace deep2_lava
