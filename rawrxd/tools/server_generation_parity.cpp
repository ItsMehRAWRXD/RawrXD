// ============================================================================
// server_generation_parity.cpp
//   F41_SERVER_INFERENCE_PARITY — the immediate A-vs-B test.
//
// The question this answers in one run:
//
//     A  [X,   X,   X,   X,  ...]   generation is stuck
//     B  [A,   B,   C,   D, ...]   every id decodes to the same text, so the
//                                   defect is tokenizer piece reconstruction
//
// It drives the PRODUCTION generation primitive -- generateStream(), the same
// call the HTTP chat route uses -- with the same model, greedy sampling and
// token budget, and prints every generated token ID next to its decoded piece,
// the KV position at that step, and the accumulated text.
//
// This cert deliberately does not go through HTTP. The HTTP layer is already
// measured; the question here is what the engine generates, and HTTP would only
// add a variable. Parity against the canonical CPU gate is a follow-up step
// once the ids are known.
//
// Usage: server_generation_parity <model.gguf> [maxTokens] [prompt]
// ============================================================================
#include <cstdio>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "deep2/Deep2Engine.h"

using Deep2::Deep2Engine;

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr,
                     "usage: server_generation_parity <model.gguf> [maxTokens] [prompt]\n");
        return 2;
    }
    const std::string modelPath = argv[1];
    const uint32_t maxTokens = (argc > 2) ? static_cast<uint32_t>(std::atoi(argv[2])) : 24u;
    const std::string prompt =
        (argc > 3) ? argv[3] : "What is the capital of France? Answer in one word.";

    Deep2Engine engine;
    // RAWRXD_ATTN_VISIBILITY_TRACE_001
    // Route selection is an INPUT to the measurement, not a fixed default:
    // "CPU only" and "Vulkan" are two different products and the visibility
    // question has a different answer on each. Hard-coding enableVulkan(false)
    // would make it impossible to obtain the GPU half of the comparison from
    // this driver at all.
    //
    //   RAWRXD_PARITY_ROUTE=cpu     (default) Vulkan disabled
    //   RAWRXD_PARITY_ROUTE=vulkan  Vulkan enabled if the device initialises
    //
    // The route actually taken is printed, because a run that silently fell
    // back to CPU while claiming Vulkan would be worse than no run.
    const char* routeEnv = std::getenv("RAWRXD_PARITY_ROUTE");
    const bool wantVulkan = routeEnv && std::strcmp(routeEnv, "vulkan") == 0;
    engine.enableVulkan(wantVulkan);

    Deep2::EngineConfig cfg;
    if (!engine.initialize(cfg)) { std::printf("INIT_OK=0\n"); return 3; }
    Deep2::ModelLoadDiag diag;
    if (!engine.loadModel(modelPath, &diag)) {
        std::printf("LOAD_OK=0 STAGE=%s MSG=%s\n",
                    diag.stageName.c_str(), diag.message.c_str());
        return 4;
    }
    std::printf("LOAD_OK=1\n");

    // RAWRXD_VULKAN_KV_SPLIT_001: the CPU half of the K/V hash join. The GPU
    // side publishes FNV-1a over the full kvDim of each cache slot; this probe
    // publishes the same quantity for the same (step, layer) on the CPU route,
    // so the two are compared by exact hash rather than by a tolerance.
    if (const char* probe = std::getenv("RAWRXD_PARITY_PROBE")) {
        if (*probe) {
            engine.enableParityProbe(probe, 0);
            std::printf("PARITY_PROBE=%s\n", probe);
        }
    }

    // Greedy: temperature 0, topK 1. Matches the reported temperature=0 run and
    // removes sampling as a variable.
    Deep2::GenerationOptions opts;
    opts.maxTokens = maxTokens;
    opts.temperature = 0.0f;
    opts.topP = 1.0f;
    opts.topK = 1;
    opts.repeatPenalty = 1.0f;
    opts.minP = 0.0f;
    opts.seed = 0;

    std::printf("ROUTE=%s VULKAN_REQUESTED=%d VULKAN_INITIALIZED=%d "
                "TEMPERATURE=%.2f TOPK=%u MAX_TOKENS=%u\n",
                engine.isVulkanInitialized() ? "vulkan" : "cpu",
                wantVulkan ? 1 : 0, engine.isVulkanInitialized() ? 1 : 0,
                opts.temperature, opts.topK, maxTokens);
    std::printf("PROMPT_TEXT=%s\n", prompt.c_str());
    std::printf("PROMPT_TOKEN_IDS=");
    for (int t : engine.tokenize(prompt)) std::printf("%d,", t);
    std::printf("\n");

    std::vector<int> ids;
    std::vector<std::string> pieces;
    std::string accented;

    const Deep2::GenerationResult r = engine.generateStream(
        prompt, opts,
        [&](int32_t tokenId, const std::string& token) -> bool {
            const std::size_t pos = engine.kvCacheLength();
            ids.push_back(tokenId);
            pieces.push_back(token);
            accented += token;
            std::printf("GEN_STEP=%zu TOKEN_ID=%d KV_POS=%zu PIECE=%s ACC_LEN=%zu\n",
                        ids.size() - 1, tokenId, pos, token.c_str(), accented.size());
            std::fflush(stdout);
            return true;  // never cancel
        });

    std::printf("\nGENERATED_TOKEN_IDS=");
    for (int t : ids) std::printf("%d,", t);
    std::printf("\n");
    std::printf("TOKEN_COUNT=%zu\n", ids.size());
    std::printf("FINAL_TEXT=%s\n", accented.c_str());

    // A-vs-B, decided from the ids rather than from the text.
    std::size_t distinctIds = 0;
    std::size_t distinctPieces = 0;
    for (std::size_t i = 0; i < ids.size(); ++i) {
        bool newId = true, newPiece = true;
        for (std::size_t j = 0; j < i; ++j) {
            if (ids[j] == ids[i]) newId = false;
            if (pieces[j] == pieces[i]) newPiece = false;
        }
        if (newId) ++distinctIds;
        if (newPiece) ++distinctPieces;
    }
    std::printf("DISTINCT_TOKEN_IDS=%zu\n", distinctIds);
    std::printf("DISTINCT_PIECES=%zu\n", distinctPieces);
    std::printf("IDS_REPEAT=%d\n", (ids.size() > 1 && distinctIds == 1) ? 1 : 0);
    if (ids.size() > 1 && distinctIds == 1) {
        std::printf("VERDICT=A_GENERATION_STUCK_SAME_TOKEN_ID_EVERY_STEP\n");
    } else if (ids.size() > 1 && distinctPieces == 1) {
        std::printf("VERDICT=B_DIFFERENT_IDS_SAME_PIECE_DETOKENISATION\n");
    } else {
        std::printf("VERDICT=C_IDS_AND_PIECES_VARY\n");
    }

    std::printf("GEN_STATUS=%d\n", static_cast<int>(r.status));
    std::printf("FINISH_EARLY=%d\n", (ids.size() < maxTokens) ? 1 : 0);
    return 0;
}