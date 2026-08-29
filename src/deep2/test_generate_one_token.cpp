// test_generate_one_token.cpp - Minimal: load a GGUF model and generate 1 token
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <cstring>
#include "Deep2Engine.h"
#include "AttnCertProbe.hpp"
#include "gguf_embedded_tokenizer.hpp"
#include <string>

#ifdef _WIN32
#include <windows.h>
#endif

using namespace Deep2;

static void deep2_enable_utf8_console() {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif
}

int main(int argc, char** argv) {
    deep2_enable_utf8_console();

    const char* modelPath = argc > 1 ? argv[1] : "G:\\OllamaModels\\Phi-3-mini-4k-instruct-q8_0.gguf";
    // Optional: argv[2]=prompt argv[3]=maxTokens  (PONG cert: model "PONG" 1)
    const char* promptArg = argc > 2 ? argv[2] : "hello";
    size_t kGenCount = 16;
    if (argc > 3) {
        kGenCount = static_cast<size_t>(std::max(1, atoi(argv[3])));
    }
    const bool greedyOneToken = (kGenCount == 1) || (std::getenv("RAWRXD_GREEDY") != nullptr);

    printf("[TEST] Token Generation Test\n");
    printf("[TEST] Model: %s\n", modelPath);
    printf("[TEST] Prompt: '%s' maxTokens=%zu greedy=%d\n", promptArg, kGenCount, (int)greedyOneToken);

    // Load embedded tokenizer from GGUF
    RawrXD::GGUFEmbeddedTokenizer tokenizer;
    printf("[Tokenizer] Loading from GGUF...\n");
    if (!tokenizer.LoadFromGGUF(modelPath)) {
        printf("[FAIL] Failed to load embedded tokenizer from GGUF\n");
        return 1;
    }
    printf("[Tokenizer] source=GGUF\n");
    printf("[Tokenizer] vocab=%zu\n", tokenizer.VocabSize());
    printf("[Tokenizer] external_tokenizer=false\n");
    printf("[Tokenizer] EncodeLongestMatch=ready\n");
    printf("[Tokenizer] Decode=ready\n");

    Deep2Engine engine;

    printf("[TEST] Loading model to detect architecture...\n");
    if (!engine.loadModel(modelPath)) {
        printf("[FAIL] loadModel() returned false\n");
        return 1;
    }
    const auto& mw = engine.getModelWeights();
    printf("[PASS] Model loaded: hidden=%zu layers=%zu heads=%zu kv_heads=%zu headDim=%zu vocab=%zu\n",
           mw.hiddenDim, mw.numLayers, mw.numHeads, mw.numKVHeads, mw.headDim, mw.vocabSize);

    EngineConfig cfg;
    cfg.hiddenDim   = mw.hiddenDim;
    cfg.numLayers   = mw.numLayers;
    cfg.numHeads    = mw.numHeads;
    cfg.numKVHeads  = mw.numKVHeads;
    cfg.headDim     = mw.headDim;
    cfg.vocabSize   = mw.vocabSize;
    cfg.maxSeqLen   = 4096;
    cfg.useKVCache  = true;
    cfg.useThreadPool = true;
    cfg.numThreads  = 16;

    printf("[TEST] Initializing engine (dim=%zu, layers=%zu, heads=%zu, kv_heads=%zu, headDim=%zu)...\n",
           cfg.hiddenDim, cfg.numLayers, cfg.numHeads, cfg.numKVHeads, cfg.headDim);
    if (!engine.initialize(cfg)) {
        printf("[FAIL] Engine initialization failed\n");
        return 1;
    }
    printf("[PASS] Engine initialized\n");

    // Tokenize a simple prompt using embedded tokenizer
    std::string prompt = promptArg;
    if (const char* promptFile = std::getenv("RAWRXD_PROMPT_FILE")) {
        FILE* f = fopen(promptFile, "rb");
        if (!f) {
            printf("[FAIL] cannot open RAWRXD_PROMPT_FILE=%s\n", promptFile);
            return 1;
        }
        fseek(f, 0, SEEK_END);
        long sz = ftell(f);
        fseek(f, 0, SEEK_SET);
        if (sz < 0) {
            fclose(f);
            printf("[FAIL] RAWRXD_PROMPT_FILE size error\n");
            return 1;
        }
        prompt.assign(static_cast<size_t>(sz), '\0');
        if (sz > 0 && fread(prompt.data(), 1, static_cast<size_t>(sz), f) != static_cast<size_t>(sz)) {
            fclose(f);
            printf("[FAIL] RAWRXD_PROMPT_FILE read error\n");
            return 1;
        }
        fclose(f);
        printf("[TEST] Prompt loaded from file (%zu bytes)\n", prompt.size());
    }

    std::vector<uint32_t> promptTokens;
    if (const char* idsEnv = std::getenv("RAWRXD_PROMPT_TOKEN_IDS")) {
        // Exact ID injection for parity (bypasses EncodeLongestMatch gaps on specials)
        printf("[TEST] Using RAWRXD_PROMPT_TOKEN_IDS\n");
        const char* p = idsEnv;
        while (*p) {
            while (*p == ' ' || *p == ',') ++p;
            if (!*p) break;
            char* end = nullptr;
            unsigned long v = std::strtoul(p, &end, 10);
            if (end == p) break;
            promptTokens.push_back(static_cast<uint32_t>(v));
            p = end;
        }
        if (promptTokens.empty()) {
            printf("[FAIL] RAWRXD_PROMPT_TOKEN_IDS empty/unparsed\n");
            return 1;
        }
    } else {
        printf("[TEST] Tokenizing prompt (%zu bytes)\n", prompt.size());
        if (!tokenizer.EncodeLongestMatch(prompt, promptTokens)) {
            printf("[FAIL] EncodeLongestMatch failed\n");
            return 1;
        }
    }
    // Optional BOS prefix for llama.cpp parity (TinyLlama BOS id=1)
    if (std::getenv("RAWRXD_ADD_BOS")) {
        const uint32_t bosId = 1;
        if (promptTokens.empty() || promptTokens.front() != bosId) {
            promptTokens.insert(promptTokens.begin(), bosId);
            printf("[BOS] prepended token_id=%u\n", bosId);
        }
    }

    printf("[PASS] Tokenized to %zu tokens\n", promptTokens.size());
    for (size_t i = 0; i < promptTokens.size(); ++i) {
        printf("  prompt_token[%zu]=%u text=\"%s\"\n", i, promptTokens[i],
               tokenizer.Token(promptTokens[i]).c_str());
    }

    // Convert to int vector for engine
    std::vector<int> tokens;
    for (auto t : promptTokens) tokens.push_back(static_cast<int>(t));

    // Greedy 1-token path for PONG / numerical cert
    if (greedyOneToken) {
        GenerationOptions opts{};
        opts.maxTokens = static_cast<uint32_t>(kGenCount);
        opts.temperature = 0.0f;
        opts.topK = 1;
        opts.topP = 1.0f;
        engine.configureGeneration(opts);
    }

    const bool attnCertDump = (std::getenv("RAWRXD_ATTN_CERT_DUMP") != nullptr);
    if (attnCertDump) {
        Deep2::AttnCert::clear();
        Deep2::AttnCert::enable(true);
        printf("[ATTN_CERT] enabled dump for this generate()\n");
    }

    printf("[TEST] Generating %zu tokens...\n", kGenCount);
    std::vector<int> outputTokens(kGenCount);
    size_t generated = engine.generate(tokens.data(), tokens.size(),
                                        outputTokens.data(), kGenCount);
    if (attnCertDump) {
        auto frames = Deep2::AttnCert::snapshot();
        Deep2::AttnCert::enable(false);
        printf("[ATTN_CERT] frames=%zu\n", frames.size());
        for (const auto& f : frames) {
            // Layer-0 indexing / stage digests only (RoPE pos, KV write/len, QKV).
            if (f.layer != 0) continue;
            printf("[ATTN_CERT] stage=%s layer=%u pos=%u count=%u "
                   "l2=%.9e min=%.9e max=%.9e aux=%.6f fnv=%016llx nf=%u\n",
                   Deep2::AttnCert::stageName(f.stage), f.layer, f.position, f.count,
                   f.l2, f.min, f.max, f.aux,
                   static_cast<unsigned long long>(f.fnv), f.nonfinite);
        }
        Deep2::AttnCert::clear();
    }
    if (generated == 0) {
        printf("[FAIL] generate() returned 0 tokens\n");
        return 1;
    }

    printf("[PASS] Generated %zu tokens\n", generated);
    fflush(stdout);
    std::string allText;
    for (size_t i = 0; i < generated; ++i) {
        std::string text = tokenizer.Token(static_cast<uint32_t>(outputTokens[i]));
        allText += text;
        printf("  gen_token[%zu]=%d text=\"%s\"\n", i, outputTokens[i], text.c_str());
    }

    printf("\n=== GENERATED RESPONSE ===\n");
    printf("Prompt: '%s'\n", prompt.c_str());
    printf("Response: '%s'\n", allText.c_str());
    printf("=== TOKEN GENERATION SUCCESS ===\n");
    fflush(stdout);

    // Optional exact-match gate for PONG smoke
    if (std::getenv("RAWRXD_EXPECT_CONTAINS")) {
        const char* expect = std::getenv("RAWRXD_EXPECT_CONTAINS");
        if (allText.find(expect) == std::string::npos) {
            printf("[FAIL] expected substring '%s' not in response\n", expect);
            return 2;
        }
        printf("[PASS] expected substring '%s' found\n", expect);
    }
    if (const char* expectIdEnv = std::getenv("RAWRXD_EXPECT_TOKEN_ID")) {
        const int expectId = std::atoi(expectIdEnv);
        const int actualId = generated > 0 ? outputTokens[0] : -1;
        const std::string expectPiece = tokenizer.Token(static_cast<uint32_t>(expectId));
        const std::string actualPiece =
            actualId >= 0 ? tokenizer.Token(static_cast<uint32_t>(actualId)) : std::string("?");
        printf("[BOS_CERT] expected_token_id=%d actual_token_id=%d\n", expectId, actualId);
        printf("[BOS_CERT] expected_piece=\"%s\" actual_piece=\"%s\"\n",
               expectPiece.c_str(), actualPiece.c_str());
        if (actualId != expectId) {
            printf("[FAIL] expected_token_id=%d actual_token_id=%d\n", expectId, actualId);
            return 2;
        }
        printf("[PASS] expected_token_id=%d matched\n", expectId);
    }

    printf("[TEST] Returning 0\n");
    fflush(stdout);

    // ── Fast-exit teardown A/B: bypass CRT teardown to test for destructor crash ──
    if (std::getenv("RAWRXD_CERT_FAST_EXIT")) {
#ifdef _WIN32
        ::ExitProcess(0);
#else
        std::_Exit(0);
#endif
    }

    return 0;
}
