// ============================================================================
// inference_standalone_main.cpp — RawrXD-InferenceEngine Standalone Entry
// ============================================================================
//
// Self-hosting inference engine: no Qt, no GUI, no IDE dependencies.
// This is the Phase 6 "Inference-Standalone" endpoint.
//
// Usage:
//   RawrXD-InferenceEngine.exe --model <path.gguf> [--prompt "..."] [--bench]
//
// The T4 Autonomous Recovery Orchestrator can invoke this binary directly
// for reasoning tasks during self-repair operations.
//
// Pattern: PatchResult-style, no exceptions, factory results.
// Rule:    NO SOURCE FILE IS TO BE SIMPLIFIED.
// ============================================================================

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sstream>
#include <chrono>
#include <vector>
#include <functional>
#include <atomic>
#include <unordered_map>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#endif

#include "cpu_inference_engine.h"
#include "ultra_fast_inference.h"
#include "RawrXD_LlamaNative.h"
#include "RawrXD_VulkanAccelerator.h"
#include "token_generator.h"
#include "chat_session.h"

// ============================================================================
// Forward declarations — these live in the inference core sources
// ============================================================================
namespace rawrxd { namespace inference {
    class UltraFastInferenceEngine;
} }

// ============================================================================
// Telemetry integration (MASM kernel)
// ============================================================================
#if defined(RAWRXD_LINK_TELEMETRY_KERNEL_ASM) || defined(RAWR_HAS_MASM)
extern "C" {
    void UTC_LogEvent(const char* msg);
    void UTC_IncrementCounter(void* counter);
    uint64_t UTC_ReadCounter(void* counter);
}
#else
static inline void UTC_LogEvent(const char*) {}
#endif

// ============================================================================
// Production speculative decode configuration — validated by sweep 2026-06-04
// ============================================================================
constexpr struct {
    const char* draft_model_path = "";  // DISABLED: truncated draft models crash during graph reserve (GGML_ASSERT mem_buffer != NULL)
    uint32_t    draft_layers = 12;
    uint32_t    spec_depth = 1;
    float       min_acceptance = 0.30f;
    uint32_t    min_proposed = 32;
    bool        auto_disable = true;
} kSpeculativeConfig;

// ============================================================================
// CLI argument parser (minimal, no dependencies)
// ============================================================================
struct InferenceCLI {
    std::string modelPath;
    std::string prompt;
    std::string traceCsvPath;
    int maxTokens       = 256;
    float temperature   = 0.7f;
    bool benchmark      = false;
    bool interactive    = false;
    bool traceSummary   = false;
    bool verbose        = false;
    bool stream         = false;
    bool chat           = false;
    bool chatSmoke      = false;
    bool vulkanSmoke    = false;
    bool debugPrompt    = false;
    bool specActiveDepth1 = false;
    bool specOracleDraft = false;
    bool specShadowEnabled = true;
    std::string specDraftModelPath;
    float specMinAcceptance = -1.0f;   // -1 = use kSpeculativeConfig default
    int specMinProposed = -1;           // -1 = use kSpeculativeConfig default
    int smokeTurns      = 2;
    int threads         = 8;

    static InferenceCLI parse(int argc, char* argv[]) {
        InferenceCLI cli;
        for (int i = 1; i < argc; ++i) {
            if (strcmp(argv[i], "--model") == 0 && i + 1 < argc) {
                cli.modelPath = argv[++i];
            } else if (strcmp(argv[i], "--prompt") == 0 && i + 1 < argc) {
                cli.prompt = argv[++i];
            } else if (strcmp(argv[i], "--threads") == 0 && i + 1 < argc) {
                cli.threads = atoi(argv[++i]);
            } else if (strcmp(argv[i], "--max-tokens") == 0 && i + 1 < argc) {
                cli.maxTokens = atoi(argv[++i]);
            } else if (strcmp(argv[i], "--temperature") == 0 && i + 1 < argc) {
                cli.temperature = static_cast<float>(atof(argv[++i]));
            } else if (strcmp(argv[i], "--bench") == 0) {
                cli.benchmark = true;
            } else if (strcmp(argv[i], "--stream") == 0) {
                cli.stream = true;
            } else if (strcmp(argv[i], "--chat") == 0) {
                cli.chat = true;
            } else if (strcmp(argv[i], "--chat-smoke") == 0) {
                cli.chatSmoke = true;
                cli.chat = true;
            } else if (strcmp(argv[i], "--vulkan-smoke") == 0) {
                cli.vulkanSmoke = true;
            } else if (strcmp(argv[i], "--debug-prompt") == 0) {
                cli.debugPrompt = true;
            } else if (strcmp(argv[i], "--spec-active-depth1") == 0) {
                cli.specActiveDepth1 = true;
            } else if (strcmp(argv[i], "--spec-oracle-draft") == 0) {
                cli.specOracleDraft = true;
                cli.specActiveDepth1 = true;
            } else if (strcmp(argv[i], "--spec-shadow-off") == 0) {
                cli.specShadowEnabled = false;
            } else if (strcmp(argv[i], "--spec-draft-model") == 0 && i + 1 < argc) {
                cli.specDraftModelPath = argv[++i];
                cli.specActiveDepth1 = true;
            } else if (strcmp(argv[i], "--spec-min-acceptance") == 0 && i + 1 < argc) {
                cli.specMinAcceptance = static_cast<float>(atof(argv[++i]));
            } else if (strcmp(argv[i], "--spec-min-proposed") == 0 && i + 1 < argc) {
                cli.specMinProposed = atoi(argv[++i]);
            } else if (strcmp(argv[i], "--smoke-turns") == 0 && i + 1 < argc) {
                cli.smokeTurns = atoi(argv[++i]);
                if (cli.smokeTurns < 1) cli.smokeTurns = 1;
            } else if (strcmp(argv[i], "--interactive") == 0) {
                cli.interactive = true;
            } else if (strcmp(argv[i], "--trace-token-summary") == 0) {
                cli.traceSummary = true;
            } else if (strcmp(argv[i], "--trace-token-csv") == 0 && i + 1 < argc) {
                cli.traceCsvPath = argv[++i];
            } else if (strcmp(argv[i], "--verbose") == 0) {
                cli.verbose = true;
            } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
                printf("RawrXD-InferenceEngine v1.0.0 — Standalone Inference\n");
                printf("  --model <path>       Path to GGUF model file\n");
                printf("  --prompt <text>      Prompt text for inference\n");
                printf("  --max-tokens <n>     Maximum tokens to generate (default: 256)\n");
                printf("  --temperature <f>    Sampling temperature (default: 0.7)\n");
                printf("  --bench              Run TPS benchmark\n");
                printf("  --stream             Stream tokens to stdout as generated\n");
                printf("  --interactive        Interactive REPL mode\n");
                printf("  --chat-smoke         Run deterministic bridge chat smoke (non-interactive)\n");
                printf("  --vulkan-smoke       Run sovereign Vulkan RMSNorm smoke test (no model required)\n");
                printf("  --smoke-turns <n>    Number of smoke turns (default: 2)\n");
                printf("  --debug-prompt       Print prompt payload preview before generation\n");
                printf("  --spec-active-depth1     [DEBUG] Override: enable guarded depth-1 active speculative gate\n");
                printf("  --spec-oracle-draft      [DEBUG] Override: active mode with perfect-oracle draft token\n");
                printf("  --spec-shadow-off        [DEBUG] Override: disable shadow draft telemetry in non-active mode\n");
                printf("  --spec-draft-model <path> [DEBUG] Override: use a separate draft GGUF (default: %s)\n", kSpeculativeConfig.draft_model_path);
                printf("  --spec-min-acceptance <f> [DEBUG] Override: auto-disable threshold (default: %.2f)\n", kSpeculativeConfig.min_acceptance);
                printf("  --spec-min-proposed <n>   [DEBUG] Override: minimum proposals before gate (default: %u)\n", kSpeculativeConfig.min_proposed);
                printf("  --trace-token-summary Emit Titan token trace summary after generation\n");
                printf("  --trace-token-csv <path> Dump Titan token trace CSV after generation\n");
                printf("  --verbose            Verbose telemetry output\n");
                exit(0);
            }
        }
        return cli;
    }
};

// ============================================================================
// TPS Benchmark
// ============================================================================
struct BenchmarkResult {
    double tokensPerSecond;
    double timeToFirstTokenMs;
    int totalTokens;
    double totalTimeMs;
};

static BenchmarkResult runBenchmark(const InferenceCLI& cli) {
    BenchmarkResult result = {};

    printf("[Benchmark] Model: %s\n", cli.modelPath.c_str());
    printf("[Benchmark] Max tokens: %d, Temperature: %.2f\n",
           cli.maxTokens, cli.temperature);

    auto start = std::chrono::high_resolution_clock::now();

    // Load model via polymorphic_loader → ultra_fast_inference
    rawrxd::inference::AutonomousInferenceEngine::InferenceConfig config;
    config.max_memory_mb = 0; // Auto-detect
    config.quality_target = 0.8f;
    config.enable_streaming_pruning = true;
    config.enable_hotpatching = true;
    config.enable_gpu = true;

    rawrxd::inference::AutonomousInferenceEngine engine(config);

    if (!engine.loadModelAutomatic(cli.modelPath)) {
        printf("[Benchmark] ERROR: Failed to load model: %s\n", cli.modelPath.c_str());
        result.tokensPerSecond = 0;
        return result;
    }

    // Tokenize prompt (simplified: one token per word)
    std::vector<int32_t> prompt_tokens;
    std::istringstream iss(cli.prompt.empty() ? "Hello world" : cli.prompt);
    std::string word;
    while (iss >> word) {
        // Simple hash-based token ID
        uint32_t h = 0;
        for (char c : word) h = h * 31 + static_cast<uint32_t>(c);
        prompt_tokens.push_back(static_cast<int32_t>(h % 32000));
    }

    // Run inference with token callback
    int tokens = 0;
    auto firstTokenTime = start;
    bool firstToken = false;

    engine.infer(prompt_tokens, [&](const std::string& token) {
        if (!firstToken) {
            firstTokenTime = std::chrono::high_resolution_clock::now();
            firstToken = true;
        }
        tokens++;
        if (cli.interactive) {
            printf("%s", token.c_str());
            fflush(stdout);
        }
    }, cli.maxTokens);

    auto end = std::chrono::high_resolution_clock::now();
    double totalMs = std::chrono::duration<double, std::milli>(end - start).count();
    double ttftMs  = std::chrono::duration<double, std::milli>(firstTokenTime - start).count();

    result.totalTokens = tokens;
    result.totalTimeMs = totalMs;
    result.timeToFirstTokenMs = ttftMs;
    result.tokensPerSecond = (totalMs > 0) ? (tokens * 1000.0 / totalMs) : 0;

    printf("[Benchmark] Results:\n");
    printf("  Tokens generated: %d\n", result.totalTokens);
    printf("  Total time:       %.2f ms\n", result.totalTimeMs);
    printf("  Time to first:    %.2f ms\n", result.timeToFirstTokenMs);
    printf("  Throughput:       %.2f tok/s\n", result.tokensPerSecond);

    return result;
}

static int runTitanTrace(const InferenceCLI& cli)
{
    auto engine = RawrXD::CPUInferenceEngine::GetSharedInstance();
    if (!engine)
    {
        std::fprintf(stderr, "[TitanTrace] Failed to acquire CPUInferenceEngine shared instance\n");
        return 3;
    }

    if (!engine->IsModelLoaded() && !engine->LoadModel(cli.modelPath))
    {
        std::fprintf(stderr, "[TitanTrace] LoadModel failed: %s\n", engine->GetLastLoadErrorMessage().c_str());
        return 4;
    }

    engine->ClearTokenTraceBuffer();
    const std::vector<int32_t> promptTokens = engine->Tokenize(cli.prompt);
    if (promptTokens.empty())
    {
        std::fprintf(stderr, "[TitanTrace] Tokenize failed or returned no tokens\n");
        return 5;
    }

    std::string response;
    int generatedTokens = 0;
    engine->GenerateStreaming(
        promptTokens,
        cli.maxTokens,
        [&](const std::string& token)
        {
            response += token;
            if (cli.verbose)
            {
                std::printf("%s", token.c_str());
                std::fflush(stdout);
            }
        },
        [&]() {},
        [&](int32_t)
        {
            ++generatedTokens;
        });

    if (cli.verbose)
        std::printf("\n");

    if (cli.traceSummary)
    {
        std::printf("%s", engine->DumpTokenTraceSummary(static_cast<size_t>(cli.maxTokens)).c_str());
    }

    if (!cli.traceCsvPath.empty())
    {
        if (!engine->DumpTokenTracesToCSV(cli.traceCsvPath))
        {
            std::fprintf(stderr, "[TitanTrace] Failed to write CSV: %s\n", cli.traceCsvPath.c_str());
            return 6;
        }
        std::printf("trace_csv=%s\n", cli.traceCsvPath.c_str());
    }

    std::printf("generated_tokens=%d\n", generatedTokens);
    std::printf("response=%s\n", response.c_str());
    return 0;
}

static std::wstring utf8ToWide(const std::string& text) {
#ifdef _WIN32
    if (text.empty()) {
        return {};
    }

    const int required = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, nullptr, 0);
    if (required <= 0) {
        return {};
    }

    std::wstring wide(static_cast<size_t>(required - 1), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, wide.data(), required);
    return wide;
#else
    return std::wstring(text.begin(), text.end());
#endif
}

static std::string normalizeAssistantText(const std::string& text) {
    return text;
}

static uint64_t fnv1a64(const std::string& data) {
    uint64_t h = 1469598103934665603ull;
    for (unsigned char c : data) {
        h ^= static_cast<uint64_t>(c);
        h *= 1099511628211ull;
    }
    return h;
}

struct LookaheadDraft {
    static constexpr uint32_t kNgram = 4;
    static constexpr uint32_t kHistoryCap = 4096;

    std::vector<uint32_t> history;
    std::unordered_map<uint64_t, std::unordered_map<uint32_t, uint32_t>> transitions;

    static uint64_t hashState(const uint32_t* data, uint32_t n) {
        uint64_t h = 1469598103934665603ull;
        for (uint32_t i = 0; i < n; ++i) {
            uint32_t v = data[i];
            for (int b = 0; b < 4; ++b) {
                h ^= static_cast<uint64_t>((v >> (b * 8)) & 0xFFu);
                h *= 1099511628211ull;
            }
        }
        return h;
    }

    void observe(const std::vector<int32_t>& tokens) {
        if (tokens.empty()) {
            return;
        }
        for (int32_t t : tokens) {
            history.push_back(static_cast<uint32_t>(t));
        }
        if (history.size() > kHistoryCap) {
            const size_t trim = history.size() - kHistoryCap;
            history.erase(history.begin(), history.begin() + static_cast<std::ptrdiff_t>(trim));
            transitions.clear();
            if (history.size() <= kNgram) {
                return;
            }
            for (size_t i = kNgram; i < history.size(); ++i) {
                const uint64_t key = hashState(&history[i - kNgram], kNgram);
                transitions[key][history[i]]++;
            }
            return;
        }

        if (history.size() <= kNgram) {
            return;
        }

        size_t start = history.size() - tokens.size();
        if (start < kNgram) {
            start = kNgram;
        }
        for (size_t i = start; i < history.size(); ++i) {
            const uint64_t key = hashState(&history[i - kNgram], kNgram);
            transitions[key][history[i]]++;
        }
    }

    size_t generate(uint32_t* outTokens, size_t maxDraft) const {
        if (!outTokens || maxDraft == 0 || history.size() < kNgram) {
            return 0;
        }

        std::vector<uint32_t> state(history.end() - static_cast<std::ptrdiff_t>(kNgram), history.end());
        size_t produced = 0;
        while (produced < maxDraft) {
            const uint64_t key = hashState(state.data(), kNgram);
            auto it = transitions.find(key);
            if (it == transitions.end() || it->second.empty()) {
                break;
            }

            uint32_t bestToken = 0;
            uint32_t bestCount = 0;
            for (const auto& kv : it->second) {
                if (kv.second > bestCount) {
                    bestCount = kv.second;
                    bestToken = kv.first;
                }
            }
            if (bestCount == 0) {
                break;
            }

            outTokens[produced++] = bestToken;
            state.erase(state.begin());
            state.push_back(bestToken);
        }
        return produced;
    }
};

static int runBridgeChat(const InferenceCLI& cli) {
    auto& bridge = GetLlamaBridge();
    bridge.SetKVCachePreservation(true);

    constexpr int32_t kContextLimitTokens = 2048;
    constexpr int32_t kProactiveRolloverThreshold = kContextLimitTokens - 128;
    constexpr size_t kRolloverKeepTurns = 24;

    if (!bridge.Initialize(nullptr)) {
        std::printf("[Chat] WARNING: llama bridge init failed: %s\n", bridge.GetLastError());
        return 1;
    }
    bridge.SetThreads(cli.threads);

    const std::wstring modelPathW = utf8ToWide(cli.modelPath);
    if (modelPathW.empty() || !bridge.LoadModel(modelPathW.c_str(), 0, 2048)) {
        std::printf("[Chat] WARNING: llama bridge load failed: %s\n", bridge.GetLastError());
        return 1;
    }

    LlamaNativeBridge draftBridge;
    bool draftBridgeReady = false;
    if (cli.specActiveDepth1) {
        const std::string draftPath = cli.specDraftModelPath.empty() ? kSpeculativeConfig.draft_model_path : cli.specDraftModelPath;
        const std::wstring draftPathW = utf8ToWide(draftPath);
        // Draft model is small; 2 threads are plenty and avoid over-subscription.
        int32_t draftThreads = (cli.threads > 4) ? 2 : 1;
        draftBridge.SetThreads(draftThreads); 
        if (!draftPathW.empty() && draftBridge.Initialize(nullptr) && draftBridge.LoadModel(draftPathW.c_str(), 0, 2048)) {
            draftBridge.SetKVCachePreservation(true);
            draftBridgeReady = true;
            std::printf("[Spec] draft_model=loaded path=%s\n", draftPath.c_str());
        } else {
            std::printf("[Spec] WARNING: failed to load draft model (%s); falling back to n-gram/oracle path\n",
                        draftPath.c_str());
        }
    }

    struct ChatTurn {
        std::string user;
        std::string assistant;
    };

    std::vector<ChatTurn> history;
    const std::string systemPrompt = "You are a concise, helpful assistant. Reply with one short sentence unless asked otherwise.";

    auto buildTurnSuffix = [&](const std::string& userText) -> std::string {
        std::string prompt;
        prompt.reserve(1024);
        prompt += "<|user|>\n";
        prompt += userText;
        prompt += "\n<|assistant|>\n";
        return prompt;
    };

    auto buildFirstPrompt = [&](const std::string& userText) -> std::string {
        std::string prompt;
        prompt.reserve(4096);
        prompt += "<|system|>\n";
        prompt += systemPrompt;
        prompt += "\n";
        prompt += buildTurnSuffix(userText);
        return prompt;
    };

    auto buildFullPrompt = [&](const std::string& userText) -> std::string {
        std::string prompt;
        prompt.reserve(4096 + history.size() * 512);
        prompt += "<|system|>\n";
        prompt += systemPrompt;
        prompt += "\n";
        for (const auto& turn : history) {
            prompt += "<|user|>\n";
            prompt += turn.user;
            prompt += "\n<|assistant|>\n";
            prompt += turn.assistant;
            prompt += "\n";
        }
        prompt += buildTurnSuffix(userText);
        return prompt;
    };

    auto escapeJson = [](const std::string& s) -> std::string {
        std::string out;
        out.reserve(s.size() + 16);
        for (char c : s) {
            switch (c) {
                case '\\': out += "\\\\"; break;
                case '"': out += "\\\""; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default: out.push_back(c); break;
            }
        }
        return out;
    };

    size_t turnCount = 0;
    size_t cacheHitCount = 0;
    std::atomic<uint64_t> fallbackTotal{0};
    std::atomic<uint64_t> fallbackSuccess{0};
    std::atomic<uint64_t> fallbackFailure{0};
    std::atomic<uint64_t> speculativeDraftProposed{0};
    std::atomic<uint64_t> speculativeDraftAccepted{0};
    LookaheadDraft lookaheadDraft;
    uint64_t totalGeneratedTokens = 0;
    double sumTtftMs = 0.0;
    double sumPrefillMs = 0.0;
    double sumDecodeMs = 0.0;
    double sumTotalMs = 0.0;
    double sumTps = 0.0;
    double sumDraftMs = 0.0;
    double sumVerifyMs = 0.0;
    size_t proactiveRolloverCount = 0;
    bool specAutoDisabled = false;
    size_t specAutoDisabledTurn = 0;
    int32_t lastNPastEnd = 0;
    int32_t prevNPastEnd = -1;
    size_t nPastMismatchCount = 0;
    uint64_t lastPromptHash = 0;
    bool conversationInitialized = false;
    auto resetStats = [&]() {
        turnCount = 0;
        cacheHitCount = 0;
        sumTtftMs = 0.0;
        sumPrefillMs = 0.0;
        sumDecodeMs = 0.0;
        sumTotalMs = 0.0;
        sumTps = 0.0;
        proactiveRolloverCount = 0;
        specAutoDisabled = false;
        specAutoDisabledTurn = 0;
        lastNPastEnd = 0;
        prevNPastEnd = -1;
        nPastMismatchCount = 0;
        lastPromptHash = 0;
        conversationInitialized = false;
        fallbackTotal.store(0, std::memory_order_relaxed);
        fallbackSuccess.store(0, std::memory_order_relaxed);
        fallbackFailure.store(0, std::memory_order_relaxed);
        speculativeDraftProposed.store(0, std::memory_order_relaxed);
        speculativeDraftAccepted.store(0, std::memory_order_relaxed);
        lookaheadDraft.history.clear();
        lookaheadDraft.transitions.clear();
        totalGeneratedTokens = 0;
        sumDraftMs = 0.0;
        sumVerifyMs = 0.0;
    };

    auto runBridgeTurn = [&](const std::string& userText, bool printDialogue, std::string* failReason) -> bool {
        if (userText.empty()) {
            return false;
        }

        const std::string normalizedUser = normalizeAssistantText(userText);
        bool proactiveRollover = false;
        int32_t cachedBeforeRollover = 0;
        size_t droppedTurns = 0;
        if (conversationInitialized) {
            cachedBeforeRollover = bridge.GetCachedTokenCount();
            if (cachedBeforeRollover >= kProactiveRolloverThreshold) {
                proactiveRollover = true;
                if (history.size() > kRolloverKeepTurns) {
                    droppedTurns = history.size() - kRolloverKeepTurns;
                    history.erase(history.begin(), history.begin() + static_cast<std::ptrdiff_t>(droppedTurns));
                }
                bridge.ClearKVCache();
                if (draftBridgeReady) {
                    draftBridge.ClearKVCache();
                }
                conversationInitialized = false;
                ++proactiveRolloverCount;
                std::printf("[KV] proactive_rollover cached_before=%d dropped_turns=%zu kept_turns=%zu\n",
                            cachedBeforeRollover,
                            droppedTurns,
                            history.size());
            }
        }

        const std::string promptPayload = proactiveRollover
            ? buildFullPrompt(normalizedUser)
            : (conversationInitialized ? buildTurnSuffix(normalizedUser) : buildFirstPrompt(normalizedUser));
        const uint64_t promptHash = fnv1a64(promptPayload);
        if (cli.debugPrompt) {
            constexpr size_t kPreview = 240;
            std::string preview = promptPayload.substr(0, std::min(kPreview, promptPayload.size()));
            if (promptPayload.size() > kPreview) {
                preview += "...";
            }
            printf("[Prompt] bytes=%zu hash=0x%016llx prev_hash=0x%016llx preview=\"%s\"\n",
                   promptPayload.size(),
                   static_cast<unsigned long long>(promptHash),
                   static_cast<unsigned long long>(lastPromptHash),
                   preview.c_str());
        }

        if (printDialogue) {
            printf("User: %s\n", normalizedUser.c_str());
            printf("Assistant: ");
            fflush(stdout);
        }

        auto start = std::chrono::high_resolution_clock::now();
        uint32_t draftBuf[4] = {};
        size_t proposedDraft = 0;
        size_t activeProposed = 0;
        size_t activeAccepted = 0;
        double draftMs = 0.0;
        if (!cli.specActiveDepth1 && cli.specShadowEnabled) {
            const auto draftStart = std::chrono::high_resolution_clock::now();
            proposedDraft = lookaheadDraft.generate(draftBuf, 4);
            const auto draftEnd = std::chrono::high_resolution_clock::now();
            draftMs = std::chrono::duration<double, std::milli>(draftEnd - draftStart).count();
        }
        TokenCallback onToken = [printDialogue](const std::string& token) {
            if (printDialogue) {
                std::printf("%s", token.c_str());
                std::fflush(stdout);
            }
        };

        LlamaNativeBridge::GenerationResult result;
        if (!cli.specActiveDepth1) {
            result = conversationInitialized
                ? bridge.ContinueStream(
                    promptPayload,
                    onToken,
                    cli.maxTokens,
                    cli.temperature,
                    0.95f,
                    40)
                : bridge.GenerateStream(
                    promptPayload,
                    onToken,
                    cli.maxTokens,
                    cli.temperature,
                    0.95f,
                    40);
        } else {
            // Active depth-1 path: decode prompt only, then do guarded one-token speculative commits.
            result = conversationInitialized
                ? bridge.ContinueStream(
                    promptPayload,
                    nullptr,
                    0,
                    cli.temperature,
                    0.95f,
                    40)
                : bridge.GenerateStream(
                    promptPayload,
                    nullptr,
                    0,
                    cli.temperature,
                    0.95f,
                    40);
        }

        bool draftTurnReady = false;
        if (cli.specActiveDepth1 && result.success && draftBridgeReady) {
            LlamaNativeBridge::GenerationResult draftPrefill = conversationInitialized
                ? draftBridge.ContinueStream(
                    promptPayload,
                    nullptr,
                    0,
                    cli.temperature,
                    0.95f,
                    40)
                : draftBridge.GenerateStream(
                    promptPayload,
                    nullptr,
                    0,
                    cli.temperature,
                    0.95f,
                    40);
            if (!draftPrefill.success) {
                std::printf("[Spec] WARNING: draft prefill failed this turn: %s\n", draftPrefill.error.c_str());
            } else {
                draftTurnReady = true;
            }
        }

        bool recoveredByReplay = false;
        if (conversationInitialized && !result.success) {
            fallbackTotal.fetch_add(1, std::memory_order_relaxed);
            const std::string replayPrompt = buildFullPrompt(normalizedUser);
            const uint64_t replayHash = fnv1a64(replayPrompt);
            printf("\n[KV] continuation_failed_once; replaying_full_prompt\n");
            if (cli.debugPrompt) {
                printf("[Prompt] replay bytes=%zu hash=0x%016llx\n",
                       replayPrompt.size(),
                       static_cast<unsigned long long>(replayHash));
            }

            bridge.ClearKVCache();
            if (draftBridgeReady) {
                draftBridge.ClearKVCache();
            }
            conversationInitialized = false;
            result = bridge.GenerateStream(
                replayPrompt,
                cli.specActiveDepth1 ? TokenCallback{} : onToken,
                cli.specActiveDepth1 ? 0 : cli.maxTokens,
                cli.temperature,
                0.95f,
                40);
            if (result.success) {
                recoveredByReplay = true;
                fallbackSuccess.fetch_add(1, std::memory_order_relaxed);
            } else {
                fallbackFailure.fetch_add(1, std::memory_order_relaxed);
            }
        }

        if (cli.specActiveDepth1 && result.success) {
            const auto activeDecodeStart = std::chrono::high_resolution_clock::now();
            result.text.clear();
            result.generated_token_ids.clear();
            result.tokens_generated = 0;
            result.t_first_token_ms = 0.0;
            const int32_t eosToken = bridge.GetModelInfo().eos;
            std::vector<int32_t> oneToken;
            oneToken.reserve(1);

            for (int32_t i = 0; i < cli.maxTokens; ++i) {
                const int32_t topToken = bridge.GetTopToken();
                if (topToken < 0) {
                    result.error = "Active depth1 failed to read top token";
                    result.success = false;
                    break;
                }

                uint32_t oneDraft[1] = {};
                size_t oneProposed = 0;
                if (!specAutoDisabled && cli.specOracleDraft) {
                    oneDraft[0] = static_cast<uint32_t>(topToken);
                    oneProposed = 1;
                } else if (!specAutoDisabled && draftTurnReady) {
                    const int32_t draftTop = draftBridge.GetTopToken();
                    if (draftTop >= 0) {
                        oneDraft[0] = static_cast<uint32_t>(draftTop);
                        oneProposed = 1;
                    }
                } else if (!specAutoDisabled) {
                    const auto stepDraftStart = std::chrono::high_resolution_clock::now();
                    oneProposed = lookaheadDraft.generate(oneDraft, 1);
                    const auto stepDraftEnd = std::chrono::high_resolution_clock::now();
                    draftMs += std::chrono::duration<double, std::milli>(stepDraftEnd - stepDraftStart).count();
                }

                int32_t commitToken = topToken;
                if (oneProposed > 0) {
                    ++activeProposed;
                    speculativeDraftProposed.fetch_add(1, std::memory_order_relaxed);
                    const auto verifyStart = std::chrono::high_resolution_clock::now();
                    const bool accepted = static_cast<int32_t>(oneDraft[0]) == topToken;
                    const auto verifyEnd = std::chrono::high_resolution_clock::now();
                    sumVerifyMs += std::chrono::duration<double, std::milli>(verifyEnd - verifyStart).count();
                    if (accepted) {
                        ++activeAccepted;
                        speculativeDraftAccepted.fetch_add(1, std::memory_order_relaxed);
                        commitToken = static_cast<int32_t>(oneDraft[0]);
                    }
                }

                if (commitToken == eosToken || commitToken == 2) {
                    break;
                }

                oneToken.clear();
                oneToken.push_back(commitToken);
                if (!bridge.DecodeTokenBatch(oneToken, true)) {
                    result.error = bridge.GetLastError();
                    result.success = false;
                    break;
                }

                if (draftTurnReady && !specAutoDisabled) {
                    if (!draftBridge.DecodeTokenBatch(oneToken, true)) {
                        std::printf("[Spec] WARNING: draft decode desync; disabling draft for this turn\n");
                        draftTurnReady = false;
                    }
                }

                std::string piece = bridge.TokenToPiece(commitToken);
                result.text += piece;
                if (!piece.empty() && result.t_first_token_ms <= 0.0) {
                    const auto now = std::chrono::high_resolution_clock::now();
                    result.t_first_token_ms = std::chrono::duration<double, std::milli>(now - start).count();
                }
                if (onToken && !piece.empty()) {
                    onToken(piece);
                }

                result.generated_token_ids.push_back(commitToken);
                ++result.tokens_generated;
            }

            const auto activeDecodeEnd = std::chrono::high_resolution_clock::now();
            result.t_gen_ms = std::chrono::duration<double, std::milli>(activeDecodeEnd - activeDecodeStart).count();
            result.n_past_end = bridge.GetCachedTokenCount();
            if (result.success && result.t_first_token_ms <= 0.0 && result.tokens_generated > 0) {
                result.t_first_token_ms = result.t_prompt_ms;
            }
        }

        if (!result.success) {
            std::printf("\n[Chat] Generation failed: %s\n\n", result.error.c_str());
            if (failReason) {
                *failReason = result.error;
            }
            return false;
        }

        history.push_back(ChatTurn{normalizedUser, normalizeAssistantText(result.text)});
        conversationInitialized = true;

        size_t proposedThisTurn = 0;
        size_t acceptedThisTurn = 0;
        double verifyMs = 0.0;
        if (!cli.specActiveDepth1 && cli.specShadowEnabled && proposedDraft > 0 && !result.generated_token_ids.empty()) {
            const auto verifyStart = std::chrono::high_resolution_clock::now();
            size_t accepted = 0;
            const size_t verifyCount = std::min(proposedDraft, result.generated_token_ids.size());
            for (size_t i = 0; i < verifyCount; ++i) {
                if (draftBuf[i] != static_cast<uint32_t>(result.generated_token_ids[i])) {
                    break;
                }
                ++accepted;
            }
            const auto verifyEnd = std::chrono::high_resolution_clock::now();
            verifyMs = std::chrono::duration<double, std::milli>(verifyEnd - verifyStart).count();
            proposedThisTurn = proposedDraft;
            acceptedThisTurn = accepted;
            speculativeDraftProposed.fetch_add(static_cast<uint64_t>(proposedDraft), std::memory_order_relaxed);
            speculativeDraftAccepted.fetch_add(static_cast<uint64_t>(accepted), std::memory_order_relaxed);
        }
        if (cli.specActiveDepth1) {
            proposedThisTurn = activeProposed;
            acceptedThisTurn = activeAccepted;
        }
        lookaheadDraft.observe(result.generated_token_ids);

        auto end = std::chrono::high_resolution_clock::now();
        double ms = std::chrono::duration<double, std::milli>(end - start).count();
        double tps = (result.t_gen_ms > 0.0) ? (result.tokens_generated * 1000.0 / result.t_gen_ms) : 0.0;
        const int32_t expectedTokensFromPrev = proactiveRollover ? result.n_past_start : std::max(prevNPastEnd, 0);
        ++turnCount;

        if (cli.specActiveDepth1 && !cli.specOracleDraft && !specAutoDisabled) {
            const float effMinAcceptance = (cli.specMinAcceptance >= 0.0f) ? cli.specMinAcceptance : kSpeculativeConfig.min_acceptance;
            const int   effMinProposed   = (cli.specMinProposed > 0)       ? cli.specMinProposed   : static_cast<int>(kSpeculativeConfig.min_proposed);
            const uint64_t draftP = speculativeDraftProposed.load(std::memory_order_relaxed);
            const uint64_t draftA = speculativeDraftAccepted.load(std::memory_order_relaxed);
            if (draftP >= static_cast<uint64_t>(effMinProposed)) {
                const double ratio = static_cast<double>(draftA) / static_cast<double>(draftP);
                if (ratio < static_cast<double>(effMinAcceptance)) {
                    specAutoDisabled = true;
                    specAutoDisabledTurn = turnCount;
                    std::printf("[Spec] auto_disable turn=%zu acceptance=%.4f threshold=%.4f proposed=%llu\n",
                                turnCount,
                                ratio,
                                static_cast<double>(effMinAcceptance),
                                static_cast<unsigned long long>(draftP));
                }
            }
        }

        if (result.cache_hit) {
            ++cacheHitCount;
        }
        if (prevNPastEnd >= 0 && result.n_past_start != prevNPastEnd && !proactiveRollover) {
            ++nPastMismatchCount;
        }
        prevNPastEnd = result.n_past_end;
        lastNPastEnd = result.n_past_end;
        sumTtftMs += result.t_first_token_ms;
        sumPrefillMs += result.t_prompt_ms;
        sumDecodeMs += result.t_gen_ms;
        sumTotalMs += ms;
        sumTps += tps;
        sumDraftMs += draftMs;
        sumVerifyMs += verifyMs;
        totalGeneratedTokens += static_cast<uint64_t>(result.tokens_generated);

        if (printDialogue) {
            printf("\n");
        }
        printf("[KV] hit=%s reused=%d computed=%d\n",
               result.cache_hit ? "yes" : "no",
               result.prompt_tokens_reused,
               result.prompt_tokens_computed);
        if (recoveredByReplay) {
            printf("[KV] recovery=full_replay_once\n");
        }
        if (result.cache_reset_due_to_mismatch) {
            printf("[KV] reset_reason=prefix_mismatch\n");
        } else if (result.cache_reset_due_to_policy) {
            printf("[KV] reset_reason=policy_disabled\n");
        } else {
            printf("[KV] reset_reason=none\n");
        }
        printf("[KV] nPast start=%d end=%d\n", result.n_past_start, result.n_past_end);
         printf("[KV] matched_pre_reset=%d cached_before_reset=%d\n",
             result.prefix_tokens_matched_pre_reset,
             result.cached_tokens_before_reset);
        printf("[KV] matched_tokens=%d expected_tokens=%d\n", result.prompt_tokens_reused, expectedTokensFromPrev);
                if ((cli.specActiveDepth1) || (cli.specShadowEnabled && proposedDraft > 0)) {
            const uint64_t draftP = speculativeDraftProposed.load(std::memory_order_relaxed);
            const uint64_t draftA = speculativeDraftAccepted.load(std::memory_order_relaxed);
            const double ratio = (draftP > 0)
                ? (100.0 * static_cast<double>(draftA) / static_cast<double>(draftP))
                : 0.0;
            printf("[Spec] mode=%s proposed=%zu accepted_prefix=%zu cumulative=%llu ratio=%.1f%%\n",
                                     cli.specActiveDepth1
                                             ? (cli.specOracleDraft ? "active_d1_oracle" : (draftBridgeReady ? "active_d1_dual" : "active_d1"))
                                             : "shadow",
                     proposedThisTurn,
                   acceptedThisTurn,
                   static_cast<unsigned long long>(draftA),
                   ratio);
        }
        printf("[Timing] ttft=%.2f ms prefill=%.2f ms decode=%.2f ms total=%.2f ms\n",
               result.t_first_token_ms,
               result.t_prompt_ms,
               result.t_gen_ms,
               ms);
        printf("[Perf] %.1f tok/s\n\n", tps);
         lastPromptHash = promptHash;
        return true;
    };

    auto emitSmokeSummary = [&](int requestedTurns, int failureTurn, const std::string& failReason) {
        const double turns = static_cast<double>(turnCount > 0 ? turnCount : 1);
        const double hitRate = (turnCount > 0)
            ? (100.0 * static_cast<double>(cacheHitCount) / static_cast<double>(turnCount))
            : 0.0;
        const uint64_t fbTotal = fallbackTotal.load(std::memory_order_relaxed);
        const uint64_t fbSuccess = fallbackSuccess.load(std::memory_order_relaxed);
        const uint64_t fbFailure = fallbackFailure.load(std::memory_order_relaxed);
        const uint64_t draftProposed = speculativeDraftProposed.load(std::memory_order_relaxed);
        const uint64_t draftAccepted = speculativeDraftAccepted.load(std::memory_order_relaxed);
        const double targetDecodeMs = sumDecodeMs;
        const double draftMs = sumDraftMs;
        const double verifyMs = sumVerifyMs;
        const double avgDecodeMsPerToken = (totalGeneratedTokens > 0)
            ? (sumDecodeMs / static_cast<double>(totalGeneratedTokens))
            : 0.0;
        const double savedDecodeMsEst = avgDecodeMsPerToken * static_cast<double>(draftAccepted);
        const double netSpeedupPct = (targetDecodeMs > 0.0)
            ? ((savedDecodeMsEst - (draftMs + verifyMs)) / targetDecodeMs) * 100.0
            : 0.0;
        const double stability = (turnCount > 0)
            ? (1.0 - (static_cast<double>(fbTotal) / static_cast<double>(turnCount)))
            : 1.0;
        const double draftAcceptance = (draftProposed > 0)
            ? (static_cast<double>(draftAccepted) / static_cast<double>(draftProposed))
            : 0.0;
        const char* status = (failureTurn == 0) ? "ok" : "partial";

        printf("[ChatSmoke] summary=\"");
        printf("{");
        printf("\\\"status\\\":\\\"%s\\\",", status);
        printf("\\\"requested_turns\\\":%d,", requestedTurns);
        printf("\\\"turns\\\":%zu,", turnCount);
        printf("\\\"cache_hits\\\":%zu,", cacheHitCount);
        printf("\\\"hit_rate_pct\\\":%.2f,", hitRate);
        printf("\\\"avg_ttft_ms\\\":%.2f,", sumTtftMs / turns);
        printf("\\\"avg_prefill_ms\\\":%.2f,", sumPrefillMs / turns);
        printf("\\\"avg_decode_ms\\\":%.2f,", sumDecodeMs / turns);
        printf("\\\"avg_total_ms\\\":%.2f,", sumTotalMs / turns);
        printf("\\\"avg_tps\\\":%.2f,", sumTps / turns);
        printf("\\\"final_n_past\\\":%d,", lastNPastEnd);
        printf("\\\"n_past_mismatch_count\\\":%zu,", nPastMismatchCount);
        printf("\\\"fallback_total\\\":%llu,", static_cast<unsigned long long>(fbTotal));
        printf("\\\"fallback_success\\\":%llu,", static_cast<unsigned long long>(fbSuccess));
        printf("\\\"fallback_failure\\\":%llu,", static_cast<unsigned long long>(fbFailure));
        printf("\\\"proactive_rollover_count\\\":%zu,", proactiveRolloverCount);
        printf("\\\"spec_auto_disabled\\\":%s,", specAutoDisabled ? "true" : "false");
        printf("\\\"spec_auto_disabled_turn\\\":%zu,", specAutoDisabledTurn);
        printf("\\\"spec_draft_proposed\\\":%llu,", static_cast<unsigned long long>(draftProposed));
        printf("\\\"spec_draft_accepted\\\":%llu,", static_cast<unsigned long long>(draftAccepted));
        printf("\\\"spec_acceptance\\\":%.6f,", draftAcceptance);
        printf("\\\"target_decode_ms\\\":%.3f,", targetDecodeMs);
        printf("\\\"draft_ms\\\":%.3f,", draftMs);
        printf("\\\"verify_ms\\\":%.3f,", verifyMs);
        printf("\\\"tokens_saved\\\":%llu,", static_cast<unsigned long long>(draftAccepted));
        printf("\\\"net_speedup_pct\\\":%.3f,", netSpeedupPct);
        printf("\\\"stability\\\":%.6f,", stability);
        printf("\\\"last_prompt_hash\\\":\\\"0x%016llx\\\",", static_cast<unsigned long long>(lastPromptHash));
        printf("\\\"failure_turn\\\":%d,", failureTurn);
        printf("\\\"error\\\":\\\"%s\\\"", escapeJson(failReason).c_str());
        printf("}");
        printf("\"\n");
    };

    if (cli.chatSmoke) {
        resetStats();
        printf("[ChatSmoke] starting turns=%d max_tokens=%d\n", cli.smokeTurns, cli.maxTokens);
        int failureTurn = 0;
        std::string failReason;
        for (int i = 0; i < cli.smokeTurns; ++i) {
            const std::string prompt = (i == 0)
                ? "Hello there. Reply in one short sentence."
                : "Continue the same thought in one short sentence.";
            if (!runBridgeTurn(prompt, false, &failReason)) {
                failureTurn = i + 1;
                break;
            }
        }
        emitSmokeSummary(cli.smokeTurns, failureTurn, failReason);
        return (failureTurn == 0) ? 0 : 2;
    }

    printf("[Chat] Bridge session started. Type 'exit' to quit, 'reset' to clear history, '/stats' for metrics, '/stats reset' to clear metrics.\n\n");

    char line[1024];
    while (true) {
        printf("User: ");
        fflush(stdout);
        if (!fgets(line, sizeof(line), stdin)) break;
        line[strcspn(line, "\n")] = '\0';

        if (strcmp(line, "exit") == 0) break;
        if (strcmp(line, "reset") == 0 || strcmp(line, "/reset") == 0) {
            history.clear();
            bridge.ClearKVCache();
            if (draftBridgeReady) draftBridge.ClearKVCache();
            conversationInitialized = false;
            printf("[Chat] History cleared.\n\n");
            continue;
        }
        if (strcmp(line, "stats reset") == 0 || strcmp(line, "/stats reset") == 0) {
            resetStats();
            printf("[Stats] Metrics cleared.\n\n");
            continue;
        }
        if (strcmp(line, "stats") == 0 || strcmp(line, "/stats") == 0) {
            if (turnCount == 0) {
                printf("[Stats] No completed turns yet.\n\n");
                continue;
            }
            const double hitRate = (turnCount > 0)
                ? (100.0 * static_cast<double>(cacheHitCount) / static_cast<double>(turnCount))
                : 0.0;
            printf("[Stats] turns=%zu cache_hits=%zu hit_rate=%.1f%%\n", turnCount, cacheHitCount, hitRate);
            printf("[Stats] avg_ttft=%.2f ms avg_prefill=%.2f ms avg_decode=%.2f ms avg_total=%.2f ms\n",
                   sumTtftMs / static_cast<double>(turnCount),
                   sumPrefillMs / static_cast<double>(turnCount),
                   sumDecodeMs / static_cast<double>(turnCount),
                   sumTotalMs / static_cast<double>(turnCount));
            printf("[Stats] avg_tps=%.1f tok/s\n\n", sumTps / static_cast<double>(turnCount));
            continue;
        }
        if (strlen(line) == 0) continue;

        std::string failReason;
        if (!runBridgeTurn(line, true, &failReason)) {
            continue;
        }
    }

    return 0;
}

// ============================================================================
// Interactive REPL
// ============================================================================
static void runInteractive(const InferenceCLI& cli) {
    printf("RawrXD-InferenceEngine Interactive Mode (LlamaNativeBridge)\n");
    printf("Model: %s\n", cli.modelPath.c_str());
    printf("Type 'exit' or 'quit' to stop.\n\n");

    auto& bridge = GetLlamaBridge();
    bridge.SetKVCachePreservation(true);

    if (!bridge.Initialize(nullptr)) {
        printf("[Interactive] ERROR: Bridge init failed: %s\n", bridge.GetLastError());
        return;
    }
    bridge.SetThreads(cli.threads);

    const std::wstring modelPathW = utf8ToWide(cli.modelPath);
    if (modelPathW.empty() || !bridge.LoadModel(modelPathW.c_str(), 0, 2048)) {
        printf("[Interactive] ERROR: Model load failed: %s\n", bridge.GetLastError());
        return;
    }
    printf("[Interactive] Model loaded.\n\n");

    struct ChatTurn { std::string user; std::string assistant; };
    std::vector<ChatTurn> history;
    const std::string systemPrompt = "You are a concise, helpful assistant.";
    bool conversationInitialized = false;

    auto buildFirstPrompt = [&](const std::string& userText) -> std::string {
        std::string p = "<|system|>\n" + systemPrompt + "\n<|user|>\n" + userText + "\n<|assistant|>\n";
        return p;
    };
    auto buildTurnSuffix = [&](const std::string& userText) -> std::string {
        return "<|user|>\n" + userText + "\n<|assistant|>\n";
    };
    auto buildFullPrompt = [&](const std::string& userText) -> std::string {
        std::string p = "<|system|>\n" + systemPrompt + "\n";
        for (const auto& t : history) {
            p += "<|user|>\n" + t.user + "\n<|assistant|>\n" + t.assistant + "\n";
        }
        p += buildTurnSuffix(userText);
        return p;
    };

    char lineBuf[4096];
    while (true) {
        printf(">>> ");
        fflush(stdout);
        if (!fgets(lineBuf, sizeof(lineBuf), stdin)) break;

        size_t len = strlen(lineBuf);
        while (len > 0 && (lineBuf[len-1] == '\n' || lineBuf[len-1] == '\r')) lineBuf[--len] = '\0';
        if (strcmp(lineBuf, "exit") == 0 || strcmp(lineBuf, "quit") == 0) break;
        if (len == 0) continue;

        std::string userText(lineBuf);
        std::string prompt = conversationInitialized ? buildTurnSuffix(userText) : buildFirstPrompt(userText);
        if (conversationInitialized) {
            // Proactive rollover check
            int32_t cached = bridge.GetCachedTokenCount();
            if (cached >= 1920 && history.size() > 24) {
                size_t drop = history.size() - 24;
                history.erase(history.begin(), history.begin() + static_cast<std::ptrdiff_t>(drop));
                bridge.ClearKVCache();
                conversationInitialized = false;
                prompt = buildFullPrompt(userText);
                printf("[KV] proactive_rollover cached=%d dropped=%zu\n", cached, drop);
            }
        }

        printf("Assistant: ");
        fflush(stdout);

        int tokenCount = 0;
        auto onToken = [&](const std::string& token) {
            printf("%s", token.c_str());
            fflush(stdout);
            tokenCount++;
        };

        LlamaNativeBridge::GenerationResult result = conversationInitialized
            ? bridge.ContinueStream(prompt, onToken, cli.maxTokens, cli.temperature, 0.95f, 40)
            : bridge.GenerateStream(prompt, onToken, cli.maxTokens, cli.temperature, 0.95f, 40);

        if (result.success) {
            history.push_back(ChatTurn{userText, result.text});
            conversationInitialized = true;
            printf("\n[%d tokens, %.1f tok/s]\n\n", tokenCount, result.t_gen_ms > 0 ? (tokenCount * 1000.0 / result.t_gen_ms) : 0);
        } else {
            printf("\n[Interactive] ERROR: %s\n\n", result.error.c_str());
        }
    }
}

static void runSingleShot(const InferenceCLI& cli) {
    printf("[Inference] Prompt: %s\n", cli.prompt.c_str());
    printf("[Inference] Generating up to %d tokens...\n", cli.maxTokens);

    auto& bridge = GetLlamaBridge();
    if (!bridge.Initialize(nullptr)) {
        printf("[Inference] ERROR: Bridge init failed: %s\n", bridge.GetLastError());
        return;
    }
    bridge.SetThreads(cli.threads);

    const std::wstring modelPathW = utf8ToWide(cli.modelPath);
    if (modelPathW.empty() || !bridge.LoadModel(modelPathW.c_str(), 0, 2048)) {
        printf("[Inference] ERROR: Model load failed: %s\n", bridge.GetLastError());
        return;
    }

    int tokenCount = 0;
    auto onToken = [&](const std::string& token) {
        printf("%s", token.c_str());
        fflush(stdout);
        tokenCount++;
    };

    LlamaNativeBridge::GenerationResult result = bridge.GenerateStream(
        cli.prompt, onToken, cli.maxTokens, cli.temperature, 0.95f, 40);

    if (result.success) {
        printf("\n[%d tokens generated]\n", tokenCount);
    } else {
        printf("\n[Inference] ERROR: %s\n", result.error.c_str());
    }
}

// ============================================================================
// Sovereign Vulkan Smoke Test — RMSNorm end-to-end pipeline
// ============================================================================
static int runVulkanSmoke() {
    printf("[VulkanSmoke] Sovereign Data Plane RMSNorm smoke test\n");

    rawrxd::VulkanAccelerator& accel = rawrxd::GetVulkanAccelerator();
    if (!accel.Initialize()) {
        printf("[VulkanSmoke] FAIL: VulkanAccelerator::Initialize() returned false\n");
        return 1;
    }
    if (!accel.IsReady()) {
        printf("[VulkanSmoke] FAIL: accelerator not ready after init\n");
        return 1;
    }

    printf("[VulkanSmoke] GPU ready. Loading RMSNorm kernel...\n");

    // Load the SPIR-V kernel (must exist at this path)
    uint32_t kernel_id = accel.LoadKernel("rmsnorm", "kernels/rmsnorm.spv", 3);
    if (kernel_id == 0) {
        // Fallback: try source-relative path when running from build dir
        kernel_id = accel.LoadKernel("rmsnorm", "../src/inference/kernels/rmsnorm.spv", 3);
    }
    if (kernel_id == 0) {
        printf("[VulkanSmoke] FAIL: LoadKernel returned 0 (SPIR-V not found or pipeline creation failed)\n");
        return 1;
    }
    printf("[VulkanSmoke] Kernel loaded id=%u\n", kernel_id);

    // Synthetic test: 1 row, hidden_size = 256, all-ones input, weight=2.0
    constexpr uint32_t hidden_size = 256;
    constexpr uint32_t num_rows    = 1;
    constexpr float    eps         = 1e-6f;

    std::vector<float> host_in(hidden_size, 1.0f);
    std::vector<float> host_w(hidden_size, 2.0f);
    std::vector<float> host_out(hidden_size, 0.0f);

    rawrxd::TensorDesc desc_in{};
    desc_in.name = "rmsnorm_in";
    desc_in.format = rawrxd::TensorFormat::F32;
    desc_in.rows = num_rows;
    desc_in.cols = hidden_size;
    desc_in.host_ptr = host_in.data();
    desc_in.size_bytes = host_in.size() * sizeof(float);

    rawrxd::TensorDesc desc_w{};
    desc_w.name = "rmsnorm_w";
    desc_w.format = rawrxd::TensorFormat::F32;
    desc_w.rows = 1;
    desc_w.cols = hidden_size;
    desc_w.host_ptr = host_w.data();
    desc_w.size_bytes = host_w.size() * sizeof(float);

    rawrxd::TensorDesc desc_out{};
    desc_out.name = "rmsnorm_out";
    desc_out.format = rawrxd::TensorFormat::F32;
    desc_out.rows = num_rows;
    desc_out.cols = hidden_size;
    desc_out.host_ptr = nullptr;  // device-only output
    desc_out.size_bytes = host_out.size() * sizeof(float);

    rawrxd::GpuTensorHandle h_in  = accel.UploadTensor(desc_in, false);
    rawrxd::GpuTensorHandle h_w   = accel.UploadTensor(desc_w, false);
    rawrxd::GpuTensorHandle h_out = accel.UploadTensor(desc_out, false);

    if (!h_in.IsValid() || !h_w.IsValid() || !h_out.IsValid()) {
        printf("[VulkanSmoke] FAIL: tensor upload failed\n");
        return 1;
    }
    printf("[VulkanSmoke] Tensors uploaded. Dispatching RMSNorm...\n");

    rawrxd::RMSNormDesc rms{};
    rms.input      = h_in;
    rms.output     = h_out;
    rms.weight     = h_w;
    rms.hidden_size = hidden_size;
    rms.eps        = eps;
    rms.num_rows   = num_rows;

    if (!accel.DispatchRMSNorm(rms, kernel_id)) {
        printf("[VulkanSmoke] FAIL: DispatchRMSNorm returned false\n");
        return 1;
    }

    // Synchronize and read back
    if (!accel.Wait(10'000'000'000ULL)) {
        printf("[VulkanSmoke] FAIL: Wait timed out\n");
        return 1;
    }

    if (!accel.ReadbackTensor(h_out, host_out.data())) {
        printf("[VulkanSmoke] FAIL: ReadbackTensor returned false\n");
        return 1;
    }

    // Validate: input=all-ones, weight=2.0
    // RMS = sqrt(mean(1^2) + eps) = sqrt(1 + eps) ≈ 1.0
    // output = x / RMS * weight = 1.0 * 2.0 = 2.0
    bool pass = true;
    float max_err = 0.0f;
    for (size_t i = 0; i < host_out.size(); ++i) {
        float expected = 2.0f;
        float err = std::abs(host_out[i] - expected);
        if (err > max_err) max_err = err;
        if (err > 1e-3f) {
            pass = false;
            if (i < 4) {
                printf("[VulkanSmoke] MISMATCH[%zu]: got %.4f expected %.4f\n",
                       i, host_out[i], expected);
            }
        }
    }

    printf("[VulkanSmoke] max_error=%.6f\n", max_err);
    if (pass) {
        printf("[VulkanSmoke] PASS: RMSNorm pipeline verified (output≈2.0 for all-ones*2.0)\n");
    } else {
        printf("[VulkanSmoke] FAIL: output deviation exceeds 1e-3\n");
    }

    accel.Shutdown();
    return pass ? 0 : 1;
}

// ============================================================================
// Main
// ============================================================================
int main(int argc, char* argv[]) {
    InferenceCLI cli = InferenceCLI::parse(argc, argv);

#if defined(RAWRXD_LINK_TELEMETRY_KERNEL_ASM) || defined(RAWR_HAS_MASM)
    UTC_LogEvent("[InferenceEngine] Standalone entry point initialized");
#endif

    if (cli.modelPath.empty() && !cli.benchmark && !cli.vulkanSmoke) {
        printf("RawrXD-InferenceEngine v1.0.0\n");
        printf("Error: --model <path> is required (or use --bench / --vulkan-smoke)\n");
        printf("Run with --help for usage.\n");
        return 1;
    }

    if (cli.verbose) {
        printf("[Config] Model:       %s\n", cli.modelPath.c_str());
        printf("[Config] MaxTokens:   %d\n", cli.maxTokens);
        printf("[Config] Temperature: %.2f\n", cli.temperature);
        printf("[Config] Benchmark:   %s\n", cli.benchmark ? "yes" : "no");
        printf("[Config] Interactive: %s\n", cli.interactive ? "yes" : "no");
    }

    if (cli.benchmark) {
        BenchmarkResult bench = runBenchmark(cli);
        (void)bench;
        return 0;
    }

    if (cli.stream) {
        printf("[Stream] Loading model: %s\n", cli.modelPath.c_str());

        auto& bridge = GetLlamaBridge();
        if (!bridge.Initialize(nullptr)) {
            printf("[Stream] ERROR: Bridge init failed: %s\n", bridge.GetLastError());
            return 1;
        }
        bridge.SetThreads(cli.threads);

        const std::wstring modelPathW = utf8ToWide(cli.modelPath);
        if (modelPathW.empty() || !bridge.LoadModel(modelPathW.c_str(), 0, 2048)) {
            printf("[Stream] ERROR: Model load failed: %s\n", bridge.GetLastError());
            return 1;
        }

        printf("[Stream] Generating (press Ctrl+C to cancel)...\n\n");

        int tokenCount = 0;
        auto onToken = [&](const std::string& token) {
            printf("%s", token.c_str());
            fflush(stdout);
            tokenCount++;
        };

        LlamaNativeBridge::GenerationResult result = bridge.GenerateStream(
            cli.prompt.empty() ? "Hello world" : cli.prompt,
            onToken, cli.maxTokens, cli.temperature, 0.95f, 40);

        if (result.success) {
            printf("\n\n[Stream] %d tokens generated | %.2f tok/s\n",
                tokenCount,
                result.t_gen_ms > 0 ? (tokenCount * 1000.0 / result.t_gen_ms) : 0.0);
        } else {
            printf("\n[Stream] ERROR: %s\n", result.error.c_str());
            return 1;
        }
        return 0;
    }

    if (cli.traceSummary || !cli.traceCsvPath.empty()) {
        return runTitanTrace(cli);
    }

    if (cli.vulkanSmoke) {
        return runVulkanSmoke();
    }

    if (cli.chat) {
        const int bridgeRc = runBridgeChat(cli);
        if (bridgeRc == 0) {
            return 0;
        }

        printf("[Chat] ERROR: Bridge chat unavailable.\n");
        printf("[Chat] Safe-mode blocks session fallback because this lane is currently hitting snmalloc init failure.\n");
        printf("[Chat] Place llama.dll + ggml*.dll beside RawrXD-InferenceEngine.exe or pass a bridge-ready deployment.\n");
        return bridgeRc;
    }

    if (cli.interactive) {
        runInteractive(cli);
        return 0;
    }

    // Single-shot inference
    if (!cli.prompt.empty()) {
        runSingleShot(cli);
        return 0;
    }

#if defined(RAWRXD_LINK_TELEMETRY_KERNEL_ASM) || defined(RAWR_HAS_MASM)
    UTC_LogEvent("[InferenceEngine] Standalone exit");
#endif

    return 0;
}
