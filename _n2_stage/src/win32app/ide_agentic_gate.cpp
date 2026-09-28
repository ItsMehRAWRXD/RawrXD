#include "ide_agentic_gate.hpp"
#include "BP1BraidStreamer.h"
#include "streaming_inference_engine.h"
#include "agentic_model_streamer_bridge.h"
#include "streaming_command_handler.h"
#include "StreamingResultChannel.h"
#include "deep2/Deep2Engine.h"
#include "deep2/AgentToolRegistry.hpp"
#include "deep2/AgentToolAuthority.hpp"

#include <windows.h>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <fstream>
#include <sstream>
#include <cstdio>
#include <cstdarg>
#include <algorithm>
#include <atomic>
#include <condition_variable>

namespace RawrXD::IDE {

// ── Headless trace file logger (GUI apps have no stderr) ──────────────
static void gateTraceLog(const char* fmt, ...)
{
    static FILE* fp = nullptr;
    if (!fp) {
        fp = std::fopen("headless_gate_log.txt", "a");
        if (fp) std::setvbuf(fp, nullptr, _IONBF, 0);
    }
    if (fp) {
        std::va_list args;
        va_start(args, fmt);
        std::vfprintf(fp, fmt, args);
        va_end(args);
    }
}

// ── Interruptible watchdog wrapper ─────────────────────────────────────
template<typename F>
bool runWithWatchdog(RawrXD::Runtime::BP1BraidStreamer& braid, F&& fn,
                     std::chrono::seconds timeout,
                     std::atomic<bool>& outFired) {
    std::mutex mu;
    std::condition_variable cv;
    bool done = false;
    bool fired = false;
    bool result = false;
    std::exception_ptr ex;

    std::thread watchdog([&]() {
        try {
            std::unique_lock<std::mutex> lk(mu);
            if (!cv.wait_for(lk, timeout, [&]() { return done; })) {
                fired = true;
                outFired.store(true, std::memory_order_release);
                braid.requestCancel();
            }
        } catch (...) {
            // Watchdog exceptions silently ignored — main work owns failure
        }
    });

    try {
        result = fn();
    } catch (...) {
        ex = std::current_exception();
    }

    {
        std::lock_guard<std::mutex> lk(mu);
        done = true;
    }
    cv.notify_one();
    if (watchdog.joinable())
        watchdog.join();

    if (ex)
        std::rethrow_exception(ex);
    return result;
}

// ── Simple JSON path extractor (minimal, no deps) ──────────────────────
static std::string extractPathFromJson(const std::string& json) {
    size_t pathKey = json.find("\"path\"");
    if (pathKey == std::string::npos) return "";
    size_t colon = json.find(":", pathKey + 6);
    if (colon == std::string::npos) return "";
    size_t firstQuote = json.find("\"", colon + 1);
    if (firstQuote == std::string::npos) return "";
    size_t secondQuote = json.find("\"", firstQuote + 1);
    if (secondQuote == std::string::npos) return "";
    return json.substr(firstQuote + 1, secondQuote - firstQuote - 1);
}

// ── Chat-template helpers for Llama 3.2 Instruct ──────────────────────
static std::string applyLlamaChatTemplate(const std::string& system,
                                            const std::string& user) {
    // Llama 3.x chat template
    // <|begin_of_text|><|start_header_id|>system<|end_header_id|>
    // ... system ...<|eot_id|><|start_header_id|>user<|end_header_id|>
    // ... user ...<|eot_id|><|start_header_id|>assistant<|end_header_id|>
    return "<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n" +
           system +
           "<|eot_id|><|start_header_id|>user<|end_header_id|>\n" +
           user +
           "<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n";
}

static std::string applyLlamaContinuationPrompt(const std::string& system,
                                                   const std::string& user) {
    return "<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n" +
           system +
           "<|eot_id|><|start_header_id|>user<|end_header_id|>\n" +
           user +
           "<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n";
}

// ── Simple test tool: read_file ──────────────────────────────────────────
static RawrXD::Agentic::ToolResult toolReadFile(const RawrXD::Agentic::ToolRequest& req,
                                                   RawrXD::Agentic::ToolContext& ctx)
{
    (void)ctx;
    RawrXD::Agentic::ToolResult res;
    std::string path;
    if (!req.args.empty()) path = req.args[0];
    else if (!req.stdin_text.empty()) path = extractPathFromJson(req.stdin_text);
    if (path.empty()) path = req.tool_id;
    if (path == "read_file") {
        res.exit_code = 1;
        res.stderr_text = "read_file: missing path argument";
        return res;
    }

    std::ifstream f(path, std::ios::binary);
    if (!f) {
        res.exit_code = 1;
        res.stderr_text = "cannot open file: " + path;
        return res;
    }
    std::ostringstream oss;
    oss << f.rdbuf();
    res.stdout_text = oss.str();
    return res;
}

AgenticGateResult runAgenticGate()
{
    AgenticGateResult r;
    r.failStage = "UNKNOWN";
    gateTraceLog("AGENT_GATE_ENTER\n");

    try {
        const std::string fixturePath = "F:\\\\~dev\\\\rawrxd\\\\agent_gate_workspace\\\\nonce.txt";

        // ── 1. Initialize Deep2Engine ─────────────────────────────────────
        Deep2::EngineConfig cfg{};
        cfg.maxSeqLen       = 8192;
        cfg.hiddenDim       = 0;
        cfg.numHeads        = 0;
        cfg.numLayers       = 0;
        cfg.vocabSize       = 0;
        cfg.intermediateDim = 0;

        Deep2::Deep2Engine engine;
        r.engineInitOk = engine.initialize(cfg);
        if (!r.engineInitOk) {
            r.failStage = "ENGINE_INIT";
            r.diagnostics = "Deep2Engine::initialize failed.";
            return r;
        }

        // ── 2. Backend selection (CPU-only for gate to avoid GPU TDR) ────
        engine.enableVulkan(false);
        engine.setVulkanStrictNoCpuFallback(false);
        r.diagnostics += "[BACKEND=CPU] ";

        // ── 3. Model path (strict: no fixture fallback) ─────────────────────
        std::string modelPath = "D:\\rawrxd\\gemma3-1b-Q2_K.gguf";
        const char* envModel = std::getenv("RAWRXD_AGENT_MODEL");
        if (envModel && envModel[0]) {
            modelPath = envModel;
        }
        DWORD attribs = GetFileAttributesA(modelPath.c_str());
        if (attribs == INVALID_FILE_ATTRIBUTES || (attribs & FILE_ATTRIBUTE_DIRECTORY)) {
            r.failStage = "MODEL_NOT_FOUND";
            r.diagnostics = "Model file not found: " + modelPath;
            return r;
        }
        r.modelLoadedOk = engine.loadModel(modelPath);
        if (!r.modelLoadedOk) {
            r.failStage = "MODEL_LOAD";
            r.diagnostics = "Deep2Engine::loadModel failed for model: " + modelPath;
            return r;
        }

        bool isLlamaInstruct = (modelPath.find("llama3.2") != std::string::npos ||
                                modelPath.find("Llama-3.2") != std::string::npos ||
                                modelPath.find("Llama3.2") != std::string::npos);

        // Re-enable verified speculative decoding (window=4)
        engine.enableVerifiedSpeculation(true, 4);

        // ── 4. Bind Tool Authority ──────────────────────────────────────────
        RawrXD::Agentic::AgentToolRegistry registry;
        RawrXD::Agentic::BindAgentToolAuthority(registry);

        RawrXD::Agentic::ToolDescriptor desc;
        desc.id          = "read_file";
        desc.aliases     = {"cat", "open"};
        desc.description = "Read the contents of a file";
        registry.registerTool(desc, toolReadFile);

        // ── 4. Wire streaming pipeline ──────────────────────────────────────
        RawrXD::Inference::StreamingInferenceEngine sEngine;
        sEngine.setEngine(&engine);

        RawrXD::Agentic::AgenticModelStreamerBridge bridge;
        bridge.setToolRegistry(&registry);
        bridge.clearAccumulatedText();

        RawrXD::Agentic::StreamingCommandHandler handler;
        handler.setToolRegistry(&registry);

        RawrXD::Runtime::BP1BraidStreamer braid;
        braid.setInferenceEngine(&sEngine);
        braid.setBridge(&bridge);
        braid.setCommandHandler(&handler);

        r.streamerBuilt = true;

        // ── Build Phase 1 prompt (compact to avoid TDR) ──────────────────
        std::string phase1System =
            "You are a tool agent. Available tool: read_file.\n"
            "To call: <tool>read_file</tool><args>{\"path\":\"P\"}</args>\n";
        std::string phase1User =
            "Read F:\\\\~dev\\\\rawrxd\\\\agent_gate_workspace\\\\nonce.txt. Emit only the tool call.\n";

        if (isLlamaInstruct) {
            r.promptUsed = applyLlamaChatTemplate(phase1System, phase1User);
        } else {
            r.promptUsed = phase1System + "\n" + phase1User;
        }

        // ── 5. Phase 1: generate tool request ───────────────────────────────
        RawrXD::Inference::StreamingInferenceOptions opts;
        opts.maxTokens      = 64;
        opts.temperature    = 0.0f;
        opts.topP           = 1.0f;

        r.channelOpened     = true;
        r.generationStarted = true;

        gateTraceLog("AGENT_GENERATE_BEGIN phase=1\n");
        std::atomic<bool> wd1Fired{false};
        bool session1Ok = runWithWatchdog(
            braid,
            [&]() { return braid.runSession(r.promptUsed, opts); },
            std::chrono::seconds(600),
            wd1Fired);
        gateTraceLog("AGENT_GENERATE_RETURN phase=1 ok=%d\n", (int)session1Ok);

        if (!session1Ok) {
            r.failStage = wd1Fired.load(std::memory_order_acquire) ? "WATCHDOG_TIMEOUT_PHASE1" : "SESSION_PHASE1";
            r.diagnostics = wd1Fired.load(std::memory_order_acquire)
                                ? "Phase 1 exceeded 600s watchdog limit."
                                : "BP1BraidStreamer::runSession(phase1) returned false.";
            return r;
        }

        // Gather telemetry from phase 1
        auto infCounters1 = sEngine.counters();
        auto brCounters1  = bridge.counters();

        r.streamedTokenCount = infCounters1.realTokenCount;
        r.tokenCount         = static_cast<int>(infCounters1.realTokenCount);
        r.tokensReceived     = (infCounters1.realTokenCount > 0);
        r.modelStreamStarted = r.tokensReceived;
        r.streamedText       = bridge.accumulatedText();
        if (!r.streamedText.empty()) {
            r.firstTokenText = r.streamedText.substr(0, std::min<size_t>(64, r.streamedText.size()));
        }

        r.toolRequestSeen    = (brCounters1.toolRequestsSeen > 0);
        r.toolRequestParsed  = (brCounters1.toolRequestsParsed > 0);
        r.toolAuthorityInvoked = (brCounters1.authorityCalls > 0);
        r.toolExecuted       = (brCounters1.toolExecutions > 0);
        r.toolResultReturned = (brCounters1.toolResultsProduced > 0);
        r.rawToolRequest     = bridge.lastToolRequestRaw();
        r.toolName           = bridge.lastToolName();
        r.toolResultReturnedByBridge = bridge.lastToolResultText();

        if (!r.toolRequestSeen) {
            r.failStage = "NO_TOOL_REQUEST";
            r.diagnostics =
                "Phase 1 streamed " + std::to_string(r.streamedTokenCount) +
                " tokens, but no recognizable tool request was emitted.\n"
                "Accumulated text:\n" + r.streamedText;
            return r;
        }
        if (!r.toolResultReturnedByBridge.empty()) {
            r.toolResultInjected = true;
        } else {
            r.toolResultInjected = false;
            r.failStage = "TOOL_RESULT_EMPTY";
            r.diagnostics = "Tool Authority did not produce any result text.";
            return r;
        }

        // ── 6. Phase 2: continuation with tool result ───────────────────────
        std::string phase2System =
            "You are a RawrXD agent. A tool was called and returned a result.\n"
            "Answer based ONLY on the tool result. Emit ONLY the requested value with no extra text.\n";
        std::string phase2User =
            "You previously called read_file and the tool returned:\n" +
            r.toolResultReturnedByBridge + "\n"
            "\n"
            "Based on this result, what is the value of RAWRXD_AGENT_NONCE? "
            "Answer with ONLY the value, no extra text.\n";

        std::string phase2Prompt;
        if (isLlamaInstruct) {
            phase2Prompt = applyLlamaChatTemplate(phase2System, phase2User);
        } else {
            phase2Prompt = phase2System + "\n" + phase2User;
        }

        sEngine.resetCounters();
        bridge.resetCounters();
        bridge.clearAccumulatedText();

        RawrXD::Inference::StreamingInferenceOptions opts2;
        opts2.maxTokens   = 32;
        opts2.temperature = 0.0f;
        opts2.topP        = 1.0f;

        r.continuationStarted = true;

        gateTraceLog("AGENT_GENERATE_BEGIN phase=2\n");
        std::atomic<bool> wd2Fired{false};
        bool session2Ok = runWithWatchdog(
            braid,
            [&]() { return braid.runSession(phase2Prompt, opts2); },
            std::chrono::seconds(300),
            wd2Fired);
        gateTraceLog("AGENT_GENERATE_RETURN phase=2 ok=%d\n", (int)session2Ok);

        if (!session2Ok) {
            r.failStage = wd2Fired.load(std::memory_order_acquire) ? "WATCHDOG_TIMEOUT_PHASE2" : "SESSION_PHASE2";
            r.diagnostics = wd2Fired.load(std::memory_order_acquire)
                                ? "Phase 2 exceeded 300s watchdog limit."
                                : "BP1BraidStreamer::runSession(phase2) returned false.";
            return r;
        }

        auto infCounters2 = sEngine.counters();
        r.postToolTokenCount = infCounters2.realTokenCount;

        std::string phase2Text = bridge.accumulatedText();

        bool nonceFound = (phase2Text.find("7E91B462") != std::string::npos);
        r.nonceMatched = nonceFound;

        if (!r.nonceMatched) {
            r.failStage = "NONCE_MISMATCH";
            r.diagnostics =
                "Phase 2 generated " + std::to_string(r.postToolTokenCount) +
                " tokens, but nonce '7E91B462' was not found.\n"
                "Phase 2 output:\n" + phase2Text;
            return r;
        }

        // All checkpoints passed
        r.failStage.clear();
        r.diagnostics = "Full tool loop: model emitted tool request, Tool Authority invoked read_file, "
                      "result reinjected, continuation produced nonce match.";
    } catch (const std::exception& e) {
        r.failStage = r.failStage.empty() ? "EXCEPTION" : r.failStage;
        r.diagnostics = std::string("Exception caught: ") + e.what();
    } catch (...) {
        r.failStage = r.failStage.empty() ? "UNKNOWN_EXCEPTION" : r.failStage;
        r.diagnostics = "Unknown exception caught in runAgenticGate.";
    }

    gateTraceLog("AGENT_GATE_RETURN stage=%s ok=%d\n", r.failStage.empty() ? "OK" : r.failStage.c_str(), (int)(r.failStage.empty()));
    return r;
}

} // namespace RawrXD::IDE
