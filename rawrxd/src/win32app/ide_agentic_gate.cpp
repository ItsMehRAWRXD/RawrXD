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
#include <algorithm>
#include <atomic>
#include <condition_variable>

namespace RawrXD::IDE {

// ── Interruptible watchdog wrapper ─────────────────────────────────────
template<typename F>
bool runWithWatchdog(RawrXD::Runtime::BP1BraidStreamer& braid, F&& fn,
                     std::chrono::seconds timeout,
                     std::atomic<bool>& outFired) {
    std::mutex mu;
    std::condition_variable cv;
    bool done = false;
    bool fired = false;

    std::thread watchdog([&]() {
        std::unique_lock<std::mutex> lk(mu);
        if (!cv.wait_for(lk, timeout, [&]() { return done; })) {
            fired = true;
            outFired.store(true, std::memory_order_release);
            braid.requestCancel();
        }
    });

    bool result = fn();
    {
        std::lock_guard<std::mutex> lk(mu);
        done = true;
    }
    cv.notify_one();
    watchdog.join();
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

    const std::string fixturePath = "F:\\\\~dev\\\\rawrxd\\\\agent_gate_workspace\\\\nonce.txt";

    r.promptUsed =
        "You are a RawrXD agent with access to one tool: read_file.\n"
        "To call read_file you MUST emit EXACTLY one XML block with no other text:\n"
        "<tool>read_file</tool><args>{\"path\":\"F:\\\\~dev\\\\rawrxd\\\\agent_gate_workspace\\\\nonce.txt\"}</args>\n"
        "\n"
        "Your task: read F:\\\\~dev\\\\rawrxd\\\\agent_gate_workspace\\\\nonce.txt and report the value of RAWRXD_AGENT_NONCE.\n"
        "You MUST use the read_file tool before answering.\n"
        "Emit ONLY the XML tool call. Do not add any other text.\n";

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

    // ── 2. Load real instruction model ──────────────────────────────────
    // Prefer real instruction model; fall back to test model.
    std::string modelPath = "D:\\rawrxd\\gemma3-1b-Q2_K.gguf";
    DWORD attribs = GetFileAttributesA(modelPath.c_str());
    if (attribs == INVALID_FILE_ATTRIBUTES || (attribs & FILE_ATTRIBUTE_DIRECTORY)) {
        modelPath = "F:\\~dev\\rawrxd\\src\\core\\test_tiny_with_vocab.gguf";
    }
    r.modelLoadedOk = engine.loadModel(modelPath);
    if (!r.modelLoadedOk) {
        r.failStage = "MODEL_LOAD";
        r.diagnostics = "Deep2Engine::loadModel failed for model: " + modelPath;
        return r;
    }

    // ── 3. Bind Tool Authority ──────────────────────────────────────────
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

    // ── 5. Phase 1: generate tool request ───────────────────────────────
    RawrXD::Inference::StreamingInferenceOptions opts;
    opts.maxTokens      = 64;
    opts.temperature    = 0.0f;
    opts.topP           = 1.0f;

    r.channelOpened     = true;
    r.generationStarted = true;

    std::atomic<bool> wd1Fired{false};
    bool session1Ok = runWithWatchdog(
        braid,
        [&]() { return braid.runSession(r.promptUsed, opts); },
        std::chrono::seconds(180),
        wd1Fired);

    if (!session1Ok) {
        r.failStage = wd1Fired.load(std::memory_order_acquire) ? "WATCHDOG_TIMEOUT_PHASE1" : "SESSION_PHASE1";
        r.diagnostics = wd1Fired.load(std::memory_order_acquire)
                            ? "Phase 1 exceeded 180s watchdog limit."
                            : "BP1BraidStreamer::runSession(phase1) returned false.";
        return r;
    }

    // Gather telemetry from phase 1 (from bridge/runtime counters)
    auto infCounters1 = sEngine.counters();
    auto brCounters1  = bridge.counters();

    r.streamedTokenCount = infCounters1.realTokenCount;
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
    std::string phase2Prompt =
        "You previously called read_file and the tool returned:\n" +
        r.toolResultReturnedByBridge + "\n"
        "\n"
        "Based on this result, what is the value of RAWRXD_AGENT_NONCE? "
        "Answer with ONLY the value, no extra text.\n";

    sEngine.resetCounters();
    bridge.resetCounters();
    bridge.clearAccumulatedText();

    RawrXD::Inference::StreamingInferenceOptions opts2;
    opts2.maxTokens   = 32;
    opts2.temperature = 0.0f;
    opts2.topP        = 1.0f;

    r.continuationStarted = true;

    std::atomic<bool> wd2Fired{false};
    bool session2Ok = runWithWatchdog(
        braid,
        [&]() { return braid.runSession(phase2Prompt, opts2); },
        std::chrono::seconds(180),
        wd2Fired);

    if (!session2Ok) {
        r.failStage = wd2Fired.load(std::memory_order_acquire) ? "WATCHDOG_TIMEOUT_PHASE2" : "SESSION_PHASE2";
        r.diagnostics = wd2Fired.load(std::memory_order_acquire)
                            ? "Phase 2 exceeded 180s watchdog limit."
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
    r.diagnostics = "Full tool loop: model emitted tool request, Tool Authority invoked read_file, "
                  "result reinjected, continuation produced nonce match.";
    return r;
}

} // namespace RawrXD::IDE
