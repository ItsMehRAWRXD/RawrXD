#pragma once
// ============================================================================
// HeadlessIDE — GUI-free surface for the RawrXD Win32IDE engine
// Phase 19C: Headless Surface Extraction
//
// This class exposes the full engine capabilities of Win32IDE without any
// HWND, window, or GDI dependency. It starts the LocalServer, initializes
// all backend subsystems (inference, LLM router, failure detection, agent
// history, ASM semantic, LSP, hybrid bridge, multi-response, execution
// governor, safety contract, replay journal, confidence gate, swarm,
// native debugger, hotpatch), and runs an event loop that services:
//
//   1. HTTP API on port 11435 (60+ endpoints — identical to Win32IDE)
//   2. Console REPL (optional stdin command processing)
//   3. stdin → prompt → stdout streaming inference
//
// Lifecycle:
//   HeadlessIDE ide;
//   if (!ide.initialize(argc, argv)) return 1;
//   return ide.run();   // blocks until shutdown signal
//
// NO exceptions. Returns PatchResult-style structured results.
// NO Qt. NO HWND. NO GDI. NO message loop.
// ============================================================================

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#ifdef ERROR
#undef ERROR
#endif

#include <string>
#include <vector>
#include <array>
#include <memory>
#include <map>
#include <unordered_map>
#include <thread>
#include <mutex>
#include <atomic>
#include <functional>
#include <condition_variable>
#include <climits>
#include <deque>

#include "IOutputSink.h"
#include "Win32IDE_AgenticBridge.h"
#include "Win32IDE_Autonomy.h"
#include "multi_response_engine.h"
#include "../agentic_engine.h"
#include "../gguf_loader.h"
#include "../streaming_gguf_loader.h"
#include "../model_source_resolver.h"
#include "../modules/engine_manager.h"
#include "../modules/codex_ultimate.h"
#include "../modules/ExtensionLoader.hpp"
#include <nlohmann/json.hpp>

// Forward declarations
class MultiResponseEngine;
class AgentHistoryRecorder;
class AgenticEngine;
struct AgentHistoryDeleter {
    void operator()(AgentHistoryRecorder* ptr) const;
};
struct AgentHistoryDeleter;

// ============================================================================
// Headless initialization result
// ============================================================================
struct HeadlessResult {
    bool success;
    const char* detail;
    int errorCode;

    static HeadlessResult ok(const char* msg = "OK") {
        return { true, msg, 0 };
    }
    static HeadlessResult error(const char* msg, int code = -1) {
        return { false, msg, code };
    }
};

// ============================================================================
// Headless run mode (how the main loop behaves)
// ============================================================================
enum class HeadlessRunMode {
    Server,      // Start HTTP server, block until SIGINT/SIGTERM (default)
    REPL,        // Interactive console REPL with command processing
    SingleShot,  // Process one prompt from --prompt arg, print result, exit
    Batch        // Read prompts from --input file, write results to --output
};

enum class HeadlessIngressMode {
    Local,
    Hosted
};

// ============================================================================
// Headless configuration (parsed from argc/argv)
// ============================================================================
struct HeadlessConfig {
    HeadlessRunMode mode           = HeadlessRunMode::Server;
    HeadlessIngressMode ingressMode = HeadlessIngressMode::Local;
    int             port           = 11435;
    std::string     bindAddress    = "127.0.0.1";
    std::string     modelPath;            // --model <path>
    std::string     prompt;               // --prompt <text> (SingleShot mode)
    std::string     inputFile;            // --input <file>  (Batch mode)
    std::string     outputFile;           // --output <file> (Batch mode)
    std::string     settingsFile;         // --settings <file>
    std::string     backend;              // --backend local|ollama|openai|claude|gemini
    bool            verbose        = false;
    bool            quiet          = false;
    bool            jsonOutput     = false;  // --json: emit structured JSON
    bool            enableRepl     = false;  // --repl: interactive mode
    bool            enableServer   = true;   // --no-server: disable HTTP
    int             maxTokens      = 2048;
    float           temperature    = 0.7f;
    std::string     ollamaHost     = "127.0.0.1";
    int             ollamaPort = 0;
    std::string     workingDir;             // --dir <path>
    std::string     apiKey;                 // RAWRXD_HOSTED_API_KEY
    std::string     apiScopes;              // comma-separated capability scopes
    std::string     allowedOrigins;         // exact comma-separated origins
    std::string     githubWebhookSecret;    // RAWRXD_GITHUB_WEBHOOK_SECRET
    std::string     auditFile;               // bounded JSONL audit sink
    bool            allowCloudEgress = false; // explicit RAWRXD_CLOUD_EGRESS consent
    uint64_t        cloudBudgetNanodollars = 0;
    uint64_t        cloudInputNanodollarsPerToken = 0;
    uint64_t        cloudOutputNanodollarsPerToken = 0;
    uint32_t        cloudMaxInputBytes = 4096;
    uint32_t        cloudMaxOutputTokens = 1024;
    std::string     cloudBudgetFile;
    bool            listModelsOnly = false; // --list: list Ollama models and exit
};

// ============================================================================
// Conversation session (Fix #14)
// ============================================================================
struct ConversationSession {
    std::string id;
    std::vector<std::pair<std::string, std::string>> messages; // role, content
    std::chrono::steady_clock::time_point lastActivity;
    size_t messageCount = 0;
};

struct HostedHttpRequest {
    std::string method;
    std::string path;
    std::string headers;
    std::string body;
    std::string peer;
    std::string origin;
};

struct HostedHttpResponse {
    int status = 200;
    std::string contentType = "application/json; charset=utf-8";
    std::string body;
    bool alreadySent = false;
};

class ConversationManager {
public:
    std::string createSession();
    void addMessage(const std::string& sessionId, const std::string& role, const std::string& content);
    std::vector<std::pair<std::string, std::string>> getMessages(const std::string& sessionId);
    void pruneInactive(double maxAgeSeconds);
private:
    std::mutex mutex_;
    std::unordered_map<std::string, ConversationSession> sessions_;
    std::atomic<uint64_t> nextId_{1};
};

// ============================================================================
// HeadlessIDE — the headless surface class
// ============================================================================
class HeadlessIDE {
public:
    HeadlessIDE();
    ~HeadlessIDE();

    // ---- Lifecycle ----
    HeadlessResult initialize(int argc, char* argv[]);
    HeadlessResult initialize(const HeadlessConfig& config);
    int run();                        // Main blocking event loop
    void requestShutdown() noexcept;  // Signal the run loop to exit

    // ---- Configuration ----
    const HeadlessConfig& getConfig() const { return m_config; }
    bool isRunning() const { return m_running.load(); }

    // ---- Output sink ----
    IOutputSink* getOutputSink() const { return m_outputSink.get(); }
    void setOutputSink(std::unique_ptr<IOutputSink> sink);

    // ---- Engine access (same API surface as Win32IDE) ----
    void setEngineManager(EngineManager* mgr) { m_engineManager = mgr; }
    void setCodexUltimate(CodexUltimate* codex) { m_codexUltimate = codex; }

    // ---- Model operations ----
    bool loadModel(const std::string& filepath);
    bool unloadModel();
    bool isModelLoaded() const;
    std::string getLoadedModelName() const;
    std::string getModelInfo() const;

    // ---- Inference ----
    std::string runInference(const std::string& prompt);
    std::string runInference(const std::string& prompt, int maxTokens, float temperature);
    void runInferenceStreaming(const std::string& prompt,
                               std::function<void(const char*, size_t)> tokenCallback);

    // ---- Backend switcher (Phase 8B) ----
    enum class AIBackendType {
        LocalGGUF  = 0,
        Ollama     = 1,
        OpenAI     = 2,
        Claude     = 3,
        Gemini     = 4,
        Count      = 5
    };
    bool setActiveBackend(AIBackendType type);
    AIBackendType getActiveBackendType() const;
    std::string getBackendStatusString() const;
    bool probeBackendHealth(AIBackendType type);
    std::string routeInferenceRequest(const std::string& prompt);

    // ---- LLM Router (Phase 8C) ----
    std::string routeWithIntelligence(const std::string& prompt);
    std::string getRouterStatusString() const;
    std::string getCostLatencyHeatmapString() const;

    // ---- Failure Detection (Phase 4B/6) ----
    std::string executeWithFailureDetection(const std::string& prompt);
    std::string getFailureDetectorStats() const;
    std::string getFailureIntelligenceStatsString() const;

    // ---- Agent History (Phase 6B) ----
    std::string getAgentHistoryStats() const;
    void recordSimpleEvent(const std::string& description);

    // ---- ASM Semantic (Phase 9A) ----
    void parseAsmFile(const std::string& filePath);
    void parseAsmDirectory(const std::string& dirPath, bool recursive = true);
    std::string getAsmSymbolTableString() const;
    std::string getAsmSemanticStatsString() const;

    // ---- LSP Client (Phase 9A) ----
    std::string getLSPStatusString() const;

    // ---- Hybrid Bridge (Phase 9B) ----
    std::string getHybridBridgeStatusString() const;

    // ---- Multi-Response (Phase 9C) ----
    // Generates multiple responses from different backends/temperatures

    // ---- Execution Governor (Phase 10A) ----
    std::string getGovernorStatus() const;
    std::string getGovernorStatusJson() const;

    // ---- Safety Contract (Phase 10B) ----
    std::string getSafetyStatus() const;

    // ---- Replay Journal (Phase 10C) ----
    std::string getReplayStatus() const;

    // ---- Confidence Gate (Phase 10D) ----
    std::string getConfidenceStatus() const;

    // ---- Swarm (Phase 11) ----
    std::string getSwarmStatus() const;

    // ---- Native Debugger (Phase 12) ----
    std::string getNativeDebugStatus() const;

    // ---- Hotpatch (Phase 14.2) ----
    std::string getHotpatchStatus() const;
    std::string getHotpatchStatusJson() const;

    // ---- Settings ----
    void loadSettings(const std::string& path = "");
    void saveSettings(const std::string& path = "");
    std::string getSettingsFilePath() const;

    // ---- Local HTTP Server ----
    void startServer();
    void stopServer();
    bool isServerRunning() const;
    std::string getServerStatus() const;

    // ---- Feature Manifest ----
    std::string getFeatureManifestMarkdown() const;
    std::string getFeatureManifestJSON() const;
    std::string getQuantumStatusJson() const;

    // ---- Phase 35: RawrXD-Native API helpers ----
    std::string getModelsJson() const;
    std::string getModelsOllamaJson() const;
    std::string getEngineCapabilitiesJson() const;

    // ---- Cloud backend helpers (Fix #15) ----
    std::string performCloudInference(const std::string& endpoint, const std::string& apiKey,
                                      const std::string& prompt, const std::string& model);

    // ---- Diagnostics ----
    std::string getFullStatusDump() const;
    std::string getVersionString() const;
    uint64_t getUptimeMs() const;

    // ---- Instructions Context (Phase 34 — persistent across session) ----
    std::string getInstructionsContent() const;
    bool isInstructionsLoaded() const { return m_instructionsInitialized; }

private:
    // ---- Argument parsing ----
    HeadlessResult parseArgs(int argc, char* argv[]);

    // ---- Initialization phases ----
    HeadlessResult initWinsock();
    HeadlessResult initEngines();
    HeadlessResult initBackendManager();
    HeadlessResult initLLMRouter();
    HeadlessResult initFailureDetection();
    HeadlessResult initAgentHistory();
    HeadlessResult initAsmSemantic();
    HeadlessResult initLSPClient();
    HeadlessResult initHybridBridge();
    HeadlessResult initMultiResponse();
    HeadlessResult initPhase10();
    HeadlessResult initPhase11();
    HeadlessResult initPhase12();
    HeadlessResult initHotpatch();
    HeadlessResult initInstructions();
    HeadlessResult initAgentic();

    // ---- Run modes ----
    int runServerMode();
    int runReplMode();
    int runSingleShotMode();
    int runBatchMode();

    // ---- REPL helpers ----
    void processReplCommand(const std::string& input);
    void printReplHelp();
    void printReplPrompt();

    // ---- Tool execution (parity with Win32 Agent > Run Tool; used by /api/tool and /run-tool) ----
    bool executeToolRepl(const std::string& toolName, const std::string& argsJson, std::string& outResult);

    // ---- HTTP server (consolidated hosted/local contract) ----
    void serverLoop();
    void handleClient(SOCKET clientFd);
    bool readHttpRequest(SOCKET clientFd, HostedHttpRequest& request, int& failureStatus);
    bool authorizeHttpRequest(const HostedHttpRequest& request, HostedHttpResponse& response);
    void routeHttpRequest(SOCKET clientFd, const HostedHttpRequest& request,
                          HostedHttpResponse& response);
    void routeGenerationRequest(SOCKET clientFd, const HostedHttpRequest& request,
                                HostedHttpResponse& response);
    void streamGenerationResponse(SOCKET clientFd, const HostedHttpRequest& request,
                                  const std::string& prompt, const char* protocol,
                                  HostedHttpResponse& response);
    void routeHexMagRequest(const HostedHttpRequest& request,
                            HostedHttpResponse& response);
    void routeNativeRequest(const HostedHttpRequest& request, HostedHttpResponse& response);
    bool routeStatusRequest(const HostedHttpRequest& request, HostedHttpResponse& response);
    void routeGitHubWebhook(const HostedHttpRequest& request, HostedHttpResponse& response);
    void sendHttpResponse(SOCKET clientFd, const HostedHttpRequest& request,
                          const HostedHttpResponse& response);

    // ---- Thread-safe output sink wrapper (Fix #14) ----
    void safeAppendOutput(const char* msg, OutputSeverity severity);
    void safeOnAgentStarted(const char* agent, const char* prompt);
    void safeOnAgentCompleted(const char* agent, const char* result, int durationMs);
    void safeOnAgentFailed(const char* agent, const char* reason);
    void safeOnStreamStart(const char* stream);
    void safeOnStreamEnd(const char* stream, bool ok);
    void safeOnStreamingToken(const char* token, size_t len, StreamTokenOrigin origin);
    void safeOnStatusUpdate(const char* subsystem, const char* status);

    // ---- Shutdown ----
    void shutdownAll();

    // ---- State ----
    HeadlessConfig                    m_config;
    std::unique_ptr<IOutputSink>      m_outputSink;
    std::atomic<bool>                 m_running{false};
    std::atomic<bool>                 m_shutdownRequested{false};

    // Engine pointers (not owned — same pattern as Win32IDE)
    EngineManager*                    m_engineManager   = nullptr;
    CodexUltimate*                    m_codexUltimate   = nullptr;

    // Subsystem initialized flags
    bool m_winsockInitialized         = false;
    bool m_backendManagerInitialized  = false;
    bool m_routerInitialized          = false;
    bool m_failureDetectorInitialized = false;
    bool m_agentHistoryInitialized    = false;
    bool m_asmSemanticInitialized     = false;
    bool m_lspInitialized             = false;
    bool m_hybridBridgeInitialized    = false;
    bool m_multiResponseInitialized   = false;
    bool m_phase10Initialized         = false;
    bool m_phase11Initialized         = false;
    bool m_phase12Initialized         = false;
    bool m_hotpatchInitialized        = false;
    bool m_instructionsInitialized  = false;

    // HTTP server state
    std::atomic<bool>                 m_serverRunning{false};
    std::thread                       m_serverThread;
    SOCKET                            m_serverSocket = INVALID_SOCKET;

    // GGUF model state
    bool                              m_modelLoaded     = false;
    std::string                       m_loadedModelPath;
    std::string                       m_loadedModelName;

    // Active backend state
    AIBackendType                     m_activeBackend   = AIBackendType::LocalGGUF;
    uint64_t                          m_inferenceRequestCount = 0;

    // Real subsystem instances (owned by HeadlessIDE)
    std::unique_ptr<MultiResponseEngine> m_multiResponse;
    std::unique_ptr<AgentHistoryRecorder, AgentHistoryDeleter> m_historyRecorder;

    // Agentic stack. Native subagent_core is linked by the headless target.
    std::unique_ptr<AgenticEngine>     m_agenticEngine;

    // Fix #14: Conversation manager for HTTP endpoints
    class ConversationManager;
    std::unique_ptr<ConversationManager> m_conversationManager;

    // Failure detection counters
    uint64_t                          m_failureDetections = 0;
    uint64_t                          m_failureRetries    = 0;

    // Agent history counters
    uint64_t                          m_agentEventCount   = 0;

    // ASM semantic counters
    uint32_t                          m_asmSymbolCount    = 0;
    uint32_t                          m_asmFilesParsed    = 0;

    // LSP counters
    uint32_t                          m_lspServerCount    = 0;
    uint64_t                          m_lspCompletionCount = 0;

    // Hybrid bridge counters
    uint64_t                          m_hybridCompletionCount = 0;

    // Native debugger state
    bool                              m_debugSessionActive    = false;
    uint32_t                          m_debugBreakpointCount  = 0;

    // Experimental toggles (enabled via environment/config)
    bool                              m_expHotpatchEnabled        = true;
    bool                              m_expLayerEvictionEnabled   = true;
    bool                              m_expGovernorEnabled        = true;
    bool                              m_expQuantumTimeEnabled     = false;
    bool                              m_expQuantumOrchEnabled     = false;
    bool                              m_expQuantumMissingEnabled  = false;

    // Experimental activation markers
    bool                              m_expHotpatchActivated      = false;
    bool                              m_expLayerEvictionActivated = false;
    bool                              m_expGovernorActivated      = false;
    bool                              m_expQuantumTimeActivated   = false;
    bool                              m_expQuantumOrchActivated   = false;
    bool                              m_expQuantumMissingActivated = false;

    // Fix #14: Output sink thread safety
    mutable std::mutex                m_outputSinkMutex;

    // Session
    std::string                       m_sessionId;
    uint64_t                          m_startEpochMs    = 0;

    // Fix #6: Thread pool for client handling
    std::vector<std::thread>          m_threadPool;
    std::mutex                        m_threadPoolMutex;
    std::mutex                        m_auditMutex;
    std::atomic<uint64_t>             m_cloudReservedNanodollars{0};
    size_t                            m_maxThreads = 64;

    // Version
    static constexpr const char*      VERSION = "20.0.0-headless-enterprise";
    static constexpr const char*      BUILD_PHASE = "Phase 20 Enterprise";
};
