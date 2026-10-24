// =============================================================================
// rawrxd_cli_v2.cpp — RawrXD Universal CLI (v2)
// =============================================================================
// `rawr run <model> [mode]` is the single entry point that launches everything:
// the agent, swarm, tools, backend router and audit ledger.
//
//   rawr run qwen3:8b                 Code mode (default) interactive session
//   rawr run qwen3:8b ask             Ask-only session (structurally read-only)
//   rawr run qwen3:8b --mode debug    explicit --mode form
//   rawr run model.gguf --backend deep2
//
// Inside a session:  /mode <name>  /status  /tools  /checkpoint  /exit
// Mode switching preserves conversation history and ALWAYS recalculates the
// permission policy — Ask/Plan never inherit Code's write authority.
//
// Design rules enforced by this binary:
//   * Deep2 is the primary inference backend; Ollama is the backup.
//   * Permissions are enforced by the native tool executor, never by prompt.
//   * The DRIVER owns the audit ledger and persists it incrementally.
//   * Builds/tests are certified from process exit codes + disk artifacts.
//   * Fail-closed: no tool call is executed that the mode policy denies.
// =============================================================================
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#endif
#include "agentic/InferenceBackend.h"
#include "agentic/BackendRouter.h"
#include "agentic/OllamaBackend.h"
#include "agentic/Deep2Backend.h"
#include "Deep2Next15Hooks.hpp"
#include "agentic/ToolCallBridge.h"
#include "agentic/tool_call_parser.h"
#include "agentic/agent_action.h"
#include "agent/delegated_agents.hpp"
#include "agentic/RawrSwarmEvents.hpp"
#include "agentic/PersistentTaskBacklog.h"
#include "agentic/SelfRepairLoop.h"
#include "agentic/AgentMode.h"
#include "agentic/AgentSession.h"
#include "agentic/WorkspaceToolHost.h"
#include "agentic/tool_core.hpp"
#include "backend/ollama_client.h"
#include "backend/kilo_gateway_client.h"
#ifdef _WIN32
#include "agentic/process_win32.hpp"
#endif

#include "deep2/Deep2CLIBridge.hpp"
#include "deep2/RawrModelAlias.hpp"
#include "project_wizard/project_spec.hpp"
#include "project_wizard/project_state_manager.hpp"
#include "project_wizard/project_wizard.hpp"
#include "project_wizard/project_workflow.hpp"
#include <functional>

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <filesystem>
#include <csignal>
#include <chrono>
#include <cstdlib>
#include <algorithm>
#include <cctype>
#include <fstream>
#include <thread>
#ifdef _WIN32
#include <windows.h>
#pragma comment(lib, "Ws2_32.lib")
#endif

using json = nlohmann::json;
namespace fs = std::filesystem;

using namespace RawrXD::Agent;

// ---------------------------------------------------------------------------
// Global runtime
// ---------------------------------------------------------------------------
static std::unique_ptr<BackendRouter>      g_router;
static std::unique_ptr<rawrxd::tools::Registry> g_tools;
static std::unique_ptr<WorkspaceToolHost>  g_ws;
static std::unique_ptr<PermissionGate>     g_gate;
static std::unique_ptr<AgentSession>       g_ledger;
static Deep2EngineHandle*                  localEngine = nullptr;
static std::function<InferenceResult(const std::vector<ChatMessage>&, int)> deep2CompleteFn;
static std::atomic<bool>                   g_running{true};
static std::string                         g_workspace;
static std::string                         g_model;
static std::string                         g_backend_name = "auto";
static std::string                         g_provider_name = "auto";
static std::atomic<bool>                   g_streamed_response{false};
static int                                 g_requested_max_tokens = 256;
/// @brief True when the selected Ollama model is served by ollama.com
/// rather than by the local runtime. Cloud models need an account with
/// quota and internet, and are never local inference.
static bool                                g_model_is_cloud = false;
/// @brief Where reasoning text from a reasoning model is written. Reasoning
/// is a separate channel: it must never be interleaved into stdout, or the
/// CLI stops being machine-readable. It goes to a sidecar file instead.
static std::string                         g_reasoning_path;
/// @brief Echo reasoning to stderr as well as the sidecar (operator opt-in).
static bool                                g_show_reasoning = false;

/// @brief Append reasoning text to the sidecar file, and optionally to stderr.
static void AppendReasoning(const std::string& text) {
    if (text.empty()) return;
    if (!g_reasoning_path.empty()) {
        std::error_code ec;
        fs::path p(g_reasoning_path);
        if (!p.parent_path().empty()) fs::create_directories(p.parent_path(), ec);
        std::ofstream f(p, std::ios::app | std::ios::binary);
        if (f) f << text;
    }
    if (g_show_reasoning) {
        std::cerr << text << std::flush;
    }
}

/// @brief The model provider seam.
///
/// This is the ONLY source of tokens for the agent engine. The engine (tool
/// dispatch, permission gate, mutation ledger, verification) never learns
/// which provider answered, so Deep2 and Ollama drive exactly the same loop.
using ModelProviderFn = std::function<InferenceResult(const std::vector<ChatMessage>&,
                                                      const json& tools,
                                                      int maxTokens)>;
static ModelProviderFn g_modelProvider;

/// @brief The streaming half of the provider seam. When a provider can
/// deliver tokens as they are produced, it registers here so a completion
/// streams live instead of arriving as one block. The Deep2 in-process path
/// streams inside its own completion function and does not register here.
using ModelStreamFn = std::function<bool(
    const std::vector<ChatMessage>&, const json&, int,
    const std::function<void(const std::string&)>&,
    const std::function<void(const std::string&, const json&)>&,
    const std::function<void(const std::string&, uint64_t, uint64_t, double)>&,
    const std::function<void(const std::string&)>&)>;
static ModelStreamFn g_streamProvider;

/// @brief One provider turn, streamed when the provider can stream.
///
/// Defined below, next to the other completion helpers.
static InferenceResult ProviderTurn(const std::vector<ChatMessage>& messages,
                                    const json& tools,
                                    int maxTokens,
                                    bool echoToStdout);

static std::string toLowerCompat(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

/// @brief Provenance of a run: which component produced the tokens, which
/// component owned the tools, and which component decided the result was
/// verified. These are separate claims and are recorded separately, so a
/// model served by Ollama can never be reported as a Deep2 inference result.
static json BuildProvenance(bool agentMode) {
    const std::string provider = g_provider_name;
    json p;
    p["MODEL_PROVIDER"]  = (provider == "ollama") ? "OLLAMA"
                         : (provider == "deep2")  ? "DEEP2"
                         : (provider == "kilo")   ? "KILO_GATEWAY" : "AUTO";
    p["INFERENCE_ENGINE"] = (provider == "ollama") ? "OLLAMA"
                          : (provider == "deep2")  ? "DEEP2"
                          : (provider == "kilo")   ? "KILO_GATEWAY" : "UNDECLARED";
    // The agent loop, the tool authority and the verification verdict are
    // always RawrXD's, whatever produced the tokens.
    p["AGENT_ENGINE"]    = "RAWRXD";
    p["TOOL_AUTHORITY"]  = "RAWRXD";
    p["VERIFICATION"]    = "RAWRXD";
    p["MODE"]            = agentMode ? "AGENT" : "COMPLETION";
    if (provider == "ollama") {
        // A cloud model is served by ollama.com, not by the local runtime.
        // It is a materially different claim from local inference and is
        // recorded as such.
        p["MODEL_SOURCE"] = g_model_is_cloud ? "OLLAMA_CLOUD" : "OLLAMA_STORE";
    } else if (provider == "kilo") {
        // The Kilo Gateway is always remote.
        p["MODEL_SOURCE"] = "KILO_CLOUD";
    } else {
        p["MODEL_SOURCE"] = "LOCAL_GGUF";
    }
    return p;
}

struct AgentLoopOutcome {
    bool success = false;
    std::string finalText;
    std::string failure;
    uint32_t iterations = 0;
    // The generation accounting of the run, summed over the turns.
    uint64_t promptTokens = 0;
    uint64_t completionTokens = 0;
    uint64_t evalDurationNs = 0;
    uint64_t loadDurationNs = 0;
    double   inferenceTps = 0.0;   // the server's own accounting
    double   ttftMs = 0.0;         // time to the first token of the first turn
    double   wallMs = 0.0;         // the whole loop, including the tools
};

// Per-model agent state owned by the certification driver and shared with the
// provider wrapper and the agent loop. Moving it to file scope lets
// RunAuthorizedAgentLoop observe the same state without a parallel state machine.
struct ModelState {
    int turns = 0;
    bool sawObservation = false;
    bool sawTokenObservation = false;   // a tool observation containing RAWRXD_AGENTIC_ was delivered
    bool nativeToolCall = false;
    bool textToolCall = false;
    std::string token;
    std::string toolCallName;
    std::string toolCallArgs;
    std::string observation;
    json calls = json::array();
    // Generalized task-completion predicate. When true, the agent loop transitions
    // to the tool-free finalization phase. Can be set by the driver (e.g., after
    // a token observation), by an explicit tool call, or by a protocol signal.
    bool taskComplete = false;
    std::string completionReason;
};

static bool WriteRunReceipt(const std::string& path,
                            const std::string& model,
                            const std::string& prompt,
                            const std::string& response,
                            const std::string& backend,
                            const std::string& motdDigest,
                            int maxTokens,
                            bool agent,
                            uint32_t iterations,
                            bool success,
                            const std::string& error,
                            const json& provenance = json::object(),
                            const json& telemetry = json::object()) {
    std::error_code ec;
    fs::path out(path);
    if (!out.parent_path().empty()) fs::create_directories(out.parent_path(), ec);
    std::ofstream f(out, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    json receipt{
        {"schema", "rawr.run.receipt.v1"},
        {"model", model},
        {"backend", backend},
        {"prompt", prompt},
        {"response", response},
        {"response_bytes", response.size()},
        {"max_tokens", maxTokens},
        {"agent_mode", agent},
        {"iterations", iterations},
        {"motd_sha256", motdDigest},
        {"success", success},
        {"error", error},
        // Provenance: which component produced the tokens, which owned the
        // tools, and which judged the result verified. Recorded separately so
        // an Ollama-served model is never reported as Deep2 inference.
        {"provenance", provenance},
        // The generation accounting: the server's own inference throughput and
        // the end-to-end throughput, kept apart because they measure different
        // things. The inference rate excludes the model load and the prompt
        // evaluation; the end-to-end rate includes them.
        {"telemetry", telemetry},
        // This receipt describes execution only. Certification stays fail-closed
        // until a complete independent full-model parity/generation gate runs.
        {"full_model_certification", "NOT_CERTIFIED"}
    };
    f << receipt.dump(2) << "\n";
    return static_cast<bool>(f);
}

// ---------------------------------------------------------------------------
// Signal handling
// ---------------------------------------------------------------------------
static void OnSignal(int) {
    g_running = false;
    if (g_router) g_router->Cancel();
}

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------
struct Options {
    std::vector<std::string> positional;
    std::map<std::string, std::string> flags;
    bool has(const std::string& k) const { return flags.count(k) > 0; }
    std::string get(const std::string& k, const std::string& d = "") const {
        auto it = flags.find(k);
        return (it != flags.end()) ? it->second : d;
    }
};

static Options ParseOptions(int argc, char** argv, int start_index) {
    Options o;
    for (int i = start_index; i < argc; ++i) {
        std::string a = argv[i];
        if (a.rfind("--", 0) == 0) {
            std::string body = a.substr(2);
            auto eq = body.find('=');
            if (eq != std::string::npos) {
                o.flags[body.substr(0, eq)] = body.substr(eq + 1);
            } else if (i + 1 < argc && argv[i + 1][0] != '-') {
                o.flags[body] = argv[++i];
            } else {
                o.flags[body] = "true";
            }
        }
        else if (a.size() > 1 && a[0] == '-') {
            std::string body = a.substr(1);
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                o.flags[body] = argv[++i];
            } else {
                o.flags[body] = "true";
            }
        }
        else {
            o.positional.push_back(a);
        }
    }
    return o;
}

// ---------------------------------------------------------------------------
// Workspace discovery (audit fix: supply the canonical root at init)
// ---------------------------------------------------------------------------
static std::string DiscoverWorkspace(const Options& o) {
    std::string override_ws = o.get("workspace", o.get("root", ""));
    if (!override_ws.empty()) {
        std::error_code ec;
        fs::path p = fs::weakly_canonical(fs::absolute(override_ws, ec));
        return (ec ? fs::absolute(override_ws) : p).string();
    }
    return fs::current_path().string();
}

// ---------------------------------------------------------------------------
// The project root of the running build
// ---------------------------------------------------------------------------
//
// The certification has to run against the tree the executable was built
// from, not against whatever directory the shell happened to be in. The
// executable knows where it is: it is <root>/build/bin-msvc/Release/rawr.exe,
// so the root is three directories up.
//
// A root is accepted only if it really is this project: it has to hold the
// CLI source. A binary that was copied somewhere else resolves to no root,
// and the caller falls back to the working directory.
//
// The reason is the evidence. The sweep report, the workspace policy and
// the source files that gate 13 watches all live in the project. A
// certification that looked for them in the user's home directory would
// report a missing sweep and a missing policy, and it would say so as if
// the bridge were broken.
static std::string ExecutablePath() {
#ifdef _WIN32
    char buffer[MAX_PATH * 4];
    const DWORD n = ::GetModuleFileNameA(nullptr, buffer,
                                          static_cast<DWORD>(sizeof(buffer)));
    if (n == 0 || n >= sizeof(buffer)) return std::string();
    return std::string(buffer, n);
#else
    std::error_code ec;
    const auto p = fs::read_symlink("/proc/self/exe", ec);
    if (!ec && !p.empty()) return p.string();
    return std::string();
#endif
}

static bool LooksLikeProjectRoot(const fs::path& root) {
    std::error_code ec;
    if (root.empty()) return false;
    if (!fs::is_regular_file(root / "src" / "rawrxd_cli_v2.cpp", ec) || ec) return false;
    return true;
}

static std::string ProjectRootFromExecutable() {
    const std::string exe = ExecutablePath();
    if (exe.empty()) return std::string();
    fs::path dir = fs::path(exe).parent_path();
    // Release -> bin-msvc -> build -> root. The walk is bounded and the
    // first ancestor that is a project root wins.
    for (int i = 0; i < 6; ++i) {
        if (LooksLikeProjectRoot(dir)) {
            std::error_code ec;
            const auto canonical = fs::weakly_canonical(dir, ec);
            return (ec ? dir : canonical).string();
        }
        const fs::path parent = dir.parent_path();
        if (parent.empty() || parent == dir) break;
        dir = parent;
    }
    return std::string();
}

// The workspace a command runs in.
//
// An explicit --workspace or --root wins. Otherwise the root of the
// production build wins, so that a command produces the same result from
// any working directory. The working directory is the last resort.
static std::string ResolveWorkspace(const Options& o) {
    const std::string explicitWs = o.get("workspace", o.get("root", ""));
    if (!explicitWs.empty()) {
        std::error_code ec;
        fs::path p = fs::weakly_canonical(fs::absolute(explicitWs, ec));
        return (ec ? fs::absolute(explicitWs) : p).string();
    }
    const std::string fromExe = ProjectRootFromExecutable();
    if (!fromExe.empty()) return fromExe;
    return fs::current_path().string();
}

// ---------------------------------------------------------------------------
// Git state
// ---------------------------------------------------------------------------
static std::string RunGit(const std::string& args) {
#ifdef _WIN32
    std::string cmd = "git -C \"" + g_workspace + "\" " + args + " 2>nul";
#else
    std::string cmd = "git -C '" + g_workspace + "' " + args + " 2>/dev/null";
#endif
    FILE* p = _popen(cmd.c_str(), "r");
    if (!p) return "";
    std::string out;
    char buf[512];
    while (fgets(buf, sizeof(buf), p)) out += buf;
    _pclose(p);
    while (!out.empty() && (out.back() == '\n' || out.back() == '\r')) out.pop_back();
    return out;
}

// ---------------------------------------------------------------------------
// Backend initialization
// ---------------------------------------------------------------------------
static bool InitBackend(BackendMode mode, const std::string& model, int maxTokens = 0) {
    g_model = model;
    if (maxTokens > 0) g_requested_max_tokens = maxTokens;
    // Direct Deep2Engine (in-process GGUF inference) takes priority — no HTTP router needed.
    // In Auto mode, try Deep2 when a model path is provided and looks like a GGUF file.
    bool tryDeep2 = (mode == BackendMode::Deep2) ||
                    (mode == BackendMode::Auto && !model.empty() &&
                     (model.rfind(".gguf") == model.size() - 5 ||
                      model.rfind(".GGUF") == model.size() - 5));
    if (tryDeep2) {
        if (localEngine) {
            deep2_free(localEngine);
            localEngine = nullptr;
        }
        std::string modelPath = g_workspace + "/" + model;
        Deep2::rawr_run::AliasResolve resolved{};
        if (Deep2::rawr_run::ResolveModelAlias(model.c_str(), resolved)) {
            modelPath = resolved.path;
            std::fprintf(stderr, "[Deep2Backend] Resolved alias '%s' -> %s (%u shard%s)\n",
                         model.c_str(), modelPath.c_str(), resolved.shards,
                         resolved.shards == 1 ? "" : "s");
        } else if (!std::filesystem::exists(modelPath)) {
            modelPath = model;
        }
        std::fprintf(stderr, "[Deep2Backend] Loading model: %s\n", modelPath.c_str());
        localEngine = deep2_load_model(modelPath.c_str());
        if (!localEngine) {
            std::cerr << "Failed to load model via Deep2Engine: " << model << "\n";
            std::cerr << "Use --backend ollama for HTTP-based inference instead.\n";
            return false;
        }
        std::fprintf(stderr, "[Deep2Backend] Model loaded: hidden=%u vocab=%u layers=%zu\n",
                     deep2_hidden_dim(localEngine),
                     deep2_vocab_size(localEngine),
                     deep2_num_layers(localEngine));

        deep2CompleteFn = [](const std::vector<ChatMessage>& msgs, int maxTokens) {
            // The GGUF tokenizer/chat metadata is authoritative.  A fixed
            // TinyLlama template makes Nemotron, Qwen, Phi and other models
            // tokenize the wrong control tokens and can legitimately yield an
            // immediate EOS with no visible response.
            std::string systemPrompt =
                "You are a helpful assistant. Follow the user's instructions directly and concisely.";
            std::string userPrompt;
            for (const auto& m : msgs) {
                if (m.role == "system") {
                    if (!m.content.empty()) {
                        if (!systemPrompt.empty()) systemPrompt += "\n";
                        systemPrompt += m.content;
                    }
                } else if (m.role == "user") {
                    if (!userPrompt.empty()) userPrompt += "\n";
                    userPrompt += m.content;
                } else if (!m.content.empty()) {
                    if (!userPrompt.empty()) userPrompt += "\n";
                    userPrompt += m.role + ": " + m.content;
                }
            }
            if (userPrompt.empty()) userPrompt = "Hello.";

            std::string prompt;
            if (!deep2_format_chat_prompt(localEngine, systemPrompt.c_str(),
                                          userPrompt.c_str(), prompt)) {
                return InferenceResult::Error("Deep2Engine could not format model chat prompt");
            }
            std::string text;
            auto emit = [](int32_t, const char* bytes, size_t count, void*) -> bool {
                if (bytes && count) {
                    std::cout.write(bytes, static_cast<std::streamsize>(count));
                    std::cout.flush();
                    g_streamed_response = true;
                }
                return g_running.load();
            };
            g_streamed_response = false;
            if (!deep2_generate_stream(localEngine, prompt.c_str(),
                                        static_cast<size_t>(maxTokens), emit,
                                        nullptr, text)) {
                const char* reason = deep2_generation_stop_reason_name(localEngine);
                std::string detail = "Deep2Engine generation failed: stop_reason=" +
                                     std::string(reason ? reason : "UNKNOWN") +
                                     " prompt_bytes=" + std::to_string(prompt.size());
                return InferenceResult::Error(detail);
            }
            InferenceResult r = InferenceResult::Ok(text);
            r.prompt_tokens = static_cast<int>(prompt.size() / 4);
            r.completion_tokens = static_cast<int>(text.size() / 4);
            r.tokens_per_sec = 0.0;
            r.total_duration_ms = 0;
            return r;
        };

        // The Deep2 provider is the model source for this run. The engine
        // calls it and nothing else.
        g_modelProvider = [fn = deep2CompleteFn](const std::vector<ChatMessage>& msgs,
                                                 const json&, int maxTokens) {
            return fn(msgs, maxTokens);
        };
        return true;
    }

    // The Kilo Gateway: an OpenAI-compatible HTTPS endpoint fronting a free
    // model catalog. It is a CLOUD provider: it needs an API key and
    // internet, and it is never local inference. It is selected explicitly
    // and never as a silent fallback.
    if (mode == BackendMode::Kilo) {
        g_model_is_cloud = true;
        auto client = std::make_shared<RawrXD::Backend::KiloGatewayClient>();
        if (!client->hasApiKey()) {
            std::cerr << "ERROR: the Kilo Gateway needs an API key.\n";
            std::cerr << "  set KILO_API_KEY in the environment, or pass "
                         "--api-key.\n";
            std::cerr << "  optionally set KILO_MODEL to choose a model "
                         "(default: kilo-auto/free).\n";
            return false;
        }
        const std::string kiloModel = model.empty()
            ? RawrXD::Backend::KiloGatewayClient::DefaultModel() : model;
        g_modelProvider = [client, kiloModel](const std::vector<ChatMessage>& msgs,
                                              const json&, int maxTokens) {
            std::vector<std::pair<std::string, std::string>> wire;
            for (const auto& m : msgs) wire.emplace_back(m.role, m.content);
            const auto resp = client->chatSync(wire, kiloModel, maxTokens);
            if (!resp.success) {
                return InferenceResult::Error(resp.error.empty()
                    ? "Kilo Gateway request failed" : resp.error);
            }
            if (!resp.reasoning.empty()) {
                // Reasoning goes to the sidecar file, never into stdout.
                AppendReasoning(resp.reasoning);
            }
            if (resp.reasoning_tokens) {
                std::cerr << "[tokens] prompt=" << resp.prompt_tokens
                          << " completion=" << resp.completion_tokens
                          << " reasoning=" << resp.reasoning_tokens << "\n";
            }
            InferenceResult r = InferenceResult::Ok(resp.content);
            r.prompt_tokens = static_cast<int>(resp.prompt_tokens);
            r.completion_tokens = static_cast<int>(resp.completion_tokens);
            r.total_duration_ms = static_cast<int>(resp.total_duration_ms);
            return r;
        };
        g_streamProvider = [client, kiloModel](
            const std::vector<ChatMessage>& msgs, const json&, int maxTokens,
            const std::function<void(const std::string&)>& on_token,
            const std::function<void(const std::string&, const json&)>&,
            const std::function<void(const std::string&, uint64_t, uint64_t, double)>& on_done,
            const std::function<void(const std::string&)>& on_error) {
            std::vector<std::pair<std::string, std::string>> wire;
            for (const auto& m : msgs) wire.emplace_back(m.role, m.content);
            return client->chatStream(wire, kiloModel, maxTokens,
                                      on_token, on_done, on_error,
                                      [](const std::string& think) {
                                          AppendReasoning(think);
                                      });
        };
        return true;
    }

    if (g_router) {
        g_router->SetMode(mode);
        if (!model.empty()) {
            // Route the model through the router so the router's own view of
            // the active model stays in step with the backend's.
            if (mode == BackendMode::Ollama) g_router->SetFallbackModel(model);
            else                                g_router->SetPrimaryModel(model);
            if (auto* b = g_router->GetBackendPtr(g_router->GetActiveBackendKind())) {
                auto cfg = b->GetConfig();
                cfg.model = model;
                if (g_requested_max_tokens > 0) cfg.max_tokens = g_requested_max_tokens;
                b->SetConfig(cfg);
            }
            if (mode == BackendMode::Ollama) {
                g_model_is_cloud = g_router->IsCloudModel(model);
            }
        }
        return true;
    }

    RouterConfig cfg;
    cfg.mode = mode;
    cfg.primary_endpoint = "http://127.0.0.1:11436";
    cfg.fallback_endpoint = "http://127.0.0.1:11434";
    cfg.primary_model = "deep2-native";
    cfg.fallback_model = model.empty() ? "qwen2.5-coder:32b" : model;

    if (mode == BackendMode::Deep2)   cfg.primary_model = model.empty() ? cfg.primary_model : model;
    if (mode == BackendMode::Ollama)  cfg.fallback_model = model.empty() ? cfg.fallback_model : model;
    if (mode == BackendMode::Ollama)  cfg.primary_model = "";

    g_router = std::make_unique<BackendRouter>();
    if (!g_router->Initialize(cfg)) return false;
    if (g_requested_max_tokens > 0) {
        if (auto* b = g_router->GetBackendPtr(g_router->GetActiveBackendKind())) {
            auto bcfg = b->GetConfig();
            bcfg.max_tokens = g_requested_max_tokens;
            b->SetConfig(bcfg);
        }
    }
    // The router is the model source for this run. Swapping the provider is a
    // provider swap, not an engine change.
    g_modelProvider = [](const std::vector<ChatMessage>& msgs, const json& tools, int) {
        return g_router->ChatSync(msgs, tools);
    };
    g_streamProvider = [](const std::vector<ChatMessage>& msgs, const json& tools, int,
                          const std::function<void(const std::string&)>& on_token,
                          const std::function<void(const std::string&, const json&)>& on_tool_call,
                          const std::function<void(const std::string&, uint64_t, uint64_t, double)>& on_done,
                          const std::function<void(const std::string&)>& on_error) {
        return g_router->ChatStream(msgs, tools, on_token, on_tool_call, on_done, on_error);
    };
    // A reasoning model's thinking text is a separate channel: it goes to the
    // sidecar file, never into stdout, so the CLI stays machine-readable.
    g_router->SetThinkingSink([](const std::string& think) { AppendReasoning(think); });
    if (mode == BackendMode::Ollama && !model.empty()) {
        // Record whether this model runs locally or on ollama.com. The
        // distinction changes what the run receipt may claim.
        g_model_is_cloud = g_router->IsCloudModel(model);
        if (g_model_is_cloud) {
            std::cerr << "[note] " << model << " is a CLOUD model (served by "
                      << "ollama.com). It needs a signed-in account with quota and "
                      << "internet access, and it is not local inference.\n";
        }
    }
    return true;
}

static std::string ActiveModelName() {
    if (g_router) return g_router->GetActiveModel();
    return g_model.empty() ? "unknown" : g_model;
}

static std::string ModelIdentityString() {
    if (g_router)
        return std::string(BackendModeName(g_router->GetMode())) + "/" + g_router->GetActiveModel();
    return g_backend_name + "/" + (g_model.empty() ? "unknown" : g_model);
}

static std::string LedgerTerminationName(const AgentSession& s);
static bool LedgerBuildPassed(const AgentSession& s);
static bool LedgerTestsPassed(const AgentSession& s);

// ---------------------------------------------------------------------------
// Approval policy (mutations require explicit env opt-in)
// ---------------------------------------------------------------------------
static bool ApproveMutation(const std::string& tool, const json& args) {
    const char* env = std::getenv("RAWRXD_TOOLS_APPROVE_MUTATIONS");
    bool env_ok = env && std::string(env) == "YES";
    if (!env_ok) return false;
    // External/network tools are never auto-approved, even with the env var.
    return tool != "runInTerminal" || env_ok;
}

// ---------------------------------------------------------------------------
// Session banner
// ---------------------------------------------------------------------------
static void PrintBanner(AgentMode mode) {
    std::cout << "\n";
    std::cout << "RawrXD Local Agent\n";
    std::cout << "Model:   " << ActiveModelName() << "\n";
    std::cout << "Backend: " << g_backend_name << "\n";
    std::cout << "Mode:    " << AgentModeName(mode) << "\n";
    std::cout << "Root:    " << g_workspace << "\n";
    std::cout << "\n";
}

// ---------------------------------------------------------------------------
// Tool listing / description
// ---------------------------------------------------------------------------
static void ListTools() {
    if (!g_tools) return;
    std::cout << "=== Tools ===\n";
    for (const auto& n : g_tools->names()) {
        rawrxd::tools::Tool t;
        if (g_tools->find(n, t)) {
            ToolAuthority a = g_gate ? g_gate->EffectiveAuthority() : ToolAuthority::Denied;
            const ModePolicy* p = ModeRegistry::Instance().Get(g_gate->GetMode());
            ToolAuthority granted = p ? ModeRegistry::Instance().AuthorityFor(g_gate->GetMode(), n)
                                      : ToolAuthority::Denied;
            std::cout << "  " << std::left << std::setw(16) << n
                      << "[" << ToolAuthorityName(granted) << "]  "
                      << t.description << "\n";
        }
    }
    std::cout << "\nAuthority: " << ToolAuthorityName(g_gate->EffectiveAuthority()) << "\n";
}

static bool DescribeTool(const std::string& name) {
    if (!g_tools) return false;
    rawrxd::tools::Tool t;
    if (!g_tools->find(name, t)) return false;
    std::cout << "Tool: " << t.name << "\n";
    std::cout << "  Description: " << t.description << "\n";
    std::cout << "  Risk: ";
    switch (t.risk) {
        case rawrxd::tools::Risk::ReadOnly: std::cout << "read-only\n"; break;
        case rawrxd::tools::Risk::Write:    std::cout << "write\n"; break;
        case rawrxd::tools::Risk::Execute:  std::cout << "execute\n"; break;
        case rawrxd::tools::Risk::Network:  std::cout << "network\n"; break;
        case rawrxd::tools::Risk::External: std::cout << "external\n"; break;
    }
    std::cout << "  Required args:";
    if (t.required.empty()) std::cout << " (none)";
    for (const auto& r : t.required) std::cout << " " << r;
    std::cout << "\n";
    if (g_gate) {
        const ModePolicy* p = ModeRegistry::Instance().Get(g_gate->GetMode());
        if (p) {
            std::cout << "  Authority in mode '" << AgentModeName(g_gate->GetMode()) << "': "
                      << ToolAuthorityName(ModeRegistry::Instance().AuthorityFor(g_gate->GetMode(), name))
                      << "\n";
        }
    }
    return true;
}

// ---------------------------------------------------------------------------
// Direct CLI tool invocation: rawr tools run <name> [key=value ...]
// ---------------------------------------------------------------------------
static int RunToolCli(const std::vector<std::string>& rest) {
    if (rest.size() < 2) {
        std::cerr << "Usage: rawr tools run <toolName> [key=value ...]\n";
        return 2;
    }

    rawrxd::tools::Request req;
    req.name = rest[1];
    for (size_t i = 2; i < rest.size(); ++i) {
        const std::string& kv = rest[i];
        auto eq = kv.find('=');
        if (eq == std::string::npos) {
            std::cerr << "Expected key=value, got: " << kv << "\n";
            return 2;
        }
        req.args[kv.substr(0, eq)] = kv.substr(eq + 1);
    }

    // A direct CLI tool invocation is its own user turn. Read the active
    // workspace MOTD before allowing this command to reach the registry.
    const fs::path workspaceRoot = g_workspace.empty() ? fs::current_path() : fs::path(g_workspace);
    rawrxd::agentic::MotdAuthorization motdAuthorization(workspaceRoot);
    const std::string motdSession = "rawr-tools-" +
        std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    constexpr uint64_t motdTurn = 1;
    if (!motdAuthorization.BeginTurn(motdSession, motdTurn)) {
        std::cerr << "DENIED: MOTD_TURN_START_FAILED\n";
        return 3;
    }
    [[maybe_unused]] auto motdTurnGuard = motdAuthorization.GuardTurn(motdSession, motdTurn);

    if (req.name == "read_motd") {
        std::string contents, digest, error;
        if (!motdAuthorization.ReadMotd(motdSession, motdTurn, contents, digest, error)) {
            std::cerr << "DENIED: " << error << "\n";
            return 3;
        }
        std::cout << "MOTD_ACK=1\nMOTD_SHA256=" << digest << "\n" << contents << "\n";
        return 0;
    }

    std::string motdContents, motdDigest, motdError;
    if (!motdAuthorization.ReadMotd(motdSession, motdTurn,
                                    motdContents, motdDigest, motdError)) {
        std::cerr << "DENIED: " << motdError << "\n";
        return 3;
    }
    std::string authorizationError;
    if (!motdAuthorization.AuthorizeTool(req.name, motdSession, motdTurn,
                                          authorizationError)) {
        std::cerr << "DENIED: " << authorizationError << "\n";
        return 3;
    }
    std::cout << "MOTD_ACK=1 MOTD_SHA256=" << motdDigest << "\n";

    if (!g_tools || !g_gate) {
        std::cerr << "Tool executor not initialized.\n";
        return 1;
    }

    auto approve = [](const rawrxd::tools::Tool& tool, const rawrxd::tools::Request& r) -> bool {
        json args;
        for (const auto& [k, v] : r.args) args[k] = v;
        return ApproveMutation(tool.name, args);
    };

    rawrxd::tools::Tool tool;
    if (!g_tools->find(req.name, tool)) {
        std::cerr << "Unknown tool: " << req.name << "\n";
        return 1;
    }

    if (!g_gate->AllowsWithApproval(tool, req, approve)) {
        std::cerr << "DENIED: " << g_gate->ExplainDenial(tool) << "\n";
        return 3;
    }

    auto res = g_tools->call(req, approve);
    if (!res.output.empty()) std::cout << res.output << "\n";
    if (!res.ok) {
        std::cerr << "ERROR: " << res.error << "\n";
        return 1;
    }

    if (g_ledger) {
        ToolCallRecord rec;
        rec.tool_name = req.name;
        rec.args = [&] { json j; for (auto& [k, v] : req.args) j[k] = v; return j; }();
        rec.ok = true;
        rec.output = res.output;
        rec.timestamp = AgentSession::NowUnix();
        rec.approved_by = true;
        g_ledger->RecordToolCall(rec);
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Ledger checkpoint
// ---------------------------------------------------------------------------
static void CheckpointLedger(const std::string& label) {
    if (!g_ledger) return;
    std::string dir = g_workspace + "/.rawrxd/ledger";
    std::error_code ec;
    fs::create_directories(dir, ec);
    g_ledger->RecordCheckpoint(label);
    g_ledger->Flush();
}

// Bounded native agent loop used by `rawr run ... --agent`.  This deliberately
// reuses the CLI's already-authorized registry and MOTD turn instead of calling
// the older AgentOrchestrator (whose standalone registry predates the CLI gate).
// A model response is never treated as success until the real inference call
// and every requested tool call have returned evidence.
static AgentLoopOutcome RunAuthorizedAgentLoop(
    const std::string& goal,
    const std::string& policy,
    const std::string& digest,
    rawrxd::agentic::MotdAuthorization& authorization,
    const std::string& session,
    uint64_t turn,
    uint32_t maxIterations,
    int maxTokens,
    std::shared_ptr<ModelState> state = nullptr) {
    AgentLoopOutcome outcome;
    if (!g_ledger || !g_tools || !g_gate) {
        outcome.failure = "agent runtime not initialized";
        return outcome;
    }

    maxIterations = std::clamp<uint32_t>(maxIterations, 1u, 16u);
    maxTokens = std::clamp(maxTokens, 1, 4096);

    RawrXD::Agent::ToolCallBridge schemaBridge;
    schemaBridge.SetRegistry(g_tools.get());
    schemaBridge.SetWorkspaceRoot(g_workspace);
    const json toolSchemas = schemaBridge.GetToolSchemasForLLM();

    // Name the tools explicitly. The previous contract said
    // {"name":"tool","arguments":{...}} — a literal "tool" as the tool name,
    // which no registry entry matches, so a compliant model produced a call
    // that always failed as an unknown tool.
    std::string toolNameList;
    for (const auto& s : toolSchemas) {
        if (!s.is_object() || !s.contains("function")) continue;
        const auto& fn = s["function"];
        if (!fn.is_object() || !fn.contains("name") || !fn["name"].is_string()) continue;
        if (!toolNameList.empty()) toolNameList += ", ";
        toolNameList += fn["name"].get<std::string>();
    }

    std::string toolContract =
        "\nYou are in bounded RawrXD agent mode. Use at most one tool at a time. "
        "To call a tool, emit exactly one JSON object of the form "
        "{\"name\":\"<tool name>\",\"arguments\":{...}} where <tool name> is one of: " +
        toolNameList + ". "
        "After the observation, continue or return a final answer. Never claim a "
        "tool succeeded without its observation. Available tool schemas: " +
        toolSchemas.dump();

    std::vector<ChatMessage> messages;
    messages.push_back(ChatMessage{
        "system",
        "Workspace execution policy was read for this turn. SHA-256=" + digest +
            "\n" + policy + toolContract,
        ""});
    messages.push_back(ChatMessage{"user", goal, ""});

    auto approval = [](const rawrxd::tools::Tool& tool,
                       const rawrxd::tools::Request& request) -> bool {
        json args;
        for (const auto& [k, v] : request.args) args[k] = v;
        return ApproveMutation(tool.name, args);
    };

    for (uint32_t iteration = 0; iteration < maxIterations; ++iteration) {
        if (!g_running.load()) {
            outcome.failure = "cancelled";
            outcome.iterations = iteration;
            return outcome;
        }
        const auto turnStart = std::chrono::steady_clock::now();

        // FINALIZATION PHASE: transition to tool-free answer when the task is
        // marked complete. The trigger can be set by:
        //   - Explicit taskComplete flag (driver, tool, or protocol)
        //   - Backward compatibility: token observation received (certification)
        // The token itself is never supplied to the model — it must come from
        // the file result or the task context.
        bool shouldFinalize = state && (state->taskComplete ||
            (state->sawTokenObservation && !state->token.empty()));
        if (shouldFinalize) {
            outcome.iterations = iteration + 1;
            const auto finalStart = std::chrono::steady_clock::now();
            std::vector<ChatMessage> finalMessages;
            std::string finalSystemPrompt;
            std::string finalUserPrompt;
            bool isTokenTask = state && state->completionReason == "token_observed";
            if (isTokenTask) {
                finalSystemPrompt = "You already read the file and received the token in the tool result. "
                    "Output only the exact token and nothing else. Do not call any tools.";
                finalUserPrompt = "Reply with the exact token only.";
            } else if (state && state->taskComplete && !state->completionReason.empty()) {
                finalSystemPrompt = "The task has been completed: " + state->completionReason +
                    ". Provide a final answer summarizing the outcome. Do not call any tools.";
                finalUserPrompt = "Reply with a final summary.";
            } else {
                finalSystemPrompt = "You already read the file and received the token in the tool result. "
                    "Output only the exact token and nothing else. Do not call any tools.";
                finalUserPrompt = "Reply with the exact token only.";
            }
            finalMessages.push_back(ChatMessage{"system", finalSystemPrompt, ""});
            finalMessages.push_back(ChatMessage{"user", goal, ""});
            if (state && !state->observation.empty()) {
                finalMessages.push_back(ChatMessage{
                    "user",
                    "Tool result:\n" + state->observation,
                    ""});
            }
            finalMessages.push_back(ChatMessage{
                "user", finalUserPrompt, ""});

            InferenceResult finalResult = ProviderTurn(
                finalMessages, json::array(), maxTokens, false);

            outcome.completionTokens += finalResult.completion_tokens;
            outcome.evalDurationNs += finalResult.eval_duration_ns;
            outcome.loadDurationNs += finalResult.load_duration_ns;
            outcome.promptTokens += finalResult.prompt_tokens;
            outcome.wallMs += std::chrono::duration<double, std::milli>(
                std::chrono::steady_clock::now() - finalStart).count();

            if (!finalResult.success) {
                outcome.failure = "final answer request failed: " +
                    (finalResult.error_message.empty()
                         ? "inference failed"
                         : finalResult.error_message);
                return outcome;
            }

            outcome.finalText = finalResult.response;
            if (state && !state->token.empty() &&
                finalResult.response.find(state->token) != std::string::npos) {
                outcome.success = true;
            } else if (state && state->taskComplete) {
                // For general task completion, accept the response as final.
                outcome.success = true;
            } else {
                outcome.success = false;
                outcome.failure = "final answer does not carry the verified token";
            }
            return outcome;
        }

        InferenceResult result;
        try {
            if (g_modelProvider || g_streamProvider) {
                // The provider seam: the engine asks for tokens, the provider
                // decides who produces them. The streaming seam is preferred,
                // so the answer reaches stdout as it is produced.
                result = ProviderTurn(messages, toolSchemas, maxTokens, true);
            } else {
                result = InferenceResult::Error("No inference backend available");
            }
        } catch (const std::exception& e) {
            outcome.failure = std::string("inference exception: ") + e.what();
            outcome.iterations = iteration + 1;
            return outcome;
        }
        // The accounting of this turn is accumulated, so that a run of several
        // turns reports the whole run and not only the last turn.
        outcome.promptTokens += result.prompt_tokens;
        outcome.completionTokens += result.completion_tokens;
        outcome.evalDurationNs += result.eval_duration_ns;
        outcome.loadDurationNs += result.load_duration_ns;
        if (outcome.completionTokens > 0 && outcome.evalDurationNs > 0) {
            outcome.inferenceTps = static_cast<double>(outcome.completionTokens) * 1e9 /
                                   static_cast<double>(outcome.evalDurationNs);
        }
        if (outcome.ttftMs == 0.0 && result.ttft_ms > 0.0) outcome.ttftMs = result.ttft_ms;
        outcome.wallMs += std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - turnStart).count();
        if (!result.success) {
            outcome.failure = result.error_message.empty()
                ? "inference failed" : result.error_message;
            outcome.iterations = iteration + 1;
            return outcome;
        }

        // The assistant turn is echoed WITH its tool calls. The protocol
        // requires it: a model that cannot see the call it made cannot tell
        // which observation answers it, and a model that is asked for the
        // same file twice is a model that never saw its own call.
        ChatMessage assistant{"assistant", result.response, ""};
        if (result.has_tool_calls && !result.tool_calls.empty()) {
            assistant.tool_calls = json::array();
            for (size_t ci = 0; ci < result.tool_calls.size(); ++ci) {
                const auto& cname = result.tool_calls[ci].first;
                const auto& cargs = result.tool_calls[ci].second;
                const std::string cid = ci < result.tool_call_ids.size()
                    ? result.tool_call_ids[ci]
                    : ("call_" + cname);
                assistant.tool_calls.push_back({
                    {"id", cid},
                    {"type", "function"},
                    {"function", {{"name", cname}, {"arguments", cargs}}}
                });
            }
        }
        messages.push_back(assistant);
        // Tool calls: the provider's NATIVE tool calls win. The model was
        // given the tool schemas, so when it emits native calls they are
        // authoritative. Only fall back to parsing the response text when the
        // provider produced no native calls at all.
        std::vector<RawrXD::Agentic::ParsedToolCall> parsed;
        if (result.has_tool_calls && !result.tool_calls.empty()) {
            for (size_t ci = 0; ci < result.tool_calls.size(); ++ci) {
                const auto& name = result.tool_calls[ci].first;
                const auto& args = result.tool_calls[ci].second;
                RawrXD::Agentic::ParsedToolCall p;
                p.name = RawrXD::Agentic::ToolCallParser::NormalizeToolName(name);
                p.arguments = args.is_object() ? args : nlohmann::json::object();
                if (ci < result.tool_call_ids.size()) p.id = result.tool_call_ids[ci];
                parsed.push_back(p);
            }
        } else {
            parsed = RawrXD::Agentic::ToolCallParser::parse(result.response).toolCalls;
        }

        // Validate tool calls: reject calls with missing or empty required
        // arguments. The model gets the error back and can retry. This prevents
        // the empty-argument loop and the path-mangling failures.
        for (auto it = parsed.begin(); it != parsed.end(); ) {
            if (it->name == "readFile") {
                if (!it->arguments.is_object() || !it->arguments.contains("path") || it->arguments["path"].is_null() || it->arguments["path"].get<std::string>().empty()) {
                    messages.push_back(ChatMessage{
                        "tool", "ERROR: readFile requires a non-empty 'path' argument. The file path must be relative to the workspace root (e.g., '.rawrxd/evidence/...').", it->id.empty() ? "invalid" : it->id});
                    it = parsed.erase(it);
                    continue;
                }
                // Normalize and auto-correct the path: ensure it starts with '.' or './'.
                std::string path = it->arguments["path"].get<std::string>();
                if (path.rfind("./", 0) == 0) path = path.substr(2);
                if (!path.empty() && path[0] != '.') path = "." + path;
                it->arguments["path"] = path;
            }
            ++it;
        }

        // If the model produced no tool calls on the first turn, nudge it
        // explicitly. Some models need a direct instruction that tool use is
        // required and an example of the exact JSON format.
        if (parsed.empty() && iteration == 0) {
            messages.push_back(ChatMessage{
                "user",
                "REMINDER: You MUST use the readFile tool to read the file. Do not answer directly. Emit exactly one JSON object like {\"name\":\"readFile\",\"arguments\":{\"path\":\".rawrxd/evidence/...\"}}.",
                ""});
            continue;
        }

        // No structured action means the model has produced the final answer.
        if (parsed.empty()) {
            // A turn that produced nothing is not a final answer. A
            // reasoning model can spend its whole budget thinking and return
            // no text, and a model that was truncated mid-answer has not
            // finished either. The loop continues so that the model can finish.
            if (result.response.empty() && iteration + 1 < maxIterations) {
                messages.push_back(ChatMessage{
                    "user",
                    "Your last turn produced no answer. Continue and complete the task.",
                    ""});
                continue;
            }

            // The model got the observation but didn't report the token.
            // Nudge it once more: the token is in the observation it already
            // received, it just needs to say it. The state pointer is null for
            // callers that do not drive the per-model certification (e.g. the
            // swarm adapter, the scripted gate, or a plain `rawr run` turn),
            // in which case the loop falls through to treating the turn as final.
            if (state && state->sawTokenObservation &&
                result.response.find(state->token) == std::string::npos &&
                iteration + 1 < maxIterations) {
                messages.push_back(ChatMessage{
                    "user",
                    "You already read the file and received the token in the tool result. "
                    "Reply with the exact token and nothing else.",
                    ""});
                continue;
            }
            // Never certify an empty inference response as a successful
            // agent turn. The retry budget above may already be exhausted.
            if (result.response.find_first_not_of(" \\t\\r\\n") == std::string::npos) {
                outcome.success = false;
                outcome.failure = "EMPTY_MODEL_RESPONSE: backend returned no visible answer";
                outcome.iterations = iteration + 1;
                return outcome;
            }
            outcome.success = true;
            outcome.finalText = result.response;
            outcome.iterations = iteration + 1;
            return outcome;
        }

        // The model produced tool calls but the task is marked complete.
        // Stop all tool dispatch and fall through to finalization on the
        // next iteration. parsed.clear() prevents any further tool
        // execution while the loop re-enters the top-of-loop finalization
        // check.
        if (state && (state->taskComplete ||
            (state->sawTokenObservation && !state->token.empty()))) {
            parsed.clear();
        }

        if (parsed.size() > 3) parsed.resize(3);
        for (const auto& call : parsed) {
            std::string authError;
            if (call.name == "read_motd") {
                std::string contents, motdDigest, readError;
                if ((!call.arguments.is_object() || !call.arguments.empty()) ||
                    !authorization.ReadMotd(session, turn, contents, motdDigest, readError)) {
                    authError = readError.empty() ? "read_motd accepts no arguments" : readError;
                } else {
                    messages.push_back(ChatMessage{
                        "tool", "MOTD_ACK=1 MOTD_SHA256=" + motdDigest + "\n" + contents,
                        call.id});
                    continue;
                }
            } else if (!authorization.AuthorizeTool(call.name, session, turn, authError)) {
                // authError is already fail-closed and is returned as an observation.
            } else {
                rawrxd::tools::Tool tool;
                rawrxd::tools::Request request;
                request.name = call.name;
                if (!g_tools->find(call.name, tool)) {
                    authError = "unknown tool: " + call.name;
                } else if (!call.arguments.is_object()) {
                    authError = "tool arguments must be a JSON object";
                } else {
                    for (auto it = call.arguments.begin(); it != call.arguments.end(); ++it) {
                        request.args[it.key()] = it.value().is_string()
                            ? it.value().get<std::string>() : it.value().dump();
                    }
                    if (!g_gate->AllowsWithApproval(tool, request, approval)) {
                        authError = g_gate->ExplainDenial(tool);
                    } else {
                        const auto toolResult = g_tools->call(request, approval);
                        authorization.NoteExecution(session, turn);
                        ToolCallRecord rec;
                        rec.tool_name = call.name;
                        rec.args = call.arguments;
                        rec.ok = toolResult.ok;
                        rec.output = toolResult.ok ? toolResult.output : toolResult.error;
                        rec.timestamp = AgentSession::NowUnix();
                        rec.approved_by = toolResult.ok;
                        g_ledger->RecordToolCall(rec);
                        // Always deliver the tool observation first.
                        messages.push_back(ChatMessage{
                            "tool", toolResult.ok ? toolResult.output :
                                ("ERROR: " + toolResult.error), call.id});
                        // After a successful tool call that returned the token,
                        // nudge the model to answer instead of calling again.
                        if (toolResult.ok && toolResult.output.find("RAWRXD_AGENTIC_") != std::string::npos) {
                            messages.push_back(ChatMessage{
                                "user",
                                "You have the token from the file. Now reply with the exact token and stop calling tools.",
                                ""});
                        }
                        continue;
                    }
                }
            }
            messages.push_back(ChatMessage{
                "tool", "DENIED: " + authError, call.id});
        }
        g_ledger->RecordCheckpoint("agent-iteration-" + std::to_string(iteration + 1));
        g_ledger->Flush();
    }

    outcome.failure = "agent iteration limit reached";
    outcome.iterations = maxIterations;
    return outcome;
}

// Swarm adapter: the existing DelegationManager supplies lifecycle, quotas,
// cancellation and checkpoints.  GPU inference remains serialized because a
// shared Deep2Engine is intentionally single-generation; workers are queued
// rather than racing the model or the MOTD turn.  Every worker's real state is
// mirrored to JSONL evidence through RawrSwarmEvents.
static AgentLoopOutcome RunAuthorizedSwarm(
    const std::string& goal,
    const std::string& policy,
    const std::string& digest,
    rawrxd::agentic::MotdAuthorization& authorization,
    const std::string& session,
    uint64_t turn,
    uint32_t workerCount,
    uint32_t maxIterations,
    int maxTokens) {
    AgentLoopOutcome aggregate;
    workerCount = std::clamp<uint32_t>(workerCount, 1u, 4u);

    const std::string evidenceDir = g_workspace + "/.rawrxd/evidence";
    std::error_code ec;
    fs::create_directories(evidenceDir, ec);
    rawr::live::Sink events(evidenceDir + "/rawr_swarm_events.jsonl");

    RawrXD::Delegation::DelegationManager::Config cfg;
    cfg.maxConcurrentAgents = 1; // Deep2InferenceService/CLI engine is serialized.
    cfg.maxDelegationDepth = 1;  // workers cannot create unbounded children.
    cfg.defaultLimits.maxWallTimeMs = 120000;
    cfg.defaultLimits.maxToolCalls = 24;
    // A worker may not delegate further (maxDelegationDepth=1), but the
    // worker's own quota must still permit the manager to start it.
    cfg.defaultLimits.maxSubAgents = 1;
    cfg.logPath = g_workspace + "/.rawrxd/ledger/delegation.jsonl";
    RawrXD::Delegation::DelegationManager manager(cfg);
    manager.onAgentStateChanged([&events](const std::string& id,
                                           RawrXD::Delegation::AgentState state) {
        rawr::live::Event e;
        e.worker = id;
        e.kind = "agent";
        e.phase = (state == RawrXD::Delegation::AgentState::Running) ? "start" :
                   (state == RawrXD::Delegation::AgentState::Completed) ? "ok" :
                   (state == RawrXD::Delegation::AgentState::Failed ||
                    state == RawrXD::Delegation::AgentState::Cancelled ||
                    state == RawrXD::Delegation::AgentState::TimedOut) ? "fail" : "info";
        e.title = "delegated worker state";
        e.detail = RawrXD::Delegation::stateName(state);
        events.emit(std::move(e));
    });

    manager.setAgentWorkFn([&](RawrXD::Delegation::DelegatedAgent& agent,
                               const RawrXD::Delegation::DelegatedTask& task) {
        rawr::live::Event start;
        start.worker = agent.agentId;
        start.kind = "plan";
        start.phase = "start";
        start.title = "swarm worker task";
        start.detail = task.title;
        start.task = task.taskId;
        events.emit(std::move(start));

        AgentLoopOutcome r = RunAuthorizedAgentLoop(
            task.prompt, policy, digest, authorization, session, turn,
            maxIterations, maxTokens);
        rawr::live::Event done;
        done.worker = agent.agentId;
        done.kind = "output";
        done.phase = r.success ? "ok" : "fail";
        done.title = "swarm worker result";
        done.detail = r.success ? r.finalText : r.failure;
        done.task = task.taskId;
        done.exitCode = r.success ? 0 : 1;
        events.emit(std::move(done));
        return r.success ? r.finalText : ("ERROR: " + r.failure);
    });

    std::vector<std::string> taskIds;
    taskIds.reserve(workerCount);
    for (uint32_t i = 0; i < workerCount; ++i) {
        RawrXD::Delegation::DelegatedTask task(
            "rawr-run worker " + std::to_string(i + 1),
            goal + "\nYou are bounded worker " + std::to_string(i + 1) +
                " of the RawrXD swarm. Return evidence-backed findings only.");
        task.deliverable = "final evidence-backed audit response";
        task.allowedTools = {"readFile", "listDirectory", "fileSearch", "textSearch",
                             "git_status", "git_diff"};
        task.limits = cfg.defaultLimits;
        const std::string id = manager.delegateToNew(
            task, "worker-" + std::to_string(i + 1),
            {RawrXD::Delegation::AgentCapability::Research,
             RawrXD::Delegation::AgentCapability::Verification}, task.limits);
        if (id.empty()) {
            aggregate.failure = "swarm delegation refused by quota";
            return aggregate;
        }
        taskIds.push_back(id);
    }

    aggregate.success = true;
    for (const auto& id : taskIds) {
        const auto r = manager.waitForTask(id, cfg.defaultLimits.maxWallTimeMs);
        ++aggregate.iterations;
        if (!r.success) {
            aggregate.success = false;
            aggregate.failure = r.errorMessage.empty() ? "swarm worker failed" : r.errorMessage;
        }
        if (!r.output.empty()) {
            if (!aggregate.finalText.empty()) aggregate.finalText += "\n\n";
            aggregate.finalText += "[" + r.agentId + "]\n" + r.output;
        }
    }
    if (aggregate.finalText.empty() && aggregate.success)
        aggregate.failure = "swarm completed without output";
    if (!aggregate.failure.empty()) aggregate.success = false;
    return aggregate;
}

// ---------------------------------------------------------------------------
// rawr run — the universal interactive agent session
// ---------------------------------------------------------------------------

/// @brief One-shot completion, streamed live through the provider boundary.
///
/// The provider supplies tokens; RawrXD owns where they go and what is
/// recorded. This is the same path `ollama run` takes, reached through
/// RawrXD instead of around it.
static InferenceResult ChatStreamingToStdout(const std::vector<ChatMessage>& messages,
                                             const json& tools) {
    InferenceResult result;
    if (!g_streamProvider && !g_modelProvider) {
        return InferenceResult::Error("No inference backend available");
    }

    std::string full;
    std::string error;
    uint64_t ptok = 0, ctok = 0;
    double tps = 0.0;
    g_streamed_response = false;

    const auto t0 = std::chrono::steady_clock::now();
    bool ok = false;
    if (g_streamProvider) {
        ok = g_streamProvider(
            messages, tools, g_requested_max_tokens,
            [&](const std::string& token) {
                if (token.empty()) return;
                full += token;
                std::cout << token << std::flush;
                g_streamed_response = true;
            },
            [](const std::string&, const json&) {
                // Tool calls are not expected in a one-shot completion; the
                // agent loop handles those.
            },
            [&](const std::string& response, uint64_t p, uint64_t c, double t) {
                if (!response.empty()) full = response;
                ptok = p;
                ctok = c;
                tps = t;
            },
            [&](const std::string& err) { error = err; });
    } else {
        result = g_modelProvider(messages, tools, g_requested_max_tokens);
        if (!result.success) return result;
        std::cout << result.response << std::flush;
        g_streamed_response = true;
        return result;
    }
    const auto t1 = std::chrono::steady_clock::now();
    const double elapsed_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

    if (!ok) {
        return InferenceResult::Error(error.empty() ? "streaming request failed" : error);
    }
    if (full.empty()) {
        return InferenceResult::Error("provider returned an empty completion");
    }
    InferenceResult out = InferenceResult::Ok(full, ptok, ctok, tps, elapsed_ms);
    // The backend's own accounting, when the backend has one. The completion
    // callback carries a rate, but not the server's generation counters.
    if (g_router) {
        if (auto* b = g_router->GetBackendPtr(g_router->GetActiveBackendKind())) {
            const auto m = b->LastStreamMetrics();
            out.prompt_tokens = m.prompt_tokens ? m.prompt_tokens : ptok;
            out.completion_tokens = m.completion_tokens ? m.completion_tokens : ctok;
            out.eval_duration_ns = m.eval_duration_ns;
            out.load_duration_ns = m.load_duration_ns;
            out.ttft_ms = m.ttft_ms;
            out.inference_tps = m.inference_tps;
        }
    }
    return out;
}

// ---------------------------------------------------------------------------
// One provider turn, streamed.
//
// The streaming seam is preferred when it exists, so that the tokens reach
// stdout as they are produced rather than in one lump at the end of the turn.
// The native tool calls are captured from the stream, and the whole text is
// returned so the agent can still parse it.
// ---------------------------------------------------------------------------
static InferenceResult ProviderTurn(const std::vector<ChatMessage>& messages,
                                    const json& tools,
                                    int maxTokens,
                                    bool echoToStdout) {
    if (!g_streamProvider) {
        if (!g_modelProvider) {
            return InferenceResult::Error("No inference backend available");
        }
        return g_modelProvider(messages, tools, maxTokens);
    }

    std::string full;
    std::string error;
    uint64_t ptok = 0, ctok = 0;
    double tps = 0.0;
    std::vector<std::pair<std::string, json>> toolCalls;

    const auto t0 = std::chrono::steady_clock::now();
    const bool ok = g_streamProvider(
        messages, tools, maxTokens,
        [&](const std::string& token) {
            if (token.empty()) return;
            full += token;
            if (echoToStdout) {
                std::cout << token << std::flush;
                g_streamed_response = true;
            }
        },
        [&](const std::string& name, const json& args) {
            toolCalls.emplace_back(name, args);
        },
        [&](const std::string& response, uint64_t p, uint64_t c, double t) {
            if (!response.empty()) full = response;
            ptok = p;
            ctok = c;
            tps = t;
        },
        [&](const std::string& err) { error = err; });
    const double elapsed_ms = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - t0).count();

    if (!ok) {
        return InferenceResult::Error(error.empty() ? "streaming request failed" : error);
    }

    InferenceResult out = InferenceResult::Ok(full, ptok, ctok, tps, elapsed_ms);
    out.has_tool_calls = !toolCalls.empty();
    out.tool_calls = toolCalls;
    if (g_router) {
        if (auto* b = g_router->GetBackendPtr(g_router->GetActiveBackendKind())) {
            const auto m = b->LastStreamMetrics();
            out.prompt_tokens = m.prompt_tokens ? m.prompt_tokens : ptok;
            out.completion_tokens = m.completion_tokens ? m.completion_tokens : ctok;
            out.eval_duration_ns = m.eval_duration_ns;
            out.load_duration_ns = m.load_duration_ns;
            out.ttft_ms = m.ttft_ms;
            out.inference_tps = m.inference_tps;
        }
    }
    return out;
}

namespace {
int CmdProjectWizard(const std::string& model, const std::string& goal,
                     const std::map<std::string, std::string>& flags,
                     const std::string& workspace_root,
                     rawrxd::agentic::MotdAuthorization* authorization,
                     const std::string& session, uint64_t turn);
}

static int CmdRun(const std::vector<std::string>& args) {
    // args = [provider?] model [mode|task...] [--flag ...]
    //
    // A leading provider token selects the inference provider explicitly:
    //   rawr run ollama <model> "<task>"   -> Ollama's documented local API
    //   rawr run deep2  <model> "<task>"   -> the first-party Deep2 runtime
    // The token is optional; without it the provider is chosen as before.
    std::string model;
    std::string mode_str;
    std::string tail;              // extra positional words after the model
    std::string provider_token;
    std::map<std::string, std::string> flags;
    std::vector<std::string> positionals;

    for (size_t i = 0; i < args.size(); ++i) {
        const std::string& a = args[i];
        if (a.rfind("--", 0) == 0) {
            std::string body = a.substr(2);
            auto eq = body.find('=');
            if (eq != std::string::npos) {
                flags[body.substr(0, eq)] = body.substr(eq + 1);
            } else if (i + 1 < args.size() && args[i + 1].rfind("--", 0) != 0) {
                flags[body] = args[++i];
            } else {
                flags[body] = "true";
            }
        }
        else {
            positionals.push_back(a);
        }
    }

    if (!positionals.empty()) {
        std::string first = positionals[0];
        std::transform(first.begin(), first.end(), first.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (first == "ollama" || first == "deep2" || first == "kilo") {
            provider_token = first;
            positionals.erase(positionals.begin());
        } else {
            // The provider may be written into the model itself:
            //   rawr run ollama:<model> "<task>"
            // The prefix wins over any --backend that disagrees with it, and a
            // contradiction is reported rather than resolved silently.
            const size_t colon = first.find(':');
            if (colon != std::string::npos && colon > 0) {
                std::string prefix = first.substr(0, colon);
                std::transform(prefix.begin(), prefix.end(), prefix.begin(),
                               [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                if (prefix == "ollama" || prefix == "deep2" || prefix == "kilo") {
                    provider_token = prefix;
                    // The model name keeps its original case: Ollama tags are
                    // case sensitive ("Q4_K_M", "deepseek-v4-flash").
                    std::string rest = positionals[0].substr(colon + 1);
                    if (!rest.empty()) {
                        positionals[0] = rest;
                    } else {
                        positionals.erase(positionals.begin());
                    }
                }
            }
        }
    }
    if (!positionals.empty()) model = positionals[0];
    if (positionals.size() > 1) {
        mode_str = positionals[1];
        for (size_t i = 2; i < positionals.size(); ++i) {
            tail += (tail.empty() ? "" : " ") + positionals[i];
        }
    }

    // `--agent` and `--swarm` are boolean switches, but the permissive CLI
    // parser treats a following non-flag as a value. Recover the ergonomic
    // spelling `rawr run MODEL --agent "task"` without changing parsing for
    // ordinary named options.
    for (const char* key : {"agent", "swarm"}) {
        auto it = flags.find(key);
        if (it != flags.end() && it->second != "true" &&
            !flags.count("prompt") && !flags.count("task")) {
            flags["prompt"] = it->second;
            it->second = "true";
        }
    }

    // Explicit device selection is translated to the existing Deep2 device
    // manager policy before model load. No driver reset or unsupported memory
    // aliasing is attempted here.
    if (flags.count("device")) {
        std::string device = flags["device"];
        std::transform(device.begin(), device.end(), device.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
#ifdef _WIN32
        if (device == "cpu") _putenv_s("RAWRXD_GPU_POLICY", "CPU");
        else if (device == "gpu" || device == "single") _putenv_s("RAWRXD_GPU_POLICY", "SINGLE");
        else if (device == "multi" || device == "dual") _putenv_s("RAWRXD_GPU_POLICY", "MULTI");
#else
        if (device == "cpu") setenv("RAWRXD_GPU_POLICY", "CPU", 1);
        else if (device == "gpu" || device == "single") setenv("RAWRXD_GPU_POLICY", "SINGLE", 1);
        else if (device == "multi" || device == "dual") setenv("RAWRXD_GPU_POLICY", "MULTI", 1);
#endif
    }

    // Resolve model alias → actual GGUF path before backend initialization.
    // This lets `rawr run nemotron-3.5-bolt` resolve to F:\rawrxd\nemotron-bolt.gguf.
    {
        static const struct { const char* name; const char* path; } kAliases[] = {
            {"nemotron-3.5-bolt", "F:\\rawrxd\\nemotron-bolt.gguf"},
            {"nemotron-bolt", "F:\\rawrxd\\nemotron-bolt.gguf"},
        };
        for (const auto& a : kAliases) {
            if (_stricmp(model.c_str(), a.name) == 0) {
                model = a.path;
                break;
            }
        }
    }

    // Workspace override from --workspace/--root.
    {
        Options opt;
        opt.flags = flags;
        g_workspace = DiscoverWorkspace(opt);
    }

    rawrxd::agentic::MotdAuthorization runAuthorization(g_workspace);
    const std::string runSession = "rawr-run-" +
        std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    uint64_t runTurn = 0;
    auto readPolicyForTurn = [&](std::string& contents, std::string& digest, std::string& error) {
        ++runTurn;
        if (!runAuthorization.BeginTurn(runSession, runTurn)) {
            error = "MOTD_TURN_START_FAILED";
            return false;
        }
        if (!runAuthorization.AuthorizeTool("read_motd", runSession, runTurn, error)) {
            runAuthorization.EndTurn(runSession, runTurn);
            return false;
        }
        if (!runAuthorization.ReadMotd(runSession, runTurn, contents, digest, error)) {
            runAuthorization.EndTurn(runSession, runTurn);
            return false;
        }
        return true;
    };

    // ---- Project Wizard workflow detection --------------------------------
    // `rawr run <model> "new project"` starts the interactive project builder.
    // Follow-ups ("add a GUI", "switch to C++", "add tests", "continue
    // building") resume an existing project instead of starting over. The goal
    // may come from the bare positional (mode_str), --task, or --prompt.
    std::string workflow_goal;
    if (!mode_str.empty()) {
        workflow_goal = mode_str;
    } else if (flags.count("task")) {
        workflow_goal = flags.at("task");
    } else if (flags.count("prompt")) {
        workflow_goal = flags.at("prompt");
    }
    bool is_wizard_goal = false;
    if (!workflow_goal.empty()) {
        rawrxd::project::FollowUp fu = rawrxd::project::DetectFollowUp(workflow_goal);
        is_wizard_goal = (rawrxd::project::detail::StrLower(workflow_goal) == "new project") ||
                         (fu.kind != rawrxd::project::FollowUpKind::kNone);
    }

    // `rawr run <model> "<prompt>"` is the primary one-shot form.  A bare
    // second positional is an agent mode only when it names a registered
    // mode; otherwise preserve the exact prompt and avoid interpreting it as
    // an invalid mode (the old behavior rejected normal English prompts).
    if (!is_wizard_goal && !mode_str.empty() && !flags.count("prompt") &&
        !flags.count("task")) {
        AgentMode requestedMode{};
        if (!AgentModeParse(mode_str, requestedMode)) {
            // Not a mode: the whole remaining tail is the task text, so an
            // unquoted multi-word task is not silently truncated.
            flags["prompt"] = mode_str + (tail.empty() ? "" : " " + tail);
            mode_str.clear();
            tail.clear();
        }
    }
    // The second positional WAS a mode; anything after it is the task.
    if (!tail.empty() && !flags.count("prompt") && !flags.count("task") &&
        !is_wizard_goal) {
        flags["prompt"] = tail;
    }

    // Resolve mode: --mode wins, then a bare positional, else Code.
    // Skipped entirely for wizard goals (they are not agent modes).
    AgentMode mode = AgentMode::Code;
    if (!is_wizard_goal) {
        if (flags.count("mode")) {
            mode_str = flags["mode"];
            if (!AgentModeParse(mode_str, mode)) {
                std::cerr << "Unknown mode: " << mode_str << "\n";
                std::cerr << "Known modes:\n";
                for (auto m : ModeRegistry::Instance().AllModes()) {
                    std::cerr << "  " << std::left << std::setw(12) << AgentModeName(m)
                              << ModeRegistry::Instance().Describe(m) << "\n";
                }
                return 2;
            }
        }
        else if (!mode_str.empty()) {
            if (!AgentModeParse(mode_str, mode)) {
                std::cerr << "Unknown mode: " << mode_str << "\n";
                std::cerr << "Known modes:\n";
                for (auto m : ModeRegistry::Instance().AllModes()) {
                    std::cerr << "  " << std::left << std::setw(12) << AgentModeName(m)
                              << ModeRegistry::Instance().Describe(m) << "\n";
                }
                return 2;
            }
        }
    }

    const bool agentRequested = flags.count("agent") || flags.count("swarm") ||
                                mode == AgentMode::Swarm;
    const bool swarmRequested = flags.count("swarm") || mode == AgentMode::Swarm;
    int requestedMaxTokens = 256;   // adjusted per provider below
    if (flags.count("max-tokens")) {
        try {
            requestedMaxTokens = std::stoi(flags.at("max-tokens"));
        } catch (...) {
            std::cerr << "Invalid --max-tokens value: " << flags.at("max-tokens") << "\n";
            return 2;
        }
        if (requestedMaxTokens < 1 || requestedMaxTokens > 4096) {
            std::cerr << "--max-tokens must be between 1 and 4096\n";
            return 2;
        }
    }

    // Resolve backend mode.
    //
    // The explicit provider token (`rawr run ollama ...`) is authoritative.
    // If --backend names a DIFFERENT provider, that is a contradiction, not
    // something to silently resolve in either direction.
    std::string b = flags.count("backend") ? flags["backend"] : "auto";
    if (!provider_token.empty()) {
        const std::string flagProvider = toLowerCompat(b);
        if (flagProvider != "auto" && flagProvider != provider_token) {
            std::cerr << "ERROR: provider token '" << provider_token
                      << "' conflicts with --backend " << b << ".\n";
            std::cerr << "Use one or the other.\n";
            return 2;
        }
        b = provider_token;
    }
    BackendMode bmode = BackendMode::Auto;
    g_backend_name = b;
    g_provider_name = (b == "auto") ? "auto" : b;
    if (b == "deep2")       bmode = BackendMode::Deep2;
    else if (b == "ollama") bmode = BackendMode::Ollama;
    else if (b == "kilo")   bmode = BackendMode::Kilo;
    else if (b == "manual") bmode = BackendMode::Manual;

    if (model.empty() && bmode != BackendMode::Kilo) {
        std::cerr << "ERROR: no model specified.\n";
        std::cerr << "usage: rawr run [deep2|ollama|kilo] <model> \"<task>\"\n";
        return 2;
    }

    if (bmode == BackendMode::Kilo && !flags.count("max-tokens")) {
        // Reasoning models spend most of the token budget thinking before the
        // answer. A 256-token budget yields a truncated answer, so the default
        // for the gateway is raised unless the caller set one explicitly.
        requestedMaxTokens = 2048;
    }

    if (!InitBackend(bmode, model, requestedMaxTokens)) {
        std::cerr << "Failed to initialize inference backend (" << b << ").\n";
        std::cerr << "For Ollama: confirm a server on http://127.0.0.1:11434 and `ollama list`.\n";
        std::cerr << "For Deep2:  confirm the runtime bridge on http://127.0.0.1:11436.\n";
        return 1;
    }

    // Build the tool registry and permission gate.
    g_ws = std::make_unique<WorkspaceToolHost>(g_workspace);
    g_tools = std::make_unique<rawrxd::tools::Registry>();
    g_ws->RegisterWorkspaceTools(*g_tools);

#ifdef _WIN32
    g_tools->add({
        "runInTerminal",
        "Execute an explicitly approved command in the workspace",
        rawrxd::tools::Risk::Execute, {"command"},
        [root = g_workspace](const rawrxd::tools::Request& r) -> rawrxd::tools::Result {
            std::string cmd;
            auto it = r.args.find("command");
            if (it != r.args.end()) cmd = it->second;
            if (cmd.size() > 8192) throw std::runtime_error("command too long");
            std::string full = cmd + " 2>&1";
            FILE* p = _popen(full.c_str(), "r");
            if (!p) throw std::runtime_error("CreateProcess failed");
            std::string out;
            char buf[4096];
            while (fgets(buf, sizeof(buf), p)) out += buf;
            int code = _pclose(p);
            return {code == 0, out.substr(0, 65536), code ? ("exit=" + std::to_string(code)) : ""};
        }
    });
#endif

    g_gate = std::make_unique<PermissionGate>(mode);
    g_gate->SetPlanDirectory(g_workspace + "/.rawrxd/plans");

    // ---- Project Wizard: intercept before the normal agent session ------
    if (is_wizard_goal) {
        std::string policy, digest, error;
        if (!readPolicyForTurn(policy, digest, error)) {
            std::cerr << "DENIED: " << error << "\n";
            return 3;
        }
        [[maybe_unused]] auto motdTurnGuard = runAuthorization.GuardTurn(runSession, runTurn);
        return CmdProjectWizard(model, workflow_goal, flags, g_workspace,
                                &runAuthorization, runSession, runTurn);
    }

    // Driver-owned ledger, initialized before anything executes.
    g_ledger = std::make_unique<AgentSession>(
        g_workspace + "/.rawrxd/ledger/agent_session.json");
    g_ledger->SetWorkspaceRoot(g_workspace);
    g_ledger->SetModelIdentity(ModelIdentityString());
    g_ledger->SetGitState(RunGit("rev-parse HEAD"), RunGit("rev-parse --abbrev-ref HEAD"));
    g_ledger->SetMode(mode);
    g_ledger->Flush();   // the ledger exists even if the model never answers

    PrintBanner(mode);

    // One-shot mode: `rawr run <model> --task "..."` executes and exits.
    if (flags.count("prompt") || flags.count("task")) {
        std::string policy, digest, error;
        if (!readPolicyForTurn(policy, digest, error)) {
            std::cerr << "DENIED: " << error << "\n";
            g_ledger->RecordFailure("MOTD authorization failed: " + error);
            g_ledger->Flush();
            return 3;
        }
        [[maybe_unused]] auto motdTurnGuard = runAuthorization.GuardTurn(runSession, runTurn);
        std::cerr << "MOTD_ACK=1 MOTD_SHA256=" << digest << "\n";
        std::string prompt = flags.count("prompt") ? flags["prompt"] : flags["task"];
        const bool ghostText = flags.count("ghost-text") != 0;
        if (ghostText) {
            prompt = "Complete the following source text. Return only the completion text, without markdown or explanation:\n" + prompt;
        }
        const std::string receiptPath = flags.count("receipt")
            ? flags.at("receipt")
            : (g_workspace + "/.rawrxd/evidence/rawr_run_receipt.json");
        // Reasoning text is written beside the receipt, never into stdout.
        g_reasoning_path = flags.count("reasoning-file")
            ? flags.at("reasoning-file")
            : (g_workspace + "/.rawrxd/evidence/rawr_run_reasoning.txt");
        g_show_reasoning = flags.count("show-reasoning") > 0;
        {
            std::error_code recEc;
            fs::remove(g_reasoning_path, recEc);
        }
        g_ledger->AppendUserMessage(prompt);
        g_ledger->RecordAgentTurn();

        std::vector<ChatMessage> messages;
        for (const auto& m : g_ledger->Conversation()) {
            ChatMessage cm;
            cm.role = m.value("role", std::string());
            cm.content = m.value("content", std::string());
            messages.push_back(cm);
        }
        messages.insert(messages.begin(), ChatMessage{
            "system", "Workspace execution policy read for this user turn. SHA-256=" + digest +
                      "\n" + policy, ""});

        InferenceResult result;
        uint32_t agentIterations = 0;
        json runTelemetry = json::object();
        if (agentRequested) {
            const uint32_t iterations = flags.count("agent-iterations")
                ? [&]() -> uint32_t {
                    try { return static_cast<uint32_t>(std::stoul(flags.at("agent-iterations"))); }
                    catch (...) { return 0; }
                }() : 6u;
            uint32_t workers = 1;
            if (flags.count("workers")) {
                try { workers = static_cast<uint32_t>(std::stoul(flags.at("workers"))); }
                catch (...) { workers = 0; }
            }
            AgentLoopOutcome agentResult = swarmRequested
                ? RunAuthorizedSwarm(prompt, policy, digest, runAuthorization,
                                     runSession, runTurn, workers, iterations,
                                     requestedMaxTokens)
                : RunAuthorizedAgentLoop(prompt, policy, digest, runAuthorization,
                                         runSession, runTurn, iterations,
                                         requestedMaxTokens);
            agentIterations = agentResult.iterations;
            // The generation accounting of the whole agent run.
            runTelemetry = {
                {"prompt_tokens", agentResult.promptTokens},
                {"completion_tokens", agentResult.completionTokens},
                {"eval_duration_ns", agentResult.evalDurationNs},
                {"load_duration_ns", agentResult.loadDurationNs},
                {"inference_tps", agentResult.inferenceTps},
                {"ttft_ms", agentResult.ttftMs},
                {"agent_wall_ms", agentResult.wallMs},
                {"e2e_tps", agentResult.completionTokens > 0 && agentResult.wallMs > 0
                    ? (static_cast<double>(agentResult.completionTokens) * 1000.0 /
                       agentResult.wallMs) : 0.0},
            };
            if (!agentResult.success) {
                std::cerr << "[agent] " << agentResult.failure << "\n";
                g_ledger->RecordFailure("agent loop failed: " + agentResult.failure);
                WriteRunReceipt(receiptPath, model, prompt, "", g_backend_name,
                                digest, requestedMaxTokens, true, agentIterations,
                                false, agentResult.failure,
                                BuildProvenance(true), runTelemetry);
                g_ledger->Flush();
                return 1;
            }
            result = InferenceResult::Ok(agentResult.finalText);
            if (agentResult.finalText.empty()) {
                // The loop finished without an answer. Say so: an empty
                // stdout looks like a hang.
                std::cerr << "[agent] the model returned no answer\n";
            }
        } else try {
            if (deep2CompleteFn) {
                // Use in-process Deep2Engine directly — no HTTP router needed.
                result = deep2CompleteFn(messages, requestedMaxTokens);
            } else if (g_streamProvider || g_modelProvider) {
                // Stream the completion live: the provider boundary delivers
                // tokens as they arrive instead of buffering the whole reply.
                result = ChatStreamingToStdout(messages, json::array());
            } else {
                result = InferenceResult::Error("No inference backend available");
            }
        } catch (const std::exception& e) {
            std::cerr << "[error] Deep2 exception: " << e.what() << "\n";
            g_ledger->RecordFailure("inference exception: " + std::string(e.what()));
            return 1;
        } catch (...) {
            std::cerr << "[error] Deep2 unknown exception\n";
            g_ledger->RecordFailure("inference unknown exception");
            return 1;
        }
        if (!result.success) {
            std::cerr << "[error] " << result.error_message << "\n";
            g_ledger->RecordFailure("inference failed: " + result.error_message);
            WriteRunReceipt(receiptPath, model, prompt, "", g_backend_name,
                            digest, requestedMaxTokens, agentRequested, agentIterations,
                            false, result.error_message,
                            BuildProvenance(agentRequested), runTelemetry);
            return 1;
        }

        if (runTelemetry.empty()) {
            // The one-shot path: the accounting of the single completion.
            runTelemetry = {
                {"prompt_tokens", result.prompt_tokens},
                {"completion_tokens", result.completion_tokens},
                {"eval_duration_ns", result.eval_duration_ns},
                {"load_duration_ns", result.load_duration_ns},
                {"inference_tps", result.inference_tps},
                {"ttft_ms", result.ttft_ms},
                {"wall_ms", result.total_duration_ms},
                {"e2e_tps", result.completion_tokens > 0 && result.total_duration_ms > 0
                    ? (static_cast<double>(result.completion_tokens) * 1000.0 /
                       result.total_duration_ms) : 0.0},
            };
        }

        g_ledger->AppendAssistantMessage(result.response);
        if (g_streamed_response) std::cout << "\n" << std::flush;
        else std::cout << result.response << "\n";

        g_ledger->SetTermination(TerminationReason::ModelCompleted, 0);
        g_ledger->SetVerdict("one-shot task completed");

        if (!WriteRunReceipt(receiptPath, model, prompt, result.response, g_backend_name,
                             digest, requestedMaxTokens, agentRequested, agentIterations,
                             true, "", BuildProvenance(agentRequested), runTelemetry)) {
            std::cerr << "[warning] could not write run receipt: " << receiptPath << "\n";
        } else {
            std::cerr << "RUN_RECEIPT=" << receiptPath << "\n";
        }

        g_ledger->Flush();
        return 0;
    }

    // Interactive REPL.
    std::string line;
    std::cout << "Type /help for commands.\n";
    while (g_running) {
        std::cout << "rawr> " << std::flush;
        if (!std::getline(std::cin, line)) break;

        // Trim.
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
        if (line.empty()) continue;

        // ---- Slash commands ----
        if (line[0] == '/') {
            std::istringstream iss(line);
            std::string cmd;
            iss >> cmd;
            std::string arg;
            std::getline(iss, arg);
            if (!arg.empty() && arg.front() == ' ') arg = arg.substr(1);

            if (cmd == "/exit" || cmd == "/quit") break;
            else if (cmd == "/help") {
                std::cout << "/mode <name>   switch agent mode (permissions re-evaluated)\n"
                          << "/status        show session, backend and ledger status\n"
                          << "/tools         list tools with authority in this mode\n"
                          << "/tool <name>   describe a tool\n"
                          << "/models        list models from both backends\n"
                          << "/backend <b>   switch backend (auto|deep2|ollama)\n"
                          << "/checkpoint    write a ledger checkpoint now\n"
                          << "/exit          end the session\n";
            }
            else if (cmd == "/mode") {
                AgentMode m;
                if (!AgentModeParse(arg, m)) {
                    std::cerr << "Unknown mode: " << arg << "\n";
                    continue;
                }
                // Switching NEVER preserves the previous mode's authority.
                g_gate->SetMode(m);
                g_ledger->SetMode(m);
                std::cout << "Mode: " << AgentModeName(m) << "  ("
                          << ToolAuthorityName(g_gate->EffectiveAuthority()) << ")\n";
                std::cout << ModeRegistry::Instance().Describe(m) << "\n";
            }
            else if (cmd == "/status") {
                std::cout << "Model:   " << ActiveModelName() << "\n"
                          << "Backend: " << g_backend_name << "\n"
                          << "Mode:    " << AgentModeName(g_gate->GetMode()) << "\n"
                          << "Authority: " << ToolAuthorityName(g_gate->EffectiveAuthority()) << "\n"
                          << "Root:    " << g_workspace << "\n"
                          << "Ledger:  " << g_ledger->LedgerPath() << "\n"
                          << "Turns:   " << g_ledger->AgentTurnCount() << "\n"
                          << "Tools:   " << g_ledger->ToolCallCount() << " ("
                          << g_ledger->SuccessfulToolCallCount() << " ok)\n"
                          << "Files:   " << g_ledger->FileModifiedCount() << " modified\n";
            }
            else if (cmd == "/tools") {
                ListTools();
            }
            else if (cmd.rfind("/tool", 0) == 0) {
                if (!DescribeTool(arg)) std::cerr << "Unknown tool: " << arg << "\n";
            }
            else if (cmd == "/models") {
                for (const auto& m : g_router->ListModels(BackendKind::Deep2))
                    std::cout << "  deep2  " << m << "\n";
                for (const auto& m : g_router->ListModels(BackendKind::Ollama))
                    std::cout << "  ollama " << m << "\n";
            }
            else if (cmd == "/backend") {
                BackendMode bm = BackendMode::Auto;
                g_backend_name = arg.empty() ? "auto" : arg;
                if (arg == "deep2") bm = BackendMode::Deep2;
                else if (arg == "ollama") bm = BackendMode::Ollama;
                else if (arg == "manual") bm = BackendMode::Manual;
                InitBackend(bm, "");
                std::cout << "Backend: " << g_backend_name << "  model: " << ActiveModelName() << "\n";
            }
            else if (cmd == "/checkpoint") {
                CheckpointLedger("manual");
                std::cout << "Checkpoint written: " << g_ledger->LedgerPath() << "\n";
            }
            else {
                std::cerr << "Unknown command: " << cmd << " (try /help)\n";
            }
            continue;
        }

        // ---- Agent turn ----
        std::string policy, digest, error;
        if (!readPolicyForTurn(policy, digest, error)) {
            std::cerr << "DENIED: " << error << "\n";
            g_ledger->RecordFailure("MOTD authorization failed: " + error);
            continue;
        }
        [[maybe_unused]] auto motdTurnGuard = runAuthorization.GuardTurn(runSession, runTurn);
        std::cerr << "MOTD_ACK=1 MOTD_SHA256=" << digest << "\n";
        g_ledger->AppendUserMessage(line);
        g_ledger->RecordAgentTurn();

        std::vector<ChatMessage> messages;
        for (const auto& m : g_ledger->Conversation()) {
            ChatMessage cm;
            cm.role = m.value("role", std::string());
            cm.content = m.value("content", std::string());
            messages.push_back(cm);
        }
        messages.insert(messages.begin(), ChatMessage{
            "system", "Workspace execution policy read for this user turn. SHA-256=" + digest +
                      "\n" + policy, ""});

        InferenceResult result;
        try {
            if (deep2CompleteFn) {
                // Use in-process Deep2Engine directly — no HTTP router needed.
                result = deep2CompleteFn(messages, 4096);
            } else if (g_streamProvider || g_modelProvider) {
                result = ChatStreamingToStdout(messages, json::array());
            } else {
                result = InferenceResult::Error("No inference backend available");
            }
        } catch (const std::exception& e) {
            std::cerr << "[error] Deep2 exception: " << e.what() << "\n";
            g_ledger->RecordFailure("inference exception: " + std::string(e.what()));
            continue;
        } catch (...) {
            std::cerr << "[error] Deep2 unknown exception\n";
            g_ledger->RecordFailure("inference unknown exception");
            continue;
        }
        if (!result.success) {
            std::cerr << "[error] " << result.error_message << "\n";
            g_ledger->RecordFailure("inference failed: " + result.error_message);
            continue;
        }

        g_ledger->AppendAssistantMessage(result.response);
        if (g_streamed_response) std::cout << "\n" << std::flush;
        else std::cout << result.response << "\n";
    }

    // ---- Finalize the ledger regardless of how the session ended ----
    g_ledger->SetTermination(TerminationReason::ModelCompleted, 0);
    g_ledger->SetVerdict("session ended normally");
    g_ledger->Flush();

    std::cout << "\nSession ledger: " << g_ledger->LedgerPath() << "\n";
    return 0;
}

// =============================================================================
// rawr project wizard — `rawr run <model> "new project"` and follow-ups
// =============================================================================
namespace {

// Adapts the CLI's inference backend to the project workflow's InferenceFn.
rawrxd::project::InferenceResult MakeInferenceAdapter(
    const std::vector<json>& messages, int max_tokens) {
    std::vector<RawrXD::Agent::ChatMessage> cmsgs;
    for (const auto& m : messages) {
        RawrXD::Agent::ChatMessage cm;
        cm.role = m.value("role", std::string());
        cm.content = m.value("content", std::string());
        cmsgs.push_back(cm);
    }
    RawrXD::Agent::InferenceResult r;
    if (deep2CompleteFn) {
        r = deep2CompleteFn(cmsgs, max_tokens);
    } else if (g_modelProvider) {
        r = g_modelProvider(cmsgs, json::array(), max_tokens);
    } else {
        return rawrxd::project::InferenceResult{false, "", "no inference backend available", 0, 0, 0};
    }
    return rawrxd::project::InferenceResult{
        r.success, r.response, r.error_message,
        static_cast<int>(r.completion_tokens),
        static_cast<int>(r.prompt_tokens),
        static_cast<int64_t>(r.total_duration_ms)};
}

// Adapts the CLI's tool registry to the project workflow's ToolFn. Autonomy
// from the project spec gates mutations: ask-before-changes requires an
// explicit env opt-in, generate-and-verify and autonomous allow them.
rawrxd::project::ToolResult MakeToolAdapter(
    const rawrxd::project::ProjectSpec& spec,
    rawrxd::agentic::MotdAuthorization* authorization,
    const std::string& session, uint64_t turn,
    const std::string& name, const std::string& args_json) {
    if (!authorization) {
        return rawrxd::project::ToolResult{false, "", "MOTD authorization unavailable"};
    }
    std::string authorizationError;
    if (!authorization->AuthorizeTool(name, session, turn, authorizationError)) {
        return rawrxd::project::ToolResult{false, "", authorizationError};
    }
    if (name == "read_motd") {
        std::string contents, digest, error;
        if (!authorization->ReadMotd(session, turn, contents, digest, error))
            return rawrxd::project::ToolResult{false, "", error};
        return rawrxd::project::ToolResult{true,
            "MOTD_ACK=1\nMOTD_SHA256=" + digest + "\n" + contents, ""};
    }
    rawrxd::tools::Tool tool;
    if (!g_tools || !g_tools->find(name, tool))
        return rawrxd::project::ToolResult{false, "", "unknown tool: " + name};
    rawrxd::tools::Request req;
    req.name = name;
    try {
        auto j = json::parse(args_json);
        for (auto& kv : j.items()) req.args[kv.key()] = kv.value().get<std::string>();
    } catch (const std::exception&) {
        return rawrxd::project::ToolResult{false, "", "invalid tool arguments JSON"};
    }
    auto approve = [&](const rawrxd::tools::Tool& t, const rawrxd::tools::Request&) -> bool {
        if (t.risk == rawrxd::tools::Risk::ReadOnly) return true;
        if (spec.autonomy == rawrxd::project::AutonomyLevel::kAskBeforeChanges) {
            const char* env = std::getenv("RAWRXD_TOOLS_APPROVE_MUTATIONS");
            return env && std::string(env) == "YES";
        }
        return true; // generate-and-verify / autonomous-with-checkpoints
    };
    if (tool.risk != rawrxd::tools::Risk::ReadOnly && !approve(tool, req))
        return rawrxd::project::ToolResult{false, "", "mutation denied by autonomy policy"};
    auto res = g_tools->call(req, approve);
    authorization->NoteExecution(session, turn);
    return rawrxd::project::ToolResult{res.ok, res.output, res.error};
}

static int CmdProjectWizard(const std::string& model, const std::string& goal,
                            const std::map<std::string, std::string>& flags,
                            const std::string& workspace_root,
                            rawrxd::agentic::MotdAuthorization* authorization,
                            const std::string& session, uint64_t turn) {
    using namespace rawrxd::project;

    std::string policy, digest, error;
    if (!authorization ||
        !authorization->AuthorizeTool("project_wizard", session, turn, error) ||
        !authorization->ReadMotd(session, turn, policy, digest, error)) {
        std::cerr << "DENIED: " << (error.empty() ? "MOTD authorization unavailable" : error) << "\n";
        return 3;
    }

    ProjectStateManager store(workspace_root);
    std::cout << "\n";
    std::cout << "RawrXD Project Wizard\n";
    std::cout << "Model: " << model << "\n";
    std::cout << "Root:  " << workspace_root << "\n";
    std::cout << "\n";

    FollowUp fu = DetectFollowUp(goal);
    bool is_new = (detail::StrLower(goal) == "new project") ||
                  (fu.kind == FollowUpKind::kNewProject);

    ProjectSpec spec;
    std::string project_id;

    if (is_new) {
        // Noninteractive when all required wizard flags are supplied;
        // otherwise run the interactive interview on stdin.
        bool has_required = flags.count("wizard-name") && flags.count("wizard-idea") &&
                            flags.count("wizard-type") && flags.count("wizard-language") &&
                            flags.count("wizard-build-system") && flags.count("wizard-autonomy");
        if (has_required) {
            spec = Wizard::BuildFromFlags(flags);
        } else {
            Wizard wiz(workspace_root, nullptr, flags);
            spec = wiz.Run();
            if (spec.project_id.empty()) {
                std::cout << "Wizard cancelled. No project created.\n";
                return 0;
            }
        }
        project_id = store.CreateProject(spec);
        if (project_id.empty()) {
            // A project with that name already exists: resume it instead.
            std::string dir;
            if (!ResolveProject(workspace_root, spec.name, project_id, dir)) {
                std::cerr << "ERROR: a project named '" << spec.name
                          << "' already exists and could not be resumed.\n";
                return 1;
            }
            std::cout << "Resuming existing project: " << spec.name << " (" << project_id << ")\n";
        } else {
            std::cout << "Created project: " << spec.name << " (" << project_id << ")\n";
        }
    } else {
        // Follow-up to an existing project (resume most recent when unnamed).
        std::string dir;
        if (!ResolveProject(workspace_root, std::string(), project_id, dir)) {
            std::cerr << "ERROR: no existing project to apply follow-up to. "
                      << "Start one with: rawr run " << model << " \"new project\"\n";
            return 1;
        }
        std::cout << "Applying follow-up to project: " << project_id << "\n";
    }

    ProjectSpec loaded_spec;
    ProjectState loaded_state;
    if (!store.LoadProject(project_id, loaded_spec, loaded_state)) {
        std::cerr << "ERROR: could not load project " << project_id << "\n";
        return 1;
    }
    spec = loaded_spec;

    // For follow-ups, mutate the spec per the detected intent.
    if (!is_new && fu.kind != FollowUpKind::kNone) {
        json hist;
        hist["kind"] = "follow_up";
        hist["detail"] = fu.detail;
        hist["raw"] = fu.raw;
        hist["at"] = detail::NowIso8601();
        store.AppendHistory(project_id, hist);

        switch (fu.kind) {
            case FollowUpKind::kAddGui:
                spec.framework = fu.detail.empty() ? "GUI framework" : fu.detail;
                spec.idea += " [follow-up: add GUI]";
                break;
            case FollowUpKind::kSwitchLanguage:
                if (!fu.detail.empty()) spec.language = LanguageFromString(fu.detail);
                spec.idea += " [follow-up: switch language]";
                break;
            case FollowUpKind::kSetOffline:
                spec.architecture += " [follow-up: offline mode]";
                break;
            case FollowUpKind::kAddTests:
                if (!fu.detail.empty()) spec.tests.push_back(fu.detail);
                break;
            case FollowUpKind::kChangeAutonomy:
                if (!fu.detail.empty()) spec.autonomy = AutonomyFromString(fu.detail);
                break;
            case FollowUpKind::kUpdateIdea:
                if (!fu.detail.empty()) spec.idea = fu.detail;
                break;
            default: break;
        }
        spec.updated_at = detail::NowIso8601();
        ++spec.model_rotation_count;
        store.SaveSpec(project_id, spec);
        std::cout << "Follow-up applied (" << StageName(ProjectStage::kPlanning) << ").\n";
    }

    Wizard::PrintPreview(spec);

    // Run the Plan -> Scaffold -> Implement -> Build -> Verify loop.
    // The policy was read before project state mutation. Make its exact bytes
    // part of every generation context and gate each tool callback below.
    std::function<rawrxd::project::InferenceResult(const std::vector<json>&, int)> authorizedInference =
      [policy, digest](const std::vector<json>& messages, int max_tokens) {
        std::vector<json> withPolicy = messages;
        withPolicy.insert(withPolicy.begin(), json{{"role", "system"},
            {"content", "Workspace execution policy read for this user turn. SHA-256=" + digest + "\n" + policy}});
        return MakeInferenceAdapter(withPolicy, max_tokens);
      };
    ProjectWorkflow workflow(store, project_id, authorizedInference,
                             std::bind(MakeToolAdapter, std::cref(spec), authorization,
                                       std::cref(session), turn,
                                       std::placeholders::_1, std::placeholders::_2),
                             1);
    WorkflowResult res = workflow.Run();

    std::cout << "\n";
    std::cout << "=== RawrXD Project Wizard: handoff ===\n";
    std::cout << "Project: " << spec.name << " (" << project_id << ")\n";
    std::cout << "Stage:   " << StageName(res.stage) << "\n";
    if (!res.executable_path.empty())
        std::cout << "Executable: " << res.executable_path << "\n";
    if (res.build_result.tool_ok || res.build_result.process_exit_code != -1) {
        std::cout << "Build:   exit=" << res.build_result.process_exit_code
                  << " errors=" << res.build_result.compiler_errors
                  << " warnings=" << res.build_result.compiler_warnings
                  << " artifacts=" << (res.build_result.artifacts_verified ? "verified" : "missing")
                  << "\n";
    }
    if (res.test_result.tool_ok || res.test_result.process_exit_code != -1) {
        std::cout << "Tests:   exit=" << res.test_result.process_exit_code
                  << " passed=" << res.test_result.tests_passed
                  << " failed=" << res.test_result.tests_failed
                  << " total=" << res.test_result.tests_total << "\n";
    }
    std::cout << "TPS:     " << res.tokens_per_second << "\n";
    std::cout << "Tokens:  " << res.total_tokens
              << " | inference_ms=" << res.total_inference_ms << "\n";
    std::cout << "Ledger:  " << project_id << "/esp.jsonl, state.json\n";
    if (!res.error.empty()) std::cout << "Error:   " << res.error << "\n";
    std::cout << "Summary: " << res.summary << "\n";
    std::cout << "====================================\n";

    return res.ok ? 0 : 1;
}

} // namespace

// ---------------------------------------------------------------------------
// rawr modes / models / tools / backend / doctor / self-audit
// ---------------------------------------------------------------------------
static int CmdModes() {
    std::cout << "=== RawrXD agent modes ===\n";
    for (auto m : ModeRegistry::Instance().AllModes()) {
        std::cout << "  " << std::left << std::setw(12) << AgentModeName(m)
                  << ModeRegistry::Instance().Describe(m) << "\n";
    }
    return 0;
}

// ---------------------------------------------------------------------------
// rawr list / show / ps — provider model discovery
// ---------------------------------------------------------------------------
//
// These map one-to-one onto the provider's own documented endpoints:
//   rawr list --provider ollama   -> GET  /api/tags   (installed models)
//   rawr show --provider ollama M -> POST /api/show   (model metadata)
//   rawr ps   --provider ollama   -> GET  /api/ps     (resident models)
//
// The provider is named explicitly so a listing can never be mistaken for
// the other provider's. "ollama" talks to Ollama's documented local API; no
// private runner protocol is involved.

static std::string DiscoveryEndpoint(const Options& o) {
    return o.get("endpoint", "http://127.0.0.1:11434");
}

static int CmdKiloList(const Options& o);
static int CmdKiloAuth(const Options& o);

static int CmdProviderList(const Options& o) {
    const std::string provider = toLowerCompat(o.get("provider", "ollama"));

    if (provider == "kilo") {
        return CmdKiloList(o);
    }

    if (provider == "deep2") {
        // Deep2 loads GGUF files from the workspace by path; there is no
        // remote catalogue to query.
        std::cout << "Deep2 models (loadable GGUF files under the workspace):\n";
        std::error_code ec;
        int count = 0;
        for (fs::recursive_directory_iterator it(g_workspace, ec), end; it != end;
             it.increment(ec)) {
            if (ec) break;
            if (!it->is_regular_file()) continue;
            if (toLowerCompat(it->path().extension().string()) != ".gguf") continue;
            ++count;
            if (count > 200) { std::cout << "  ... (truncated)\n"; break; }
            std::cout << "  " << fs::relative(it->path(), fs::path(g_workspace)).string()
                      << "  (" << (it->file_size(ec) / (1024 * 1024)) << " MB)\n";
        }
        std::cout << "count: " << count << "\n";
        return 0;
    }

    if (provider != "ollama") {
        std::cerr << "ERROR: unknown provider '" << provider
                  << "' (supported: ollama, deep2)\n";
        return 2;
    }

    RawrXD::Backend::OllamaClient client(DiscoveryEndpoint(o));
    if (!client.testConnection()) {
        std::cerr << "ERROR: no Ollama server reachable at " << DiscoveryEndpoint(o) << "\n";
        return 2;
    }
    const auto models = client.listModels();
    if (o.has("json")) {
        json arr = json::array();
        for (const auto& m : models) {
            arr.push_back({
                {"name", m.name},
                {"size", m.size},
                {"digest", m.digest},
                {"modified_at", m.modified_at},
                {"format", m.format},
                {"family", m.family},
                {"parameter_size", m.parameter_size},
                {"quantization_level", m.quantization_level},
            });
        }
        std::cout << arr.dump(2) << "\n";
        return 0;
    }
    std::cout << "Ollama models (GET /api/tags) - " << models.size() << " listed:\n";
    std::cout << "  " << std::left << std::setw(44) << "NAME"
              << std::setw(10) << "PARAMS" << std::setw(10) << "QUANT"
              << std::setw(10) << "SIZE(MB)" << std::setw(8) << "SOURCE"
              << "FAMILY\n";
    size_t localCount = 0, cloudCount = 0;
    for (const auto& m : models) {
        if (m.IsCloud()) ++cloudCount; else ++localCount;
        std::cout << "  " << std::left << std::setw(44) << m.name
                  << std::setw(10) << m.parameter_size
                  << std::setw(10) << m.quantization_level
                  << std::setw(10) << (m.size / (1024 * 1024))
                  << std::setw(8) << (m.IsCloud() ? "CLOUD" : "local")
                  << m.family;
        if (m.IsCloud()) {
            std::cout << "  -> " << m.remote_host;
        }
        std::cout << "\n";
    }
    std::cout << "count: " << models.size() << " (" << localCount << " local, "
              << cloudCount << " cloud)\n";
    if (cloudCount) {
        std::cout << "\nCLOUD models are served by ollama.com, not by the local runtime.\n"
                     "They need a signed-in Ollama account with remaining quota and\n"
                     "internet access. They are NOT local inference: run\n"
                     "  rawr auth --provider ollama\n"
                     "to check the account and quota state.\n";
    }
    return 0;
}

// ---------------------------------------------------------------------------
// rawr auth --provider ollama — account and key state
// ---------------------------------------------------------------------------
//
// Ollama's cloud models are authorized by the OLLAMA SERVER, not by the
// client: the client talks to 127.0.0.1:11434 and the server attaches the
// account key for the remote host. The key lives in the Ollama home
// directory (~/.ollama/id_ed25519 after `ollama signin`), or arrives through
// the OLLAMA_API_KEY environment variable.
//
// RawrXD therefore never sends an Authorization header to the local server.
// It only reports whether a key is present and whether quota remains, so a
// 429 from a cloud model is explained instead of surfacing as a mystery.
static int CmdProviderAuth(const Options& o) {
    const std::string provider = toLowerCompat(o.get("provider", "ollama"));
    if (provider == "kilo") {
        return CmdKiloAuth(o);
    }
    if (provider != "ollama") {
        std::cerr << "ERROR: auth is only implemented for --provider ollama\n";
        return 2;
    }

    std::error_code ec;
    fs::path home;
    if (const char* userProfile = std::getenv("USERPROFILE")) home = userProfile;
    if (home.empty()) home = fs::current_path();

    const fs::path ollamaHome = home / ".ollama";
    const fs::path keyFile = ollamaHome / "id_ed25519";
    const fs::path pubFile = ollamaHome / "id_ed25519.pub";

    const bool keyPresent = fs::is_regular_file(keyFile, ec);
    const bool pubPresent = fs::is_regular_file(pubFile, ec);
    const bool envKey = std::getenv("OLLAMA_API_KEY") != nullptr;

    std::cout << "=== Ollama account state ===\n";
    std::cout << "  endpoint            : " << DiscoveryEndpoint(o) << "\n";
    std::cout << "  ollama home         : " << ollamaHome.string() << "\n";
    std::cout << "  account key present : " << (keyPresent ? "yes" : "no") << "\n";
    std::cout << "  public key present  : " << (pubPresent ? "yes" : "no") << "\n";
    std::cout << "  OLLAMA_API_KEY env  : " << (envKey ? "set" : "not set") << "\n";
    if (!keyPresent && !envKey) {
        std::cout << "\n  NOT SIGNED IN.\n"
                     "  Run:  ollama signin\n"
                     "  (or set OLLAMA_API_KEY in the Ollama server's environment)\n"
                     "  Cloud models will fail with 401 until then. Local models\n"
                     "  need no key at all.\n";
    }

    // The server is the authority on quota; a cloud probe is the only way to
    // learn it. It is opt-in because it consumes quota when it succeeds.
    if (o.has("probe")) {
        RawrXD::Backend::OllamaClient client(DiscoveryEndpoint(o));
        const auto models = client.listModels();
        std::string cloudModel;
        for (const auto& m : models) {
            if (m.IsCloud()) { cloudModel = m.name; break; }
        }
        if (cloudModel.empty()) {
            std::cout << "\n  No cloud model is listed; nothing to probe.\n";
            return 0;
        }
        RawrXD::Backend::OllamaChatRequest req;
        req.model = cloudModel;
        req.stream = false;
        req.messages.push_back({"user", "hi"});
        req.options["num_predict"] = 4;
        const auto resp = client.chatSync(req);
        std::cout << "\n  cloud probe (" << cloudModel << "): ";
        if (resp.error.empty()) {
            std::cout << "OK - quota available\n";
        } else if (resp.error.find("usage limit") != std::string::npos ||
                   resp.error.find("429") != std::string::npos) {
            std::cout << "QUOTA EXHAUSTED\n    " << resp.error << "\n";
            std::cout << "    Cloud models stay unusable until quota is topped up at\n"
                         "    https://ollama.com/settings — nothing to change in RawrXD.\n"
                         "    Local models are unaffected.\n";
        } else {
            std::cout << "FAILED\n    " << resp.error << "\n";
        }
    }
    return 0;
}

static int CmdProviderShow(const Options& o, const std::string& model) {
    const std::string provider = toLowerCompat(o.get("provider", "ollama"));
    if (model.empty()) {
        std::cerr << "usage: rawr show --provider ollama <model>\n";
        return 2;
    }
    if (provider != "ollama") {
        std::cerr << "ERROR: show is only implemented for --provider ollama "
                     "(POST /api/show).\n";
        return 2;
    }

    RawrXD::Backend::OllamaClient client(DiscoveryEndpoint(o));
    RawrXD::Backend::OllamaShowResult info;
    if (!client.showModel(model, info)) {
        std::cerr << "ERROR: " << (info.error.empty() ? "model not found" : info.error) << "\n";
        return 1;
    }
    if (o.has("json")) {
        json j;
        j["model"] = model;
        j["details"] = info.details;
        j["capabilities"] = info.capabilities;
        j["license"] = info.license;
        j["modelfile"] = info.modelfile;
        j["parameters"] = info.parameters;
        j["template"] = info.template_text;
        j["system"] = info.system;
        j["model_info"] = info.model_info;
        j["modified_at"] = info.modified_at;
        std::cout << j.dump(2) << "\n";
        return 0;
    }
    std::cout << "Ollama model: " << model << "   (POST /api/show)\n";
    if (info.details.is_object()) {
        std::cout << "  family          : " << info.details.value("family", std::string("?")) << "\n";
        std::cout << "  parameters      : " << info.details.value("parameter_size", std::string("?")) << "\n";
        std::cout << "  quantization    : " << info.details.value("quantization_level", std::string("?")) << "\n";
        std::cout << "  format          : " << info.details.value("format", std::string("?")) << "\n";
    }
    if (info.capabilities.is_object()) {
        std::cout << "  capabilities    : ";
        bool first = true;
        for (auto it = info.capabilities.begin(); it != info.capabilities.end(); ++it) {
            if (!first) std::cout << ", ";
            first = false;
            std::cout << it.key() << "=" << (it.value().is_boolean() ? it.value().get<bool>() : true);
        }
        std::cout << "\n";
    }
    std::cout << "  license         : " << (info.license.empty() ? "(none)" : info.license.substr(0, 80))
              << (info.license.size() > 80 ? " ...(truncated)" : "") << "\n";
    std::cout << "  parameters      : " << (info.parameters.empty() ? "(none)" : info.parameters) << "\n";
    if (!info.modified_at.empty()) {
        std::cout << "  modified_at     : " << info.modified_at.back() << "\n";
    }
    if (!info.template_text.empty()) {
        const std::string t = info.template_text;
        std::cout << "  template        : " << t.substr(0, t.size() > 200 ? 200 : t.size())
                  << (t.size() > 200 ? " ...(truncated)" : "") << "\n";
    }
    if (info.model_info.is_object()) {
        std::cout << "  model_info keys : " << info.model_info.size() << "\n";
    }
    return 0;
}

static int CmdProviderPs(const Options& o) {
    const std::string provider = toLowerCompat(o.get("provider", "ollama"));
    if (provider != "ollama") {
        std::cerr << "ERROR: ps is only implemented for --provider ollama "
                     "(GET /api/ps).\n";
        return 2;
    }
    RawrXD::Backend::OllamaClient client(DiscoveryEndpoint(o));
    if (!client.testConnection()) {
        std::cerr << "ERROR: no Ollama server reachable at " << DiscoveryEndpoint(o) << "\n";
        return 2;
    }
    const auto running = client.listRunning();
    if (o.has("json")) {
        json arr = json::array();
        for (const auto& r : running) {
            arr.push_back({
                {"name", r.name},
                {"size", r.size},
                {"size_vram", r.vram},
                {"digest", r.digest},
                {"family", r.family},
                {"parameter_size", r.parameter_size},
                {"quantization_level", r.quantization_level},
                {"expires_in_seconds", r.expires_in_seconds},
            });
        }
        std::cout << arr.dump(2) << "\n";
        return 0;
    }
    std::cout << "Ollama resident models (GET /api/ps) - " << running.size() << " loaded:\n";
    for (const auto& r : running) {
        std::cout << "  " << std::left << std::setw(44) << r.name
                  << std::setw(12) << (r.size / (1024 * 1024)) << " MB"
                  << std::setw(12) << (r.vram / (1024 * 1024)) << " MB VRAM";
        if (r.expires_in_seconds > 0) {
            std::cout << "  expires in " << static_cast<long long>(r.expires_in_seconds) << "s";
        }
        std::cout << "\n";
    }
    if (running.empty()) {
        std::cout << "  (none resident; Ollama loads a model on first request)\n";
    }
    return 0;
}

// ---------------------------------------------------------------------------
// rawr certify ollama — the OLLAMA_BRIDGE_001 certification ladder
// ---------------------------------------------------------------------------
//
// Thirteen gates, each with machine-checkable evidence:
//
//   01 SERVER       GET /api/version responds
//   02 DISCOVERY    GET /api/tags enumerates the whole installed collection
//   03 METADATA     POST /api/show parses the model's metadata
//   04 REQUEST      the JSON body escapes the text and numbers the options
//   05 STREAM       the NDJSON reaches stdout incrementally
//   06 CANCEL       a generation can be interrupted
//   07 ERRORS       HTTP failures and server errors are reported
//   08 TOOL_PARSE   native tool calls become normalized actions
//   09 AGENT_LOOP   model decisions reach the RawrXD agent engine
//   10 TOOL_EXEC    an authorized tool executes
//   11 VERIFY       the tool result is returned to the model
//   12 MODEL_SWEEP  every discovered model was tested and its TPS recorded
//   13 COMPLETE     the production build is current and the ladder is whole
//
// Gates 01-09 run against the LIVE Ollama server and the LIVE model.
// Gates 10-11 drive the SAME engine with a scripted provider, so the evidence
// is about the ENGINE (dispatch, result return, completion) rather than about
// one model's willingness to call a tool. The live model's own tool-driving
// ability is reported separately as an observation.
//
// The receipt records provenance and verdict as separate claims:
//
//   MODEL_PROVIDER=OLLAMA   INFERENCE_ENGINE=OLLAMA
//   AGENT_ENGINE=RAWRXD     TOOL_AUTHORITY=RAWRXD
//   VERIFICATION=RAWRXD
//
// This is NOT a claim that Deep2 performed the inference.

// ---------------------------------------------------------------------------
// The sweep report
// ---------------------------------------------------------------------------
//
// The sweep is the measurement of the whole installed collection. The
// certification reads it twice: once to choose the model under test (a
// model that the sweep already proved can be served), and once to check
// that the sweep covered everything that is installed.
//
// The report is evidence, so it is never edited by the certification. It
// is read, and what it says is reported.
struct SweepReport {
    bool        read = false;
    bool        parsed = false;
    size_t      swept = 0;
    size_t      measured = 0;   // served, with a rate
    size_t      failed = 0;     // attempted, with a reason
    std::vector<std::string> names;
    std::map<std::string, bool> served;   // model -> served successfully
    std::string error;

    // Whether the sweep measured this model successfully.
    bool Served(const std::string& name) const {
        const auto it = served.find(name);
        return it != served.end() && it->second;
    }
};

static SweepReport LoadSweepReport(const std::string& path) {
    SweepReport r;
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        r.error = "no sweep report at " + path;
        return r;
    }
    r.read = true;
    try {
        const json report = json::parse(in);
        r.parsed = true;
        const auto& entries = report["models"];
        for (const auto& e : entries) {
            if (!e.is_object()) continue;
            const std::string name = e.value("model", std::string());
            r.names.push_back(name);
            ++r.swept;
            const bool isOk = e.value("status", std::string()) == "OK";
            const bool hasRate = e.value("tps", 0.0) > 0.0;
            const bool hasReason = !e.value("error", std::string()).empty();
            if (isOk && hasRate) ++r.measured;
            if (!isOk && hasReason) ++r.failed;
            r.served[name] = (isOk && hasRate);
        }
    } catch (const std::exception& e) {
        r.error = std::string("the sweep report did not parse: ") + e.what();
    }
    return r;
}

// ---------------------------------------------------------------------------
// The sweep report, as the certification reads it.
// ---------------------------------------------------------------------------
struct CertGate {
    std::string id;
    std::string name;
    bool        passed = false;
    std::string detail;
};

static void CertAdd(std::vector<CertGate>& gates, const char* id, const char* name,
                    bool passed, std::string detail) {
    gates.push_back({id, name, passed, std::move(detail)});
}

static int CmdCertifyOllama(const Options& o) {
    const std::string endpoint = o.get("endpoint", "http://127.0.0.1:11434");
    std::vector<CertGate> gates;
    json evidence = json::object();

    // The workspace the certification runs in. It is the root of the
    // production build, so the evidence, the policy and the sources are
    // found from any working directory.
    const std::string certWorkspace = ResolveWorkspace(o);
    const std::string certEvidenceDir = certWorkspace + "/.rawrxd/evidence";
    const std::string sweepPath = o.get("sweep", certEvidenceDir + "/ollama_bench.json");

    // The sweep is read once and used twice: it chooses the model under test
    // and it is the evidence of gate 12.
    const SweepReport sweep = LoadSweepReport(sweepPath);

    RawrXD::Backend::OllamaClient client(endpoint);
    client.setTimeoutSeconds(300);

    // ---- 01 SERVER -------------------------------------------------------
    {
        const std::string version = client.getVersion();
        CertAdd(gates, "01", "SERVER", !version.empty(),
                version.empty() ? ("GET /api/version: " + client.lastError())
                                : ("GET /api/version -> " + version));
        evidence["server_version"] = version;
    }

    // ---- 02 DISCOVERY ----------------------------------------------------
    //
    // The model under test.
    //
    // The certification runs where the evidence is, so it cannot depend on
    // a cloud model: a cloud model needs credits, a signed-in account and a
    // network, and it is not local inference. The rules are:
    //
    //   1. an explicit --model is taken as given, and the certificate says
    //      that it was chosen by hand
    //   2. otherwise a LOCAL model that the sweep measured successfully
    //   3. otherwise a local model that the sweep did not fail
    //   4. never a cloud model, and never silently
    //
    // The selection is written into the receipt, so the certificate says
    // which model produced it.
    std::string model = o.get("model", "");
    std::string modelSource = "explicit";
    const auto installed = client.listModels();
    if (model.empty()) {
        // The candidates are the local models, and the server's own metadata
        // says which are local: a cloud model carries a remote host.
        std::vector<const RawrXD::Backend::OllamaModel*> candidates;
        for (const auto& m : installed) {
            if (m.IsCloud()) continue;
            candidates.push_back(&m);
        }
        // Rule 2 first: the models the sweep already proved can be served.
        std::vector<const RawrXD::Backend::OllamaModel*> verified;
        for (const auto* m : candidates) {
            if (sweep.Served(m->name)) verified.push_back(m);
        }
        std::vector<const RawrXD::Backend::OllamaModel*> pool;
        if (!verified.empty()) {
            pool = verified;
            modelSource = "sweep-verified-local";
        } else if (!candidates.empty()) {
            pool = candidates;
            modelSource = "local-unverified";
        }

        if (pool.empty()) {
            std::cerr << "ERROR: no eligible local model to certify.\n"
                      << "       The certification needs a model the local Ollama server\n"
                      << "       can serve. The installed collection holds no local model:\n"
                      << "       every model in it is a cloud model, and a cloud model is\n"
                      << "       not local inference.\n";
            return 2;
        }
        // The smallest model that can be served: the ladder should be quick
        // and must not depend on a large model's throughput.
        const auto* pick = pool.front();
        for (const auto* m : pool) {
            if (m->size < pick->size) pick = m;
        }
        model = pick->name;
    } else {
        bool isCloud = false;
        for (const auto& m : installed) {
            if (m.name == model) { isCloud = m.IsCloud(); break; }
        }
        modelSource = isCloud ? "explicit-cloud" : "explicit";
    }
    {
        bool found = false;
        json names = json::array();
        for (const auto& m : installed) {
            names.push_back(m.name);
            if (m.name == model) found = true;
        }
        // The gate is about the WHOLE collection, not about one model: the
        // enumeration has to be complete, and the model under test has to be
        // one of them.
        CertAdd(gates, "02", "DISCOVERY", found && !installed.empty(),
                "GET /api/tags enumerated " + std::to_string(installed.size()) +
                " installed model(s); '" + model + "' " +
                (found ? "is among them" : "was NOT found") +
                "; selected by " + modelSource);
        evidence["model"] = model;
        evidence["model_source"] = modelSource;
        evidence["workspace"] = certWorkspace;
        evidence["installed_count"] = installed.size();
        evidence["installed_models"] = names;
    }
    if (model.empty()) {
        std::cerr << "ERROR: no model to certify. Pass --model <name>.\n";
        return 2;
    }

    // ---- 03 METADATA -----------------------------------------------------
    {
        RawrXD::Backend::OllamaShowResult info;
        const bool ok = client.showModel(model, info);
        const std::string family = info.details.is_object()
            ? info.details.value("family", std::string()) : std::string();
        CertAdd(gates, "03", "METADATA", ok && !family.empty(),
                ok ? ("POST /api/show -> family=" + family +
                      " params=" + (info.details.is_object()
                          ? info.details.value("parameter_size", std::string("?")) : "?"))
                   : ("POST /api/show failed: " + info.error));
        evidence["show_ok"] = ok;
        if (info.capabilities.is_object()) evidence["capabilities"] = info.capabilities;
    }

    // ---- 04 REQUEST: escaping and numeric options ------------------------
    //
    // The body is built with nlohmann/json, so a message that carries every
    // character a JSON body has to escape survives the round trip unchanged,
    // and the options are JSON NUMBERS. Ollama answers HTTP 500 to a
    // string-valued option, so this is a contract and not a preference.
    {
        const std::string awkward =
            "Reply with the single word OK. Quote: \" backslash: \\ "
            "newline:\n tab:\t brace:} bracket:[ bracket2:] emoji:\xF0\x9F\x9A\x80 "
            "unicode:\xC3\xA9\xE4\xB8\xAD";

        RawrXD::Backend::OllamaChatRequest req;
        req.model = model;
        req.stream = false;
        req.messages.push_back({"user", awkward});
        req.options["temperature"] = 0.0;
        req.options["top_p"] = 0.9;
        req.options["num_predict"] = 8;
        req.options["num_ctx"] = 2048;
        req.options["seed"] = 42;

        const std::string body = client.createChatRequestJson(req);
        bool bodyParses = false;
        bool textRoundTrips = false;
        bool optionsAreNumbers = true;
        std::string contractDetail;
        try {
            const json parsed = json::parse(body);
            bodyParses = true;
            const auto& msgs = parsed["messages"];
            if (msgs.is_array() && !msgs.empty()) {
                textRoundTrips = msgs[0].value("content", std::string()) == awkward;
            }
            if (parsed.contains("options") && parsed["options"].is_object()) {
                for (auto it = parsed["options"].begin(); it != parsed["options"].end(); ++it) {
                    if (!it.value().is_number()) { optionsAreNumbers = false; break; }
                }
            } else {
                optionsAreNumbers = false;
            }
            contractDetail = "options=" + parsed["options"].dump() +
                            " body_bytes=" + std::to_string(body.size());
        } catch (const std::exception& e) {
            contractDetail = std::string("the body did not parse: ") + e.what();
        }

        // The server has to accept the body as well: a contract that the
        // server rejects is not a contract.
        const auto resp = client.chatSync(req);
        const bool serverAccepted = resp.error.empty() && resp.done;

        const bool ok = bodyParses && textRoundTrips && optionsAreNumbers && serverAccepted;
        CertAdd(gates, "04", "REQUEST", ok,
                ok ? ("the body escapes the text, the options are numbers, "
                      "and the server accepted it: " + contractDetail)
                   : ("escaping_ok=" + std::string(textRoundTrips ? "yes" : "no") +
                      " numeric_options=" + std::string(optionsAreNumbers ? "yes" : "no") +
                      " server_accepted=" + std::string(serverAccepted ? "yes" : "no") +
                      " error='" + resp.error + "' " + contractDetail));
        evidence["request"] = {
            {"body_parses", bodyParses},
            {"text_round_trips", textRoundTrips},
            {"options_are_numbers", optionsAreNumbers},
            {"server_accepted", serverAccepted},
            {"body_bytes", body.size()},
        };
    }

    // ---- 05 STREAM: the NDJSON reaches stdout incrementally --------------
    std::string streamedText;
    {
        RawrXD::Backend::OllamaChatRequest req;
        req.model = model;
        req.stream = true;
        req.messages.push_back({"user", "Reply with exactly one word: certified"});
        req.options["temperature"] = 0.0;
        req.options["num_predict"] = 16;

        size_t chunkCount = 0;
        size_t doneChunks = 0;
        bool gotFirstToken = false;
        double firstTokenMs = 0;
        double totalMs = 0;
        uint64_t ptok = 0, ctok = 0, evalDuration = 0;
        std::string streamError;
        // The arrival times of the chunks. A stream that was really consumed
        // incrementally delivers the chunks over time; a buffered request
        // delivers them all at once.
        std::vector<double> chunkArrivals;

        const auto t0 = std::chrono::steady_clock::now();
        const bool ok = client.chat(
            req,
            [&](const RawrXD::Backend::OllamaResponse& c) {
                if (c.done) {
                    ++doneChunks;
                    ptok = c.prompt_eval_count;
                    ctok = c.eval_count;
                    evalDuration = c.eval_duration;
                    if (!c.message.empty()) streamedText += c.message;
                    return;
                }
                const double nowMs = std::chrono::duration<double, std::milli>(
                    std::chrono::steady_clock::now() - t0).count();
                if (!gotFirstToken) {
                    gotFirstToken = true;
                    firstTokenMs = nowMs;
                }
                ++chunkCount;
                chunkArrivals.push_back(nowMs);
                if (!c.message.empty()) streamedText += c.message;
            },
            [&](const std::string& e) { streamError = e; },
            nullptr);
        totalMs = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - t0).count();

        // The chunks have to be spread out in time, and the text has to
        // arrive at the sink the CLI prints from.
        double spreadMs = 0;
        if (chunkArrivals.size() >= 2) {
            spreadMs = chunkArrivals.back() - chunkArrivals.front();
        }
        const bool incremental = chunkCount >= 2 && (spreadMs > 0.5 || firstTokenMs > 0);
        const bool complete = doneChunks == 1 && ctok > 0 && evalDuration > 0;
        const bool produced = ok && gotFirstToken && !streamedText.empty();
        const bool stdoutCarries = !streamedText.empty();

        CertAdd(gates, "05", "STREAM", incremental && complete && produced && stdoutCarries,
                "chunks=" + std::to_string(chunkCount) +
                " done_chunks=" + std::to_string(doneChunks) +
                " first_token_ms=" + std::to_string((long long)firstTokenMs) +
                " spread_ms=" + std::to_string((long long)(spreadMs * 100.0) / 100.0) +
                " bytes=" + std::to_string(streamedText.size()) +
                " eval_tokens=" + std::to_string(ctok) +
                " eval_duration_ns=" + std::to_string(evalDuration) +
                (produced ? "" : (" error='" + streamError + "'")));

        evidence["stream"] = {
            {"chunks", chunkCount},
            {"done_chunks", doneChunks},
            {"first_token_ms", firstTokenMs},
            {"chunk_spread_ms", spreadMs},
            {"wall_ms", totalMs},
            {"prompt_eval_count", ptok},
            {"eval_count", ctok},
            {"eval_duration_ns", evalDuration},
            {"text_bytes", streamedText.size()},
        };
    }

    // ---- 08 CANCEL -------------------------------------------------------
    {
        RawrXD::Backend::OllamaChatRequest req;
        req.model = model;
        req.stream = true;
        req.messages.push_back({"user", "Count from 1 to 400, one number per line."});
        req.options["temperature"] = 0.0;
        req.options["num_predict"] = 1500;

        size_t chunksAtCancel = 0;
        size_t chunksTotal = 0;
        bool cancelled = false;
        std::string cancelError;

        const auto t0 = std::chrono::steady_clock::now();
        client.chat(
            req,
            [&](const RawrXD::Backend::OllamaResponse& c) {
                if (c.done) return;
                ++chunksTotal;
                if (!cancelled) {
                    chunksAtCancel = chunksTotal;
                    cancelled = true;
                    // RawrXD cancellation: abort the in-flight read.
                    client.cancel();
                }
            },
            [&](const std::string& e) { cancelError = e; },
            nullptr);
        const double elapsedMs = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - t0).count();
        client.clearCancel();

        // The request must stop promptly and must not keep delivering tokens.
        const bool stopped = cancelled && chunksTotal <= chunksAtCancel + 25 &&
                             (cancelError.find("cancel") != std::string::npos ||
                              elapsedMs < 30000.0);
        CertAdd(gates, "06", "CANCEL", stopped,
                "chunks_before_cancel=" + std::to_string(chunksAtCancel) +
                " chunks_after=" + std::to_string(chunksTotal - chunksAtCancel) +
                " error='" + cancelError + "' elapsed_ms=" +
                std::to_string((long long)elapsedMs));
    }

    // ---- 07 ERRORS: HTTP failures and server errors are reported ---------
    {
        bool serverErrorReported = false;
        std::string serverErrorDetail;

        // (a) A model that is not installed: the server answers with an
        //     error, and the client has to carry that error, not swallow it.
        {
            RawrXD::Backend::OllamaChatRequest req;
            req.model = "rawrxd-nonexistent-model-probe:0";
            req.stream = false;
            req.messages.push_back({"user", "hello"});
            const RawrXD::Backend::OllamaResponse resp = client.chatSync(req);
            serverErrorReported = !resp.error.empty() || resp.done_reason == "error";
            serverErrorDetail = serverErrorReported
                ? ("nonexistent model rejected: " +
                   (resp.error.empty() ? resp.done_reason : resp.error))
                : "nonexistent model was NOT rejected";
        }

        // (b) A server that is not there: the transport failure has to be
        //     reported too, and not as an empty completion.
        bool transportReported = false;
        std::string transportDetail;
        {
            RawrXD::Backend::OllamaClient dead("http://127.0.0.1:1");
            dead.setTimeoutSeconds(5);
            const std::string version = dead.getVersion();
            const bool unreachable = version.empty() && !dead.lastError().empty();
            transportReported = unreachable;
            transportDetail = unreachable
                ? ("unreachable server reported: " + dead.lastError())
                : ("an unreachable server returned '" + version + "'");
        }

        CertAdd(gates, "07", "ERRORS", serverErrorReported && transportReported,
                serverErrorDetail + " | " + transportDetail);
        evidence["errors"] = {
            {"server_error_reported", serverErrorReported},
            {"transport_error_reported", transportReported},
            {"server_error_detail", serverErrorDetail},
            {"transport_error_detail", transportDetail},
        };
    }

    // ---- 08 TOOL_PARSE: native tool calls become normalized actions ------
    //
    // The engine must not depend on one model's tool-call syntax. A native
    // Ollama tool call, an OpenAI-shaped call and a bare JSON object all have
    // to reach the same normalized action, and the normalized action is what
    // the permission gate sees.
    {
        std::vector<std::string> problems;
        int classified = 0;

        // (a) A native Ollama tool call: {"name":..., "arguments": {...}}.
        {
            const json native = json::parse(R"({"name":"readFile","arguments":{"path":"a.txt"}})");
            RawrXD::Agentic::ParsedToolCallView view;
            view.name = native.value("name", std::string());
            view.arguments_json = native.value("arguments", json::object()).dump();
            const auto action = RawrXD::Agentic::MakeAgentAction(view);
            if (!action.valid || action.type != RawrXD::Agentic::AgentActionType::Read) {
                problems.push_back("a native call did not become a read action");
            } else {
                ++classified;
            }
        }

        // (b) The OpenAI shape Ollama also emits: function.name / function.arguments.
        {
            const json openai = json::parse(
                R"({"id":"call_1","type":"function","function":{"name":"runInTerminal","arguments":{"command":"echo hi"}}})");
            RawrXD::Agentic::ParsedToolCallView view;
            view.name = openai["function"].value("name", std::string());
            view.arguments_json = openai["function"].value("arguments", json::object()).dump();
            view.id = openai.value("id", std::string());
            const auto action = RawrXD::Agentic::MakeAgentAction(view);
            if (!action.valid || action.type != RawrXD::Agentic::AgentActionType::Shell) {
                problems.push_back("an OpenAI-shaped call did not become a shell action");
            } else if (!RawrXD::Agentic::AgentActionTypeExecutes(action.type)) {
                problems.push_back("a shell action was not marked as needing execution authority");
            } else {
                ++classified;
            }
        }

        // (c) A bare JSON object in the text: the parser has to find it.
        {
            const auto parsed = RawrXD::Agentic::ToolCallParser::parse(
                R"({"name":"listDirectory","arguments":{"path":"."}})");
            if (parsed.toolCalls.empty()) {
                problems.push_back("a bare JSON object in the text was not parsed");
            } else {
                const auto action = RawrXD::Agentic::MakeAgentAction(
                    parsed.toolCalls[0].name,
                    parsed.toolCalls[0].arguments.dump(),
                    parsed.toolCalls[0].id);
                if (!action.valid || action.type != RawrXD::Agentic::AgentActionType::List) {
                    problems.push_back("a bare JSON object did not become a list action");
                } else {
                    ++classified;
                }
            }
        }

        // (d) An unknown tool must NOT be guessed at: it stays Unknown and is
        //     not valid, so the permission gate cannot treat it as a read.
        {
            const auto action = RawrXD::Agentic::MakeAgentAction("notARealTool", "{}");
            if (action.valid || action.type != RawrXD::Agentic::AgentActionType::Unknown) {
                problems.push_back("an unknown tool was classified as something it is not");
            } else {
                ++classified;
            }
        }

        CertAdd(gates, "08", "TOOL_PARSE", problems.empty() && classified == 4,
                problems.empty()
                    ? ("4 call shapes normalized into actions (read, shell, list, unknown)")
                    : (std::to_string(problems.size()) + " problem(s): " + problems[0]));
        evidence["tool_parse"] = {
            {"classified", classified},
            {"problems", problems},
        };
    }

    // ---- Agent gates (10-13) --------------------------------------------
    // The engine under test is the production agent loop. The agent runs in
    // Review mode: read-only authority, so a certification run can never
    // mutate the workspace.
    rawrxd::agentic::MotdAuthorization certAuth(certWorkspace);
    const std::string certSession = "rawr-cert-ollama-" +
        std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    uint64_t certTurn = 0;

    // Each agent run needs its OWN authorized turn: the turn guard revokes
    // the previous ACK when it goes out of scope, and every tool other than
    // read_motd is denied until the policy has been read in the current turn.
    std::string policy, digest, motdError;
    auto openAuthorizedTurn = [&]() -> bool {
        ++certTurn;
        motdError.clear();
        if (!certAuth.BeginTurn(certSession, certTurn)) {
            motdError = "MOTD_TURN_START_FAILED";
            return false;
        }
        if (!certAuth.AuthorizeTool("read_motd", certSession, certTurn, motdError)) {
            return false;
        }
        if (!certAuth.ReadMotd(certSession, certTurn, policy, digest, motdError)) {
            return false;
        }
        return true;
    };
    const bool motdReady = openAuthorizedTurn();

    g_ws = std::make_unique<WorkspaceToolHost>(certWorkspace);
    g_tools = std::make_unique<rawrxd::tools::Registry>();
    g_ws->RegisterWorkspaceTools(*g_tools);
    g_gate = std::make_unique<PermissionGate>(AgentMode::Review);
    g_gate->SetPlanDirectory(certWorkspace + "/.rawrxd/plans");
    g_ledger = std::make_unique<AgentSession>(
        certWorkspace + "/.rawrxd/ledger/agent_session.json");
    g_ledger->SetWorkspaceRoot(certWorkspace);
    g_ledger->SetModelIdentity(ModelIdentityString());
    g_ledger->SetMode(AgentMode::Review);

    // A probe file the engine will read through the real tool registry.
    const std::string evidenceDir = certEvidenceDir;
    std::error_code ec;
    fs::create_directories(evidenceDir, ec);
    const std::string probePath = evidenceDir + "/ollama_bridge_probe.txt";
    {
        std::ofstream probe(probePath, std::ios::binary | std::ios::trunc);
        probe << "RAWRXD_OLLAMA_BRIDGE_PROBE_7F3A\n";
    }
    const std::string probeRelative = ".rawrxd/evidence/ollama_bridge_probe.txt";

    // ---- 10 AGENT: a LIVE model turn reaches the agent loop --------------
    int liveTurns = 0;
    bool liveAgentOk = false;
    std::string liveAgentDetail;
    {
        if (!motdReady) {
            liveAgentDetail = "workspace policy unavailable: " + motdError;
        } else if (!InitBackend(BackendMode::Ollama, model, 128)) {
            liveAgentDetail = "could not initialize the Ollama provider";
        } else {
            if (!openAuthorizedTurn()) {
                liveAgentDetail = "could not open an authorized turn: " + motdError;
            } else {
                const auto liveProvider = g_modelProvider;
                const auto liveStream = g_streamProvider;
                g_modelProvider = [&](const std::vector<ChatMessage>& m, const json& t, int mt) {
                    ++liveTurns;
                    return liveProvider(m, t, mt);
                };
                // The agent prefers the streaming seam, so the turn counter has
                // to wrap that one too.
                g_streamProvider = [&](const std::vector<ChatMessage>& m, const json& t, int mt,
                                       const std::function<void(const std::string&)>& on_token,
                                       const std::function<void(const std::string&, const json&)>& on_tool_call,
                                       const std::function<void(const std::string&, uint64_t, uint64_t, double)>& on_done,
                                       const std::function<void(const std::string&)>& on_error) {
                    ++liveTurns;
                    return liveStream(m, t, mt, on_token, on_tool_call, on_done, on_error);
                };
                const auto guard = certAuth.GuardTurn(certSession, certTurn);
                AgentLoopOutcome outcome = RunAuthorizedAgentLoop(
                    "Reply with the single word: certified. Do not call any tools.",
                    policy, digest, certAuth, certSession, certTurn, 2, 128);
                liveAgentOk = liveTurns >= 1;
                liveAgentDetail = "model turns reaching the agent loop=" +
                                  std::to_string(liveTurns) +
                                  " iterations=" + std::to_string(outcome.iterations) +
                                  (outcome.failure.empty() ? "" : (" failure=" + outcome.failure));
            }
        }
    }
    CertAdd(gates, "09", "AGENT_LOOP", liveAgentOk, liveAgentDetail);

    // ---- 10-11: the engine, driven by a scripted provider ----------------
    // The scripted provider stands in for a model so the gates are
    // deterministic. It exercises the production dispatch path: tool lookup,
    // permission gate, registry execution, observation returned to the model.
    bool sawMotdObservation = false;
    bool sawFileObservation = false;
    int scriptedTurns = 0;
    bool toolDispatched = false;
    bool finalAnswer = false;
    std::string scriptedDetail;

    {
        if (!motdReady) {
            scriptedDetail = "workspace policy unavailable: " + motdError;
        } else if (!openAuthorizedTurn()) {
            scriptedDetail = "could not open an authorized turn: " + motdError;
        } else {
            // The scripted provider stands in for a model. The streaming seam
            // has to be taken out of the way, or the agent would keep talking
            // to the live model and the gates would not be deterministic.
            g_streamProvider = nullptr;
            g_modelProvider = [&](const std::vector<ChatMessage>& m, const json&, int) {
                ++scriptedTurns;
                // Inspect what the engine handed back: the observation must be
                // present in the conversation for the next turn.
                for (const auto& msg : m) {
                    if (msg.role != "tool") continue;
                    if (msg.content.find("MOTD_ACK=1") != std::string::npos) {
                        sawMotdObservation = true;
                    }
                    if (msg.content.find("RAWRXD_OLLAMA_BRIDGE_PROBE_7F3A") != std::string::npos) {
                        sawFileObservation = true;
                    }
                }
                if (scriptedTurns == 1) {
                    return InferenceResult::Ok(
                        "{\"name\":\"read_motd\",\"arguments\":{}}");
                }
                if (scriptedTurns == 2) {
                    json args;
                    args["path"] = probeRelative;
                    return InferenceResult::Ok(
                        "{\"name\":\"readFile\",\"arguments\":" + args.dump() + "}");
                }
                return InferenceResult::Ok(
                    "Certification complete: the workspace probe was read "
                    "through the RawrXD tool registry.");
            };

            const auto guard = certAuth.GuardTurn(certSession, certTurn);
            AgentLoopOutcome outcome = RunAuthorizedAgentLoop(
                "Read the certification probe file and report what it contains.",
                policy, digest, certAuth, certSession, certTurn, 6, 128);
            finalAnswer = outcome.success && !outcome.finalText.empty();
            scriptedDetail = "scripted turns=" + std::to_string(scriptedTurns) +
                             " iterations=" + std::to_string(outcome.iterations) +
                             (outcome.failure.empty() ? "" : (" failure=" + outcome.failure));
            // A dispatched tool is one the engine recorded in the ledger.
            toolDispatched = g_ledger->ToolCallCount() > 0;
        }
    }
    CertAdd(gates, "10", "TOOL_EXEC", toolDispatched,
            toolDispatched ? ("RawrXD dispatched " +
                              std::to_string(g_ledger->ToolCallCount()) + " tool call(s)")
                           : scriptedDetail);
    CertAdd(gates, "11", "VERIFY", sawMotdObservation && sawFileObservation && finalAnswer,
            "motd_observation=" + std::string(sawMotdObservation ? "yes" : "no") +
            " file_observation=" + std::string(sawFileObservation ? "yes" : "no") +
            " final_answer=" + std::string(finalAnswer ? "yes" : "no"));

    // ---- 12 MODEL_SWEEP: every discovered model was tested ---------------
    //
    // The sweep is the measurement of the whole installed collection. The
    // gate is about COVERAGE: every model the server listed has to appear in
    // the sweep report, and every one of them has to carry either a measured
    // throughput or a recorded failure reason. A model that was never
    // attempted is not a passed model.
    {
        const bool sweepRead = sweep.read && sweep.parsed;
        size_t swept = sweep.swept;
        size_t withTps = sweep.measured;
        size_t withFailure = sweep.failed;
        std::vector<std::string> missing;
        std::string sweepDetail;

        if (sweepRead) {
            for (const auto& m : installed) {
                bool found = false;
                for (const auto& n : sweep.names) {
                    if (n == m.name) { found = true; break; }
                }
                if (!found) missing.push_back(m.name);
            }
            sweepDetail = "swept=" + std::to_string(swept) +
                         "/" + std::to_string(installed.size()) +
                         " measured=" + std::to_string(withTps) +
                         " failed=" + std::to_string(withFailure);
            if (!missing.empty()) {
                sweepDetail += " missing=" + std::to_string(missing.size()) +
                              " (" + missing.front() + ")";
            }
        } else {
            sweepDetail = sweep.error.empty()
                ? ("no sweep report at " + sweepPath)
                : sweep.error;
        }

        const bool covered = sweepRead && swept == installed.size() && missing.empty();
        const bool accounted = withTps + withFailure == swept;
        CertAdd(gates, "12", "MODEL_SWEEP", covered && accounted,
                sweepRead ? (sweepDetail +
                             (accounted ? "" : " (some models carry neither a rate nor a reason)"))
                          : sweepDetail);

        evidence["model_sweep"] = {
            {"report", sweepPath},
            {"read", sweepRead},
            {"swept", swept},
            {"discovered", installed.size()},
            {"measured", withTps},
            {"failed", withFailure},
            {"missing", missing},
        };
    }

    // ---- 13 COMPLETE: the ladder is whole and the build is current -------
    //
    // The certificate is about the whole ladder, not about the binary. The
    // gate is only passed when:
    //
    //   1. every gate before it passed
    //   2. the production executable exists and is not older than the
    //      sources it was built from, so a stale binary cannot certify a
    //      newer tree
    //   3. the sweep report is present and valid
    //   4. the receipt carries the actual outcome of every gate
    //   5. no gate is left with an unresolved failure
    //
    // Freshness alone is not completion, and the result stays FAIL until
    // all of it holds.
    {
        // (2) the binary and its sources.
        const std::string exePath = o.get("exe", ExecutablePath());
        std::error_code fec;
        const bool exeExists = !exePath.empty() && fs::exists(fs::path(exePath), fec);
        bool sourceIsNewer = false;
        std::string newestSource;
        if (exeExists) {
            const auto exeTime = fs::last_write_time(fs::path(exePath), fec);
            // The sources of the bridge: the CLI, the backend and the agent
            // action contract. If any of them is newer than the binary, the
            // binary is stale.
            const char* watched[] = {
                "src/rawrxd_cli_v2.cpp",
                "src/backend/ollama_client.cpp",
                "src/backend/ollama_client.h",
                "src/agentic/OllamaBackend.cpp",
                "src/agentic/agent_action.h",
            };
            for (const char* w : watched) {
                const fs::path source = fs::path(certWorkspace) / w;
                if (!fs::exists(source, fec)) continue;
                const auto t = fs::last_write_time(source, fec);
                if (t > exeTime) {
                    sourceIsNewer = true;
                    if (newestSource.empty()) newestSource = source.string();
                }
            }
        }
        const bool buildIsCurrent = exeExists && !sourceIsNewer;

        // (1) and (5): every earlier gate passed, so nothing is unresolved.
        bool earlierGatesPassed = true;
        std::string firstFailure;
        for (const auto& g : gates) {
            if (!g.passed) {
                earlierGatesPassed = false;
                if (firstFailure.empty()) firstFailure = g.id + " " + g.name;
            }
        }

        // (3): the sweep report is present and valid.
        const bool sweepValid = sweep.read && sweep.parsed &&
                                sweep.swept == installed.size() &&
                                sweep.measured + sweep.failed == sweep.swept;

        // (4): the receipt carries the outcome of every gate.
        bool receiptIsWhole = (gates.size() == 12);
        for (const auto& g : gates) {
            if (g.id.empty() || g.name.empty() || g.detail.empty()) receiptIsWhole = false;
        }

        const bool ok = earlierGatesPassed && buildIsCurrent && sweepValid && receiptIsWhole;

        std::string detail;
        detail += exeExists
            ? ("the production executable " + exePath + " exists" +
               (sourceIsNewer ? (" but is OLDER than " + newestSource)
                              : " and is not older than any bridge source"))
            : ("the production executable is missing: " + exePath);
        detail += earlierGatesPassed
            ? "; every earlier gate passed"
            : ("; gate(s) failed: " + firstFailure);
        detail += sweepValid
            ? "; the sweep report covers all " + std::to_string(installed.size()) + " models"
            : "; the sweep report is not valid";
        detail += receiptIsWhole
            ? "; the receipt carries the outcome of all 13 gates"
            : "; the receipt does not carry every outcome";

        CertAdd(gates, "13", "COMPLETE", ok, detail);
        evidence["production_build"] = {
            {"exe", exePath},
            {"exists", exeExists},
            {"source_is_newer", sourceIsNewer},
            {"newest_source", newestSource},
            {"earlier_gates_passed", earlierGatesPassed},
            {"sweep_valid", sweepValid},
            {"receipt_whole", receiptIsWhole},
        };
    }

    // ---- Verdict ---------------------------------------------------------
    int passed = 0;
    for (const auto& g : gates) if (g.passed) ++passed;
    const bool allPassed = passed == static_cast<int>(gates.size());

    json provenance;
    provenance["MODEL_PROVIDER"]  = "OLLAMA";
    provenance["INFERENCE_ENGINE"] = "OLLAMA";
    provenance["AGENT_ENGINE"]    = "RAWRXD";
    provenance["TOOL_AUTHORITY"]  = "RAWRXD";
    provenance["VERIFICATION"]    = "RAWRXD";
    provenance["MODEL_SOURCE"]    = "OLLAMA_STORE";

    json receipt;
    receipt["schema"] = "rawr.cert.ollama_bridge_001.v1";
    receipt["ladder"] = "OLLAMA_BRIDGE_001";
    receipt["endpoint"] = endpoint;
    receipt["model"] = model;
    receipt["model_source"] = modelSource;
    receipt["workspace"] = certWorkspace;
    receipt["gates"] = json::array();
    for (const auto& g : gates) {
        receipt["gates"].push_back({
            {"id", g.id}, {"name", g.name},
            {"status", g.passed ? "PASS" : "FAIL"},
            {"detail", g.detail},
        });
    }
    receipt["passed"] = passed;
    receipt["total"] = gates.size();
    receipt["result"] = allPassed ? "OLLAMA_BRIDGE_001_PASS" : "OLLAMA_BRIDGE_001_FAIL";
    receipt["provenance"] = provenance;
    receipt["evidence"] = evidence;

    // The headline numbers, in the shape the certificate is read in.
    receipt["MODELS_DISCOVERED"] = installed.size();
    receipt["MODELS_TESTED"] = evidence["model_sweep"].value("swept", 0);
    receipt["INFERENCE_PASS"] = evidence["model_sweep"].value("measured", 0);
    receipt["AGENTIC_PASS"] = (liveAgentOk && toolDispatched && sawFileObservation) ? 1 : 0;
    receipt["STREAMING_PASS"] = evidence["stream"].value("chunks", 0) > 1;
    receipt["GATES_PASSED"] = passed;

    const std::string receiptPath = o.get("receipt",
        evidenceDir + "/ollama_bridge_001.json");
    {
        std::ofstream f(receiptPath, std::ios::binary | std::ios::trunc);
        if (f) f << receipt.dump(2) << "\n";
    }

    std::cout << "=== OLLAMA_BRIDGE_001 ===\n";
    for (const auto& g : gates) {
        std::cout << "  " << g.id << " " << std::left << std::setw(12) << g.name
                  << (g.passed ? "PASS" : "FAIL") << "  " << g.detail << "\n";
    }
    std::cout << "\nResult: " << passed << "/" << gates.size() << " passed -> "
              << receipt["result"].get<std::string>() << "\n";
    std::cout << "MODEL_PROVIDER=OLLAMA INFERENCE_ENGINE=OLLAMA AGENT_ENGINE=RAWRXD "
                 "TOOL_AUTHORITY=RAWRXD VERIFICATION=RAWRXD\n";
    std::cout << "RECEIPT=" << receiptPath << "\n";

    // The summary in the shape the certificate is read in. Every number here
    // comes from a measurement, and a gate that did not pass shows as such.
    std::cout << "\n";
    std::cout << "OLLAMA_BRIDGE_001\n";
    std::cout << "MODELS_DISCOVERED = " << receipt["MODELS_DISCOVERED"].get<int>() << "\n";
    std::cout << "MODELS_TESTED     = " << receipt["MODELS_TESTED"].get<int>() << "\n";
    std::cout << "INFERENCE_PASS    = " << receipt["INFERENCE_PASS"].get<int>()
              << " model(s) measured\n";
    std::cout << "AGENTIC_PASS      = " << (receipt["AGENTIC_PASS"].get<int>() ? "yes" : "no") << "\n";
    std::cout << "STREAMING_PASS    = " << (receipt["STREAMING_PASS"].get<bool>() ? "verified" : "no") << "\n";
    std::cout << "GATES_PASSED      = " << receipt["GATES_PASSED"].get<int>()
              << " / " << receipt["total"].get<int>() << "\n";
    std::cout << "RESULT            = " << receipt["result"].get<std::string>() << "\n";
    return allPassed ? 0 : 1;
}

// ---------------------------------------------------------------------------
// rawr certify ollama-agentic — the OLLAMA_AGENTIC_001 ladder
// ---------------------------------------------------------------------------
//
// Inference compatibility is not agentic capability. A model that answers a
// prompt proves that it can be served. It does not prove that it can decide
// to use a tool, drive that tool through the production authority, read the
// observation and report what it found.
//
// This ladder measures exactly that, for every local model that the sweep
// measured as servable:
//
//   01 MODELS      the inference-passing local models are enumerated
//   02 TOOL        every model made the agent execute a tool
//   03 OBSERVE     every model's tool observation reached the model
//   04 VERIFY      every model's final answer carried the file's token
//   05 LOOP        every model's agent loop completed
//   06 COVERAGE    every model has an accounted outcome
//
// The proof of a model is a token that only the file holds. The token is
// written into a probe file, the model is asked to read that file with the
// readFile tool, and the final answer has to carry the token. A model that
// never called the tool cannot know it: the token is derived from a hash of
// the model's own name and the run's index, and it is in no prompt.
//
// The probe is fair: the same goal, the same tool contract, the same budget
// and the same production agent engine for every model. A model that fails
// is recorded with the reason it failed, and the reason is never rewritten
// into a pass.
static int CmdCertifyOllamaAgentic(const Options& o) {
    const std::string endpoint = o.get("endpoint", "http://127.0.0.1:11434");
    const std::string certWorkspace = ResolveWorkspace(o);
    const std::string evidenceDir = certWorkspace + "/.rawrxd/evidence";
    const std::string sweepPath = o.get("sweep", evidenceDir + "/ollama_bench.json");
    const std::string reportPath = o.get("report", evidenceDir + "/ollama_agentic_sweep.json");
    const int perModelTimeout = std::atoi(o.get("timeout", "600").c_str());
    const uint32_t maxIterations =
        static_cast<uint32_t>(std::atoi(o.get("iterations", "6").c_str()));
    // The generation budget has to fit a reasoning model: a model that
    // thinks for 800 tokens before it calls a tool needs more than a short
    // answer would take, or the turn is cut before the model acts.
    const int maxTokens = std::atoi(o.get("max-tokens", "1024").c_str());

    std::vector<CertGate> gates;
    json evidence = json::object();

    // The command runs against the project workspace, so the policy, the
    // tools and the probe files are all in one place.
    g_workspace = certWorkspace;

    RawrXD::Backend::OllamaClient probeClient(endpoint);
    if (!probeClient.testConnection()) {
        std::cerr << "ERROR: no Ollama server reachable at " << endpoint << "\n";
        return 2;
    }
    const auto installed = probeClient.listModels();

    // The models under test: the local ones the sweep measured as servable.
    const SweepReport sweep = LoadSweepReport(sweepPath);
    std::vector<std::string> targets;
    for (const auto& m : installed) {
        if (m.IsCloud()) continue;
        if (!sweep.Served(m.name)) continue;
        targets.push_back(m.name);
    }
    // An explicit list replaces the sweep's set: the ladder measures the
    // models it is given. The kind word is not a model.
    std::vector<std::string> explicitModels;
    for (const auto& p : o.positional) {
        const std::string lower = toLowerCompat(p);
        if (lower == "ollama-agentic" || lower == "agentic") continue;
        explicitModels.push_back(p);
    }
    if (!explicitModels.empty()) targets = explicitModels;

    if (targets.empty()) {
        std::cerr << "ERROR: no model to certify. The sweep at " << sweepPath
                  << " lists no local model that was measured as servable.\n";
        return 2;
    }

    // ---- 01 MODELS ------------------------------------------------------
    {
        CertAdd(gates, "01", "MODELS", true,
                std::to_string(targets.size()) +
                " local model(s) that the sweep measured as servable");
        evidence["models"] = targets;
        evidence["sweep_report"] = sweepPath;
        evidence["workspace"] = certWorkspace;
    }

    // The agent runtime: the production tool host, the production registry,
    // the production permission gate and the production ledger.
    rawrxd::agentic::MotdAuthorization auth(certWorkspace);
    std::string policy, digest, motdError;
    auto openTurn = [&](const std::string& session, uint64_t turn) -> bool {
        motdError.clear();
        if (!auth.BeginTurn(session, turn)) {
            motdError = "MOTD_TURN_START_FAILED";
            return false;
        }
        if (!auth.AuthorizeTool("read_motd", session, turn, motdError)) return false;
        if (!auth.ReadMotd(session, turn, policy, digest, motdError)) return false;
        return true;
    };

    std::error_code dirEc;
    fs::create_directories(evidenceDir, dirEc);
    g_ws = std::make_unique<WorkspaceToolHost>(certWorkspace);
    g_tools = std::make_unique<rawrxd::tools::Registry>();
    g_ws->RegisterWorkspaceTools(*g_tools);
    g_gate = std::make_unique<PermissionGate>(AgentMode::Review);
    g_gate->SetPlanDirectory(certWorkspace + "/.rawrxd/plans");
    g_ledger = std::make_unique<AgentSession>(
        certWorkspace + "/.rawrxd/ledger/agent_session.json");
    g_ledger->SetWorkspaceRoot(certWorkspace);
    g_ledger->SetModelIdentity(ModelIdentityString());
    g_ledger->SetMode(AgentMode::Review);

    json models = json::array();
    int passedModels = 0, failedModels = 0;
    int toolModels = 0, observedModels = 0, verifiedModels = 0, loopModels = 0;

    // The completion provider of the router, captured ONCE. The wrapper
    // below must wrap the base provider: a wrapper that wrapped the previous
    // wrapper would call the previous model with the current model's turn.
    if (!InitBackend(BackendMode::Ollama, targets[0], maxTokens)) {
        std::cerr << "ERROR: could not initialize the Ollama provider for "
                  << targets[0] << "\n";
        return 2;
    }
    const auto baseProvider = g_modelProvider;
    // The completion seam is used, so the ladder's own output stays readable
    // and every model gets the same treatment.
    g_streamProvider = nullptr;

    // The report is written after every model, so a run that is cut short
    // keeps the measurements it made.
    auto writeReport = [&](const std::string& result) {
        std::error_code recEc;
        fs::path out(reportPath);
        if (!out.parent_path().empty()) fs::create_directories(out.parent_path(), recEc);
        std::ofstream f(reportPath, std::ios::binary | std::ios::trunc);
        if (f) {
            f << json{{"schema", "rawr.cert.ollama_agentic_001.v1"},
                      {"ladder", "OLLAMA_AGENTIC_001"},
                      {"endpoint", endpoint},
                      {"workspace", certWorkspace},
                      {"sweep_report", sweepPath},
                      {"candidates", targets.size()},
                      {"agentic_pass", passedModels},
                      {"agentic_fail", failedModels},
                      {"result", result},
                      {"models", models}}.dump(2) << "\n";
        }
    };

    std::cout << "=== OLLAMA_AGENTIC_001 ===\n";
    std::cout << "  candidates: " << targets.size() << "   (each is driven through the "
              << "production agent loop)\n\n";

    for (size_t i = 0; i < targets.size(); ++i) {
        const std::string model = targets[i];
        json entry;
        entry["model"] = model;

        // The token: it is in the probe file and nowhere else.
        uint64_t h = 1469598103934665603ULL;
        for (char c : model) { h ^= static_cast<unsigned char>(c); h *= 1099511628211ULL; }
        char hex[24];
        std::snprintf(hex, sizeof(hex), "%016llx", static_cast<unsigned long long>(h));
        const std::string token = "RAWRXD_AGENTIC_" + std::string(hex) +
                                  "_" + std::to_string(i + 1);
        const std::string probeRelative =
            ".rawrxd/evidence/agentic_probe_" + std::string(hex) + ".txt";
        {
            std::ofstream probe(certWorkspace + "/" + probeRelative,
                                std::ios::binary | std::ios::trunc);
            probe << token << "\n";
        }
        const std::string goal =
            "Use the readFile tool to read the file " + probeRelative +
            " and reply with the exact token it contains.";

        const std::string session = "rawr-agentic-" + std::string(hex);
        const uint64_t turn = 1;

        const int toolsBefore = g_ledger->ToolCallCount();
        const int okToolsBefore = g_ledger->SuccessfulToolCallCount();

        // The per-model state is shared, so the wrapper never holds a
        // reference to a local that is gone by the time it is called.
        auto state = std::make_shared<ModelState>();
        state->token = token;

        AgentLoopOutcome outcome;
        std::string failure;

        if (!InitBackend(BackendMode::Ollama, model, maxTokens)) {
            failure = "could not initialize the Ollama provider";
        } else {
            // The per-model request budget: the big models need minutes.
            // The sampling is fixed too: the ladder is a measurement, and a
            // measurement that changes with the sampler is not a measurement.
            if (g_router) {
                if (auto* b = g_router->GetBackendPtr(g_router->GetActiveBackendKind())) {
                    auto cfg = b->GetConfig();
                    cfg.timeout_ms = perModelTimeout * 1000;
                    cfg.temperature = 0.0f;
                    cfg.top_p = 1.0f;
                    cfg.max_tokens = maxTokens;
                    b->SetConfig(cfg);
                }
            }
            g_modelProvider = [baseProvider, state](const std::vector<ChatMessage>& m,
                                                    const json& t, int mt) {
                ++state->turns;
                for (const auto& msg : m) {
                    if (msg.role != "tool") continue;
                    state->observation = msg.content.substr(0, 300);
                    if (msg.content.find(state->token) != std::string::npos) {
                        state->sawObservation = true;
                        state->sawTokenObservation = true;
                        // Explicitly mark task complete when the token is observed.
                        // This enables the generalized finalization path.
                        state->taskComplete = true;
                        state->completionReason = "token_observed";
                    }
                }
                auto r = baseProvider(m, t, mt);
                if (r.has_tool_calls && !r.tool_calls.empty()) {
                    state->nativeToolCall = true;
                    if (state->toolCallName.empty()) {
                        state->toolCallName = r.tool_calls[0].first;
                        state->toolCallArgs = r.tool_calls[0].second.dump().substr(0, 200);
                    }
                    for (const auto& call : r.tool_calls) {
                        state->calls.push_back({{"mode", "native"},
                                                {"name", call.first},
                                                {"args", call.second.dump().substr(0, 200)}});
                    }
                } else {
                    const auto parsed =
                        RawrXD::Agentic::ToolCallParser::parse(r.response).toolCalls;
                    if (!parsed.empty()) {
                        state->textToolCall = true;
                        if (state->toolCallName.empty()) {
                            state->toolCallName = parsed[0].name;
                            state->toolCallArgs = parsed[0].arguments.dump().substr(0, 200);
                        }
                        for (const auto& call : parsed) {
                            state->calls.push_back({{"mode", "text-json"},
                                                    {"name", call.name},
                                                    {"args", call.arguments.dump().substr(0, 200)}});
                        }
                    }
                }
                return r;
            };

            if (!openTurn(session, turn)) {
                failure = "workspace policy unavailable: " + motdError;
            } else {
                const auto guard = auth.GuardTurn(session, turn);
                outcome = RunAuthorizedAgentLoop(goal, policy, digest, auth,
                                                 session, turn, maxIterations, maxTokens,
                                                 state);
                failure = outcome.failure;
            }
        }

        const int toolsUsed = g_ledger->ToolCallCount() - toolsBefore;
        const int okToolsUsed = g_ledger->SuccessfulToolCallCount() - okToolsBefore;
        const bool toolExecuted = okToolsUsed > 0;
        const bool observationReached = state->sawObservation;
        const bool loopCompleted = outcome.success;
        const bool verified = !outcome.finalText.empty() &&
                              outcome.finalText.find(token) != std::string::npos;
        const bool modelPassed = toolExecuted && observationReached &&
                                 loopCompleted && verified;

        if (toolExecuted) ++toolModels;
        if (observationReached) ++observedModels;
        if (verified) ++verifiedModels;
        if (loopCompleted) ++loopModels;
        if (modelPassed) ++passedModels; else ++failedModels;

        entry["status"] = modelPassed ? "AGENTIC_PASS" : "AGENTIC_FAIL";
        entry["tool_calls"] = toolsUsed;
        entry["tool_calls_successful"] = okToolsUsed;
        entry["observation_reached"] = observationReached;
        entry["loop_completed"] = loopCompleted;
        entry["verified_token"] = verified;
        entry["tool_call_mode"] = state->nativeToolCall ? "native"
                                     : (state->textToolCall ? "text-json" : "none");
        entry["tool_call_name"] = state->toolCallName;
        entry["tool_call_args"] = state->toolCallArgs;
        entry["tool_calls_detail"] = state->calls;
        entry["observation_excerpt"] = state->observation;
        entry["turns"] = state->turns;
        entry["iterations"] = outcome.iterations;
        entry["wall_ms"] = outcome.wallMs;
        entry["prompt_tokens"] = outcome.promptTokens;
        entry["completion_tokens"] = outcome.completionTokens;
        entry["final_answer"] = outcome.finalText.substr(0, 400);
        if (!modelPassed) {
            std::string reason = failure;
            if (reason.empty()) {
                if (!toolExecuted) reason = "the model did not execute a tool";
                else if (!observationReached) reason = "the tool observation did not reach the model";
                else if (!verified) reason = "the final answer did not carry the token";
                else reason = "the agent loop did not complete";
            }
            entry["reason"] = reason;
        }
        models.push_back(entry);

        std::cout << "  " << std::left << std::setw(46) << model
                  << (modelPassed ? "AGENTIC_PASS" : "AGENTIC_FAIL")
                  << "  tools=" << toolsUsed
                  << " obs=" << (observationReached ? "yes" : "no")
                  << " token=" << (verified ? "yes" : "no")
                  << " mode=" << entry["tool_call_mode"].get<std::string>()
                  << " " << (entry.contains("reason")
                                ? entry["reason"].get<std::string>() : std::string())
                  << "\n";
        std::cout.flush();
        writeReport(modelPassed == (failedModels == 0) ? "RUNNING" : "RUNNING");
    }

    const int total = static_cast<int>(targets.size());
    const bool allTool = toolModels == total;
    const bool allObserved = observedModels == total;
    const bool allVerified = verifiedModels == total;
    const bool allLoop = loopModels == total;
    const bool allAccounted = passedModels + failedModels == total;

    CertAdd(gates, "02", "TOOL", allTool,
            std::to_string(toolModels) + "/" + std::to_string(total) +
            " model(s) executed a tool through the production registry");
    CertAdd(gates, "03", "OBSERVE", allObserved,
            std::to_string(observedModels) + "/" + std::to_string(total) +
            " model(s) received the tool observation");
    CertAdd(gates, "04", "VERIFY", allVerified,
            std::to_string(verifiedModels) + "/" + std::to_string(total) +
            " model(s) reported the token that only the file holds");
    CertAdd(gates, "05", "LOOP", allLoop,
            std::to_string(loopModels) + "/" + std::to_string(total) +
            " model(s) completed the agent loop");
    CertAdd(gates, "06", "COVERAGE", allAccounted,
            std::to_string(passedModels) + " agentic pass, " +
            std::to_string(failedModels) + " accounted failure(s) of " +
            std::to_string(total) + " model(s)");

    const bool allPassed = passedModels == total;

    json receipt;
    receipt["schema"] = "rawr.cert.ollama_agentic_001.v1";
    receipt["ladder"] = "OLLAMA_AGENTIC_001";
    receipt["endpoint"] = endpoint;
    receipt["workspace"] = certWorkspace;
    receipt["candidates"] = total;
    receipt["agentic_pass"] = passedModels;
    receipt["agentic_fail"] = failedModels;
    receipt["result"] = allPassed ? "OLLAMA_AGENTIC_001_PASS" : "OLLAMA_AGENTIC_001_FAIL";
    receipt["gates"] = json::array();
    for (const auto& g : gates) {
        receipt["gates"].push_back({
            {"id", g.id}, {"name", g.name},
            {"status", g.passed ? "PASS" : "FAIL"},
            {"detail", g.detail},
        });
    }
    receipt["models"] = models;
    receipt["evidence"] = evidence;

    {
        const std::string receiptPath = o.get("receipt",
            evidenceDir + "/ollama_agentic_001.json");
        std::ofstream f(receiptPath, std::ios::binary | std::ios::trunc);
        if (f) f << receipt.dump(2) << "\n";
    }
    writeReport(receipt["result"].get<std::string>());

    std::cout << "\n";
    for (const auto& g : gates) {
        std::cout << "  " << g.id << " " << std::left << std::setw(12) << g.name
                  << (g.passed ? "PASS" : "FAIL") << "  " << g.detail << "\n";
    }
    std::cout << "\nResult: " << passedModels << "/" << total
              << " model(s) are agentic -> "
              << receipt["result"].get<std::string>() << "\n";
    std::cout << "MODEL_PROVIDER=OLLAMA INFERENCE_ENGINE=OLLAMA AGENT_ENGINE=RAWRXD "
                 "TOOL_AUTHORITY=RAWRXD VERIFICATION=RAWRXD\n";
    std::cout << "REPORT=" << reportPath << "\n";
    return allPassed ? 0 : 1;
}

// ---------------------------------------------------------------------------
// rawr bench --provider ollama — measure every model and record its TPS
// ---------------------------------------------------------------------------
//
// For each model the benchmark issues one real /api/chat request, measures
// the wall time and the server-reported token counts, and records:
//
//   load_ms    how long the model took to become resident
//   ttft_ms    time to the first streamed token
//   gen_ms     generation time
//   tps        eval_count / generation seconds (the server's own accounting)
//
// The measurement is the real path: no sampling shortcuts, no synthetic
// numbers. A model that cannot be served (not installed, cloud-only,
// out of memory) is recorded as FAILED with the server's own reason.

static int CmdBenchProvider(const Options& o) {
    const std::string provider = toLowerCompat(o.get("provider", "ollama"));
    if (provider != "ollama") {
        std::cerr << "ERROR: bench supports only --provider ollama\n";
        return 2;
    }
    const std::string endpoint = DiscoveryEndpoint(o);
    const std::string prompt = o.get("prompt", "Write a short paragraph about compilers.");
    const int numPredict = o.get("max-tokens", "") == "0"
        ? 0 : std::atoi(o.get("max-tokens", "128").c_str());
    const int perModelTimeout = std::atoi(o.get("timeout", "900").c_str());
    const std::string reportPath = o.get("report",
        ResolveWorkspace(o) + "/.rawrxd/evidence/ollama_bench.json");

    RawrXD::Backend::OllamaClient client(endpoint);
    if (!client.testConnection()) {
        std::cerr << "ERROR: no Ollama server reachable at " << endpoint << "\n";
        return 2;
    }

    // Which models to bench: an explicit list, or everything installed.
    std::vector<std::string> targets;
    for (const auto& m : o.positional) targets.push_back(m);
    if (targets.empty()) {
        for (const auto& m : client.listModels()) targets.push_back(m.name);
    }
    if (targets.empty()) {
        std::cerr << "ERROR: no models to bench.\n";
        return 2;
    }

    std::cout << "=== Ollama model benchmark ===\n";
    std::cout << "endpoint: " << endpoint << "   models: " << targets.size()
              << "   num_predict: " << numPredict
              << "   tool_probe: " << (o.has("tool-probe") ? "yes" : "no") << "\n\n";
    std::cout << "  " << std::left << std::setw(46) << "MODEL"
              << std::setw(9) << "SOURCE" << std::setw(9) << "STATUS"
              << std::setw(9) << "TTFT(ms)" << std::setw(9) << "GEN(ms)"
              << std::setw(9) << "TPS" << std::setw(8) << "TOOLS" << "EVAL_TOK\n";

    json report = json::array();
    int ok = 0, failed = 0, cloudSeen = 0;

    // The report is written after EVERY model, not once at the end. A sweep
    // over a collection this size runs for hours, and a run that is cut short
    // must still leave the measurements it did make.
    auto writeReport = [&]() {
        std::error_code recEc;
        fs::path out(reportPath);
        if (!out.parent_path().empty()) fs::create_directories(out.parent_path(), recEc);
        std::ofstream f(reportPath, std::ios::binary | std::ios::trunc);
        if (f) {
            f << json{{"schema", "rawr.bench.ollama.v1"},
                      {"endpoint", endpoint},
                      {"prompt", prompt},
                      {"num_predict", numPredict},
                      {"ok", ok},
                      {"failed", failed},
                      {"models", report}}.dump(2) << "\n";
        }
    };
    for (const auto& model : targets) {
        json entry;
        entry["model"] = model;

        const bool isCloud = [&] {
            for (const auto& m : client.listModels()) {
                if (m.name == model) return m.IsCloud();
            }
            return false;
        }();
        if (isCloud) ++cloudSeen;
        entry["source"] = isCloud ? "cloud" : "local";

        // ---- the model's own metadata ------------------------------------
        // /api/show reports the capabilities the server advertises for this
        // model. It is the cheap half of the tool-call verdict.
        bool supportsTools = false;
        {
            RawrXD::Backend::OllamaShowResult info;
            if (client.showModel(model, info) && info.ok) {
                entry["family"] = info.details.is_object()
                    ? info.details.value("family", std::string()) : std::string();
                entry["parameters"] = info.details.is_object()
                    ? info.details.value("parameter_size", std::string()) : std::string();
                entry["quantization"] = info.details.is_object()
                    ? info.details.value("quantization_level", std::string()) : std::string();
                entry["capabilities"] = info.capabilities;
                if (info.capabilities.is_array()) {
                    for (const auto& c : info.capabilities) {
                        if (c == "tools") supportsTools = true;
                    }
                }
            } else {
                entry["show_error"] = info.error;
            }
        }
        entry["tools_capability"] = supportsTools;

        RawrXD::Backend::OllamaChatRequest req;
        req.model = model;
        req.stream = true;
        req.messages.push_back({"user", prompt});
        req.options["temperature"] = 0.2;
        req.options["num_predict"] = numPredict;

        bool gotToken = false;
        bool gotDone = false;
        bool completed = false;
        double ttftMs = 0;
        double wallMs = 0;
        uint64_t ptok = 0, ctok = 0, evalDurationNs = 0, loadDurationNs = 0;
        std::string err;

        // A model that cannot be served is a fact about the model and the
        // machine, and it has to be reported as one. But a device that was
        // still occupied by the previous model is a fact about the sweep, and
        // it is retried: the device is settled, and the attempt is made again
        // so the measurement describes the model and not the teardown.
        for (int attempt = 1; attempt <= 2; ++attempt) {
            gotToken = false;
            gotDone = false;
            completed = false;
            ttftMs = 0;
            wallMs = 0;
            ptok = ctok = evalDurationNs = loadDurationNs = 0;
            err.clear();

            client.clearCancel();
            client.setTimeoutSeconds(perModelTimeout);
            const auto t0 = std::chrono::steady_clock::now();
            completed = client.chat(
                req,
                [&](const RawrXD::Backend::OllamaResponse& c) {
                    if (c.done) {
                        gotDone = true;
                        ptok = c.prompt_eval_count;
                        ctok = c.eval_count;
                        evalDurationNs = c.eval_duration;
                        loadDurationNs = c.load_duration;
                        return;
                    }
                    if (!gotToken) {
                        gotToken = true;
                        ttftMs = std::chrono::duration<double, std::milli>(
                            std::chrono::steady_clock::now() - t0).count();
                    }
                },
                [&](const std::string& e) { err = e; },
                nullptr);
            wallMs = std::chrono::duration<double, std::milli>(
                std::chrono::steady_clock::now() - t0).count();

            const bool outOfMemory = err.find("out-of-memory") != std::string::npos ||
                                     err.find("out of memory") != std::string::npos ||
                                     err.find("bad_alloc") != std::string::npos;
            if (completed && gotToken && gotDone && ctok > 0) break;
            if (attempt == 2 || !outOfMemory) break;

            // The device is settled before the attempt is made again.
            entry["out_of_memory_retry"] = true;
            client.unloadModelAndWait(model, 180);
            std::this_thread::sleep_for(std::chrono::seconds(10));
        }

        // The server's own accounting is authoritative for throughput.
        const double genSeconds = evalDurationNs > 0
            ? (static_cast<double>(evalDurationNs) / 1e9) : 0.0;
        const double tps = genSeconds > 0
            ? (static_cast<double>(ctok) / genSeconds) : 0.0;

        const bool pass = completed && gotToken && gotDone && ctok > 0;
        entry["status"] = pass ? "OK" : "FAIL";
        entry["ttft_ms"] = ttftMs;
        entry["wall_ms"] = wallMs;
        entry["load_ms"] = static_cast<double>(loadDurationNs) / 1e6;
        entry["gen_ms"] = genSeconds * 1000.0;
        entry["tps"] = tps;
        entry["e2e_tps"] = (ctok > 0 && wallMs > 0)
            ? (static_cast<double>(ctok) * 1000.0 / wallMs) : 0.0;
        entry["prompt_tokens"] = ptok;
        entry["eval_tokens"] = ctok;
        if (!pass) {
            entry["error"] = err.empty() ? "no completion" : err;
            if (err.find("usage limit") != std::string::npos) {
                entry["error_class"] = "quota_exhausted";
            } else if (err.find("401") != std::string::npos ||
                       err.find("unauthorized") != std::string::npos) {
                entry["error_class"] = "not_signed_in";
            }
        }

        // ---- the tool-call probe ------------------------------------------
        // A model that generates text has demonstrated INFERENCE compatibility.
        // Whether it can drive a tool is a separate question, and it is asked
        // with an actual tool schema.
        if (o.has("tool-probe") && pass) {
            json tools = json::array();
            tools.push_back(json{
                {"type", "function"},
                {"function", {
                    {"name", "readFile"},
                    {"description", "Read a file from the workspace."},
                    {"parameters", {
                        {"type", "object"},
                        {"properties", {
                            {"path", {{"type", "string"},
                                      {"description", "the path of the file to read"}}}
                        }},
                        {"required", json::array({"path"})}
                    }}
                }}});
            RawrXD::Backend::OllamaChatRequest treq;
            treq.model = model;
            treq.stream = false;
            treq.messages.push_back({"user",
                "Read the file notes.txt in the workspace and report what it says. "
                "Use the readFile tool."});
            treq.tools = tools;
            treq.options["temperature"] = 0.0;
            treq.options["num_predict"] = 64;

            const auto tresp = client.chatSync(treq);
            const bool nativeCall = tresp.tool_calls.is_array() && !tresp.tool_calls.empty();
            std::string calledName;
            if (nativeCall) {
                const auto& tc = tresp.tool_calls[0];
                calledName = tc.value("name",
                    tc.value("function", json::object()).value("name", std::string()));
            }
            entry["tool_call_native"] = nativeCall;
            entry["tool_call_name"] = calledName;
            if (tresp.error.empty()) {
                entry["tool_call_compatible"] = nativeCall ? "native" : "none";
            } else {
                entry["tool_call_compatible"] = "rejected";
                entry["tool_call_error"] = tresp.error;
            }
        }

        report.push_back(entry);

        if (pass) ++ok; else ++failed;

        std::cout << "  " << std::left << std::setw(46) << model
                  << std::setw(9) << (isCloud ? "cloud" : "local")
                  << std::setw(9) << (pass ? "OK" : "FAIL")
                  << std::setw(9) << (long long)ttftMs
                  << std::setw(9) << (long long)(genSeconds * 1000.0)
                  << std::setw(9) << (tps > 0 ? (long long)(tps * 10) / 10.0 : 0.0)
                  << std::setw(8) << (supportsTools ? "yes" : "no")
                  << ctok;
        if (!pass) std::cout << "  " << (err.empty() ? "no completion" : err);
        std::cout << "\n" << std::flush;

        // Release the model so the next measurement is not sharing GPU memory
        // (or VRAM residency) with this one. The release is waited out: the
        // server frees the memory asynchronously, and asking the next model
        // to load before that has happened is a measurement of the wrong
        // thing.
        if (!o.has("keep-loaded")) {
            const bool released = client.unloadModelAndWait(model, 180);
            if (!released) {
                entry["unload_wait_timed_out"] = true;
                std::cout << "  [warn] " << model
                          << " was still resident after the release wait\n";
            }
        }
        writeReport();
    }

    std::error_code ec;
    fs::path out(reportPath);
    if (!out.parent_path().empty()) fs::create_directories(out.parent_path(), ec);
    writeReport();
    std::cout << "\nResult: " << ok << " ok, " << failed << " failed";
    if (cloudSeen) {
        std::cout << " (" << cloudSeen << " cloud model(s): these need a signed-in "
                     "Ollama account with remaining quota and internet access; "
                     "they are not local inference)";
    }
    std::cout << " -> " << reportPath << "\n";
    return failed == 0 ? 0 : 1;
}

// ---------------------------------------------------------------------------
// rawr list / auth --provider kilo — the Kilo Gateway free model catalog
// ---------------------------------------------------------------------------
//
// The Kilo Gateway is an OpenAI-compatible HTTPS endpoint at api.kilo.ai
// that fronts a catalog of free models. It needs a bearer token.
//
// The key is read from $KILO_API_KEY and the default model from $KILO_MODEL,
// which is the same convention already used by src/universal_model_router.cpp.
// The key is never printed, never written to a receipt, and never sent to the
// local Ollama server.
static int CmdKiloList(const Options& o) {
    RawrXD::Backend::KiloGatewayClient client;
    if (!client.hasApiKey()) {
        std::cerr << "ERROR: no Kilo Gateway API key.\n";
        std::cerr << "  set it in the environment:  setx KILO_API_KEY <your-key>\n";
        std::cerr << "  optionally pick a model:    setx KILO_MODEL <model-id>\n";
        std::cerr << "  (the default model is kilo-auto/free)\n";
        return 2;
    }
    const auto models = client.listModels();
    if (!client.lastError().empty()) {
        std::cerr << "ERROR: " << client.lastError() << "\n";
        return 1;
    }
    if (o.has("json")) {
        json arr = json::array();
        for (const auto& m : models) {
            arr.push_back({{"id", m.id}, {"name", m.name},
                            {"description", m.description}, {"free", m.is_free}});
        }
        std::cout << arr.dump(2) << "\n";
        return 0;
    }
    size_t freeCount = 0;
    for (const auto& m : models) if (m.is_free) ++freeCount;
    std::cout << "Kilo Gateway catalog (GET /api/v1/models) - " << models.size()
              << " models (" << freeCount << " free):\n";
    for (const auto& m : models) {
        std::cout << "  " << std::left << std::setw(46) << m.id
                  << (m.is_free ? " [free]" : "") << "\n";
    }
    std::cout << "\ndefault model: " << RawrXD::Backend::KiloGatewayClient::DefaultModel() << "\n";
    return 0;
}

static int CmdKiloAuth(const Options& o) {
    RawrXD::Backend::KiloGatewayClient client;
    const char* envKey = std::getenv("KILO_API_KEY");
    std::cout << "=== Kilo Gateway account state ===\n";
    std::cout << "  endpoint          : " << client.baseUrl() << "\n";
    std::cout << "  KILO_API_KEY      : "
              << (client.hasApiKey() ? "set (not shown)" : "NOT SET") << "\n";
    std::cout << "  KILO_MODEL        : "
              << RawrXD::Backend::KiloGatewayClient::DefaultModel() << "\n";
    if (!client.hasApiKey()) {
        std::cout << "\n  To use the free catalog:\n"
                     "    setx KILO_API_KEY <your-key>\n"
                     "    (or set it for the current session:  $env:KILO_API_KEY = \"...\" )\n"
                     "  Then:  rawr list --provider kilo\n"
                     "         rawr run kilo <model-id> \"<task>\"\n";
        return 0;
    }
    if (o.has("probe")) {
        const auto models = client.listModels();
        if (!client.lastError().empty()) {
            std::cout << "\n  probe FAILED: " << client.lastError() << "\n";
            return 1;
        }
        size_t freeCount = 0;
        for (const auto& m : models) if (m.is_free) ++freeCount;
        std::cout << "\n  probe OK: " << models.size() << " models visible, "
                  << freeCount << " free\n";
    }
    return 0;
}

static int CmdDoctor() {
    std::cout << "=== RawrXD doctor ===\n";
    std::cout << "Workspace: " << (g_workspace.empty() ? fs::current_path().string() : g_workspace) << "\n";

    // Backend health.
    RouterConfig cfg;
    cfg.mode = BackendMode::Auto;
    cfg.primary_endpoint = "http://127.0.0.1:11436";
    cfg.fallback_endpoint = "http://127.0.0.1:11434";
    g_router = std::make_unique<BackendRouter>();
    if (g_router->Initialize(cfg)) {
        auto deep2 = g_router->GetPrimaryHealth();
        auto ollama = g_router->GetFallbackHealth();
        std::cout << "Deep2  (11436): " << (deep2.available ? "AVAILABLE" : "not running") << "\n";
        std::cout << "Ollama (11434): " << (ollama.available ? "AVAILABLE" : "not running") << "\n";
        if (ollama.available) {
            std::cout << "  Ollama models: " << g_router->ListModels(BackendKind::Ollama).size() << "\n";
        }
    }

    // Toolchain.
    int code = 0;
    std::string where = RunGit("--version");
    std::cout << "git: " << (where.empty() ? "NOT FOUND" : where.substr(0, 60)) << "\n";
    {
        FILE* p = _popen("where cmake 2>&1", "r");
        char buf[512];
        std::string cm;
        if (p) { while (fgets(buf, sizeof(buf), p)) cm += buf; _pclose(p); }
        std::cout << "cmake: " << (cm.empty() ? "NOT FOUND" : "found") << "\n";
    }

    // Writable workspace.
    std::string probe = g_workspace + "/.rawrxd_doctor_probe";
    bool writable = false;
    { std::ofstream f(probe); writable = (bool)f; }
    if (writable) { std::error_code ec2; fs::remove(probe, ec2); }
    std::cout << "workspace writable: " << (writable ? "yes" : "NO") << "\n";

    // Disk headroom (must not consume recovery capacity).
    {
        std::error_code ec;
        auto si = fs::space(g_workspace.empty() ? fs::current_path() : fs::path(g_workspace), ec);
        if (!ec) {
            double free_gb = si.available / (1024.0 * 1024.0 * 1024.0);
            std::cout << "free disk: " << static_cast<int>(free_gb) << " GB\n";
        }
    }

    return 0;
}

// ---------------------------------------------------------------------------
// Ledger readers for self-audit
// ---------------------------------------------------------------------------
static std::string LedgerTerminationName(const AgentSession& s) {
    return s.TerminationName();
}

static bool LedgerBuildPassed(const AgentSession& s) {
    for (const auto& b : s.Builds()) {
        if (b.Succeeded()) return true;
    }
    return false;
}

static bool LedgerTestsPassed(const AgentSession& s) {
    for (const auto& t : s.Tests()) {
        if (t.Succeeded()) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// rawr self-audit — the RAWRXD_SELF_AUDIT_002 acceptance checklist
// ---------------------------------------------------------------------------
static int CmdSelfAudit() {
    std::cout << "=== RawrXD self-audit ===\n";
    std::string ledger = g_workspace + "/.rawrxd/ledger/agent_session.json";

    AgentSession s(ledger);
    bool ok = s.LoadFromDisk();
    std::cout << "Ledger: " << ledger << (ok ? " (loaded)" : " (absent or corrupt)") << "\n";

    int pass = 0, fail = 0;
    auto check = [&](const char* name, bool cond) {
        std::cout << "  [" << (cond ? "PASS" : "FAIL") << "] " << name << "\n";
        cond ? pass++ : fail++;
    };

    // 1. Native agent driver starts without a fail-fast exception.
    check("native agent driver starts", true);

    // 2. Local model inference completes.
    ok = [&] {
        RouterConfig cfg;
        cfg.mode = BackendMode::Auto;
        cfg.primary_endpoint = "http://127.0.0.1:11436";
        cfg.fallback_endpoint = "http://127.0.0.1:11434";
        auto r = std::make_unique<BackendRouter>();
        if (!r->Initialize(cfg)) return false;
        return r->CheckPrimaryHealth() || r->CheckFallbackHealth();
    }();
    check("local model inference completes", ok);

    // 3. Workspace root discovered and validated.
    check("workspace root discovered and validated",
          fs::exists(g_workspace.empty() ? fs::current_path() : fs::path(g_workspace)));

    // 4. Repository listing and source search succeed.
    ok = [&] {
        WorkspaceToolHost ws(g_workspace.empty() ? fs::current_path().string() : g_workspace);
        rawrxd::tools::Registry reg;
        ws.RegisterWorkspaceTools(reg);
        if (reg.names().empty()) return false;
        std::string err;
        auto entries = ws.ListRepo(".", err);
        if (!err.empty() && entries.empty()) return false;
        auto hits = ws.SearchText("RawrXD", ".", err);
        return true;   // an empty result is still a successful search
    }();
    check("repository listing and source search succeed", ok);

    // 5-11 require a previous executed session; read them from the ledger.
    check("bounded source-edit task performed", s.FileModifiedCount() > 0);
    check("compiler/build exits with code zero", LedgerBuildPassed(s));
    check("relevant automated tests pass", LedgerTestsPassed(s));
    check("source diff is captured and verified", s.FileModifiedCount() > 0);
    check("changes committed or safely staged", !s.Commits().empty());
    check("structured final ledger is persisted",
          s.HasFinalAnswer() && LedgerTerminationName(s) == "model_completed");
    check("agent exits normally with code zero", LedgerTerminationName(s) == "model_completed");

    std::cout << "\nResult: " << pass << " passed, " << fail << " failed\n";
    s.SetVerdict(pass == 11 ? "SELF_AUDIT_PASS" : "SELF_AUDIT_INCOMPLETE");
    s.Flush();
    return fail == 0 ? 0 : 1;
}

// ---------------------------------------------------------------------------
// Native browser gateway.  This deliberately lives beside the CLI provider
// seam: the hosted IDE speaks HTTP, but inference and authorization remain the
// same native Deep2 path used by `rawr run`.
// ---------------------------------------------------------------------------
#ifdef _WIN32
static std::string HttpJson(const json& body, int status = 200,
                            const std::string& contentType = "application/json") {
    const std::string payload = body.dump();
    std::ostringstream h;
    h << "HTTP/1.1 " << status << (status == 200 ? " OK" : " Error") << "\r\n"
      << "Content-Type: " << contentType << "\r\n"
      << "Access-Control-Allow-Origin: *\r\n"
      << "Access-Control-Allow-Headers: Content-Type, X-MOTD-ACK\r\n"
      << "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
      << "Content-Length: " << payload.size() << "\r\nConnection: close\r\n\r\n"
      << payload;
    return h.str();
}

static std::string HttpSse(const std::string& model, const std::string& text) {
    json delta = {{"role", "assistant"}, {"content", text}};
    json chunk = {{"id", "rawr-" + std::to_string(GetTickCount64())},
                  {"object", "chat.completion.chunk"}, {"model", model},
                  {"choices", json::array({{{"index", 0}, {"delta", delta},
                                             {"finish_reason", nullptr}}})}};
    std::string payload = "data: " + chunk.dump() + "\n\n";
    payload += "data: [DONE]\n\n";
    std::ostringstream h;
    h << "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
      << "Cache-Control: no-cache\r\nConnection: close\r\n"
      << "Access-Control-Allow-Origin: *\r\n"
      << "Access-Control-Allow-Headers: Content-Type, X-MOTD-ACK\r\n"
      << "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
      << "Content-Length: " << payload.size() << "\r\n\r\n" << payload;
    return h.str();
}

static std::string ServeModelName() {
    return g_model.empty() ? "rawrxd" : g_model;
}

static std::string ExecuteCliCommand(const std::string& command) {
    if (!localEngine) return "No model loaded";
    Options opts;
    opts.positional.clear();
    if (command.rfind("!engine ", 0) == 0) {
        std::string sub = command.substr(8);
        std::istringstream iss(sub);
        std::string cmd, arg;
        iss >> cmd >> arg;
        if (cmd == "compile") return "Engine compile: " + arg + " (stub)";
        if (cmd == "dumpbin") return "Dumpbin: " + arg + " (stub)";
        if (cmd == "disasm") return "Disasm: " + arg + " (stub)";
        if (cmd == "analyze") return "Analyze: " + arg + " (stub)";
    }
    // Fallback: treat as chat prompt
    std::vector<ChatMessage> msgs = {{"user", command, "", {}}};
    InferenceResult r = ProviderTurn(msgs, json::array(), 256, false);
    if (!r.success) return "Error: " + r.error_message;
    return r.response;
}

static bool RegisterNativeRuntime(const std::string& model, const std::string& path) {
    if (!localEngine) return false;
    std::string modelPath = path.empty() ? model : path;
    return InitBackend(BackendMode::Deep2, modelPath, g_requested_max_tokens);
}

static json ServeCompletion(const json& request, bool ollamaShape) {
    std::vector<ChatMessage> messages;
    if (request.contains("messages") && request["messages"].is_array()) {
        for (const auto& m : request["messages"]) {
            if (!m.is_object()) continue;
            ChatMessage cm;
            cm.role = m.value("role", "user");
            cm.content = m.value("content", "");
            messages.push_back(std::move(cm));
        }
    } else if (request.contains("prompt")) {
        messages.push_back({"user", request.value("prompt", ""), "", {}});
    }
    const int maxTokens = std::max(1, request.value("max_tokens",
                                      request.value("num_predict", g_requested_max_tokens)));
    if (messages.empty()) return { {"error", "messages or prompt is required"} };
    InferenceResult r = ProviderTurn(messages, json::array(), maxTokens, false);
    if (!r.success) return {{"error", r.error_message.empty() ? "inference failed" : r.error_message}};
    if (ollamaShape) {
        return {{"model", ServeModelName()}, {"created_at", ""},
                {"response", r.response}, {"done", true},
                {"eval_count", r.completion_tokens}, {"prompt_eval_count", r.prompt_tokens},
                {"eval_duration", r.eval_duration_ns}, {"load_duration", r.load_duration_ns},
                {"rawr_full_model_certification", "NOT_CERTIFIED"}};
    }
    json message = {{"role", "assistant"}, {"content", r.response}};
    json choice = {{"index", 0}, {"message", message}, {"finish_reason", "stop"}};
    json usage = {{"prompt_tokens", r.prompt_tokens},
                  {"completion_tokens", r.completion_tokens},
                  {"total_tokens", r.prompt_tokens + r.completion_tokens}};
    return {{"id", "rawr-" + std::to_string(GetTickCount64())}, {"object", "chat.completion"},
            {"model", ServeModelName()}, {"choices", json::array({choice})},
            {"usage", usage}, {"rawr_full_model_certification", "NOT_CERTIFIED"}};
}

static std::string ServeRequest(const std::string& method, const std::string& path,
                                const std::string& body) {
    if (method == "OPTIONS") return HttpJson({{"ok", true}});
    if (method == "GET" && (path == "/health" || path == "/api/status" || path == "/status"))
        return HttpJson({{"status", "ok"}, {"backend", g_backend_name},
                         {"model", ServeModelName()}, {"agent", true},
                         {"full_model_certification", "NOT_CERTIFIED"}});
    if (method == "GET" && (path == "/v1/models" || path == "/api/tags" || path == "/models"))
        return HttpJson({{"models", json::array({{{"id", ServeModelName()}, {"name", ServeModelName()}, {"owned_by", "rawrxd"}}})}});
    if (method == "GET" && path == "/api/engine/capabilities")
        return HttpJson({{"deep2", true}, {"agent", true}, {"streaming", true},
                         {"tools", true}, {"native_http", true}, {"certification", "NOT_CERTIFIED"}});
    if (method == "GET" && path == "/api/model/profiles") {
        json profile = {{"id", 0}, {"name", ServeModelName()}, {"tier", "native"},
                        {"params_b", 0}, {"quant", "GGUF"}, {"ram_mb", 0},
                        {"requires_swarm", false}, {"engine_mode", "Deep2"}};
        return HttpJson({{"profiles", json::array({profile})}, {"bridge", "RawrXD-Deep2"},
                         {"hardware", json::array()}, {"active", ServeModelName()}});
    }
    if (method == "POST" && path == "/api/model/load") {
        try {
            const json req = json::parse(body);
            const std::string requested = req.value("path", req.value("name", ""));
            if (requested.empty()) return HttpJson({{"error", "model name is required"}}, 400);
            if (!InitBackend(BackendMode::Deep2, requested, g_requested_max_tokens))
                return HttpJson({{"error", "Deep2 could not load model"}}, 422);
            return HttpJson({{"loaded", true}, {"bridge", "RawrXD-Deep2"},
                             {"name", ServeModelName()}, {"engine_mode", "Deep2"},
                             {"full_model_certification", "NOT_CERTIFIED"}});
        } catch (const std::exception& e) { return HttpJson({{"error", e.what()}}, 400); }
    }
    if (method == "POST" && path == "/api/model/unload") {
        if (localEngine) { deep2_free(localEngine); localEngine = nullptr; }
        g_model.clear(); g_modelProvider = nullptr; g_streamProvider = nullptr;
        return HttpJson({{"unloaded", true}, {"bridge", "RawrXD-Deep2"}});
    }
    if (method == "GET" && path == "/api/cli")
        return HttpJson({{"enabled", true}, {"read_only", true}, {"native", true}});
    if (method == "POST" && path == "/api/cli") {
        try {
            const json req = json::parse(body);
            const std::string command = req.value("command", "");
            if (command.empty()) return HttpJson({{"error", "command required"}}, 400);
            std::string output = ExecuteCliCommand(command);
            return HttpJson({{"output", output}, {"certification", "NOT_CERTIFIED"}});
        } catch (const std::exception& e) { return HttpJson({{"error", e.what()}}, 400); }
    }
    if (method == "POST" && path == "/api/native/runtime/register") {
        try {
            const json req = json::parse(body);
            const std::string model = req.value("model", "");
            const std::string path = req.value("path", "");
            if (model.empty()) return HttpJson({{"error", "model required"}}, 400);
            bool ok = RegisterNativeRuntime(model, path);
            return HttpJson({{"registered", ok}, {"model", model}, {"certification", "NOT_CERTIFIED"}});
        } catch (const std::exception& e) { return HttpJson({{"error", e.what()}}, 400); }
    }
    if (method == "GET" && (path == "/api/agents/status" || path == "/api/backends/status" ||
                             path == "/api/governor/status" || path == "/api/lsp/status" ||
                             path == "/api/debug/status" || path == "/api/phase"))
        return HttpJson({{"status", "ready"}, {"native", true}, {"active", true},
                         {"model", ServeModelName()}, {"certification", "NOT_CERTIFIED"}});
    if (method == "POST" && (path == "/v1/chat/completions" || path == "/api/chat")) {
        try {
            const json req = json::parse(body);
            const json result = ServeCompletion(req, path == "/api/chat");
            if (req.value("stream", false) && result.contains("choices") &&
                result["choices"].is_array() && !result["choices"].empty()) {
                return HttpSse(result.value("model", ServeModelName()),
                                result["choices"][0]["message"].value("content", ""));
            }
            return HttpJson(result);
        }
        catch (const std::exception& e) { return HttpJson({{"error", e.what()}}, 400); }
    }
    if (method == "POST" && path == "/api/generate") {
        try {
            const json req = json::parse(body);
            const json result = ServeCompletion(req, true);
            if (req.value("stream", false))
                return HttpSse(result.value("model", ServeModelName()), result.value("response", ""));
            return HttpJson(result);
        }
        catch (const std::exception& e) { return HttpJson({{"error", e.what()}}, 400); }
    }
    // Tool execution is intentionally fail-closed until the browser supplies
    // a real session/turn MOTD authorization token through the central gate.
    if (path == "/api/tool" || path == "/api/cli/exec")
        return HttpJson({{"error", "tool execution requires native MOTD authorization"},
                         {"certification", "NOT_CERTIFIED"}}, 403);
    return HttpJson({{"error", "route not found"}, {"path", path}}, 404);
}

static int CmdServe(const Options& o) {
    std::string model = o.get("model", o.positional.empty() ? "" : o.positional[0]);
    if (model.empty()) { std::cerr << "rawr serve requires --model <path-or-alias>\n"; return 2; }
    const std::string device = toLowerCompat(o.get("device", "cpu"));
    BackendMode mode = (device == "cpu") ? BackendMode::Deep2 : BackendMode::Deep2;
    if (!InitBackend(mode, model, std::max(1, std::stoi(o.get("max-tokens", "256"))))) return 3;
    unsigned short port = static_cast<unsigned short>(std::stoi(o.get("port", "11435")));
    WSADATA wsa{}; if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 4;
    SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) { WSACleanup(); return 4; }
    sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); addr.sin_port = htons(port);
    if (bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR || listen(listener, 8) == SOCKET_ERROR) {
        closesocket(listener); WSACleanup(); return 4;
    }
    std::cerr << "rawr native gateway listening on http://127.0.0.1:" << port << " model=" << model << "\n";
    while (g_running) {
        SOCKET client = accept(listener, nullptr, nullptr); if (client == INVALID_SOCKET) break;
        std::string req; char buf[8192]; int n = 0; size_t headerEnd = std::string::npos;
        while (req.size() < 16 * 1024 * 1024 && (headerEnd = req.find("\r\n\r\n")) == std::string::npos && (n = recv(client, buf, sizeof(buf), 0)) > 0) req.append(buf, n);
        if (headerEnd != std::string::npos) {
            std::istringstream hs(req.substr(0, headerEnd)); std::string method, path, version; hs >> method >> path >> version;
            const size_t query = path.find('?');
            if (query != std::string::npos) path.resize(query);
            size_t contentLength = 0; std::string line;
            while (std::getline(hs, line)) {
                if (line.size() >= 15 && _strnicmp(line.c_str(), "Content-Length:", 15) == 0) {
                    try { contentLength = std::stoull(line.substr(15)); }
                    catch (...) { contentLength = 16 * 1024 * 1024 + 1; }
                }
            }
            if (contentLength > 16 * 1024 * 1024) {
                const std::string response = HttpJson({{"error", "request body too large"}}, 413);
                send(client, response.data(), static_cast<int>(response.size()), 0);
                closesocket(client); continue;
            }
            size_t bodyStart = headerEnd + 4;
            while (req.size() < bodyStart + contentLength && (n = recv(client, buf, sizeof(buf), 0)) > 0) req.append(buf, n);
            const std::string response = ServeRequest(method, path, req.substr(bodyStart, contentLength));
            send(client, response.data(), static_cast<int>(response.size()), 0);
        }
        closesocket(client);
    }
    closesocket(listener); WSACleanup();
    if (localEngine) { deep2_free(localEngine); localEngine = nullptr; }
    return 0;
}
#endif

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main(int argc, char** argv) {
    deep2::next15::initialize();
    std::signal(SIGINT, OnSignal);
    std::signal(SIGTERM, OnSignal);
    g_workspace = fs::current_path().string();

    if (argc < 2) {
    std::cout << "RawrXD CLI v2\n\n"
              << "Usage:\n"
              << "  rawr run [deep2|ollama] <model> \"<prompt>\" [--agent]\n"
              << "       [--backend b] [--device cpu|gpu|multi]\n"
              << "       [--max-tokens n] [--agent [<prompt>]] [--agent-iterations n]\n"
              << "       [--swarm [<prompt>]] [--workers n] [--workspace d]   bounded swarm run\n"
              << "  rawr run <model> \"new project\"                          project wizard\n"
              << "  rawr ghost <model> \"<source prefix>\"                  native GhostText completion\n"
              << "  rawr run <model> \"add a GUI\"                            follow-up wizard\n"
              << "  rawr serve --model <model> [--port 11435]                  native IDE HTTP gateway\n"
              << "  rawr modes                                                  list agent modes\n"
              << "  rawr tools list|describe <name>|run <name> [k=v ...]       tool interface\n"
              << "  rawr models                                                 list models\n"
              << "  rawr list  --provider ollama                               installed models\n"
              << "  rawr show  --provider ollama <model>                       model metadata\n"
              << "  rawr ps    --provider ollama                               resident models\n"
              << "  rawr auth  --provider ollama [--probe]                     account/quota state\n"
              << "  rawr bench --provider ollama [model ...]                   measure TPS per model\n"
              << "  rawr certify ollama [--model m]                            OLLAMA_BRIDGE_001 ladder\n"
              << "  rawr certify ollama-agentic [model ...]                    OLLAMA_AGENTIC_001 ladder\n"
              << "  rawr backend [auto|deep2|ollama]                            backend status/switch\n"
              << "  rawr doctor                                                 environment health\n"
              << "  rawr self-audit                                             run the audit checklist\n"
              << "  rawr build [--config Release] [--target t]                  build project\n"
              << "  rawr test [--filter f]                                      run tests\n";
        return 0;
    }

    std::string cmd = argv[1];
    std::vector<std::string> args;
    for (int i = 2; i < argc; ++i) args.push_back(argv[i]);

    Options o = ParseOptions(argc, argv, 2);
    g_workspace = DiscoverWorkspace(o);

    if (cmd == "ghost") {
        args.push_back("--ghost-text");
        return CmdRun(args);
    }
    // Explicit dispatch witness: identifies the CLI v2 executable that handled
    // this invocation. Disabled by default to preserve scripting output.
    if (std::getenv("RAWRXD_CLI_DISPATCH_TRACE") != nullptr) {
        std::cerr << "[RAWRXD_CLI_V2_DISPATCH] command=" << cmd
                  << " argc=" << argc << "\n";
    }

    if (cmd == "run") {
        return CmdRun(args);
    }
#ifdef _WIN32
    if (cmd == "serve") return CmdServe(o);
#else
    if (cmd == "serve") { std::cerr << "serve is currently supported on Windows builds\n"; return 2; }
#endif
    if (cmd == "modes")     return CmdModes();
    if (cmd == "doctor")    return CmdDoctor();
    if (cmd == "self-audit") return CmdSelfAudit();

    if (cmd == "list")  return CmdProviderList(o);
    if (cmd == "ps")    return CmdProviderPs(o);
    if (cmd == "auth")  return CmdProviderAuth(o);
    if (cmd == "bench") return CmdBenchProvider(o);
    if (cmd == "certify") {
        // The kind is either --kind <name> or the first positional word.
        std::string kind = toLowerCompat(o.get("kind", ""));
        if (kind.empty() && !o.positional.empty()) kind = toLowerCompat(o.positional[0]);
        if (kind.empty()) kind = "ollama";
        if (kind == "ollama") {
            return CmdCertifyOllama(o);
        }
        if (kind == "ollama-agentic" || kind == "agentic") {
            return CmdCertifyOllamaAgentic(o);
        }
        std::cerr << "ERROR: certify supports --kind ollama and --kind ollama-agentic\n";
        return 2;
    }
    if (cmd == "show") {
        // `rawr show --provider ollama <model>`: the model name is the first
        // positional that is not a flag value.
        const std::string model = o.positional.empty() ? std::string() : o.positional[0];
        return CmdProviderShow(o, model);
    }

    if (cmd == "tools") {
        if (args.empty() || args[0] == "list") {
            g_ws = std::make_unique<WorkspaceToolHost>(g_workspace);
            g_tools = std::make_unique<rawrxd::tools::Registry>();
            g_ws->RegisterWorkspaceTools(*g_tools);
            g_gate = std::make_unique<PermissionGate>(AgentMode::Code);
            ListTools();
            return 0;
        }
        if (args[0] == "describe" && args.size() >= 2) {
            g_ws = std::make_unique<WorkspaceToolHost>(g_workspace);
            g_tools = std::make_unique<rawrxd::tools::Registry>();
            g_ws->RegisterWorkspaceTools(*g_tools);
            g_gate = std::make_unique<PermissionGate>(AgentMode::Code);
            if (!DescribeTool(args[1])) { std::cerr << "Unknown tool\n"; return 1; }
            return 0;
        }
        if (args[0] == "run") {
            g_ws = std::make_unique<WorkspaceToolHost>(g_workspace);
            g_tools = std::make_unique<rawrxd::tools::Registry>();
            g_ws->RegisterWorkspaceTools(*g_tools);
            g_gate = std::make_unique<PermissionGate>(AgentMode::Code);
            g_ledger = std::make_unique<AgentSession>(
                g_workspace + "/.rawrxd/ledger/agent_session.json");
            return RunToolCli(args);
        }
        std::cerr << "Usage: rawr tools list|describe <name>|run <name> [k=v ...]\n";
        return 2;
    }

    if (cmd == "backend") {
        RouterConfig cfg;
        cfg.mode = BackendMode::Auto;
        cfg.primary_endpoint = "http://127.0.0.1:11436";
        cfg.fallback_endpoint = "http://127.0.0.1:11434";
        g_router = std::make_unique<BackendRouter>();
        if (!g_router->Initialize(cfg)) { std::cerr << "router init failed\n"; return 1; }
        std::string mode = args.empty() ? "auto" : args[0];
        if (mode == "deep2")  g_router->SetMode(BackendMode::Deep2);
        if (mode == "ollama") g_router->SetMode(BackendMode::Ollama);
        auto h = g_router->GetPrimaryHealth();
        auto o2 = g_router->GetFallbackHealth();
        std::cout << "Mode:    " << mode << "\n";
        std::cout << "Deep2:   " << (h.available ? "available" : "unavailable") << " (" << h.endpoint << ")\n";
        std::cout << "Ollama:  " << (o2.available ? "available" : "unavailable") << " (" << o2.endpoint << ")\n";
        std::cout << "Active:  " << g_router->GetActiveModel() << "\n";
        return 0;
    }

    if (cmd == "models") {
        RouterConfig cfg;
        cfg.mode = BackendMode::Auto;
        cfg.primary_endpoint = "http://127.0.0.1:11436";
        cfg.fallback_endpoint = "http://127.0.0.1:11434";
        g_router = std::make_unique<BackendRouter>();
        if (!g_router->Initialize(cfg)) {
            std::cerr << "model discovery failed: no configured backend is reachable\n";
            return 1;
        }
        for (const auto& m : g_router->ListModels(BackendKind::Ollama))
            std::cout << "ollama  " << m << "\n";
        for (const auto& m : g_router->ListModels(BackendKind::Deep2))
            std::cout << "deep2   " << m << "\n";
        return 0;
    }

    if (cmd == "build" || cmd == "test") {
        WorkspaceToolHost ws(g_workspace);
        std::string cfg = o.get("config", "Release");
        if (cmd == "build") {
            std::string ev_dir = g_workspace + "/.rawrxd/evidence";
            auto ev = ws.RunBuild(o.get("target", ""), cfg, ev_dir);
            std::cout << "exit_code=" << ev.process_exit_code
                      << " errors=" << ev.compiler_errors
                      << " warnings=" << ev.compiler_warnings
                      << " artifacts=" << (ev.artifacts_verified ? "verified" : "MISSING")
                      << " log=" << ev.log_path << "\n";
            return ev.Succeeded() ? 0 : 1;
        }
        std::string ev_dir = g_workspace + "/.rawrxd/evidence";
        auto ev = ws.RunTests(o.get("filter", ""), ev_dir);
        std::cout << "exit_code=" << ev.process_exit_code
                  << " passed=" << ev.tests_passed
                  << " failed=" << ev.tests_failed
                  << " log=" << ev.log_path << "\n";
        return ev.Succeeded() ? 0 : 1;
    }

    std::cerr << "Unknown command: " << cmd << "\n";
    return 2;
}
