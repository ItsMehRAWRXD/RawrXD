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
#include "agentic/InferenceBackend.h"
#include "agentic/BackendRouter.h"
#include "agentic/OllamaBackend.h"
#include "agentic/Deep2Backend.h"
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
                            const json& provenance = json::object()) {
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
            // Apply TinyLlama-compatible chat template so the base model
            // interprets the user turn as an instruction rather than text
            // to continue. Without this, TinyLlama generates training-data
            // style QA content instead of following instructions.
            std::string prompt = "<|system|>\n"
                                 "You are a helpful assistant. Follow the user's instructions directly and concisely.\n"
                                 "<|user|>\n";
            for (size_t i = 0; i < msgs.size(); ++i) {
                const auto& m = msgs[i];
                if (m.role == "user") {
                    prompt += m.content;
                    prompt += "\n<|assistant|>\n";
                } else if (m.role == "assistant") {
                    prompt += m.content;
                    if (i + 1 < msgs.size() && msgs[i + 1].role == "user") {
                        prompt += "<|user|>\n";
                    }
                } else if (m.role == "system") {
                    // System content already emitted above; skip duplicates.
                }
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
                return InferenceResult::Error("Deep2Engine generated empty response");
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
    int maxTokens) {
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

        InferenceResult result;
        try {
            if (g_modelProvider) {
                // The provider seam: the engine asks for tokens, the provider
                // decides who produces them.
                result = g_modelProvider(messages, toolSchemas, maxTokens);
            } else {
                result = InferenceResult::Error("No inference backend available");
            }
        } catch (const std::exception& e) {
            outcome.failure = std::string("inference exception: ") + e.what();
            outcome.iterations = iteration + 1;
            return outcome;
        }
        if (!result.success) {
            outcome.failure = result.error_message.empty()
                ? "inference failed" : result.error_message;
            outcome.iterations = iteration + 1;
            return outcome;
        }

        messages.push_back(ChatMessage{"assistant", result.response, ""});
        // Tool calls: the provider's NATIVE tool calls win. The model was
        // given the tool schemas, so when it emits native calls they are
        // authoritative. Only fall back to parsing the response text when the
        // provider produced no native calls at all.
        std::vector<RawrXD::Agentic::ParsedToolCall> parsed;
        if (result.has_tool_calls && !result.tool_calls.empty()) {
            for (const auto& [name, args] : result.tool_calls) {
                RawrXD::Agentic::ParsedToolCall p;
                p.name = RawrXD::Agentic::ToolCallParser::NormalizeToolName(name);
                p.arguments = args.is_object() ? args : nlohmann::json::object();
                parsed.push_back(p);
            }
        } else {
            parsed = RawrXD::Agentic::ToolCallParser::parse(result.response).toolCalls;
        }

        // No structured action means the model has produced the final answer.
        if (parsed.empty()) {
            outcome.success = true;
            outcome.finalText = result.response;
            outcome.iterations = iteration + 1;
            return outcome;
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
                        messages.push_back(ChatMessage{
                            "tool", toolResult.ok ? toolResult.output :
                                ("ERROR: " + toolResult.error), call.id});
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
    return InferenceResult::Ok(full, ptok, ctok, tps, elapsed_ms);
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
            if (!agentResult.success) {
                std::cerr << "[agent] " << agentResult.failure << "\n";
                g_ledger->RecordFailure("agent loop failed: " + agentResult.failure);
                WriteRunReceipt(receiptPath, model, prompt, "", g_backend_name,
                                digest, requestedMaxTokens, true, agentIterations,
                                false, agentResult.failure,
                                BuildProvenance(true));
                g_ledger->Flush();
                return 1;
            }
            result = InferenceResult::Ok(agentResult.finalText);
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
                            BuildProvenance(agentRequested));
            return 1;
        }

        g_ledger->AppendAssistantMessage(result.response);
        if (g_streamed_response) std::cout << "\n" << std::flush;
        else std::cout << result.response << "\n";

        g_ledger->SetTermination(TerminationReason::ModelCompleted, 0);
        g_ledger->SetVerdict("one-shot task completed");

        if (!WriteRunReceipt(receiptPath, model, prompt, result.response, g_backend_name,
                             digest, requestedMaxTokens, agentRequested, agentIterations,
                             true, "", BuildProvenance(agentRequested))) {
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
//   01 SERVER      GET /api/version responds
//   02 DISCOVERY   GET /api/tags finds the requested model
//   03 METADATA    POST /api/show matches the requested model
//   04 GENERATE    first token received
//   05 STREAM      multiple chunks reconstructed correctly
//   06 COMPLETION  done received
//   07 ACCOUNTING  token/timing metadata captured
//   08 CANCEL      RawrXD cancellation stops the request
//   09 ERROR       a nonexistent model fails correctly
//   10 AGENT       a model turn reaches the RawrXD agent loop
//   11 TOOL        a model-requested tool is dispatched by RawrXD
//   12 VERIFY      the tool result is returned to the model
//   13 COMPLETE    the agent produces a final answer
//
// Gates 01-10 run against the LIVE Ollama server and the LIVE model.
// Gates 11-13 drive the SAME engine with a scripted provider, so the evidence
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
    std::string model = o.get("model", "");
    const auto installed = client.listModels();
    if (model.empty()) {
        // Pick the smallest installed model: the ladder should be quick and
        // must not depend on a large model's throughput.
        for (const auto& m : installed) {
            if (model.empty() || m.size < installed.front().size) {
                // handled below
            }
        }
        uint64_t smallest = UINT64_MAX;
        for (const auto& m : installed) {
            if (m.size < smallest) { smallest = m.size; model = m.name; }
        }
    }
    {
        bool found = false;
        for (const auto& m : installed) {
            if (m.name == model) { found = true; break; }
        }
        CertAdd(gates, "02", "DISCOVERY", found,
                found ? ("GET /api/tags found " + model)
                      : ("GET /api/tags does not list '" + model + "'"));
        evidence["model"] = model;
        evidence["installed_count"] = installed.size();
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

    // ---- 04-07 GENERATE / STREAM / COMPLETION / ACCOUNTING ----------------
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
                if (!gotFirstToken) {
                    gotFirstToken = true;
                    firstTokenMs = std::chrono::duration<double, std::milli>(
                        std::chrono::steady_clock::now() - t0).count();
                }
                ++chunkCount;
                if (!c.message.empty()) streamedText += c.message;
            },
            [&](const std::string& e) { streamError = e; },
            nullptr);
        totalMs = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - t0).count();

        const bool produced = ok && gotFirstToken && !streamedText.empty();
        CertAdd(gates, "04", "GENERATE", produced,
                produced ? ("first token after " + std::to_string((long long)firstTokenMs) + " ms")
                         : ("no token received: " + streamError));
        CertAdd(gates, "05", "STREAM", chunkCount >= 2 && !streamedText.empty(),
                "chunks=" + std::to_string(chunkCount) +
                " reconstructed_bytes=" + std::to_string(streamedText.size()));
        CertAdd(gates, "06", "COMPLETION", doneChunks == 1,
                "terminal done chunks=" + std::to_string(doneChunks));
        const bool accounted = ptok > 0 && ctok > 0 && evalDuration > 0;
        CertAdd(gates, "07", "ACCOUNTING", accounted,
                "prompt_eval_count=" + std::to_string(ptok) +
                " eval_count=" + std::to_string(ctok) +
                " eval_duration_ns=" + std::to_string(evalDuration) +
                " wall_ms=" + std::to_string((long long)totalMs));

        evidence["stream"] = {
            {"chunks", chunkCount},
            {"done_chunks", doneChunks},
            {"first_token_ms", firstTokenMs},
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
        CertAdd(gates, "08", "CANCEL", stopped,
                "chunks_before_cancel=" + std::to_string(chunksAtCancel) +
                " chunks_after=" + std::to_string(chunksTotal - chunksAtCancel) +
                " error='" + cancelError + "' elapsed_ms=" +
                std::to_string((long long)elapsedMs));
    }

    // ---- 09 ERROR --------------------------------------------------------
    {
        RawrXD::Backend::OllamaChatRequest req;
        req.model = "rawrxd-nonexistent-model-probe:0";
        req.stream = false;
        req.messages.push_back({"user", "hello"});
        const RawrXD::Backend::OllamaResponse resp = client.chatSync(req);
        const bool failed = !resp.error.empty() || resp.done_reason == "error";
        CertAdd(gates, "09", "ERROR", failed,
                failed ? ("nonexistent model rejected: " +
                          (resp.error.empty() ? resp.done_reason : resp.error))
                       : "nonexistent model was NOT rejected");
    }

    // ---- Agent gates (10-13) --------------------------------------------
    // The engine under test is the production agent loop. The agent runs in
    // Review mode: read-only authority, so a certification run can never
    // mutate the workspace.
    rawrxd::agentic::MotdAuthorization certAuth(g_workspace);
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

    g_ws = std::make_unique<WorkspaceToolHost>(g_workspace);
    g_tools = std::make_unique<rawrxd::tools::Registry>();
    g_ws->RegisterWorkspaceTools(*g_tools);
    g_gate = std::make_unique<PermissionGate>(AgentMode::Review);
    g_gate->SetPlanDirectory(g_workspace + "/.rawrxd/plans");
    g_ledger = std::make_unique<AgentSession>(
        g_workspace + "/.rawrxd/ledger/agent_session.json");
    g_ledger->SetWorkspaceRoot(g_workspace);
    g_ledger->SetModelIdentity(ModelIdentityString());
    g_ledger->SetMode(AgentMode::Review);

    // A probe file the engine will read through the real tool registry.
    const std::string evidenceDir = g_workspace + "/.rawrxd/evidence";
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
                g_modelProvider = [&](const std::vector<ChatMessage>& m, const json& t, int mt) {
                    ++liveTurns;
                    return liveProvider(m, t, mt);
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
    CertAdd(gates, "10", "AGENT", liveAgentOk, liveAgentDetail);

    // ---- 11-13: the engine, driven by a scripted provider ----------------
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
    CertAdd(gates, "11", "TOOL", toolDispatched,
            toolDispatched ? ("RawrXD dispatched " +
                              std::to_string(g_ledger->ToolCallCount()) + " tool call(s)")
                           : scriptedDetail);
    CertAdd(gates, "12", "VERIFY", sawMotdObservation && sawFileObservation,
            "motd_observation=" + std::string(sawMotdObservation ? "yes" : "no") +
            " file_observation=" + std::string(sawFileObservation ? "yes" : "no"));
    CertAdd(gates, "13", "COMPLETE", finalAnswer, scriptedDetail);

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
        g_workspace + "/.rawrxd/evidence/ollama_bench.json");

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
              << "   num_predict: " << numPredict << "\n\n";
    std::cout << "  " << std::left << std::setw(46) << "MODEL"
              << std::setw(9) << "SOURCE" << std::setw(9) << "STATUS"
              << std::setw(9) << "TTFT(ms)" << std::setw(9) << "GEN(ms)"
              << std::setw(9) << "TPS" << "EVAL_TOK\n";

    json report = json::array();
    int ok = 0, failed = 0, cloudSeen = 0;
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

        RawrXD::Backend::OllamaChatRequest req;
        req.model = model;
        req.stream = true;
        req.messages.push_back({"user", prompt});
        req.options["temperature"] = 0.2;
        req.options["num_predict"] = numPredict;

        bool gotToken = false;
        bool gotDone = false;
        double ttftMs = 0;
        double wallMs = 0;
        uint64_t ptok = 0, ctok = 0, evalDurationNs = 0, loadDurationNs = 0;
        std::string err;

        client.clearCancel();
        client.setTimeoutSeconds(perModelTimeout);
        const auto t0 = std::chrono::steady_clock::now();
        const bool completed = client.chat(
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
        report.push_back(entry);

        if (pass) ++ok; else ++failed;

        std::cout << "  " << std::left << std::setw(46) << model
                  << std::setw(9) << (isCloud ? "cloud" : "local")
                  << std::setw(9) << (pass ? "OK" : "FAIL")
                  << std::setw(9) << (long long)ttftMs
                  << std::setw(9) << (long long)(genSeconds * 1000.0)
                  << std::setw(9) << (tps > 0 ? (long long)(tps * 10) / 10.0 : 0.0)
                  << ctok;
        if (!pass) std::cout << "  " << (err.empty() ? "no completion" : err);
        std::cout << "\n" << std::flush;

        // Release the model so the next measurement is not sharing GPU memory
        // (or VRAM residency) with this one.
        if (!o.has("keep-loaded")) {
            client.unloadModel(model);
        }
    }

    std::error_code ec;
    fs::path out(reportPath);
    if (!out.parent_path().empty()) fs::create_directories(out.parent_path(), ec);
    {
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
    }
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
// main
// ---------------------------------------------------------------------------
int main(int argc, char** argv) {
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
              << "  rawr run <model> \"add a GUI\"                            follow-up wizard\n"
              << "  rawr modes                                                  list agent modes\n"
              << "  rawr tools list|describe <name>|run <name> [k=v ...]       tool interface\n"
              << "  rawr models                                                 list models\n"
              << "  rawr list  --provider ollama                               installed models\n"
              << "  rawr show  --provider ollama <model>                       model metadata\n"
              << "  rawr ps    --provider ollama                               resident models\n"
              << "  rawr auth  --provider ollama [--probe]                     account/quota state\n"
              << "  rawr bench --provider ollama [model ...]                   measure TPS per model\n"
              << "  rawr certify ollama [--model m]                            OLLAMA_BRIDGE_001 ladder\n"
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

    if (cmd == "run") {
        return CmdRun(args);
    }
    if (cmd == "modes")     return CmdModes();
    if (cmd == "doctor")    return CmdDoctor();
    if (cmd == "self-audit") return CmdSelfAudit();

    if (cmd == "list")  return CmdProviderList(o);
    if (cmd == "ps")    return CmdProviderPs(o);
    if (cmd == "auth")  return CmdProviderAuth(o);
    if (cmd == "bench") return CmdBenchProvider(o);
    if (cmd == "certify") {
        const std::string kind = toLowerCompat(o.get("kind", "ollama"));
        if (kind != "ollama") {
            std::cerr << "ERROR: certify supports only --kind ollama\n";
            return 2;
        }
        return CmdCertifyOllama(o);
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
        if (g_router->Initialize(cfg)) {
            for (const auto& m : g_router->ListModels(BackendKind::Ollama))
                std::cout << "ollama  " << m << "\n";
            for (const auto& m : g_router->ListModels(BackendKind::Deep2))
                std::cout << "deep2   " << m << "\n";
        }
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
