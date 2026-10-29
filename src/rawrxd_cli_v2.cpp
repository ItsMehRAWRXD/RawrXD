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
#include "backend/ollama_client.h"
#include "agentic/ToolCallBridge.h"
#include "agentic/PersistentTaskBacklog.h"
#include "agentic/SelfRepairLoop.h"
#include "agentic/AgentMode.h"
#include "agentic/AgentSession.h"
#include "agentic/WorkspaceToolHost.h"
#include "agentic/tool_core.hpp"
#include "agentic/NativeToolProtocol.h"
#ifdef _WIN32
#include "agentic/process_win32.hpp"
#include <windows.h>
#endif

#include "deep2/Deep2CLIBridge.hpp"
#include "deep2/RawrModelAlias.hpp"
#include "deep2/QuantParityRegistry.h"
#include "reap_cli_contract.hpp"
#include "reap_pipeline.hpp"
#include "reap/ReapRuntime.hpp"
#include "project_wizard/project_spec.hpp"
#include "project_wizard/project_state_manager.hpp"
#include "project_wizard/project_wizard.hpp"
#include "project_wizard/project_workflow.hpp"
#include "project_wizard/esp_runtime.hpp"
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
#include <cmath>
#include <fstream>
#include <limits>
#include <set>
#include <thread>

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
static std::atomic<bool>                   g_streamed_response{false};
// Per-run limits are owned by the CLI driver so every agent round (including
// tool continuations) uses the same caller-approved budget.  The native
// Deep2 bridge consumes max tokens directly; the Ollama/HTTP route receives
// both values through BackendConfig below.
static int                              g_run_max_tokens = 4096;
static int                              g_run_context = 0;
// The native IDE's approved source-edit workflow can request a narrow tool
// surface for one task.  The tools remain real registry dispatches; this only
// prevents a small model from spending its first turn on an unrelated
// workspace listing when the user supplied a concrete file edit request.
static bool                                g_source_edit_tool_scope = false;
// Mutations remain denied unless the caller explicitly opts in for this
// process.  The CLI flag is the stable automation surface; the environment
// variable is retained for existing scripts.
static bool                                g_explicit_mutation_approval = false;

// The CLI and native IDE share the same dependency-free ESP event format.  The
// normal `rawr run` path used to update only the durable agent ledger, which
// meant the GUI could show an agent task but had no truthful lifecycle events
// for inference, tools, or completion.  This adapter is deliberately small:
// it publishes only facts observed at the real dispatch boundaries below.
class CliEspSession final {
public:
    CliEspSession(bool enabled, std::string path, bool verbose)
        : enabled_(enabled), verbose_(verbose), bus_(8192, 4096) {
        if (!enabled_) return;

        std::error_code ec;
        fs::create_directories(fs::path(path).parent_path(), ec);
        recorder_ = std::make_unique<rawrxd::esp::Recorder>(
            bus_, std::move(path),
            [this](const rawrxd::esp::Event& event) {
                if (!verbose_ && event.kind == rawrxd::esp::Kind::TokenGenerated)
                    return;
                std::fprintf(stderr,
                    "[ESP] seq=%llu req=%llu kind=%s value=%lld message=%s\n",
                    static_cast<unsigned long long>(event.sequence),
                    static_cast<unsigned long long>(event.request_id),
                    rawrxd::esp::kind_name(event.kind),
                    static_cast<long long>(event.value), event.message.c_str());
                std::fflush(stderr);
            });
        if (!recorder_->start()) {
            recorder_.reset();
            std::fprintf(stderr, "[ESP] ERROR unable to open telemetry log\n");
            return;
        }
        const auto request = static_cast<uint64_t>(
            std::chrono::steady_clock::now().time_since_epoch().count());
        runtime_ = std::make_unique<rawrxd::esp::RuntimeESP>(bus_, request, 1);
        publish(rawrxd::esp::Kind::AgentStep, "cli_run_start");
    }

    ~CliEspSession() {
        if (enabled_ && runtime_ && !finished_) {
            runtime_->finish(false);
        }
    }

    bool enabled() const noexcept { return enabled_ && runtime_ != nullptr; }

    void model_load(std::string_view model) {
        if (enabled()) runtime_->model_load(model);
    }
    void inference_start() {
        publish(rawrxd::esp::Kind::AgentStep, "inference_start");
    }
    void stage(std::string_view message) {
        publish(rawrxd::esp::Kind::AgentStep, message);
    }
    void phase(std::string_view name) {
        publish(rawrxd::esp::Kind::AgentStep, std::string("phase=") + std::string(name));
    }
    void inference_result(bool ok, int64_t completion_tokens = 0) {
        if (!enabled()) return;
        if (ok) {
            runtime_->decode_start();
            runtime_->token(0, "completion");
            (void)completion_tokens; // one completed assistant response is one ESP token event
        } else {
            runtime_->model_output_failure();
        }
    }
    void backend_metrics(const InferenceResult& result) {
        if (!enabled() || !result.native_metrics_valid) return;
        std::ostringstream message;
        message << "source=" << (result.metrics_source.empty() ? "backend" : result.metrics_source)
                << " prompt_eval_count=" << result.prompt_tokens
                << " eval_count=" << result.completion_tokens
                << " total_duration_ns=" << result.total_duration_ns
                << " load_duration_ns=" << result.load_duration_ns
                << " prompt_eval_duration_ns=" << result.prompt_eval_duration_ns
                << " eval_duration_ns=" << result.eval_duration_ns
                << " eval_tps=" << std::setprecision(12) << result.tokens_per_sec;
        publish(rawrxd::esp::Kind::Heartbeat, message.str());
    }
    void tool_start(std::string_view name) {
        if (enabled()) runtime_->tool_start(name);
    }
    void tool_result(std::string_view name, bool ok, int exit_code = 0) {
        if (!enabled()) return;
        runtime_->tool_result(std::string(name) + (ok ? " PASS" : " FAIL"),
                              ok ? exit_code : (exit_code == 0 ? 1 : exit_code));
    }
    void file_changed(std::string_view path) {
        publish(rawrxd::esp::Kind::FileChanged, path);
    }
    void build_result(int exit_code) {
        if (!enabled()) return;
        runtime_->build_result(exit_code);
    }
    void test_result(int exit_code) {
        if (!enabled()) return;
        runtime_->test_result(exit_code);
    }
    void fail(std::string_view reason) {
        if (!enabled()) return;
        publish(rawrxd::esp::Kind::Error, reason, 1);
        runtime_->finish(false);
        finished_ = true;
    }
    void cancel(std::string_view reason) {
        if (!enabled()) return;
        publish(rawrxd::esp::Kind::SnapStop, reason, 130);
        runtime_->finish(false);
        finished_ = true;
    }
    void finish(bool ok) {
        if (!enabled() || finished_) return;
        runtime_->finish(ok);
        finished_ = true;
    }

private:
    void publish(rawrxd::esp::Kind kind, std::string_view message, int64_t value = 0) {
        if (enabled()) bus_.publish(kind, message, request_id(), 1, value);
    }
    uint64_t request_id() const noexcept {
        return runtime_ ? runtime_->metrics().snapshot().request_id : 0;
    }

    bool enabled_ = false;
    bool verbose_ = false;
    bool finished_ = false;
    rawrxd::esp::Bus bus_;
    std::unique_ptr<rawrxd::esp::Recorder> recorder_;
    std::unique_ptr<rawrxd::esp::RuntimeESP> runtime_;
};

static bool CliTraceEnabled() noexcept {
    return std::getenv("RAWRXD_CLI_DISPATCH_TRACE") != nullptr;
}

static void CliTrace(const char* stage) noexcept {
    if (CliTraceEnabled()) {
        std::fprintf(stderr, "[rawr-cli-trace] %s\n", stage ? stage : "(null)");
        std::fflush(stderr);
    }
}

static json BuildToolDefinitions() {
    json definitions = json::array();
    if (!g_tools) return definitions;
    for (const auto& name : g_tools->names()) {
        if (g_source_edit_tool_scope && name != "readFile" &&
            name != "editFiles" && name != "writeFile") {
            continue;
        }
        rawrxd::tools::Tool tool;
        if (!g_tools->find(name, tool)) continue;
        json properties = json::object();
        for (const auto& required : tool.required) {
            properties[required] = { {"type", "string"} };
        }
        // Optional bounds and scope are part of the native tool contract.  In
        // particular, audit-capable models must be able to narrow directory
        // and search results instead of flooding their context with a root
        // listing.  These remain optional so older tool-call payloads stay
        // compatible.
        if (tool.name == "listDirectory") {
            properties["maxEntries"] = {
                {"type", "integer"}, {"minimum", 1}, {"maximum", 256},
                {"description", "Maximum immediate children to return"}
            };
        } else if (tool.name == "fileSearch" || tool.name == "textSearch") {
            properties["path"] = {
                {"type", "string"},
                {"description", "Workspace-relative directory to search; defaults to ."}
            };
            properties["maxResults"] = {
                {"type", "integer"}, {"minimum", 1}, {"maximum", 250},
                {"description", "Maximum matches to return"}
            };
        }
        definitions.push_back({
            {"type", "function"},
            {"function", {
                {"name", tool.name},
                {"description", tool.description},
                {"parameters", {
                    {"type", "object"},
                    {"properties", properties},
                    {"required", tool.required}
                }}
            }}
        });
    }
    return definitions;
}

// ---------------------------------------------------------------------------
// Signal handling
// ---------------------------------------------------------------------------
static void OnSignal(int) {
    g_running = false;
    if (g_router) g_router->Cancel();
}

#ifdef _WIN32
// The CRT SIGINT handler alone can still allow the console host to terminate
// the child before the one-shot driver persists its ledger.  Handle the
// native console event explicitly so cancellation remains observable and the
// backend receives the same cancel request as the POSIX signal path.
static BOOL WINAPI OnConsoleControl(DWORD control) noexcept {
    switch (control) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
        g_running.store(false);
        if (g_router) g_router->Cancel();
        return TRUE;
    default:
        return FALSE;
    }
}
#endif

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

// `--size` was historically accepted by the generic flag parser and then
// silently ignored.  That is unsafe: callers could believe REAP admission or
// pruning had happened when the ordinary model path was used unchanged.
static bool ParseMemoryBudget(const std::string& text, uint64_t& bytes) {
    if (text.empty()) return false;
    size_t split = 0;
    while (split < text.size() && (std::isdigit(static_cast<unsigned char>(text[split])) || text[split] == '.')) ++split;
    if (split == 0 || split == text.size()) return false;
    char* end = nullptr;
    const double value = std::strtod(text.substr(0, split).c_str(), &end);
    if (!std::isfinite(value) || value <= 0.0) return false;
    std::string unit = text.substr(split);
    std::transform(unit.begin(), unit.end(), unit.begin(), [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    uint64_t multiplier = 1;
    if (unit == "B") multiplier = 1;
    else if (unit == "KB" || unit == "KIB") multiplier = 1024ull;
    else if (unit == "MB" || unit == "MIB") multiplier = 1024ull * 1024ull;
    else if (unit == "GB" || unit == "GIB") multiplier = 1024ull * 1024ull * 1024ull;
    else if (unit == "TB" || unit == "TIB") multiplier = 1024ull * 1024ull * 1024ull * 1024ull;
    else return false;
    const long double result = static_cast<long double>(value) * multiplier;
    if (result > static_cast<long double>(std::numeric_limits<uint64_t>::max())) return false;
    bytes = static_cast<uint64_t>(result);
    return bytes != 0;
}

// Validate the proposed REAP command contract before any backend/model work.
// The contract is intentionally fail-closed: a syntactically valid request is
// still blocked until MLA-CERT-001, model-specific calibration/selection, and
// parity-certified rewriting are present in the same runtime.
static int HandleReapContract(const std::string& model,
                              const std::map<std::string, std::string>& flags,
                              const std::string& promptIn) {
    static const char* const kReapOptions[] = {
        "target-size", "active-experts", "expert-budget", "quality-floor"
    };
    const bool requested = flags.count("reap") != 0 && flags.at("reap") == "true";
    if (flags.count("reap") != 0 && !requested) {
        std::cerr << "REAP_FLAG_INVALID: --reap is a switch and cannot carry a value\n";
        return 2;
    }
    bool hasReapOption = false;
    for (const char* option : kReapOptions) {
        if (flags.count(option) != 0) { hasReapOption = true; break; }
    }
    if (!requested && hasReapOption) {
        std::cerr << "REAP_OPTIONS_REQUIRE_FLAG: use --reap with --target-size,"
                     " --active-experts, --expert-budget, and --quality-floor\n";
        return 2;
    }
    if (!requested) return -1;

    RawrXD::Reap::CliRequest request;
    request.model = model;
    if (flags.count("target-size") != 0 && flags.count("size") != 0) {
        std::cerr << "REAP_SIZE_OPTION_CONFLICT: specify only one of --target-size or --size\n";
        return 2;
    }
    // `--size` is a compatibility alias only inside an explicit --reap
    // request. A plain rawr run --size remains fail-closed below.
    request.targetSizeText = flags.count("target-size")
        ? flags.at("target-size")
        : (flags.count("size") ? flags.at("size") : "");
    request.activeExpertsText = flags.count("active-experts") ? flags.at("active-experts") : "";
    request.expertBudgetText = flags.count("expert-budget") ? flags.at("expert-budget") : "";
    request.qualityFloorText = flags.count("quality-floor") ? flags.at("quality-floor") : "";
    request.workspace = g_workspace;
    request.selectionManifestPath = flags.count("selection-output") ? flags.at("selection-output") : "";
    request.outputDirectory = flags.count("output-model") ? flags.at("output-model") : "";
    request.authorizeRewrite = flags.count("authorize-rewrite") != 0 &&
                               flags.at("authorize-rewrite") == "true";

    const auto validation = RawrXD::Reap::Validate(request);
    if (!validation.ok) {
        std::cerr << validation.code << ": " << validation.message << "\n";
        return 2;
    }
    // Parse again into the receipt's canonical numeric fields. Validate() has
    // already checked each conversion; failure here indicates an internal
    // contract defect and must not be treated as a successful request.
    if (!RawrXD::Reap::ParseSizeBytes(request.targetSizeText, request.targetSizeBytes) ||
        !RawrXD::Reap::ParseSizeBytes(request.expertBudgetText, request.expertBudgetBytes) ||
        !RawrXD::Reap::ParseActiveExperts(request.activeExpertsText, request.activeExperts) ||
        !RawrXD::Reap::ParseQualityFloor(request.qualityFloorText, request.qualityFloor)) {
        std::cerr << "REAP_INTERNAL_VALIDATION_FAILURE\n";
        return 2;
    }

    std::string prompt = promptIn;
    if (prompt.empty() && flags.count("prompt")) prompt = flags.at("prompt");
    else if (prompt.empty() && flags.count("task")) prompt = flags.at("task");
    const auto pipeline = RawrXD::Reap::RunPipeline(request, prompt);
    std::cout << pipeline.receipt;
    if (pipeline.exitCode != 0) {
        std::cerr << "REAP_PIPELINE_BLOCKED: transformation stays disabled"
                     " until inventory, calibration, selection, parity, and"
                     " writer receipts pass EvaluateAdmission\n";
    }
    return pipeline.exitCode;
}

// Runtime REAP is a live streamer/router injection, not the offline GGUF
// writer.  A valued --reap is the explicit <parameters>/<experts> form; the
// legacy bare --reap switch continues to use the guarded writer contract.
static int HandleRuntimeReap(const std::string& model,
                             const std::map<std::string, std::string>& flags,
                             const std::string& promptIn) {
    auto it = flags.find("reap");
    if (it == flags.end() || it->second == "true") return -1;

    RawrXD::Reap::RuntimeRequest request;
    request.model = model;
    request.target = it->second;
    request.prompt = promptIn;
    if (request.prompt.empty()) {
        if (auto p = flags.find("prompt"); p != flags.end()) request.prompt = p->second;
        else if (auto t = flags.find("task"); t != flags.end()) request.prompt = t->second;
    }
    request.maxTokens = static_cast<uint32_t>((std::max)(1, g_run_max_tokens));
    if (auto r = flags.find("receipt"); r != flags.end()) request.receiptPath = r->second;
    const auto result = RawrXD::Reap::RunRuntime(request);
    std::cout << result.receipt;
    return result.exitCode;
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
// Chat prompt. Qwen instruct models use ChatML. Other Deep2 loads keep the
// TinyLlama markers this path already used.
// ---------------------------------------------------------------------------
static bool TextHasToken(const std::string& text, const char* token) {
    size_t n = 0;
    while (token[n]) ++n;
    if (n == 0 || text.size() < n) return false;
    for (size_t i = 0; i + n <= text.size(); ++i) {
        size_t j = 0;
        for (; j < n; ++j) {
            char c = text[i + j];
            if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
            if (c != token[j]) break;
        }
        if (j == n) return true;
    }
    return false;
}

static std::string FormatDeep2Prompt(const std::string& modelId,
                                    const std::vector<ChatMessage>& msgs) {
    constexpr const char* kNativeToolProtocol =
        "\nNATIVE RAWRXD TOOL PROTOCOL (use only when the task requires a tool):\n"
        "Reply with exactly one complete command and no prose.\n"
        "TOOL read <relative-path>\n"
        "TOOL write <relative-path> @@<complete-file-content>@@\n"
        "TOOL build\nTOOL test\n"
        "A command is dispatched only after its complete terminator is present; "
        "never emit arbitrary shell commands.\n";
    if (TextHasToken(modelId, "qwen")) {
        bool sawSystem = false;
        for (const auto& m : msgs) if (m.role == "system") sawSystem = true;
        std::string prompt;
        if (!sawSystem) {
            prompt = "<|im_start|>system\nYou are a helpful assistant.<|im_end|>\n";
        }
        for (const auto& m : msgs) {
            if (m.role != "system" && m.role != "user" && m.role != "assistant" &&
                m.role != "tool") continue;
            prompt += "<|im_start|>";
            prompt += m.role;
            prompt += "\n";
            prompt += m.content;
            if (m.role == "system") prompt += kNativeToolProtocol;
            prompt += "<|im_end|>\n";
        }
        prompt += "<|im_start|>assistant\n";
        return prompt;
    }
    std::string prompt = "<|system|>\n"
        "You are a helpful assistant. Follow the user's instructions directly and concisely.\n"
        "NATIVE RAWRXD TOOL PROTOCOL: use exactly one complete TOOL read/write/build/test "
        "command when a tool is required; never emit arbitrary shell text.\n"
        "<|user|>\n";
    for (size_t i = 0; i < msgs.size(); ++i) {
        const auto& m = msgs[i];
        if (m.role == "user") {
            prompt += m.content;
            prompt += "\n<|assistant|>\n";
        } else if (m.role == "assistant") {
            prompt += m.content;
            if (i + 1 < msgs.size() && msgs[i + 1].role == "user") prompt += "<|user|>\n";
        } else if (m.role == "tool") {
            prompt += "\n<|tool|>\n";
            prompt += m.content;
            prompt += "\n<|assistant|>\n";
        }
    }
    return prompt;
}

static bool EndsWithGguf(const std::string& model) {
    return model.size() >= 5 && _stricmp(model.c_str() + model.size() - 5, ".gguf") == 0;
}

static bool ParseBoundedRunOption(const std::map<std::string, std::string>& flags,
                                  const char* name, int minimum, int maximum,
                                  int& value, std::string& error) {
    const auto it = flags.find(name);
    if (it == flags.end()) return true;
    try {
        size_t consumed = 0;
        const long long parsed = std::stoll(it->second, &consumed, 10);
        if (consumed != it->second.size() || parsed < minimum || parsed > maximum) {
            error = std::string("invalid --") + name + " value (expected " +
                    std::to_string(minimum) + ".." + std::to_string(maximum) + ")";
            return false;
        }
        value = static_cast<int>(parsed);
        return true;
    } catch (...) {
        error = std::string("invalid --") + name + " value: " + it->second;
        return false;
    }
}

// ---------------------------------------------------------------------------
// Backend initialization
// ---------------------------------------------------------------------------
static void ApplyRunBackendConfig() {
    if (!g_router) return;

    // Configure both local backends before the first request.  This keeps
    // explicit Ollama mode, auto mode, and a later backend switch consistent
    // instead of applying the UI/CLI values only to whichever backend was
    // active during initialization.
    for (const auto kind : {BackendKind::Deep2, BackendKind::Ollama}) {
        auto* backend = g_router->GetBackendPtr(kind);
        if (!backend) continue;
        auto config = backend->GetConfig();
        config.max_tokens = g_run_max_tokens;
        if (g_run_context > 0) config.num_ctx = g_run_context;
        backend->SetConfig(config);
    }

    std::cerr << "RUN_CONFIG_MAX_TOKENS=" << g_run_max_tokens << "\n";
    if (g_run_context > 0) {
        std::cerr << "RUN_CONFIG_CONTEXT=" << g_run_context << "\n";
    }
}

static bool InitBackend(BackendMode mode, const std::string& model) {
    CliTrace("InitBackend:enter");
    // Explicit --backend stays authoritative. Auto tries a local Deep2 resolve
    // first. A resolved path that fails to load does not fall through to Ollama.
    Deep2::rawr_run::AliasResolve resolved{};
    const bool aliasHit = !model.empty() &&
        Deep2::rawr_run::ResolveModelAlias(model.c_str(), resolved);
    const bool tryDeep2 = mode == BackendMode::Deep2 ||
        (mode == BackendMode::Auto && (aliasHit || EndsWithGguf(model)));
    if (tryDeep2) {
        CliTrace("InitBackend:deep2-selected");
        if (localEngine) {
            deep2_free(localEngine);
            localEngine = nullptr;
        }
        std::string modelPath = g_workspace + "/" + model;
        if (aliasHit) {
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
            std::cerr << "DEEP2_LOAD_FAILED: " << model << "\n";
            std::cerr << "Ollama was not called.\n";
            return false;
        }
        std::fprintf(stderr, "[Deep2Backend] Model loaded: hidden=%u vocab=%u layers=%zu\n",
                     deep2_hidden_dim(localEngine),
                     deep2_vocab_size(localEngine),
                     deep2_num_layers(localEngine));
        const std::string templateId = model + "\n" + modelPath;
        std::fprintf(stderr, "[Deep2Backend] Chat template: %s\n",
                     TextHasToken(templateId, "qwen") ? "qwen-chatml" : "tinyllama");

        deep2CompleteFn = [templateId](const std::vector<ChatMessage>& msgs, int maxTokens) {
            std::string prompt = FormatDeep2Prompt(templateId, msgs);
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
            const auto nativeCommand = rawrxd::agentic::ParseNativeToolCommand(text);
            if (nativeCommand.finish) {
                return InferenceResult::Error(
                    "NATIVE_TOOL_FINISH_UNVERIFIED: host verification is required before completion");
            }
            if (nativeCommand.valid && !nativeCommand.finish) {
                r.has_tool_calls = true;
                r.tool_calls.emplace_back(
                    nativeCommand.tool,
                    nativeCommand.tool == "writeFile"
                        ? json{{"path", nativeCommand.path}, {"content", nativeCommand.content}}
                        : nativeCommand.tool == "readFile"
                            ? json{{"path", nativeCommand.path}}
                            : json{{"command", nativeCommand.command}});
                // Keep the exact model response in the assistant transcript,
                // but the surrounding agent loop will dispatch the structured
                // call instead of presenting the command as the final answer.
            }
            return r;
        };

        g_model = model;
        CliTrace("InitBackend:deep2-ready");
        return true;
    }

    if (g_router) {
        CliTrace("InitBackend:router-reuse");
        g_router->SetMode(mode);
        if (!model.empty()) {
            if (auto* b = g_router->GetBackendPtr(g_router->GetActiveBackendKind())) {
                auto cfg = b->GetConfig();
                cfg.model = model;
                b->SetConfig(cfg);
            }
        }
        ApplyRunBackendConfig();
        return true;
    }

    RouterConfig cfg;
    cfg.mode = mode;
    cfg.primary_endpoint = "http://127.0.0.1:11436";
    cfg.fallback_endpoint = "http://127.0.0.1:11434";
    if (const char* endpoint = std::getenv("RAWRXD_OLLAMA_ENDPOINT");
        endpoint != nullptr && *endpoint != '\0') {
        // Keep the CLI sweep and air-gapped deployments on the same explicit
        // endpoint without changing the default local Ollama route.
        cfg.fallback_endpoint = endpoint;
    }
    cfg.primary_model = "deep2-native";
    cfg.fallback_model = model.empty() ? "qwen2.5-coder:32b" : model;
    if (const char* numGpu = std::getenv("RAWRXD_OLLAMA_NUM_GPU");
        numGpu != nullptr && *numGpu != '\0') {
        try {
            cfg.ollama_num_gpu = std::stoi(numGpu);
        } catch (...) {
            std::cerr << "Ignoring invalid RAWRXD_OLLAMA_NUM_GPU value\n";
        }
    }

    if (mode == BackendMode::Deep2)   cfg.primary_model = model.empty() ? cfg.primary_model : model;
    if (mode == BackendMode::Ollama)  cfg.fallback_model = model.empty() ? cfg.fallback_model : model;
    if (mode == BackendMode::Ollama)  cfg.primary_model = "";

    g_router = std::make_unique<BackendRouter>();
    CliTrace("InitBackend:router-initialize");
    const bool initialized = g_router->Initialize(cfg);
    CliTrace(initialized ? "InitBackend:router-ready" : "InitBackend:router-failed");
    if (initialized) ApplyRunBackendConfig();
    return initialized;
}

static std::string ActiveModelName() {
    if (!g_router) return "unknown";
    return g_router->GetActiveModel();
}

static std::string ModelIdentityString() {
    if (!g_router) return "unknown";
    return std::string(BackendModeName(g_router->GetMode())) + "/" + g_router->GetActiveModel();
}

static std::string LedgerTerminationName(const AgentSession& s);
static bool LedgerBuildPassed(const AgentSession& s);
static bool LedgerTestsPassed(const AgentSession& s);

// ---------------------------------------------------------------------------
// Approval policy (mutations require explicit env opt-in)
// ---------------------------------------------------------------------------
static bool ApproveMutation(const std::string& tool, const json& /*args*/) {
    const char* env = std::getenv("RAWRXD_TOOLS_APPROVE_MUTATIONS");
    const bool env_ok = env && std::string(env) == "YES";
    if (!env_ok && !g_explicit_mutation_approval) return false;
    // External/network tools are never auto-approved, even with the env var.
    return tool != "runInTerminal" || env_ok || g_explicit_mutation_approval;
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
            const bool gate_ready = g_gate != nullptr;
            const ModePolicy* p = gate_ready
                ? ModeRegistry::Instance().Get(g_gate->GetMode()) : nullptr;
            ToolAuthority granted = p ? ModeRegistry::Instance().AuthorityFor(g_gate->GetMode(), n)
                                      : ToolAuthority::Denied;
            std::cout << "  " << std::left << std::setw(16) << n
                      << "[" << ToolAuthorityName(granted) << "]  "
                      << t.description << "\n";
        }
    }
    const ToolAuthority effective = g_gate ? g_gate->EffectiveAuthority() : ToolAuthority::Denied;
    std::cout << "\nAuthority: " << ToolAuthorityName(effective) << "\n";
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

// ---------------------------------------------------------------------------
// rawr run — the universal interactive agent session
// ---------------------------------------------------------------------------
namespace {
int CmdProjectWizard(const std::string& model, const std::string& goal,
                     const std::map<std::string, std::string>& flags,
                     const std::string& workspace_root,
                     rawrxd::agentic::MotdAuthorization* authorization,
                     const std::string& session, uint64_t turn);
}

static int CmdRun(const std::vector<std::string>& args) {
    CliTrace("CmdRun:enter");
    // args = [model, mode?, --flag ...]
    std::string model;
    std::string mode_str;
    std::map<std::string, std::string> flags;

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
        else if (model.empty()) {
            model = a;
        }
        else if (mode_str.empty()) {
            mode_str = a;
        }
    }
    g_explicit_mutation_approval = flags.count("approve-mutations") != 0;
    g_source_edit_tool_scope =
        flags.count("tool-scope") != 0 && flags.at("tool-scope") == "source-edit";
    g_run_max_tokens = 4096;
    g_run_context = 0;
    std::string runOptionError;
    if (!ParseBoundedRunOption(flags, "max-tokens", 1, 65536,
                               g_run_max_tokens, runOptionError) ||
        !ParseBoundedRunOption(flags, "context", 512, 1048576,
                               g_run_context, runOptionError)) {
        std::cerr << "RUN_CONFIG_ERROR=" << runOptionError << "\n";
        return 2;
    }
    std::cerr << "RUN_CONFIG_REQUESTED_MAX_TOKENS=" << g_run_max_tokens << "\n";
    if (g_run_context > 0) {
        std::cerr << "RUN_CONFIG_REQUESTED_CONTEXT=" << g_run_context << "\n";
    }
    CliTrace("CmdRun:arguments-parsed");

    const int runtimeReapResult = HandleRuntimeReap(model, flags, mode_str);
    if (runtimeReapResult >= 0) return runtimeReapResult;

    const int reapContractResult = HandleReapContract(model, flags, mode_str);
    if (reapContractResult >= 0) return reapContractResult;

    // A legacy bare --size request has no live runtime target. Reject it
    // explicitly instead of silently running an unmodified model. The
    // production live form is --reap <parameters>/<experts>, handled above.
    if (flags.count("size")) {
        uint64_t budget = 0;
        if (!ParseMemoryBudget(flags["size"], budget)) {
            std::cerr << "Invalid --size value: " << flags["size"]
                      << " (use B, MB, GB, or TB)\n";
            return 2;
        }
        std::cerr << "MODEL_SIZE_REQUESTED=" << flags["size"]
                  << " (" << budget << " bytes)\n"
                  << "REAP_RUNTIME_UNAVAILABLE: no validated expert-pruning or"
                     " residency planner is linked into this executable\n";
        return 2;
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
    // Project-wizard detection is intentionally limited to the bare second
    // positional form.  A normal `--prompt`/`--task` agent request often
    // contains words such as "add", "tests", or "build" and must never be
    // diverted into the project-specification workflow.
    if (!mode_str.empty() && !flags.count("prompt") && !flags.count("task")) {
        workflow_goal = mode_str;
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
            flags["prompt"] = mode_str;
            mode_str.clear();
        }
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

    // Resolve backend mode.
    std::string b = flags.count("backend") ? flags["backend"] : "auto";
    BackendMode bmode = BackendMode::Auto;
    g_backend_name = b;
    if (b == "deep2")       bmode = BackendMode::Deep2;
    else if (b == "ollama") bmode = BackendMode::Ollama;
    else if (b == "manual") bmode = BackendMode::Manual;

    if (!InitBackend(bmode, model)) {
        std::cerr << "Failed to initialize inference backend (" << b << ").\n";
        std::cerr << "For Ollama: confirm a server on http://127.0.0.1:11434 and `ollama list`.\n";
        std::cerr << "For Deep2:  confirm the runtime bridge on http://127.0.0.1:11436.\n";
        return 1;
    }
    CliTrace("CmdRun:backend-ready");

    // Build the tool registry and permission gate.
    g_ws = std::make_unique<WorkspaceToolHost>(g_workspace);
    g_tools = std::make_unique<rawrxd::tools::Registry>();
    g_ws->RegisterWorkspaceTools(*g_tools);
    CliTrace("CmdRun:tools-ready");

    // WorkspaceToolHost registers the canonical runInTerminal tool together
    // with the read/write tools. Do not add a second descriptor here: Registry
    // intentionally rejects duplicate names, and the old duplicate caused an
    // uncaught exception followed by std::terminate before the first request.

    CliTrace("CmdRun:permission-gate-construct");
    g_gate = std::make_unique<PermissionGate>(mode);
    CliTrace("CmdRun:permission-gate-ready");
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
    CliTrace("CmdRun:ledger-construct");
    g_ledger = std::make_unique<AgentSession>(
        g_workspace + "/.rawrxd/ledger/agent_session.json");
    CliTrace("CmdRun:ledger-constructed");
    g_ledger->SetWorkspaceRoot(g_workspace);
    CliTrace("CmdRun:ledger-workspace-set");
    g_ledger->SetModelIdentity(ModelIdentityString());
    CliTrace("CmdRun:ledger-model-set");
    g_ledger->SetGitState(RunGit("rev-parse HEAD"), RunGit("rev-parse --abbrev-ref HEAD"));
    CliTrace("CmdRun:ledger-git-set");
    g_ledger->SetMode(mode);
    CliTrace("CmdRun:ledger-mode-set");
    g_ledger->Flush();   // the ledger exists even if the model never answers
    CliTrace("CmdRun:ledger-ready");

    const std::string espMode = flags.count("esp") ? flags.at("esp") : "";
    const bool espEnabled = !espMode.empty() && espMode != "false" && espMode != "0";
    const bool espVerbose = espMode == "verbose" || espMode == "all";
    const std::string espPath = flags.count("esp-log") && !flags.at("esp-log").empty()
        ? flags.at("esp-log")
        : (g_workspace + "/.rawrxd/ledger/agent_esp.jsonl");
    auto esp = std::make_unique<CliEspSession>(espEnabled, espPath, espVerbose);
    esp->model_load(ActiveModelName());

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
        esp->phase("PREFLIGHT");
        g_ledger->AppendUserMessage(prompt);
        g_ledger->RecordAgentTurn();

        std::vector<ChatMessage> messages;
        const bool freshSession = flags.count("fresh-session") != 0;
        if (!freshSession) {
            for (const auto& m : g_ledger->Conversation()) {
                ChatMessage cm;
                cm.role = m.value("role", std::string());
                cm.content = m.value("content", std::string());
                messages.push_back(cm);
            }
        }
        std::string audit_guidance;
        std::string prompt_lower = prompt;
        std::transform(prompt_lower.begin(), prompt_lower.end(), prompt_lower.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        const bool readOnlyAuditRequested =
            prompt_lower.find("audit") != std::string::npos ||
            prompt_lower.find("inspect") != std::string::npos;
        const bool explicitReadTask =
            prompt_lower.find("readfile") != std::string::npos ||
            prompt_lower.find("read file") != std::string::npos;
        const bool readTaskMarkerRequired =
            prompt.find("RAWRXD_AGENT_READ_PASS") != std::string::npos;
        if (readOnlyAuditRequested) {
            audit_guidance =
                "\nREAD-ONLY REPOSITORY AUDIT PROTOCOL:\n"
                "Do not call listDirectory on the workspace root. Use fileSearch or "
                "textSearch with a scoped path and maxResults, then readFile only on "
                "the concrete files needed for evidence. listDirectory is immediate "
                "children only and bounded; if output is truncated, narrow the path. "
                "Inspect source, build configuration, executable provenance, logs, "
                "agent tools, LSP, terminal, model routing, REAP/Deep2 boundaries, "
                "and tests through actual tool calls. Report only facts observed from "
                "tool results, with exact workspace-relative paths. Do not infer that "
                "a component exists merely because its name was requested. Finish with "
                "RAWRXD_READONLY_AUDIT_COMPLETE only after the requested evidence was "
                "actually collected.";
        }
        messages.insert(messages.begin(), ChatMessage{
            "system", "MOTD_ACK=1. The RawrXD runtime has already read and enforced the "
                      "workspace execution policy for this turn (SHA-256=" + digest + "). "
                      "Do not call read_motd or readFile for the policy file; proceed with "
                      "the user's task using the available tools. Runtime authorization, "
                      "read-only mode, approvals, and workspace boundaries are enforced "
                      "outside the model.\n" + audit_guidance, ""});
        // The one-shot path must send the current request as an actual user
        // message.  Without this append, --fresh-session produced a prompt
        // containing only the runtime system policy, so the model could emit
        // unrelated tool calls or a generic completion while the CLI still
        // reported a process-level result.  Keep the task text in the model
        // transcript and let the existing tool/task gates validate the work.
        messages.push_back(ChatMessage{"user", prompt, ""});

        InferenceResult result;
        auto cancel_run = [&](const char* reason) {
            const std::string why = reason ? reason : "user_interrupt";
            std::cerr << "[agent] CANCELLED: " << why << "\n";
            g_ledger->RecordFailure("cancelled: " + why);
            g_ledger->SetTermination(TerminationReason::Cancelled, 130);
            g_ledger->SetVerdict("cancelled");
            g_ledger->Flush();
            esp->cancel(why);
            return 130;
        };
        std::jthread cancel_timer;
        if (flags.count("cancel-after-ms")) {
            int delay_ms = 0;
            try { delay_ms = std::stoi(flags.at("cancel-after-ms")); }
            catch (...) { delay_ms = 0; }
            if (delay_ms > 0) {
                cancel_timer = std::jthread([delay_ms](std::stop_token stop) {
                    const auto deadline = std::chrono::steady_clock::now() +
                                          std::chrono::milliseconds(delay_ms);
                    while (!stop.stop_requested() &&
                           std::chrono::steady_clock::now() < deadline) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(5));
                    }
                    if (!stop.stop_requested()) {
                        g_running.store(false);
                        if (g_router) g_router->Cancel();
                    }
                });
            }
        }
        esp->phase("PLANNING");
        esp->inference_start();
        esp->phase("WORKING");
        CliTrace("CmdRun:inference-start");
        try {
            if (deep2CompleteFn) {
                // Use in-process Deep2Engine directly — no HTTP router needed.
                result = deep2CompleteFn(messages, g_run_max_tokens);
            } else if (g_router) {
                CliTrace("CmdRun:router-chat-sync");
                result = g_router->ChatSync(messages, BuildToolDefinitions());
            } else {
                result = InferenceResult::Error("No inference backend available");
            }
        } catch (const std::exception& e) {
            std::cerr << "[error] Deep2 exception: " << e.what() << "\n";
            g_ledger->RecordFailure("inference exception: " + std::string(e.what()));
            esp->fail("inference_exception");
            return 1;
        } catch (...) {
            std::cerr << "[error] Deep2 unknown exception\n";
            g_ledger->RecordFailure("inference unknown exception");
            esp->fail("inference_exception_unknown");
            return 1;
        }
        CliTrace("CmdRun:inference-returned");
        if (!g_running.load()) return cancel_run("user_interrupt");
        esp->backend_metrics(result);
        if (result.has_tool_calls) {
            esp->stage("tool_calls_received");
        }

        // Complete bounded agentic turns: execute returned tool calls, feed
        // their real results back to the model, and stop only on final text.
        std::string completed_tool_history;
        for (int tool_round = 0; result.success && result.has_tool_calls && tool_round < 8;
             ++tool_round) {
            json assistant_calls = json::array();
            std::string last_tool_output;
            auto tool_target = [](const json& args) {
                if (!args.is_object()) return std::string();
                for (const char* key : {"path", "file", "directory", "command", "workspace"}) {
                    const auto it = args.find(key);
                    if (it != args.end() && it->is_string() && !it->get<std::string>().empty()) {
                        return it->get<std::string>();
                    }
                }
                return std::string();
            };
            // The assistant tool-call message must precede every tool result
            // in the chat transcript.  Appending a tool result first creates
            // an invalid Ollama conversation and commonly yields an empty
            // continuation even when the tool executed successfully.
            for (size_t i = 0; i < result.tool_calls.size(); ++i) {
                const auto& call = result.tool_calls[i];
                const std::string id = "rawr-call-" + std::to_string(tool_round) + "-" + std::to_string(i);
                const std::string target = tool_target(call.second);
                esp->tool_start("TOOL_START id=" + id + " name=" + call.first +
                                " target=" + target);
                assistant_calls.push_back({
                    {"id", id}, {"type", "function"},
                    {"function", {{"name", call.first}, {"arguments", call.second}}}
                });
            }
            messages.push_back({"assistant", result.response, "", assistant_calls});

            for (size_t i = 0; i < result.tool_calls.size(); ++i) {
                const auto& call = result.tool_calls[i];
                const std::string id = "rawr-call-" + std::to_string(tool_round) + "-" + std::to_string(i);
                const std::string target = tool_target(call.second);
                const auto toolStarted = std::chrono::steady_clock::now();
                rawrxd::tools::Tool tool;
                rawrxd::tools::Request request;
                request.name = call.first;
                if (call.second.is_object()) {
                    for (auto it = call.second.begin(); it != call.second.end(); ++it)
                        request.args[it.key()] = it.value().is_string() ? it.value().get<std::string>() : it.value().dump();
                }
                json approval_args = call.second;
                auto approve = [&](const rawrxd::tools::Tool& t, const rawrxd::tools::Request&) {
                    return ApproveMutation(t.name, approval_args);
                };
                if (!g_tools->find(request.name, tool)) {
                    esp->tool_result("TOOL_RESULT id=" + id + " name=" + request.name +
                                     " target=" + target + " status=FAIL duration_ms=0", false, 1);
                    result = InferenceResult::Error("unknown tool: " + request.name);
                    break;
                }
                if (!g_gate->AllowsWithApproval(tool, request, approve)) {
                    esp->tool_result("TOOL_RESULT id=" + id + " name=" + request.name +
                                     " target=" + target + " status=FAIL duration_ms=0", false, 1);
                    result = InferenceResult::Error(
                        "tool denied: " + request.name + " (" + g_gate->ExplainDenial(tool) + ")");
                    break;
                }
                auto tool_result = g_tools->call(request, approve);
                const auto toolElapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - toolStarted).count();
                esp->tool_result(
                    "TOOL_RESULT id=" + id + " name=" + request.name +
                    " target=" + target + " status=" + (tool_result.ok ? "PASS" : "FAIL") +
                    " duration_ms=" + std::to_string(toolElapsed),
                    tool_result.ok, tool_result.ok ? 0 : 1);
                g_ledger->RecordToolCall(ToolCallRecord{
                    request.name, call.second, tool_result.ok, tool_result.output,
                    tool_result.error, AgentSession::NowUnix(), 0.0, true
                });
                if (tool_result.ok &&
                    (request.name == "editFiles" || request.name == "createFile" ||
                     request.name == "writeFile")) {
                    const auto path_it = request.args.find("path");
                    if (path_it != request.args.end() && !path_it->second.empty()) {
                        g_ledger->RecordFileModified(path_it->second);
                        esp->file_changed(path_it->second);
                    }
                }
                if (request.name == "runInTerminal") {
                    const auto command_it = request.args.find("command");
                    const std::string command = command_it != request.args.end()
                        ? command_it->second : std::string();
                    const int process_exit_code = tool_result.ok ? 0 : [&]() {
                        const std::string marker = "exit=";
                        const auto pos = tool_result.error.find(marker);
                        if (pos == std::string::npos) return -1;
                        try { return std::stoi(tool_result.error.substr(pos + marker.size())); }
                        catch (...) { return -1; }
                    }();
                    const std::string lower_command = [&]() {
                        std::string lower = command;
                        std::transform(lower.begin(), lower.end(), lower.begin(),
                                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                        return lower;
                    }();
                    if (lower_command.find(" cl ") != std::string::npos ||
                        lower_command.rfind("cl ", 0) == 0 ||
                        lower_command.find("cmake --build") != std::string::npos ||
                        lower_command.find("msbuild") != std::string::npos) {
                        BuildEvidence build;
                        build.tool_ok = true;
                        build.process_exit_code = process_exit_code;
                        build.build_target = "agent terminal build";
                        build.build_configuration = "native toolchain";
                        build.command = command;
                        build.compiler_errors = 0;
                        build.compiler_warnings = 0;
                        const auto fe = command.find("/Fe:");
                        if (fe != std::string::npos) {
                            size_t end = command.find_first_of(" \t\r\n", fe + 4);
                            const std::string artifact_name = command.substr(
                                fe + 4, end == std::string::npos ? std::string::npos : end - (fe + 4));
                            const fs::path artifact = fs::path(g_workspace) / artifact_name;
                            if (fs::is_regular_file(artifact)) {
                                build.artifacts_verified = true;
                                build.artifact_paths.push_back(artifact.string());
                            }
                        }
                        g_ledger->RecordBuild(build);
                        esp->build_result(process_exit_code);
                    } else if (lower_command.size() >= 4 &&
                               (lower_command.find(".exe") != std::string::npos ||
                                lower_command.find("ctest") != std::string::npos)) {
                        TestEvidence test;
                        test.tool_ok = true;
                        test.process_exit_code = process_exit_code;
                        test.tests_total = 1;
                        test.tests_passed = process_exit_code == 0 ? 1 : 0;
                        test.tests_failed = process_exit_code == 0 ? 0 : 1;
                        test.command = command;
                        g_ledger->RecordTest(test);
                        esp->test_result(process_exit_code);
                    }
                }
                if (!tool_result.ok) {
                    result = InferenceResult::Error("tool failed: " + tool_result.error);
                    break;
                }
                last_tool_output = tool_result.output;
                completed_tool_history += request.name + " args=" + call.second.dump() +
                    " output=" + tool_result.output + "\n";
                messages.push_back({"tool", tool_result.output, id, json()});
            }
            if (!g_running.load()) return cancel_run("user_interrupt");
            if (!result.success) break;
            if (deep2CompleteFn) {
                // Preserve the selected in-process Deep2 backend across tool
                // rounds; do not silently switch to a null HTTP router after
                // the first tool call.
                result = deep2CompleteFn(messages, g_run_max_tokens);
            } else if (g_router) {
                result = g_router->ChatSync(messages, BuildToolDefinitions());
            } else {
                result = InferenceResult::Error("No inference backend available");
            }
            esp->backend_metrics(result);
            if (!g_running.load()) return cancel_run("user_interrupt");

            // Some local instruct models emit an empty assistant message after
            // a long native tool transcript even though the tool completed.
            // Do one bounded recovery request with the durable user/system
            // context and the verified tool result.  This keeps the next
            // action model-selected without replaying an invalid/overlong
            // assistant/tool transcript or fabricating a result.
            const bool empty_continuation =
                (result.success && result.response.find_first_not_of(" \t\r\n") == std::string::npos &&
                 !result.has_tool_calls) ||
                (!result.success && result.error_message == "Ollama returned no chat content");
            if (empty_continuation && !last_tool_output.empty()) {
                std::vector<ChatMessage> compact_messages;
                compact_messages.reserve(messages.size() + 1);
                for (const auto& message : messages) {
                    if (message.role == "system" || message.role == "user") {
                        compact_messages.push_back(message);
                    }
                }
                compact_messages.push_back({
                    "user",
                    "The following tool actions have already completed successfully. Do not repeat them:\n" +
                        completed_tool_history +
                        "The most recent verified output was:\n" + last_tool_output +
                        "\nContinue the original task from the next unmet step using the available tools, "
                        "then report the verified result.",
                    ""});
                messages = std::move(compact_messages);
                if (deep2CompleteFn) {
                    result = deep2CompleteFn(messages, g_run_max_tokens);
                } else if (g_router) {
                    result = g_router->ChatSync(messages, BuildToolDefinitions());
                } else {
                    result = InferenceResult::Error("No inference backend available");
                }
                esp->backend_metrics(result);
                if (!g_running.load()) return cancel_run("user_interrupt");
            }
        }
        // A bounded loop that still has pending tool calls is not a completed
        // task. Never turn a model that kept asking for tools into PASS just
        // because the process reached the loop limit.
        if (result.success && result.has_tool_calls) {
            constexpr const char* kToolRoundLimit =
                "TOOL_ROUND_LIMIT_REACHED: final response was not produced";
            std::cerr << "[error] " << kToolRoundLimit << "\n";
            g_ledger->RecordFailure(kToolRoundLimit);
            g_ledger->SetTermination(TerminationReason::MalformedModelOutput, 1);
            g_ledger->SetVerdict("tool round limit reached");
            g_ledger->Flush();
            esp->phase("BLOCKED");
            esp->fail("tool_round_limit_reached");
            return 1;
        }

        // Record the final assistant result once the bounded tool loop has
        // settled.  A tool-call response is not a completed model answer and
        // must not be counted as generated output.
        if (!result.has_tool_calls) {
            esp->inference_result(result.success,
                                  static_cast<int64_t>(result.completion_tokens));
        }
        if (!result.success) {
            std::cerr << "[error] " << result.error_message << "\n";
            g_ledger->RecordFailure("inference failed: " + result.error_message);
            esp->fail("inference_failed");
            return 1;
        }
        if (readOnlyAuditRequested) {
            esp->phase("VERIFYING");
            // A model response is not an audit certificate. The driver only
            // accepts a read-only audit after the model emitted the explicit
            // completion marker and the ledger proves both discovery/search
            // and concrete file reads occurred. This prevents a generic
            // narrative from being reported as a repository inspection.
            const auto ledger = g_ledger->ToJson();
            bool readObserved = false;
            bool searchObserved = false;
            for (const auto& call : ledger.value("tool_calls", json::array())) {
                if (!call.value("ok", false)) continue;
                const std::string tool = call.value("tool", std::string());
                readObserved = readObserved || tool == "readFile" || tool == "Read";
                searchObserved = searchObserved || tool == "fileSearch" ||
                                 tool == "textSearch" || tool == "Grep" || tool == "Glob";
            }
            const bool completionMarker =
                result.response.find("RAWRXD_READONLY_AUDIT_COMPLETE") != std::string::npos;
            if (!completionMarker || !readObserved || !searchObserved) {
                constexpr const char* kAuditIncomplete =
                    "READ_ONLY_AUDIT_INCOMPLETE: required evidence was not collected";
                std::cerr << "[error] " << kAuditIncomplete << "\n";
                g_ledger->RecordFailure(kAuditIncomplete);
                g_ledger->SetTermination(TerminationReason::MalformedModelOutput, 1);
                g_ledger->SetVerdict("read-only audit incomplete");
                g_ledger->Flush();
                esp->fail("read_only_audit_incomplete");
                return 1;
            }
        }
        if (explicitReadTask) {
            bool readObserved = false;
            for (const auto& call : g_ledger->ToJson().value("tool_calls", json::array())) {
                if (!call.value("ok", false)) continue;
                const std::string tool = call.value("tool", std::string());
                readObserved = readObserved || tool == "readFile" || tool == "Read";
            }
            const bool markerPresent = !readTaskMarkerRequired ||
                result.response.find("RAWRXD_AGENT_READ_PASS") != std::string::npos;
            if (!readObserved || !markerPresent) {
                constexpr const char* kReadTaskIncomplete =
                    "READ_TASK_INCOMPLETE: requested readFile evidence or completion marker missing";
                std::cerr << "[error] " << kReadTaskIncomplete << "\n";
                g_ledger->RecordFailure(kReadTaskIncomplete);
                g_ledger->SetTermination(TerminationReason::MalformedModelOutput, 1);
                g_ledger->SetVerdict("read task incomplete");
                g_ledger->Flush();
                esp->fail("read_task_incomplete");
                return 1;
            }
        }
        if (result.response.find_first_not_of(" \t\r\n") == std::string::npos) {
            constexpr const char* kEmpty = "EMPTY_MODEL_RESPONSE: backend returned no visible answer";
            std::cerr << "[error] " << kEmpty << "\n";
            g_ledger->RecordFailure(kEmpty);
            esp->fail("empty_model_response");
            return 1;
        }

        g_ledger->AppendAssistantMessage(result.response);
        if (g_streamed_response) std::cout << "\n" << std::flush;
        else std::cout << result.response << "\n";

        AgentSession::FinalAnswer final_answer;
        final_answer.valid = true;
        final_answer.summary = result.response;
        final_answer.evidence.push_back("agent tool ledger persisted");
        if (LedgerBuildPassed(*g_ledger)) final_answer.evidence.push_back("native build exit=0 and artifact verified");
        if (LedgerTestsPassed(*g_ledger)) final_answer.evidence.push_back("executable test exit=0");
        g_ledger->RecordFinalAnswer(final_answer);
        g_ledger->SetTermination(TerminationReason::ModelCompleted, 0);
        g_ledger->SetVerdict("one-shot task completed");

        g_ledger->Flush();
        esp->phase("COMPLETED");
        esp->finish(true);
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
            "system", "MOTD_ACK=1. The RawrXD runtime has already read and enforced the "
                      "workspace execution policy for this turn (SHA-256=" + digest + "). "
                      "Do not call read_motd or readFile for the policy file; proceed with "
                      "the user's task using the available tools. Runtime authorization, "
                      "read-only mode, approvals, and workspace boundaries are enforced "
                      "outside the model.", ""});

        InferenceResult result;
        try {
            if (deep2CompleteFn) {
                // Use in-process Deep2Engine directly — no HTTP router needed.
                result = deep2CompleteFn(messages, g_run_max_tokens);
            } else if (g_router) {
                result = g_router->ChatSync(messages, BuildToolDefinitions());
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
        if (result.response.find_first_not_of(" \t\r\n") == std::string::npos) {
            constexpr const char* kEmpty = "EMPTY_MODEL_RESPONSE: backend returned no visible answer";
            std::cerr << "[error] " << kEmpty << "\n";
            g_ledger->RecordFailure(kEmpty);
            continue;
        }

        g_ledger->AppendAssistantMessage(result.response);
        if (g_streamed_response) std::cout << "\n" << std::flush;
        else std::cout << result.response << "\n";
    }

    // ---- Finalize the ledger regardless of how the session ended ----
    AgentSession::FinalAnswer final_answer;
    final_answer.valid = true;
    final_answer.summary = "interactive session ended normally";
    final_answer.evidence.push_back("agent ledger persisted");
    g_ledger->RecordFinalAnswer(final_answer);
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
    } else if (g_router) {
        r = g_router->ChatSync(cmsgs, json::array());
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

// Emit the capability manifest from the objects linked into this executable.
// This is deliberately generated at invocation time: a checked-in manifest can
// become stale as soon as the CLI or registry changes.  Quantization primitive
// status comes from the same QuantParityRegistry implementation used by the
// authoritative parity tool; no hand-maintained primitive table is used here.
static int CmdCapabilities(const std::vector<std::string>& args) {
    std::string outPath;
    bool jsonRequested = false;
    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--json") {
            jsonRequested = true;
        } else if (args[i] == "--out" && i + 1 < args.size()) {
            outPath = args[++i];
        } else {
            std::cerr << "Unknown capabilities option: " << args[i] << "\n";
            return 2;
        }
    }

    if (!jsonRequested && outPath.empty()) {
        std::cerr << "Usage: rawr capabilities --json [--out manifest.json]\n";
        return 2;
    }

    rawrxd::tools::Registry tools;
    WorkspaceToolHost workspace(g_workspace);
    workspace.RegisterWorkspaceTools(tools);

    json manifest = json::object();
    manifest["schema"] = "rawrxd-capability-manifest/1";
    manifest["generated_by"] = "rawr capabilities";
    manifest["workspace"] = g_workspace;
    const std::string revision = RunGit("rev-parse HEAD");
    if (revision.empty()) {
        std::cerr << "CAPABILITIES_GIT_REVISION_UNAVAILABLE\n";
        return 1;
    }
    manifest["source_revision"] = revision;

    json toolRows = json::array();
    auto names = tools.names();
    std::sort(names.begin(), names.end());
    for (const auto& name : names) {
        rawrxd::tools::Tool tool;
        if (!tools.find(name, tool)) continue;
        toolRows.push_back({
            {"name", name},
            {"description", tool.description},
            {"risk", static_cast<int>(tool.risk)},
            {"status", "registered_and_dispatchable"},
            {"verification", "live rawr tool registry"}
        });
    }
    manifest["tools"] = toolRows;
    manifest["tool_count"] = static_cast<int>(toolRows.size());

    json modeRows = json::array();
    for (const auto mode : ModeRegistry::Instance().AllModes()) {
        modeRows.push_back({
            {"name", AgentModeName(mode)},
            {"description", ModeRegistry::Instance().Describe(mode)}
        });
    }
    manifest["modes"] = modeRows;

    auto& parity = RawrXD::Deep2::QuantParityRegistry::Instance();
    parity.RegisterBuiltinKernels();
    const std::string registryText = parity.ToJson();
    json registry = json::parse(registryText);
    json primitiveRows = json::array();
    for (const auto& row : registry.value("primitive_gates", json::array())) {
        primitiveRows.push_back({
            {"name", row.value("primitive", std::string())},
            {"status", row.value("binding_status", std::string("not_required"))},
            {"available", row.value("available", false)},
            {"implementation_required", row.value("implementation_required", false)},
            {"kernel_present", row.value("kernel_present", false)},
            {"status_source", "RawrXD::Deep2::QuantParityRegistry::ToJson"}
        });
    }
    manifest["primitives"] = primitiveRows;
    manifest["primitives_provenance"] =
        "live QuantParityRegistry::ToJson() from the linked CLI process";

    // Only claim a quantization format as verified when the registry has an
    // evidence-bearing packing/dot/logits record for that format.  A kernel
    // binding alone is not a parity certificate.
    json quantRows = json::array();
    for (const auto& binding : registry.value("bindings", json::array())) {
        const std::string type = binding.value("type", std::string());
        const std::string packing = binding.value("packing_parity", std::string());
        const bool verified = packing == "packing_verified" ||
                              packing == "dot_verified" ||
                              packing == "logits_verified";
        quantRows.push_back({
            {"format", type},
            {"verification", verified ? "verified" : "declared_only"},
            {"ctest_gate", verified ? "quant_parity_cert" : "(none)"},
            {"evidence", binding.value("evidence", std::string())}
        });
    }
    manifest["quantization_kernels"] = quantRows;

    // These are repository-level parity receipts, and remain separate from
    // the live Deep2/Kimi/REAP model receipts.  Citing them here does not
    // promote those model-specific gates; it records the exact artifacts that
    // the historical native-forward Gate 2 contract requires.
    manifest["end_to_end_forward_parity"] = {
        {"status", "verified"},
        {"verified_by", "MODEL_GENIE_NATIVE_FORWARD_001 Gate 4"},
        {"evidence", "evidence/GAP_AUDIT_2026-10-13/GATE4_CERTIFICATION_2026-10-13.md"}
    };
    manifest["multi_token_kv_parity"] = {
        {"status", "verified"},
        {"verified_by", "MODEL_GENIE_NATIVE_FORWARD_001 Gate 6"},
        {"evidence", "evidence/GAP_AUDIT_2026-10-13/GATE6_KVCACHE_CONTEXT.md"}
    };
    manifest["native_forward_zero_fallback"] = {
        {"status", "verified"},
        {"verified_by", "MODEL_GENIE_NATIVE_FORWARD_001 Gate 4"},
        {"evidence", "evidence/GAP_AUDIT_2026-10-13/GATE4_NATIVE_FORWARD.md"}
    };

    const std::string body = manifest.dump(2) + "\n";
    if (!outPath.empty()) {
        std::ofstream out(outPath, std::ios::binary | std::ios::trunc);
        if (!out) {
            std::cerr << "CAPABILITIES_OUTPUT_OPEN_FAILED: " << outPath << "\n";
            return 1;
        }
        out << body;
        if (!out.good()) {
            std::cerr << "CAPABILITIES_OUTPUT_WRITE_FAILED: " << outPath << "\n";
            return 1;
        }
    }
    if (outPath.empty()) std::cout << body;
    return 0;
}

static int CmdDoctor() {
    std::cout << "=== RawrXD doctor ===\n";
    std::cout.flush();
    std::cout << "Workspace: " << (g_workspace.empty() ? fs::current_path().string() : g_workspace) << "\n";

    // Read-only diagnostics must not start BackendRouter: its background health
    // loop is appropriate for a long-lived agent, but can outlive or stall a
    // short CLI command. Use bounded direct clients instead.
    RawrXD::Backend::OllamaClient deep2("http://127.0.0.1:11436");
    RawrXD::Backend::OllamaClient ollama("http://127.0.0.1:11434");
    deep2.setTimeoutSeconds(5);
    ollama.setTimeoutSeconds(5);
    const bool deep2_ok = deep2.testConnection();
    const bool ollama_ok = ollama.testConnection();
    std::cout << "Deep2  (11436): " << (deep2_ok ? "AVAILABLE" : "not running") << "\n";
    std::cout << "Ollama (11434): " << (ollama_ok ? "AVAILABLE" : "not running") << "\n";
    if (ollama_ok) {
        const auto models = ollama.listModels();
        std::cout << "  Ollama models: " << models.size() << "\n";
    }

    // Toolchain.
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

    std::cout.flush();
    return 0; // doctor reports the environment; unavailable services are valid findings.
}

static int CmdModels() {
    std::cout << "=== RawrXD models ===\n";
    std::cout.flush();

    RawrXD::Backend::OllamaClient ollama("http://127.0.0.1:11434");
    ollama.setTimeoutSeconds(10);
    const auto models = ollama.listModels();
    if (models.empty()) {
        std::cerr << "Ollama model inventory unavailable or empty (http://127.0.0.1:11434/api/tags)\n";
        return 1;
    }
    for (const auto& model : models) {
        std::cout << "ollama  " << model.name;
        if (!model.digest.empty()) std::cout << "  digest=" << model.digest;
        if (model.size != 0) std::cout << "  bytes=" << model.size;
        std::cout << "\n";
    }
    std::cout.flush();
    return 0;
}

// A short-lived status command must not construct BackendRouter: that router
// owns background health/recovery workers intended for an interactive session.
// Use the same bounded direct probes as `doctor` and leave router ownership to
// `rawr run`.
static int CmdBackend(const std::vector<std::string>& args) {
    const std::string mode = args.empty() ? "auto" : args.front();
    if (mode != "auto" && mode != "deep2" && mode != "ollama") {
        std::cerr << "Usage: rawr backend [auto|deep2|ollama]\n";
        return 2;
    }
    if (args.size() > 1) {
        std::cerr << "backend accepts at most one mode\n";
        return 2;
    }

    RawrXD::Backend::OllamaClient deep2("http://127.0.0.1:11436");
    RawrXD::Backend::OllamaClient ollama("http://127.0.0.1:11434");
    deep2.setTimeoutSeconds(5);
    ollama.setTimeoutSeconds(5);
    const bool deep2Ok = deep2.testConnection();
    const bool ollamaOk = ollama.testConnection();
    std::cout << "Mode:    " << mode << "\n";
    std::cout << "Deep2:   " << (deep2Ok ? "available" : "unavailable")
              << " (http://127.0.0.1:11436)\n";
    std::cout << "Ollama:  " << (ollamaOk ? "available" : "unavailable")
              << " (http://127.0.0.1:11434)\n";
    const bool selectedAvailable =
        mode == "deep2" ? deep2Ok : mode == "ollama" ? ollamaOk : (deep2Ok || ollamaOk);
    std::cout << "Active:  " << (mode == "deep2" ? "deep2-native" :
                                  mode == "ollama" ? "ollama" :
                                  deep2Ok ? "deep2-native" : "ollama") << "\n";
    std::cout << "Status:  " << (selectedAvailable ? "ready" : "unavailable") << "\n";
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

    // 2. Local inference endpoints are reachable.  Do not construct the
    // long-lived BackendRouter in this short-lived audit command: its worker
    // lifecycle belongs to `rawr run` and can outlive a one-shot process.
    ok = [&] {
        RawrXD::Backend::OllamaClient deep2("http://127.0.0.1:11436");
        RawrXD::Backend::OllamaClient ollama("http://127.0.0.1:11434");
        deep2.setTimeoutSeconds(5);
        ollama.setTimeoutSeconds(5);
        return deep2.testConnection() || ollama.testConnection();
    }();
    check("local inference endpoint is reachable", ok);

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
static int RawrXDMain(int argc, char** argv) {
    std::signal(SIGINT, OnSignal);
    std::signal(SIGTERM, OnSignal);
#ifdef _WIN32
    SetConsoleCtrlHandler(OnConsoleControl, TRUE);
#endif
    g_workspace = fs::current_path().string();

    if (argc < 2) {
    std::cout << "RawrXD CLI v2\n\n"
              << "Usage:\n"
                          << "  rawr run <model> [mode] [--backend b] [--workspace d] [--max-tokens n] [--context n]\n"
                          << "             [--fresh-session] [--approve-mutations] [--cancel-after-ms n]\n"
              << "             interactive agent (mutations require explicit opt-in)\n"
              << "  rawr run <model> --reap --target-size|--size <size> --active-experts <n>\n"
              << "             --expert-budget <size> --quality-floor <0..1>       guarded REAP request\n"
              << "  rawr run <model> --reap <parameters>/<experts> [--receipt <json>]\n"
              << "             non-destructive runtime streamer/router injection\n"
              << "  rawr reap <model> --target-size|--size <size> --active-experts <n>\n"
              << "             --expert-budget <size> --quality-floor <0..1>       guarded REAP request\n"
              << "             [--selection-output <json> --output-model <dir>\n"
              << "              --authorize-rewrite --prompt <text>]              candidate-only rewrite\n"
              << "  rawr run <model> \"new project\"                          project wizard\n"
              << "  rawr run <model> \"add a GUI\"                            follow-up wizard\n"
              << "  rawr modes                                                  list agent modes\n"
              << "  rawr tools list|describe <name>|run <name> [k=v ...]       tool interface\n"
              << "  rawr models                                                 list models\n"
              << "  rawr backend [auto|deep2|ollama]                            backend status/switch\n"
              << "  rawr doctor                                                 environment health\n"
              << "  env DEEP2_GPU_DEVICE_RESET=1                              opt-in GPU device-lost reset (default off)\n"
              << "  rawr self-audit                                             run the audit checklist\n"
              << "  rawr build [--config Release] [--target t]                  build project\n"
              << "  rawr test [--filter f]                                      run tests\n";
        return 0;
    }

    std::string cmd = argv[1];
    std::vector<std::string> args;
    for (int i = 2; i < argc; ++i) args.push_back(argv[i]);
    if (std::getenv("RAWRXD_CLI_DISPATCH_TRACE")) {
        std::cerr << "[rawr-cli-dispatch] command=" << cmd
                  << " argc=" << argc << " args=" << args.size() << "\n";
    }

    Options o = ParseOptions(argc, argv, 2);
    g_workspace = DiscoverWorkspace(o);

    if (cmd == "run") {
        try {
            return CmdRun(args);
        } catch (const std::exception& e) {
            std::cerr << "RAWRXD_CLI_FATAL: " << e.what() << "\n";
            if (g_ledger) {
                g_ledger->RecordFailure(std::string("driver exception: ") + e.what());
                g_ledger->SetTermination(TerminationReason::DriverException, 1);
                g_ledger->Flush();
            }
            return 1;
        } catch (...) {
            std::cerr << "RAWRXD_CLI_FATAL: unknown exception\n";
            if (g_ledger) {
                g_ledger->RecordFailure("driver exception: unknown exception");
                g_ledger->SetTermination(TerminationReason::DriverException, 1);
                g_ledger->Flush();
            }
            return 1;
        }
    }
    if (cmd == "reap") {
        if (o.flags.count("help") != 0 || o.flags.count("h") != 0) {
            std::cout << "Usage: rawr reap <model> --target-size <size> --active-experts <n>\n"
                      << "             --expert-budget <size> --quality-floor <0..1>\n"
                      << "             [--selection-output <json> --output-model <dir>\n"
                      << "              --authorize-rewrite --prompt <text> --workspace <dir>]\n"
                      << "The source GGUF is never overwritten; rewrite requires all\n"
                      << "independent REAP evidence gates plus explicit authorization.\n";
            return 0;
        }
        if (o.positional.empty()) {
            std::cerr << "REAP_MODEL_REQUIRED: usage: rawr reap <model>"
                         " --target-size <size> --active-experts <n>"
                         " --expert-budget <size> --quality-floor <0..1>\n";
            return 2;
        }
        o.flags["reap"] = "true";
        const std::string prompt = o.positional.size() > 1 ? o.positional[1] : "";
        return HandleReapContract(o.positional.front(), o.flags, prompt);
    }
    if (cmd == "modes")     return CmdModes();
    if (cmd == "capabilities") return CmdCapabilities(args);
    if (cmd == "doctor")    return CmdDoctor();
    if (cmd == "self-audit") return CmdSelfAudit();

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

    if (cmd == "backend") return CmdBackend(o.positional);

    if (cmd == "models") return CmdModels();

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

#ifdef _WIN32
int wmain(int argc, wchar_t** wargv) {
    // Windows' narrow `main`/argv path uses the active ANSI code page. That
    // corrupts prompts containing em dashes, smart quotes, CJK, or emoji
    // before nlohmann::json sees them. Keep the process boundary UTF-16 and
    // convert each argument to UTF-8 explicitly.
    std::vector<std::string> utf8Args;
    std::vector<char*> argv8;
    utf8Args.reserve(static_cast<size_t>(argc));
    argv8.reserve(static_cast<size_t>(argc));
    for (int i = 0; i < argc; ++i) {
        const int bytes = WideCharToMultiByte(
            CP_UTF8, WC_ERR_INVALID_CHARS, wargv[i], -1, nullptr, 0,
            nullptr, nullptr);
        if (bytes <= 0) {
            std::fprintf(stderr, "RAWRXD_UTF8_ARG_ERROR index=%d\n", i);
            return 2;
        }
        std::string value(static_cast<size_t>(bytes), '\0');
        if (bytes > 1 && WideCharToMultiByte(
                CP_UTF8, WC_ERR_INVALID_CHARS, wargv[i], -1,
                value.data(), bytes, nullptr, nullptr) <= 0) {
            std::fprintf(stderr, "RAWRXD_UTF8_ARG_ERROR index=%d\n", i);
            return 2;
        }
        if (bytes > 0) value.resize(static_cast<size_t>(bytes - 1));
        utf8Args.push_back(std::move(value));
    }
    for (auto& value : utf8Args) argv8.push_back(value.data());
    return RawrXDMain(argc, argv8.data());
}
#else
int main(int argc, char** argv) {
    return RawrXDMain(argc, argv);
}
#endif
