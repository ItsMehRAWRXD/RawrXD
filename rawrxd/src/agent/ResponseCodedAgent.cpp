// ResponseCodedAgent.cpp — RAWRXD_RESPONSE_CODED_AGENT_001
#include "agent/ResponseCodedAgent.h"

#include "ProcessUtil.h"

#include "deep2/Deep2Engine.h"
#include "deep2/ReceiptAuthority.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace fs = std::filesystem;

namespace rawrxd { namespace deep2 {
std::string resolveModelPathForAgent(const std::string& nameOrPath);
}}

namespace rawrxd { namespace rcagent {

namespace {

std::string trimStr(const std::string& s) {
    size_t b = 0, e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return s.substr(b, e - b);
}

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

// Run git with a fixed argument vector. There is deliberately no shell here:
// `repoRoot` reaches the process as one argv entry, so a value containing a
// quote, & or | cannot escape into a command interpreter. The previous
// implementation built "git -C \"<root>\" status ..." and passed it to _popen,
// which made a path such as  x" & calc.exe & "  execute arbitrary commands.
std::string runGit(const std::string& repoRoot, const std::vector<std::string>& args,
                   int& exitCode) {
    std::string out;
    int32_t code = -1;
    const procutil::RunResult r =
        procutil::runProcessNoShell("git", args, out, code);
    if (r == procutil::RunResult::SpawnFailed) { exitCode = -1; return {}; }
    exitCode = static_cast<int>(code);
    while (!out.empty() && (out.back() == '\n' || out.back() == '\r')) out.pop_back();
    return out;
}

} // namespace

// ------------------------------------------------------------ the model side

LocalModelBackend::LocalModelBackend(std::string modelRef)
    : modelRef_(std::move(modelRef)) {}

bool LocalModelBackend::available(std::string& reason) {
    resolvedPath_ = deep2::resolveModelPathForAgent(modelRef_);
    if (resolvedPath_.empty()) {
        reason = "could not resolve '" + modelRef_ + "' to a GGUF path";
        return false;
    }
    return true;
}

void LocalModelBackend::beginNewSession() { sessionFresh_ = true; }

std::string LocalModelBackend::generate(const std::string& prompt, uint32_t maxTokens,
                                       bool& ok, std::string& reason) {
    ok = false; reason.clear();
    if (resolvedPath_.empty()) { reason = "model not resolved"; return {}; }

    static thread_local Deep2::Deep2Engine* engine = nullptr;
    static thread_local std::string enginePath;
    if (sessionFresh_ || !engine || enginePath != resolvedPath_) {
        if (engine) { delete engine; engine = nullptr; }
        engine = new Deep2::Deep2Engine();
        Deep2::EngineConfig cfg;
        cfg.maxSeqLen  = 4096;
        cfg.numThreads = 0;
        if (!engine->initialize(cfg)) {
            reason = "Deep2Engine::initialize failed";
            delete engine; engine = nullptr; return {};
        }
        engine->enableVulkan(false);
        Deep2::ModelLoadDiag diag{};
        if (!engine->loadModel(resolvedPath_, &diag)) {
            reason = "loadModel failed at " + diag.stageName + ": " + diag.message;
            delete engine; engine = nullptr; return {};
        }
        enginePath = resolvedPath_;
        sessionFresh_ = false;
    }

    Deep2::GenerationOptions opts;
    opts.maxTokens  = maxTokens;
    opts.temperature = 0.0f;
    opts.topK        = 1;
    opts.topP        = 1.0f;
    opts.seed        = 7;

    std::string text;
    auto cb = [&text](int32_t, const std::string& tok) -> bool { text += tok; return true; };
    const Deep2::GenerationResult r = engine->generateStream(prompt, opts, cb);
    if (!r.completed) {
        reason = "generation incomplete";
        if (!r.failureDetail.empty()) reason += ": " + r.failureDetail;
        return text;
    }
    ok = true;
    return text;
}

// ------------------------------------------------------------ the tool side

const std::vector<ToolSpec>& toolRegistry() {
    // The complete READ_ONLY registry. Adding a mutating entry here would be
    // a change to the agent's authority, not a feature.
    static const std::vector<ToolSpec> kRegistry = {
        { "git_status", "show current branch and worktree status (read-only)" },
        { "read_file",  "read a file inside the repository (read-only)" },
        { "list_dir",   "list a directory inside the repository (read-only)" },
    };
    return kRegistry;
}

bool isWhitelisted(const std::string& name) {
    const std::string n = lower(name);
    for (const auto& t : toolRegistry()) if (n == t.name) return true;
    return false;
}

ToolOutcome executeTool(const std::string& repoRoot, const ToolRequest& req) {
    ToolOutcome o;
    if (!req.present) { o.status = ToolStatus::NotRequested; return o; }

    const std::string name = lower(req.name);
    o.tool = name;
    if (!isWhitelisted(name)) {
        o.status = ToolStatus::NotWhitelisted;
        o.detail = "tool '" + req.name + "' is not in the READ_ONLY registry";
        return o;
    }

    if (name == "git_status") {
        o.output = runGit(repoRoot, { "-C", repoRoot, "status", "--short", "--branch" },
                          o.exitCode);
        o.status = (o.exitCode == 0) ? ToolStatus::Executed : ToolStatus::ExecutionFailed;
        o.detail = "git status --short --branch";
        return o;
    }

    // Filesystem tools are confined to the repository root.
    //
    // Order matters. The previous code probed existence FIRST and classified
    // anything outside the sandbox as "no such path", which told the model
    // whether arbitrary paths exist outside the repository. Confinement is
    // now decided before the filesystem is touched at all.
    std::error_code ec;
    const fs::path rootCanon = fs::weakly_canonical(fs::path(repoRoot), ec);
    if (ec) {
        o.status = ToolStatus::ExecutionFailed;
        o.detail = "cannot canonicalize repository root";
        return o;
    }
    const fs::path canon = fs::weakly_canonical(fs::path(repoRoot) / req.arg, ec);
    if (ec) {
        o.status = ToolStatus::ExecutionFailed;
        o.detail = "cannot canonicalize '" + req.arg + "'";
        return o;
    }
    // Component-wise containment, not a string prefix: "F:\~dev\rawrxd_backup"
    // starts with "F:\~dev\rawrxd" but is not inside it.
    if (!procutil::isInsideRoot(canon, rootCanon)) {
        o.status = ToolStatus::ExecutionFailed;
        o.detail = "path escapes repository root: " + req.arg;
        return o;
    }
    if (!fs::exists(canon, ec)) {
        o.status = ToolStatus::ExecutionFailed;
        o.detail = "no such path: " + req.arg;
        return o;
    }

    o.exitCode = 0;
    if (name == "list_dir") {
        std::ostringstream os;
        for (const auto& e : fs::directory_iterator(canon, ec)) {
            if (ec) break;
            os << e.path().filename().string() << "\n";
        }
        o.output = os.str();
    } else {
        // Bounded read, shared with AgentCore. The previous in-line loop was
        // `while (total < kMax && in.read(..) || in.gcount() > 0)`, which
        // parses as `(total < kMax && in.read(..)) || (in.gcount() > 0)`.
        // Once total reached kMax the read short-circuited, gcount() kept its
        // stale non-zero value, and `kMax - total` underflowed as size_t — so
        // read_file never returned for any file of 1500 bytes or more.
        o.output = procutil::readBounded(canon, 1500);
    }
    o.status = ToolStatus::Executed;
    o.detail = name + " " + req.arg;
    return o;
}

// ------------------------------------------------------------- the protocol

ModelTurn parseModelTurn(const std::string& text) {
    ModelTurn t;
    t.raw = text;
    std::istringstream is(text);
    std::string line;
    std::string body;
    bool inBody = false;
    bool sawAnyTag = false;

    while (std::getline(is, line)) {
        const std::string s = trimStr(line);
        if (!sawAnyTag) {
            if (s == "RAWR_TOOL")    { t.sawToolTag = true;     sawAnyTag = true; inBody = true; continue; }
            if (s == "RAWR_RESPONSE") { t.sawResponseTag = true; sawAnyTag = true; inBody = true; continue; }
        }
        if (inBody) {
            if (s.rfind("name=", 0) == 0) { t.tool.name = trimStr(s.substr(5)); t.hasTool = true; }
            else if (s.rfind("arg=", 0) == 0) { t.tool.arg = trimStr(s.substr(4)); }
            else if (!s.empty()) body += s + "\n";
        }
    }
    t.tool.raw   = t.tool.name;
    t.tool.present = t.hasTool;
    t.response = trimStr(body);

    if (!t.sawToolTag && !t.sawResponseTag) {
        t.malformed = "model emitted neither RAWR_TOOL nor RAWR_RESPONSE";
    } else if (t.sawToolTag && t.hasTool && t.tool.name.empty()) {
        t.malformed = "RAWR_TOOL without a name=";
    }
    return t;
}

// ------------------------------------------------------------ the one turn

AgentTurn runOneTurn(const std::string& userInput, IModelBackend& backend,
                     const std::string& repoRoot) {
    AgentTurn t;
    t.userInput = userInput;

    std::string reason;
    if (!backend.available(reason)) {
        t.verdict = "FAIL";
        t.rationale = reason;
        return t;
    }
    t.modelRef     = backend.modelRef();
    t.resolvedPath = backend.resolvedPath();

    // ---- system framing: the model writes the response, not the host ----
    std::string sys;
    sys += "You are the RawrXD response-coded agent.\n";
    sys += "Answer the user's request. Reply in EXACTLY one of two forms.\n\n";
    sys += "Form 1, when you already know the answer:\n";
    sys += "RAWR_RESPONSE\n<your answer in plain text>\n\n";
    sys += "Form 2, when you need one real fact from the machine:\n";
    sys += "RAWR_TOOL\n";
    sys += "name=<one tool name>\n";
    sys += "arg=<argument if the tool needs one>\n\n";
    sys += "Available read-only tools:\n";
    for (const auto& tool : toolRegistry()) {
        sys += std::string("  ") + tool.name + " - " + tool.description + "\n";
    }
    sys += "Use RAWR_TOOL at most once. Output nothing before the tag.\n";

    backend.beginNewSession();
    bool ok = false;
    t.firstTurn = backend.generate(sys + "\nUSER: " + userInput + "\n", 96, ok, reason);
    if (!ok) { t.verdict = "FAIL"; t.rationale = "first inference failed: " + reason; return t; }

    const ModelTurn first = parseModelTurn(t.firstTurn);
    t.toolRaw = first.tool.raw;
    if (!first.malformed.empty()) {
        t.protocolValid = false;
        t.verdict = "FAIL_PROTOCOL";
        t.rationale = first.malformed;
        return t;
    }
    t.protocolValid = true;

    // No tool requested: the first turn is already the final response.
    if (!first.sawToolTag) {
        t.finalResponse = first.response;
        t.completed = !t.finalResponse.empty();
        t.verdict = t.completed ? "PASS" : "FAIL_EMPTY_RESPONSE";
        if (!t.completed) t.rationale = "RAWR_RESPONSE was empty";
        return t;
    }

    t.toolRequested = true;
    const ToolOutcome o = executeTool(repoRoot, first.tool);
    t.toolName     = o.tool;
    t.toolExitCode = o.exitCode;
    t.toolExecuted = (o.status == ToolStatus::Executed);

    // Build the observation block. This is real output, or an honest report
    // that the tool did not run. It is never replaced by an assumption.
    std::string obs;
    obs += "RAWR_OBSERVATION\n";
    obs += "tool=" + (o.tool.empty() ? std::string("(none)") : o.tool) + "\n";
    obs += "status=" + std::string(o.status == ToolStatus::Executed ? "executed"
                                : o.status == ToolStatus::NotWhitelisted ? "not_whitelisted"
                                : o.status == ToolStatus::ExecutionFailed ? "failed"
                                : "not_requested") + "\n";
    obs += "exit_code=" + std::to_string(o.exitCode) + "\n";
    obs += "output=" + (o.output.empty() ? o.detail : o.output) + "\n";
    t.observation = obs;

    // ---- same conversation context, one more inference, then STOP ----
    std::string cont = sys;
    cont += "\nUSER: " + userInput + "\n";
    cont += "ASSISTANT: " + trimStr(t.firstTurn) + "\n";
    cont += t.observation;
    cont += "\nNow answer the user in Form 1 (RAWR_RESPONSE). Do not request another tool.\n";

    t.finalResponse = backend.generate(cont, 128, ok, reason);
    if (!ok) { t.verdict = "FAIL"; t.rationale = "follow-up inference failed: " + reason; return t; }

    const ModelTurn second = parseModelTurn(t.finalResponse);
    t.finalResponse = second.sawResponseTag ? second.response
                     : (second.sawToolTag ? std::string() : trimStr(t.finalResponse));
    t.completed = !t.finalResponse.empty();
    if (!t.completed) {
        t.verdict = "FAIL_NO_FINAL_RESPONSE";
        t.rationale = "model did not produce a RAWR_RESPONSE after the observation";
        return t;
    }
    t.verdict = "PASS";
    return t;
}

std::string deriveVerdict(const AgentTurn& t) {
    if (!t.protocolValid) return "FAIL_PROTOCOL";
    if (!t.completed)     return "FAIL_NO_FINAL_RESPONSE";
    return "PASS";
}

void writeReceipt(const std::string& path, const AgentTurn& t) {
    receipt::beginGate(path, "RAWRXD_RESPONSE_CODED_AGENT_001");
    receipt::writeKeyValue(path, "FEATURE", "RAWRXD_RESPONSE_CODED_AGENT_001");
    receipt::writeKeyValue(path, "TRIGGER", "user_input");
    receipt::writeKeyValueInt(path, "AUTONOMOUS_BACKGROUND_EXECUTION", 0);
    receipt::writeKeyValueInt(path, "SELF_PROMPTING", 0);
    receipt::writeKeyValueInt(path, "CONTINUOUS_LOOP", 0);
    receipt::writeKeyValueInt(path, "REPOSITORY_MUTATION", 0);
    receipt::writeKeyValueInt(path, "ARBITRARY_SHELL", 0);
    receipt::writeKeyValueInt(path, "BACKGROUND_PROCESS", 0);
    receipt::writeKeyValueInt(path, "SCHEDULER", 0);
    receipt::writeKeyValue(path, "STOP_CONDITION", "final_response");
    receipt::writeKeyValue(path, "USER_INPUT", t.userInput);
    receipt::writeKeyValue(path, "MODEL_REF", t.modelRef);
    receipt::writeKeyValue(path, "RESOLVED_PATH", t.resolvedPath);
    receipt::writeKeyValueInt(path, "PROTOCOL_VALID", t.protocolValid ? 1 : 0);
    receipt::writeKeyValueInt(path, "TOOL_REQUESTED", t.toolRequested ? 1 : 0);
    receipt::writeKeyValueInt(path, "TOOL_EXECUTED", t.toolExecuted ? 1 : 0);
    receipt::writeKeyValue(path, "TOOL_NAME", t.toolName);
    receipt::writeKeyValueInt(path, "TOOL_EXIT_CODE", t.toolExitCode);
    receipt::writeKeyValueInt(path, "FOLLOWUP_INFERENCE", t.toolRequested ? 1 : 0);
    receipt::writeKeyValueInt(path, "COMPLETED", t.completed ? 1 : 0);
    receipt::writeKeyValueInt(path, "STUB_FALLBACKS", 0);
    receipt::writeKeyValue(path, "FIRST_TURN", t.firstTurn);
    receipt::writeKeyValue(path, "OBSERVATION", t.observation);
    receipt::writeKeyValue(path, "FINAL_RESPONSE", t.finalResponse);
    receipt::writeKeyValue(path, "RATIONALE", t.rationale);
    receipt::endGate(path, t.verdict.c_str());
}

}} // namespace rawrxd::rcagent
