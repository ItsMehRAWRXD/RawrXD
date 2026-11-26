// Shared agent controller implementation. See agent_controller.hpp.
#include "agent/agent_controller.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace rawr {
namespace {

std::string lc(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}
std::string trunc(const std::string& s, size_t n) {
    return s.size() <= n ? s : s.substr(0, n);
}

// FNV-1a 64-bit content hash for deliverable-integrity verification.
uint64_t fnv1a(const std::string& s) {
    uint64_t h = 1469598103934665603ULL;
    for (unsigned char c : s) { h ^= c; h *= 1099511628211ULL; }
    return h;
}
bool readFileStr(const std::string& path, std::string& out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    std::ostringstream ss;
    ss << f.rdbuf();
    out = ss.str();
    return true;
}

// Extract concatenated JSON objects from free text (models often wrap JSON in
// prose or emit several objects back-to-back).
std::vector<json> extractObjects(const std::string& text) {
    std::vector<json> out;
    const size_t n = text.size();
    size_t i = 0;
    while (i < n) {
        if (text[i] != '{') { ++i; continue; }
        int depth = 0;
        bool inStr = false, esc = false;
        size_t j = i;
        for (; j < n; ++j) {
            char c = text[j];
            if (inStr) {
                if (esc) esc = false;
                else if (c == '\\') esc = true;
                else if (c == '"') inStr = false;
                continue;
            }
            if (c == '"') { inStr = true; continue; }
            if (c == '{') ++depth;
            else if (c == '}') { --depth; if (depth == 0) { ++j; break; } }
        }
        if (depth == 0 && j <= n && j > i) {
            try {
                json o = json::parse(text.substr(i, j - i));
                if (o.is_object()) out.push_back(o);
            } catch (...) {
            }
            i = j;
        } else {
            ++i;
        }
    }
    return out;
}

struct Pending {
    std::string tool;
    json args = json::object();
};

bool resolveCall(const json& obj, Pending& out) {
    if (!obj.is_object()) return false;
    std::string action, tool;
    if (obj.contains("action") && obj["action"].is_string())
        action = lc(obj["action"].get<std::string>());
    if (obj.contains("tool") && obj["tool"].is_string())
        tool = lc(obj["tool"].get<std::string>());
    static const std::set<std::string> known = {
        "list_repo", "read_file", "search_text", "git_status", "write_file",
        "run_build", "run_tests", "edit_files", "git_diff", "run_shell"};
    std::string name;
    if (known.count(action)) name = action;       // action is authoritative
    else if (known.count(tool)) name = tool;
    else if (!action.empty()) name = action;
    else name = tool;
    if (name.empty() || name == "final" || name == "finish" || name == "done" ||
        name == "final_answer" || name == "result")
        return false;
    if (!known.count(name)) return false;
    out.tool = name;
    if (obj.contains("args") && obj["args"].is_object()) out.args = obj["args"];
    if (out.args.empty()) {
        for (auto it = obj.begin(); it != obj.end(); ++it) {
            const std::string k = it.key();
            if (k == "action" || k == "tool" || k == "findings" || k == "summary" ||
                k == "next_actions")
                continue;
            if (it.value().is_object()) continue;
            out.args[k] = it.value();
        }
    }
    return true;
}

bool isFinal(const json& o) {
    if (o.contains("action") && o["action"].is_string()) {
        std::string a = lc(o["action"].get<std::string>());
        if (a == "final" || a == "finish" || a == "done" || a == "final_answer" ||
            a == "result")
            return true;
    }
    if (o.contains("findings")) return true;
    if (o.contains("summary") && o.contains("next_actions")) return true;
    return false;
}

const char* RUN_PROMPT =
    "You are the RawrXD local coding agent. You work inside a real repository "
    "and have a real tool registry.\n\n"
    "Call tools by replying with ONE JSON object and nothing else:\n"
    "{\"action\":\"tool\",\"tool\":\"<name>\",\"args\":{...}}\n\n"
    "Tools (strict schema; unknown args rejected):\n"
    "list_repo{path}, read_file{path}, search_text{query,path},"
    "git_status{}, write_file{path,action,content}, edit_files{path,old,new},"
    "run_build{config,dir}, run_tests{filter,dir,config}, run_shell{command},"
    "git_diff{}.\n\n"
    "run_shell takes ONE command string in \"command\". It runs via cmd.exe /c "
    "and rejects chaining. Compile and run in separate calls.\n\n"
    "Rules:\n"
    "- Reply with ONLY the JSON object. No prose, no markdown fences.\n"
    "- edit_files replaces an EXACT substring. \"old\" must be copied verbatim "
    "and must NOT be empty. Keep \"old\" short but unique.\n"
    "- Relative paths only; never escape the workspace.\n"
    "- You will receive the real tool result, then continue or finish.\n"
    "- To finish, reply with {\"action\":\"final\",\"summary\":\"...\","
    "\"findings\":[...],\"next_actions\":[...]}\n"
    "- Never invent tool output. Base every claim on a result you actually saw.\n";

const char* ASK_PROMPT =
    "You are a helpful assistant. Follow the user's instructions exactly. "
    "Reply with the requested text only — no JSON, no tools, no markdown fences.\n";

}  // namespace

AgentResult runAgentController(
    const std::function<InferenceResult(const std::vector<json>&, int)>& completeFn,
    ToolRegistry& reg, const Workspace& ws, const AgentConfig& cfg,
    const AgentLogFn& log, const AgentCancelFn& cancel) {
    AgentResult res;
    std::string modeName = cfg.modeName.empty() ? std::string("code") : cfg.modeName;
    std::string modeDesc = cfg.modeDescription;
    ModeProfile mode;
    mode.name = modeName.c_str();
    mode.description = modeDesc.c_str();
    mode.caps = CAP_READ | CAP_SEARCH;
    if (cfg.sourceEditsAllowed) mode.caps |= CAP_WRITE;
    if (cfg.executeByDefault) mode.caps |= CAP_EXEC;
    mode.planFilesOnly = false;
    mode.commitAllowed = false;
    mode.sourceEditsAllowed = cfg.sourceEditsAllowed;
    mode.executeByDefault = cfg.executeByDefault;
    ToolContext ctx;
    ctx.mode = &mode;
    ctx.ws = &ws;

    const bool askMode = (cfg.modeName == "ask");
    const std::string banner =
        askMode ? (std::string(ASK_PROMPT) + "Active mode: ask\n")
                : (std::string(RUN_PROMPT) + "\nActive mode: " + cfg.modeName +
                   " (" + cfg.modeDescription + ")\n");

    std::vector<json> messages;
    std::string digest, pendingAssistant;
    std::vector<json> recent;
    int strikes = 0;
    const size_t MAXD = 2400;
    auto rebuild = [&]() {
        messages.clear();
        messages.push_back({{"role", "system"}, {"content", banner}});
        messages.push_back({{"role", "user"}, {"content", cfg.goal}});
        if (!digest.empty()) {
            std::string d = digest.size() > MAXD ? digest.substr(digest.size() - MAXD)
                                                 : digest;
            messages.push_back({{"role", "user"},
                                {"content", "EVIDENCE SO FAR (real tool outputs, "
                                            "summarized):\n" + d}});
        }
        for (const auto& m : recent) messages.push_back(m);
    };
    auto commit = [&](const std::string& userMsg) {
        if (!pendingAssistant.empty())
            recent.push_back({{"role", "assistant"}, {"content", pendingAssistant}});
        pendingAssistant.clear();
        recent.push_back({{"role", "user"}, {"content", userMsg}});
        if (recent.size() > 2) recent.erase(recent.begin());
        rebuild();
    };
    rebuild();

    const int decodeBudget = cfg.maxTokensPerTurn > 0 ? cfg.maxTokensPerTurn : 1024;
    size_t lastCount = 0;
    int stall = 0;

    // F04-V completion integrity: per-session deliverable evidence. A model FINAL
    // is a completion REQUEST, not proof. The controller verifies real tool
    // evidence before issuing an authoritative receipt.
    std::map<std::string, uint64_t> writtenHashes;  // path -> content hash at write
    auto verifyCompletion = [&](std::string& reason) -> bool {
        const std::string goalLow = lc(cfg.goal);
        const bool wantsWrite =
            goalLow.find("create") != std::string::npos ||
            goalLow.find("write") != std::string::npos ||
            goalLow.find("file") != std::string::npos ||
            goalLow.find("implement") != std::string::npos ||
            goalLow.find("generate") != std::string::npos;
        const bool wantsBuild = goalLow.find("compile") != std::string::npos ||
                                goalLow.find("build") != std::string::npos;
        const bool wantsTest = goalLow.find("test") != std::string::npos;
        const bool wantsExec = wantsBuild || wantsTest ||
                               goalLow.find("run") != std::string::npos;

        // A failed attempt is SUPERSEDED by any later successful tool (corrective
        // execution, F04-C). Only an unresolved TRAILING failure blocks completion.
        if (!res.results.empty()) {
            const AgentReceipt& last = res.results.back();
            if (!last.ok && !last.denied) {
                reason = "last tool " + last.tool + " failed (exit " +
                         std::to_string(last.exitCode) +
                         "); fix it and re-run before finishing";
                return false;
            }
        }

        // Session-written files must still exist with the content we recorded.
        for (const auto& kv : writtenHashes) {
            std::string content;
            const std::string abs = ws.root() + "/" + kv.first;
            if (!readFileStr(abs, content)) {
                reason = "deliverable missing: " + kv.first;
                return false;
            }
            if (fnv1a(content) != kv.second) {
                reason = "deliverable modified after write: " + kv.first;
                return false;
            }
        }

        bool hasWrite = false, hasBuild = false, hasTest = false, hasRun = false;
        for (const auto& r : res.results) {
            if (!r.ok) continue;
            if (r.tool == "write_file" || r.tool == "edit_files") hasWrite = true;
            if (r.tool == "run_build") hasBuild = true;
            if (r.tool == "run_tests") hasTest = true;
            if (r.tool == "run_shell" && r.exitCode == 0) hasRun = true;
        }
        const bool hasExecOk = hasBuild || hasTest || hasRun;

        // Read-only tasks need no filesystem/exec deliverable.
        if (res.results.empty() && (wantsWrite || wantsExec)) {
            reason = "no tool was executed; emit a real tool call first";
            return false;
        }
        if (wantsWrite && !hasWrite) {
            reason = "task requires a file deliverable but no write_file/edit_files "
                     "succeeded";
            return false;
        }
        // Compilation and testing are SEPARATE receipts when both are required.
        if (wantsBuild && !hasBuild && !hasRun) {
            reason = "task requires compilation but no successful build/run was "
                     "executed";
            return false;
        }
        if (wantsTest && !hasTest && !hasRun) {
            reason = "task requires tests but no successful test/run was executed";
            return false;
        }
        return true;
    };

    for (int turn = 1; turn <= cfg.maxTurns; ++turn) {
        if (cancel && cancel()) {
            res.canceled = true;
            res.completed = false;
            if (log) log("run: cancelled by user (Ctrl-C)");
            break;
        }
        res.turns = turn;
        if (res.results.size() == lastCount) {
            if (++stall >= 3) {
                if (log)
                    log("run: no-progress termination at turn " +
                        std::to_string(turn) + " (no new tool result in 3 turns)");
                res.completed = false;
                res.summary = "no-progress: no new tool result in 3 turns";
                break;
            }
        } else {
            stall = 0;
            lastCount = res.results.size();
        }

        InferenceResult r = completeFn(messages, decodeBudget);
        if (r.canceled || (cancel && cancel())) {
            res.canceled = true;
            res.completed = false;
            if (!r.content.empty()) res.summary = r.content;
            if (log)
                log("run: cancelled during inference at turn " +
                    std::to_string(turn));
            break;
        }
        if (!r.ok) {
            if (log)
                log("run: inference failure at turn " + std::to_string(turn) +
                    ": " + r.error);
            break;
        }

        std::vector<json> objects;
        if (r.content.empty()) {
            pendingAssistant = "";
            if (log)
                log("run: empty model response at turn " + std::to_string(turn));
        } else {
            pendingAssistant = r.content;
            objects = extractObjects(r.content);
        }

        std::set<std::string> done;
        for (const auto& t : res.results) done.insert(t.tool + "|" + t.args);
        std::vector<Pending> pending;
        std::set<std::string> queued;
        const json* finalObj = nullptr;
        for (const auto& cand : objects) {
            if (isFinal(cand)) {
                if (!finalObj) finalObj = &cand;
                continue;
            }
            Pending pc;
            if (!resolveCall(cand, pc)) continue;
            std::string key = pc.tool + "|" + pc.args.dump();
            if (done.count(key)) continue;
            if (!queued.insert(key).second) continue;
            pending.push_back(pc);
        }
        const bool haveFinal = (finalObj != nullptr);

        if (askMode && pending.empty() && !haveFinal) {
            res.summary = r.content;
            res.completed = true;
            if (log)
                log("run: ask mode answer accepted at turn " +
                    std::to_string(turn));
            break;
        }

        // Dispatch ALL pending tools first (plan order). A final is deferred to
        // the next turn so the tools actually run before any verdict.
        if (!pending.empty()) {
            std::string combined;
            for (const auto& pc : pending) {
                if (log) log("run: tool call " + pc.tool + " args=" + pc.args.dump());
                ToolResult tr = reg.dispatch(pc.tool, pc.args, ctx);
                AgentReceipt ar;
                ar.tool = tr.tool;
                ar.args = tr.argsJson;
                ar.output = tr.output;
                ar.ok = tr.ok;
                ar.denied = tr.denied;
                ar.exitCode = static_cast<int>(tr.exitCode);
                res.results.push_back(ar);
                if (tr.denied) ++res.denied;
                // F04-V: record deliverable evidence for later verification.
                if (tr.ok && (pc.tool == "write_file" || pc.tool == "edit_files")) {
                    std::string path =
                        pc.args.contains("path") && pc.args["path"].is_string()
                            ? pc.args["path"].get<std::string>()
                            : std::string();
                    if (!path.empty()) {
                        std::string content;
                        if (pc.tool == "write_file" && pc.args.contains("content") &&
                            pc.args["content"].is_string())
                            content = pc.args["content"].get<std::string>();
                        else
                            readFileStr(ws.root() + "/" + path, content);
                        writtenHashes[path] = fnv1a(content);
                    }
                }
                std::string fl = tr.output.substr(0, tr.output.find('\n'));
                if (fl.size() > 140) fl = fl.substr(0, 140);
                combined += "- " + tr.tool + " " + tr.argsJson + " -> " +
                            (tr.ok ? "OK" : (tr.denied ? "DENIED" : "FAILED")) +
                            " | " + fl + "\n";
            }
            digest += combined;
            commit("TOOL_RESULT (real output, summarized):\n" +
                   trunc(combined, 1400) +
                   "\n\nContinue with the next step of your plan, or reply with "
                   "{\"action\":\"final\",\"summary\":\"...\",\"findings\":[...],"
                   "\"next_actions\":[...]}");
            continue;
        }

        if (haveFinal) {
            std::string proposed;
            if (finalObj->contains("summary") &&
                (*finalObj)["summary"].is_string())
                proposed = (*finalObj)["summary"].get<std::string>();
            const bool vacuous = proposed.empty();
            const std::string low = lc(proposed);
            const bool negated =
                low.find("missing") != std::string::npos ||
                low.find("not run") != std::string::npos ||
                low.find("failed") != std::string::npos ||
                low.find("incomplete") != std::string::npos;
            // A model FINAL is a completion REQUEST, not proof of completion.
            if (negated) {
                res.summary = proposed;
                res.completed = false;
                if (log)
                    log("run: final answer reports an incomplete/failed run; "
                        "completed=false");
                break;
            }
            if (vacuous) {
                if (strikes < 3) {
                    ++strikes;
                    if (log)
                        log("run: final answer rejected (empty summary) strike " +
                            std::to_string(strikes));
                    commit("Your last reply had an empty \"summary\". Reply with a "
                           "tool_call JSON or a final with a real summary.");
                    continue;
                }
                res.completed = false;
                res.summary = "no-progress: repeated empty final summary";
                break;
            }
            // F04-V: independent completion verification against real evidence.
            std::string vreason;
            if (!verifyCompletion(vreason)) {
                if (strikes < 3) {
                    ++strikes;
                    if (log)
                        log("run: COMPLETION REJECTED: " + vreason + " (strike " +
                            std::to_string(strikes) + ")");
                    commit("COMPLETION REJECTED: " + vreason +
                           ". Do the real work with the tools, wait for the real "
                           "output, then reply with {\"action\":\"final\","
                           "\"summary\":\"...\"}.");
                    continue;
                }
                res.completed = false;
                res.summary = "verification failed: " + vreason;
                if (log) log("run: completion verification exhausted retries");
                break;
            }
            // Accepted: controller-owned authoritative completion receipt.
            res.summary = proposed;
            if (finalObj->contains("findings"))
                res.findings = (*finalObj)["findings"].dump(2);
            if (finalObj->contains("next_actions"))
                res.nextActions = (*finalObj)["next_actions"].dump(2);
            res.completed = true;
            if (log)
                log("run: VERIFIED completion at turn " + std::to_string(turn) +
                    " (" + std::to_string(res.results.size()) +
                    " tool results, " + std::to_string(writtenHashes.size()) +
                    " deliverables verified)");
            break;
        }

        // No pending tool and no final: bounded re-prompt, then terminate.
        if (++strikes > 3) {
            res.completed = false;
            res.summary = "no-progress: model produced no tool call or final";
            if (log) log("run: no-progress termination (no tool/final)");
            break;
        }
        commit("I could not parse that. Reply with exactly one JSON object: "
               "{\"action\":\"tool\",\"tool\":\"...\",\"args\":{...}} or "
               "{\"action\":\"final\",...}");
    }

    // ---- Host verdict synthesis (deterministic task completion) ----
    if (!askMode && !res.completed && !res.canceled) {
        auto hasOk = [&res](const char* t) {
            for (const auto& r : res.results)
                if (r.ok && r.tool == t) return true;
            return false;
        };
        bool ranOk = false;
        for (const auto& r : res.results)
            if (r.ok && r.tool == "run_shell" && r.exitCode == 0) ranOk = true;
        const bool edited = hasOk("edit_files") || hasOk("write_file");
        const bool built = hasOk("run_build");
        const std::string low = lc(cfg.goal);
        const bool expectsRun =
            low.find("run") != std::string::npos ||
            low.find("exit 0") != std::string::npos ||
            low.find("return 0") != std::string::npos ||
            low.find("compile") != std::string::npos ||
            low.find("build") != std::string::npos;
        if (edited && built && ranOk && expectsRun) {
            ToolResult gd = reg.dispatch("git_diff", json::object(), ctx);
            res.completed = true;
            res.summary =
                "HOST_VERDICT: SUCCESS - verified edit+build+run (run_shell "
                "exit 0).";
            if (gd.ok && !gd.output.empty())
                res.summary += "\nSource revision (git_diff):\n" +
                               trunc(gd.output, 800);
            if (log) log("run: host verdict SUCCESS (edit+build+run verified)");
        }
    }

    res.toolCalls = static_cast<int>(res.results.size());
    return res;
}

}  // namespace rawr