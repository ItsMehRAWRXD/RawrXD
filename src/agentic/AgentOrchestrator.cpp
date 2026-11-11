// AgentOrchestrator.cpp — Autonomous agent orchestration layer
// Wires Deep2 inference + ToolCallParser + rawrxd::tools::Registry
// into a ReAct loop.

#include "AgentOrchestrator.h"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <array>
#include <memory>
#include <cstdio>
#include <filesystem>

namespace RawrXD {
namespace Agent {

AgentOrchestrator::AgentOrchestrator(const Config& cfg)
    : m_cfg(cfg) {}

AgentOrchestrator::~AgentOrchestrator() = default;

void AgentOrchestrator::ensureToolsRegistered() {
    if (m_toolsRegistered) return;

    std::string wsRoot = m_cfg.workspaceRoot.empty()
        ? std::filesystem::current_path().string()
        : m_cfg.workspaceRoot;

    // Read-only tools (no approval needed)
    m_toolRegistry.add({"read_file", "Read a file within the workspace",
                        rawrxd::tools::Risk::ReadOnly, {"path"},
        [wsRoot](const rawrxd::tools::Request& r) -> rawrxd::tools::Result {
            try {
                auto p = rawrxd::tools::scoped(wsRoot, rawrxd::tools::arg(r, "path"));
                std::string content = rawrxd::tools::read_text(p);
                return {true, content, ""};
            } catch (const std::exception& e) {
                return {false, "", e.what()};
            }
        }});

    m_toolRegistry.add({"grep_files", "Search for text in workspace files",
                        rawrxd::tools::Risk::ReadOnly, {"needle"},
        [wsRoot](const rawrxd::tools::Request& r) -> rawrxd::tools::Result {
            try {
                std::string needle = rawrxd::tools::arg(r, "needle");
                std::ostringstream out;
                size_t matches = 0;
                std::error_code ec;
                std::filesystem::recursive_directory_iterator endIt;
                for (auto it = std::filesystem::recursive_directory_iterator(wsRoot,
                         std::filesystem::directory_options::skip_permission_denied, ec),
                         end = endIt;
                     it != end && matches < 250 && !ec;
                     it.increment(ec)) {
                    std::string relPath = std::filesystem::relative(it->path(), wsRoot).string();
                    size_t depth = std::count(relPath.begin(), relPath.end(), '/') + 
                                   std::count(relPath.begin(), relPath.end(), '\\');
                    if (depth > 24) { it.disable_recursion_pending(); continue; }
                    if (!it->is_regular_file(ec) || it->file_size(ec) > 1024 * 1024) continue;
                    std::ifstream f(it->path());
                    std::string line;
                    size_t ln = 0;
                    while (std::getline(f, line) && matches < 250) {
                        ++ln;
                        if (line.find(needle) != std::string::npos) {
                            out << std::filesystem::relative(it->path(), wsRoot).string()
                                << ":" << ln << ":" << line.substr(0, 240) << '\n';
                            ++matches;
                        }
                    }
                }
                return {true, out.str(), ""};
            } catch (const std::exception& e) {
                return {false, "", e.what()};
            }
        }});

    m_toolRegistry.add({"search_files", "Find files by name pattern",
                        rawrxd::tools::Risk::ReadOnly, {"pattern"},
        [wsRoot](const rawrxd::tools::Request& r) -> rawrxd::tools::Result {
            try {
                std::string pattern = rawrxd::tools::arg(r, "pattern");
                std::ostringstream out;
                size_t count = 0;
                std::error_code ec;
                std::filesystem::recursive_directory_iterator endIt;
                for (auto it = std::filesystem::recursive_directory_iterator(wsRoot,
                         std::filesystem::directory_options::skip_permission_denied, ec),
                         end = endIt;
                     it != end && count < 500 && !ec;
                     it.increment(ec)) {
                    std::string relPath = std::filesystem::relative(it->path(), wsRoot).string();
                    size_t depth = std::count(relPath.begin(), relPath.end(), '/') + 
                                   std::count(relPath.begin(), relPath.end(), '\\');
                    if (depth > 24) { it.disable_recursion_pending(); continue; }
                    if (it->path().filename().string().find(pattern) != std::string::npos) {
                        out << std::filesystem::relative(it->path(), wsRoot).string() << '\n';
                        ++count;
                    }
                }
                return {true, out.str(), ""};
            } catch (const std::exception& e) {
                return {false, "", e.what()};
            }
        }});

    // Write/edit tools (approval needed)
    m_toolRegistry.add({"write_file", "Create or overwrite a file",
                        rawrxd::tools::Risk::Write, {"path", "content"},
        [wsRoot](const rawrxd::tools::Request& r) -> rawrxd::tools::Result {
            try {
                auto p = rawrxd::tools::scoped(wsRoot, rawrxd::tools::arg(r, "path"));
                rawrxd::tools::write_atomic(p, rawrxd::tools::arg(r, "content"));
                return {true, "written", ""};
            } catch (const std::exception& e) {
                return {false, "", e.what()};
            }
        }});

    m_toolRegistry.add({"edit_files", "Replace exact unique text in a file",
                        rawrxd::tools::Risk::Write, {"path", "old", "new"},
        [wsRoot](const rawrxd::tools::Request& r) -> rawrxd::tools::Result {
            try {
                auto p = rawrxd::tools::scoped(wsRoot, rawrxd::tools::arg(r, "path"));
                std::string text = rawrxd::tools::read_text(p);
                std::string old = rawrxd::tools::arg(r, "old");
                if (old.empty()) throw std::runtime_error("empty match");
                size_t pos = text.find(old);
                if (pos == std::string::npos ||
                    text.find(old, pos + old.size()) != std::string::npos)
                    throw std::runtime_error("match must occur exactly once");
                text.replace(pos, old.size(), rawrxd::tools::arg(r, "new"));
                rawrxd::tools::write_atomic(p, text);
                return {true, "edited", ""};
            } catch (const std::exception& e) {
                return {false, "", e.what()};
            }
        }});

    // Execution tools
    m_toolRegistry.add({"run_command", "Execute a shell command",
                        rawrxd::tools::Risk::Execute, {"command"},
        [wsRoot](const rawrxd::tools::Request& r) -> rawrxd::tools::Result {
            try {
                std::string cmd = rawrxd::tools::arg(r, "command");
                std::string fullCmd;
#ifdef _WIN32
                fullCmd = "cd /D \"" + wsRoot + "\" && " + cmd;
#else
                fullCmd = "cd \"" + wsRoot + "\" && " + cmd;
#endif
                // Use popen for simplicity
                std::array<char, 4096> buffer;
                std::string result;
                std::unique_ptr<FILE, decltype(&_pclose)> pipe(_popen(fullCmd.c_str(), "r"), _pclose);
                if (!pipe) return {false, "", "failed to execute"};
                while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
                    result += buffer.data();
                }
                return {true, result, ""};
            } catch (const std::exception& e) {
                return {false, "", e.what()};
            }
        }});

    m_toolRegistry.add({"run_build", "Run cmake build",
                        rawrxd::tools::Risk::Execute, {},
        [wsRoot](const rawrxd::tools::Request& r) -> rawrxd::tools::Result {
            try {
                std::string config = r.args.count("config") ? r.args.at("config") : "Release";
                std::string target = r.args.count("target") ? r.args.at("target") : "";
                std::string cmd;
#ifdef _WIN32
                cmd = "cd /D \"" + wsRoot + "\" && cmake --build . --config " + config;
                if (!target.empty()) cmd += " --target " + target;
#else
                cmd = "cd \"" + wsRoot + "\" && cmake --build . --config " + config;
                if (!target.empty()) cmd += " --target " + target;
#endif
                std::array<char, 4096> buffer;
                std::string result;
                std::unique_ptr<FILE, decltype(&_pclose)> pipe(_popen(cmd.c_str(), "r"), _pclose);
                if (!pipe) return {false, "", "failed to execute"};
                while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
                    result += buffer.data();
                }
                return {true, result, ""};
            } catch (const std::exception& e) {
                return {false, "", e.what()};
            }
        }});

    m_toolRegistry.add({"run_tests", "Run ctest tests",
                        rawrxd::tools::Risk::Execute, {},
        [wsRoot](const rawrxd::tools::Request& r) -> rawrxd::tools::Result {
            try {
                std::string config = r.args.count("config") ? r.args.at("config") : "Release";
                std::string cmd;
#ifdef _WIN32
                cmd = "cd /D \"" + wsRoot + "\" && ctest --config " + config + " --output-on-failure";
#else
                cmd = "cd \"" + wsRoot + "\" && ctest --config " + config + " --output-on-failure";
#endif
                std::array<char, 4096> buffer;
                std::string result;
                std::unique_ptr<FILE, decltype(&_pclose)> pipe(_popen(cmd.c_str(), "r"), _pclose);
                if (!pipe) return {false, "", "failed to execute"};
                while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
                    result += buffer.data();
                }
                return {true, result, ""};
            } catch (const std::exception& e) {
                return {false, "", e.what()};
            }
        }});

    m_toolRegistry.add({"git_status", "Show git status",
                        rawrxd::tools::Risk::ReadOnly, {},
        [wsRoot](const rawrxd::tools::Request& r) -> rawrxd::tools::Result {
            try {
                std::string cmd;
#ifdef _WIN32
                cmd = "cd /D \"" + wsRoot + "\" && git status --porcelain";
#else
                cmd = "cd \"" + wsRoot + "\" && git status --porcelain";
#endif
                std::array<char, 4096> buffer;
                std::string result;
                std::unique_ptr<FILE, decltype(&_pclose)> pipe(_popen(cmd.c_str(), "r"), _pclose);
                if (!pipe) return {false, "", "failed to execute"};
                while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
                    result += buffer.data();
                }
                return {true, result, ""};
            } catch (const std::exception& e) {
                return {false, "", e.what()};
            }
        }});

    m_toolRegistry.add({"git_diff", "Show git diff",
                        rawrxd::tools::Risk::ReadOnly, {},
        [wsRoot](const rawrxd::tools::Request& r) -> rawrxd::tools::Result {
            try {
                std::string cmd;
#ifdef _WIN32
                cmd = "cd /D \"" + wsRoot + "\" && git diff";
#else
                cmd = "cd \"" + wsRoot + "\" && git diff";
#endif
                std::array<char, 4096> buffer;
                std::string result;
                std::unique_ptr<FILE, decltype(&_pclose)> pipe(_popen(cmd.c_str(), "r"), _pclose);
                if (!pipe) return {false, "", "failed to execute"};
                while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
                    result += buffer.data();
                }
                return {true, result, ""};
            } catch (const std::exception& e) {
                return {false, "", e.what()};
            }
        }});

    m_toolsRegistered = true;
}

bool AgentOrchestrator::think(const std::string& goal,
                               const std::vector<OrchestrationStep>& trace,
                               std::string& thought,
                               std::string& toolName,
                               json& toolArgs,
                               std::string& finalAnswer) {
    // Build scratchpad from previous trace
    std::ostringstream scratchpad;
    for (const auto& step : trace) {
        scratchpad << "Iteration " << step.iteration << ":\n";
        if (!step.thought.empty()) scratchpad << "Thought: " << step.thought << "\n";
        if (!step.toolName.empty()) scratchpad << "Action: " << step.toolName << "\n";
        if (!step.observation.empty()) scratchpad << "Observation: " << step.observation << "\n";
        scratchpad << "\n";
    }

    // Build the full prompt with hardened agent instructions
    std::string toolsXml;
    auto toolNames = m_toolRegistry.names();
    for (const auto& tn : toolNames) {
        rawrxd::tools::Tool tool;
        if (m_toolRegistry.find(tn, tool)) {
            toolsXml += "<tool>\n<name>" + tn + "</name>\n<description>"
                + tool.description + "</description>\n</tool>\n";
        }
    }

    std::string systemPrompt = rawrxd::BuildHardenedAgentPrompt(toolsXml);

    std::string userQuery = "TASK: " + goal + "\n\nSCRATCHPAD:\n" + scratchpad.str()
        + "\n\nYou must decide: call a tool or give a final answer.";

    std::string fullPrompt = systemPrompt + "\n<|user|>\n" + userQuery
        + "\n</|user|>\n<|assistant|>\n";

    // Generate via Deep2
    std::string modelOutput = RawrXD::Deep2InferenceService::instance()
        .generateText(fullPrompt, 512);

    if (modelOutput.empty()) {
        thought = "Model returned empty output";
        return false;
    }

    thought = modelOutput;

    // Parse tool calls from model output
    auto parseResult = RawrXD::Agentic::ToolCallParser::parse(modelOutput);

    if (parseResult.toolCalls.empty()) {
        // No tool call found - check if it looks like a final answer
        std::string lower = modelOutput;
        std::transform(lower.begin(), lower.end(), lower.begin(),
                       [](unsigned char c){ return std::tolower(c); });
        if (lower.find("final answer") != std::string::npos ||
            lower.find("complete") != std::string::npos ||
            lower.find("done") != std::string::npos) {
            finalAnswer = modelOutput;
            return true;
        }
        // Model didn't call a tool and didn't complete - ask again
        return true; // Continue loop with empty toolName
    }

    // Use the first tool call
    const auto& call = parseResult.toolCalls[0];
    toolName = call.name;
    toolArgs = call.arguments;

    return true;
}

std::string AgentOrchestrator::act(const std::string& toolName, const json& args) {
    rawrxd::tools::Request req;
    req.name = toolName;
    for (auto it = args.begin(); it != args.end(); ++it) {
        req.args[it.key()] = it.value().get<std::string>();
    }

    auto approval = [](const rawrxd::tools::Tool& tool,
                       const rawrxd::tools::Request& request) -> bool {
        // Auto-approve all tools for autonomous operation
        (void)tool; (void)request;
        return true;
    };

    auto result = m_toolRegistry.call(req, approval);

    if (result.ok) {
        return result.output;
    } else {
        return "Error: " + result.error;
    }
}

OrchestrationResult AgentOrchestrator::run(const std::string& taskDescription) {
    OrchestrationResult result;
    result.totalIterations = 0;

    m_running.store(true);
    m_abortFlag.store(false);

    ensureToolsRegistered();

    auto totalStart = std::chrono::steady_clock::now();

    std::vector<OrchestrationStep> trace;

    for (uint32_t iter = 0; iter < m_cfg.maxIterations && !m_abortFlag.load(); ++iter) {
        if (m_abortFlag.load()) break;

        auto stepStart = std::chrono::steady_clock::now();

        OrchestrationStep step;
        step.iteration = iter;

        std::string thought;
        std::string toolName;
        json toolArgs;
        std::string finalAnswer;
        bool goalReached = false;

        // Think
        bool thinkOk = think(taskDescription, trace, thought, toolName, toolArgs, finalAnswer);
        if (!thinkOk) {
            result.failReason = "Think function failed at iteration " + std::to_string(iter);
            break;
        }

        step.thought = thought;
        step.toolName = toolName;
        step.toolArgs = toolArgs;

        // Check for completion
        if (goalReached || !finalAnswer.empty()) {
            step.goalReached = true;
            step.observation = "Task completed by model";
            step.durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - stepStart).count();
            trace.push_back(step);

            result.success = true;
            result.finalAnswer = finalAnswer.empty() ? thought : finalAnswer;
            result.trace = trace;
            result.totalIterations = iter + 1;
            result.totalMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - totalStart).count();

            m_running.store(false);
            return result;
        }

        if (toolName.empty()) {
            step.goalReached = false;
            step.observation = "No action requested";
            step.durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - stepStart).count();
            trace.push_back(step);
            continue;
        }

        // Act
        std::string observation = act(toolName, toolArgs);
        step.observation = observation;

        if (m_cfg.verbose) {
            std::cout << "[Orchestrator] Iteration " << iter
                      << ": Tool=" << toolName
                      << ", Observation=" << (observation.size() > 200
                          ? observation.substr(0, 200) + "..."
                          : observation) << std::endl;
        }

        step.durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - stepStart).count();
        trace.push_back(step);

        // Check total timeout
        auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - totalStart).count();
        if (elapsedMs >= static_cast<int64_t>(m_cfg.totalTimeoutMs)) {
            result.failReason = "Total timeout exceeded";
            break;
        }
    }

    result.success = false;
    result.trace = trace;
    result.totalIterations = static_cast<uint32_t>(trace.size());
    result.totalMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - totalStart).count();

    if (result.failReason.empty()) {
        result.failReason = "Max iterations reached without completion";
    }

    m_running.store(false);
    return result;
}

void AgentOrchestrator::abort() {
    m_abortFlag.store(true);
}

} // namespace Agent
} // namespace RawrXD
