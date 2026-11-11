// ============================================================================
// agentic_bounded_smoke.cpp — deterministic framework smoke test and live probe
// ============================================================================

#include "agentic/BoundedAgentLoop.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <nlohmann/json.hpp>

namespace fs = std::filesystem;
using RawrXD::Agent::AgentLoopConfig;
using RawrXD::Agent::BoundedAgentLoop;
using RawrXD::Agent::LLMChatRequest;
using RawrXD::Agent::LLMChatResponse;

static void WriteText(const fs::path& path, const std::string& value) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out << value;
}

static bool RunDeterministicSelfTest() {
    const fs::path root = fs::temp_directory_path() / "rawrxd_bounded_agent_smoke";
    std::error_code ec;
    fs::remove_all(root, ec);
    fs::create_directories(root, ec);
    if (ec) return false;

    const fs::path fixture = root / "fixture.txt";
    WriteText(fixture, "RAWRXD_AGENT_FIXTURE_OK\n");

    AgentLoopConfig config;
    config.workingDirectory = root.string();
    config.maxSteps = 3;
    config.maxTokensPerRequest = 64;
    config.transcriptPath = (root / "transcript.json").string();

    BoundedAgentLoop loop;
    loop.Configure(config);
    int calls = 0;
    loop.SetLLMBackend([&calls](const LLMChatRequest&) {
        LLMChatResponse response;
        response.success = true;
        ++calls;
        if (calls == 1) {
            response.hasToolCall = true;
            response.toolCallId = "smoke_read_1";
            response.toolName = "readFile";
            response.toolArgs = {{"path", "fixture.txt"}};
        } else {
            response.content = "Read result verified.";
        }
        return response;
    });

    const std::string answer = loop.Execute("Read fixture.txt and report the result.");
    const bool pass = answer == "Read result verified." &&
                      loop.GetState() == RawrXD::Agent::AgentLoopState::Complete &&
                      loop.GetTranscript().ToolCallCount() == 1 &&
                      fs::exists(root / "transcript.json");
    fs::remove_all(root, ec);
    return pass;
}

static int RunLive(int argc, char** argv) {
    std::string workspace = fs::current_path().string();
    std::string model;
    std::string endpoint = "http://127.0.0.1:11434";
    std::string prompt =
        "Use readFile on agentic_live_fixture.txt, then reply with its exact contents. "
        "Do not guess and do not edit files.";
    std::string receiptPath;
    int maxSteps = 4;

    for (int i = 2; i < argc; ++i) {
        const std::string arg = argv[i];
        auto next = [&](std::string& out) {
            if (i + 1 < argc) out = argv[++i];
        };
        if (arg == "--workspace") next(workspace);
        else if (arg == "--model") next(model);
        else if (arg == "--endpoint") next(endpoint);
        else if (arg == "--prompt") next(prompt);
        else if (arg == "--receipt") next(receiptPath);
        else if (arg == "--max-steps" && i + 1 < argc) maxSteps = std::stoi(argv[++i]);
    }

    const fs::path fixture = fs::path(workspace) / "agentic_live_fixture.txt";
    WriteText(fixture, "RAWRXD_LIVE_FIXTURE_OK\n");

    AgentLoopConfig config;
    config.workingDirectory = workspace;
    config.ollamaBaseUrl = endpoint;
    config.model = model;
    config.maxSteps = maxSteps;
    // Reasoning models may spend part of the budget in a separate thinking
    // channel before emitting a tool call. Keep the live probe bounded, but
    // do not make the budget too small to reach the visible/tool response.
    config.maxTokensPerRequest = 1024;
    if (!receiptPath.empty()) config.transcriptPath = receiptPath;

    BoundedAgentLoop loop;
    loop.Configure(config);
    loop.SetProgressCallback([](int step, int maxSteps, const std::string& status,
                                const std::string& detail) {
        std::cout << "PROGRESS step=" << step << "/" << maxSteps
                  << " status=" << status << " detail=" << detail << "\n";
    });

    const std::string answer = loop.Execute(prompt);
    nlohmann::json receipt = {
        {"test", "RAWRXD_AUTONOMOUS_AGENT_OLLAMA_LIVE_001"},
        {"endpoint", endpoint},
        {"requested_model", model},
        {"workspace", workspace},
        {"answer", answer},
        {"state", static_cast<int>(loop.GetState())},
        {"steps", loop.GetTranscript().StepCount()},
        {"tool_calls", loop.GetTranscript().ToolCallCount()},
        {"tool_errors", loop.GetTranscript().ErrorCount()},
        {"transcript", loop.GetTranscript().toJson()}
    };
    std::cout << receipt.dump(2) << "\n";
    if (!receiptPath.empty()) {
        std::ofstream out(receiptPath, std::ios::trunc);
        out << receipt.dump(2);
    }

    std::error_code ec;
    fs::remove(fixture, ec);
    const bool pass = loop.GetState() == RawrXD::Agent::AgentLoopState::Complete &&
                      !answer.empty() && loop.GetTranscript().ToolCallCount() > 0;
    return pass ? 0 : 2;
}

int main(int argc, char** argv) {
    if (argc > 1 && std::string(argv[1]) == "--live") return RunLive(argc, argv);
    const bool pass = RunDeterministicSelfTest();
    std::cout << "BOUNDED_AGENT_SELF_TEST=" << (pass ? "PASS" : "FAIL") << "\n";
    return pass ? 0 : 1;
}
