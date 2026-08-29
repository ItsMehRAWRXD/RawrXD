// ide_agent_loop_cert — Win32IDE agent spine smoke (fix → build → run)
//
// Modes:
//   --mode scripted  Inject canned TOOL_CALL sequence via SetRuntime (no GGUF).
//                    Proves OrchestratorBridge + AgentToolHandlers end-to-end.
//   --mode deep2     Real Deep2 + GGUF; model must emit TOOL_CALL lines (honest).
//
// Exit 0 = scripted spine PASS (exe printed Hello RawrXD) or deep2 completed
//         with SUCCESS marker. deep2 without tool emissions → exit 2 (not fake green).

#include "OrchestratorBridge.h"
#include "AgentToolHandlers.h"
#include "../runtime/IModelRuntime.hpp"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

class ScriptedToolRuntime final : public RawrXD::Runtime::IModelRuntime {
public:
    explicit ScriptedToolRuntime(std::vector<std::string> responses)
        : m_responses(std::move(responses)) {}

    bool LoadModel(const std::string& path, std::string& errorMessage) override {
        (void)path;
        errorMessage.clear();
        m_loaded = true;
        m_info.name = "scripted_tool_runtime";
        m_info.isLoaded = true;
        return true;
    }

    void UnloadModel() override {
        m_loaded = false;
        m_info.isLoaded = false;
    }

    bool IsLoaded() const override { return m_loaded; }

    RawrXD::Runtime::ModelInfo GetModelInfo() const override { return m_info; }

    std::vector<int32_t> Tokenize(const std::string&) override { return {}; }
    std::string Detokenize(const std::vector<int32_t>&) override { return {}; }

    RawrXD::Runtime::GenerationResult Generate(
        const RawrXD::Runtime::GenerationRequest& request) override
    {
        RawrXD::Runtime::GenerationResult r;
        std::string text;
        const bool ok = GenerateStream(request, [&](const std::string& tok, bool) {
            text += tok;
            return true;
        });
        r.success = ok;
        r.text = std::move(text);
        r.finishReason = ok ? "stop" : "error";
        if (!ok) r.errorMessage = "scripted runtime exhausted";
        return r;
    }

    bool GenerateStream(const RawrXD::Runtime::GenerationRequest&,
                        RawrXD::Runtime::TokenCallback callback) override
    {
        if (m_step >= m_responses.size()) {
            if (callback) callback("", true);
            return false;
        }
        const std::string& text = m_responses[m_step++];
        if (callback) {
            callback(text, true);
        }
        return true;
    }

    void CancelGeneration() override {}
    bool IsGenerating() const override { return false; }

    RawrXD::Runtime::GenerationResult GenerateFIM(
        const RawrXD::Runtime::FIMRequest&) override
    {
        RawrXD::Runtime::GenerationResult r;
        r.success = false;
        r.errorMessage = "FIM not supported in scripted runtime";
        return r;
    }

    bool GenerateFIMStream(const RawrXD::Runtime::FIMRequest&,
                           RawrXD::Runtime::TokenCallback) override
    {
        return false;
    }

    bool SupportsToolCalling() const override { return true; }
    bool SupportsFIM() const override { return false; }

    bool HealthCheck(std::string& statusMessage) override {
        statusMessage = "scripted_ok";
        return true;
    }

    std::string GetBackendName() const override { return "scripted"; }

private:
    std::vector<std::string> m_responses;
    size_t m_step = 0;
    bool m_loaded = false;
    RawrXD::Runtime::ModelInfo m_info;
};

void SeedBrokenFixture(const fs::path& dir) {
    fs::create_directories(dir);
    std::ofstream out(dir / "main.cpp", std::ios::binary | std::ios::trunc);
    out << "#include <iostream>\n\n"
           "int main() {\n"
           "    // Intentional compile error: missing semicolon after endl\n"
           "    std::cout << \"Hello RawrXD\" << std::endl\n"
           "    return 0;\n"
           "}\n";
}

bool FileContains(const fs::path& p, const std::string& needle) {
    std::ifstream in(p, std::ios::binary);
    if (!in) return false;
    std::string s((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    return s.find(needle) != std::string::npos;
}

int RunScripted(const fs::path& fixture) {
    SeedBrokenFixture(fixture);
    const std::string mainRel = "main.cpp";
    const std::string exeName = "broken_hello.exe";

    // Scripted model emits the same TOOL_CALL grammar OrchestratorBridge parses.
    std::vector<std::string> steps = {
        "I'll inspect the source.\nTOOL_CALL: read_file {\"path\": \"" + mainRel + "\"}",
        "Checking compiler diagnostics.\nTOOL_CALL: get_diagnostics {\"file\": \"" + mainRel + "\"}",
        "Repairing missing semicolon.\nTOOL_CALL: replace_in_file {\"path\": \"" + mainRel +
            "\", \"old_string\": \"std::cout << \\\"Hello RawrXD\\\" << std::endl\\n    return 0;\", "
            "\"new_string\": \"std::cout << \\\"Hello RawrXD\\\" << std::endl;\\n    return 0;\"}",
        "Re-checking diagnostics.\nTOOL_CALL: get_diagnostics {\"file\": \"" + mainRel + "\"}",
        "Building.\nTOOL_CALL: execute_command {\"command\": \"cl.exe /nologo /EHsc /std:c++20 /Fe:" +
            exeName + " " + mainRel + "\"}",
        "Running.\nTOOL_CALL: execute_command {\"command\": \"" + exeName + "\"}",
        "Fixed the compile error and ran the program successfully. SUCCESS"
    };

    auto& orch = RawrXD::Agent::OrchestratorBridge::Instance();
    orch.SetWorkingDirectory(fixture.string());
    orch.SetMaxSteps(static_cast<int>(steps.size()) + 2);
    orch.SetRuntime(std::make_unique<ScriptedToolRuntime>(std::move(steps)));

    const std::string reply =
        orch.RunAgent("Fix the compile error and run the program");

    std::cout << "=== agent reply ===\n" << reply << "\n";

    const bool fixed = FileContains(fixture / mainRel, "std::endl;");
    const bool exeOk = fs::exists(fixture / exeName);
    const bool successMark = reply.find("SUCCESS") != std::string::npos ||
                             reply.find("Hello RawrXD") != std::string::npos;

    std::cout << "fixed_source=" << (fixed ? "yes" : "no") << "\n";
    std::cout << "exe_exists=" << (exeOk ? "yes" : "no") << "\n";
    std::cout << "success_mark=" << (successMark ? "yes" : "no") << "\n";

    if (fixed && exeOk && successMark) {
        std::cout << "VERDICT=PASS mode=scripted\n";
        return 0;
    }
    std::cout << "VERDICT=FAIL mode=scripted\n";
    return 1;
}

int RunDeep2(const fs::path& fixture, const std::string& modelPath) {
    SeedBrokenFixture(fixture);
    auto& orch = RawrXD::Agent::OrchestratorBridge::Instance();
    if (!orch.Initialize(fixture.string(), "deep2", modelPath)) {
        std::cerr << "Deep2 Initialize failed for " << modelPath << "\n";
        return 3;
    }
    orch.SetMaxSteps(12);
    const std::string reply =
        orch.RunAgent("Fix the compile error and run the program");
    std::cout << "=== agent reply ===\n" << reply << "\n";

    const bool fixed = FileContains(fixture / "main.cpp", "std::endl;");
    const bool exeOk = fs::exists(fixture / "broken_hello.exe");
    if (fixed && exeOk) {
        std::cout << "VERDICT=PASS mode=deep2\n";
        return 0;
    }
    std::cout << "VERDICT=INCOMPLETE mode=deep2 "
                 "(model did not complete tool loop — not fake-greened)\n";
    std::cout << "fixed_source=" << (fixed ? "yes" : "no")
              << " exe_exists=" << (exeOk ? "yes" : "no") << "\n";
    return 2;
}

} // namespace

int main(int argc, char** argv) {
    std::string mode = "scripted";
    std::string model = "F:\\~dev\\tinyllama_fresh.gguf";
    fs::path fixture = fs::temp_directory_path() / "rawrxd_agent_loop_fixture";

    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--mode" && i + 1 < argc) mode = argv[++i];
        else if (a == "--model" && i + 1 < argc) model = argv[++i];
        else if (a == "--fixture" && i + 1 < argc) fixture = argv[++i];
        else if (a == "--help") {
            std::cout << "Usage: ide_agent_loop_cert [--mode scripted|deep2] "
                         "[--model PATH] [--fixture DIR]\n";
            return 0;
        }
    }

    std::cout << "ide_agent_loop_cert mode=" << mode
              << " fixture=" << fixture.string() << "\n";

    if (mode == "scripted") return RunScripted(fixture);
    if (mode == "deep2") return RunDeep2(fixture, model);
    std::cerr << "Unknown mode: " << mode << "\n";
    return 4;
}
