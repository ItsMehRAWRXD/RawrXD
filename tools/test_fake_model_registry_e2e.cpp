// Deterministic no-GPU model-to-tool pipeline smoke.
// Uses production AgentToolRegistry and portable production reply parser.
// editFiles is TEST-ONLY, not the actual IDE/CLI editFiles implementation.
#include "rawr_agent.hpp"
#include "deep2/AgentToolRegistry.hpp"
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
using namespace RawrXD::Agentic;
namespace fs = std::filesystem;
static int failures = 0, checks = 0;
static void check(bool yes, const char* name) {
    ++checks;
    std::cout << (yes ? "PASS " : "FAIL ") << name << '\n';
    if (!yes) ++failures;
}
static std::string read(const fs::path& path) {
    std::ifstream f(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(f), {});
}
int main() {
    const auto unique = std::chrono::steady_clock::now().time_since_epoch().count();
    const fs::path root = fs::temp_directory_path() /
                          ("rawrxd_fake_model_" + std::to_string(unique));
    fs::create_directories(root);
    const auto fixture = root / "fixture.cpp";
    { std::ofstream f(fixture, std::ios::binary); f << "int before = 1;\n"; }
    const std::string initial = read(fixture);
    AgentToolRegistry registry;
    bool approved = false;
    int mutations = 0;
    registry.registerTool({"editFiles", {"edit_files"}, "TEST-ONLY fixture editor"},
        [&](const ToolRequest& req, ToolContext&) -> ToolResult {
            if (!approved) return {77, "", "mutation denied"};
            // This deterministic fake provider accepts exactly one known
            // fixture transaction. Never claim that it tests arbitrary JSON
            // parsing or the production editFiles implementation.
            const std::string expected =
                R"({"path":"fixture.cpp","old":"int before = 1;","new":"int after = 2;"})";
            if (req.stdin_text != expected)
                return {64, "", "unexpected fixture transaction"};
            const std::string original = read(fixture);
            const std::string oldText = "int before = 1;";
            const auto pos = original.find(oldText);
            if (pos == std::string::npos) return {66, "", "old text not found"};
            auto revised = original;
            revised.replace(pos, oldText.size(), "int after = 2;");
            { std::ofstream out(fixture, std::ios::binary | std::ios::trunc);
              if (!out) return {74, "", "write failed"};
              out << revised;
              if (!out) return {74, "", "write failed"; }
            ++mutations;
            return {0, "edit complete", ""};
        });
    registry.registerTool({"readFile", {"read_file"}, "TEST-ONLY fixture reader"},
        [&](const ToolRequest& req, ToolContext&) -> ToolResult {
            if (req.stdin_text != R"({"path":"fixture.cpp"})")
                return {64, "", "invalid fixture read"};
            return {0, read(fixture), ""};
        });
    rawrxd::agent::setKnownToolNames({"editFiles", "readFile"});
    const std::string fakeModelOutput =
        "<tool>editFiles</tool>\n<args>{\"path\":\"fixture.cpp\","
        "\"old\":\"int before = 1;\",\"new\":\"int after = 2;\"}</args>";
    const auto parsed = rawrxd::agent::parseModelReplyForTest(fakeModelOutput);
    check(parsed.isTool, "01_model_reply_parses_as_tool");
    check(parsed.tool == "editFiles", "02_model_tool_name_preserved");
    check(parsed.args == R"({"path":"fixture.cpp","old":"int before = 1;","new":"int after = 2;"})", "03_model_args_preserved_exactly");
    check(registry.contains(parsed.tool), "04_tool_registered");
    // Fail-closed parser probes: a malformed tool reply must not be
    // interpreted as a valid dispatchable tool call.
    const auto malformed = rawrxd::agent::parseModelReplyForTest(
        "<tool>editFiles</tool><args>{}</args>TRAILING");
    check(!malformed.isTool, "20_trailing_tool_text_rejected");
    const auto doubled = rawrxd::agent::parseModelReplyForTest(
        "<tool>editFiles</tool><args>{}</args><tool>readFile</tool><args>{}</args>");
    check(!doubled.isTool, "21_duplicate_tool_frames_rejected");
    ToolRequest req;
    req.surface = AgentToolSurface::AgentCore;
    req.tool_id = parsed.tool;
    req.stdin_text = parsed.args;
    req.working_directory = root;
    const auto denied = registry.invoke(req, {});
    check(denied.exit_code == 77, "05_mutation_denied_without_approval");
    check(read(fixture) == initial, "06_denial_preserves_disk_bytes");
    approved = true;
    // Negative controls: a test-only handler must not silently edit when
    // model arguments are wrong or contain an unexpected path.
    const std::string validPayload = req.stdin_text;
    req.stdin_text = R"({"path":"../outside.cpp","old":"int before = 1;","new":"int after = 2;"})";
    check(registry.invoke(req, {}).exit_code == 64,
          "16_traversal_payload_rejected");
    check(read(fixture) == initial, "17_traversal_preserves_disk");
    req.stdin_text = R"({"path":"fixture.cpp","old":"wrong","new":"int after = 2;"})";
    check(registry.invoke(req, {}).exit_code == 64,
          "18_wrong_old_text_rejected");
    check(read(fixture) == initial, "19_bad_payload_preserves_disk");
    req.stdin_text = validPayload;
    const auto edited = registry.invoke(req, {});
    check(edited.ok(), "07_approved_mutation_dispatch");
    check(mutations == 1, "08_one_edit_executed");
    check(read(fixture) == "int after = 2;\n", "09_exact_disk_readback");
    req.tool_id = "readFile";
    req.stdin_text = R"({"path":"fixture.cpp"})";
    const auto readback = registry.invoke(req, {});
    check(readback.ok(), "10_readback_tool_dispatch");
    check(readback.stdout_text == read(fixture), "11_tool_result_matches_disk");
    const std::string simulatedNextPrompt =
        "[TOOL EXIT_CODE=0 STATUS=SUCCESS]\n[STDOUT]\n" + readback.stdout_text;
    check(simulatedNextPrompt ==
          "[TOOL EXIT_CODE=0 STATUS=SUCCESS]\n[STDOUT]\nint after = 2;\n",
          "12_mock_prompt_matches_exact_expected_bytes");
    const auto fakeFinal = rawrxd::agent::parseModelReplyForTest("Done.");
    check(fakeFinal.isFinal, "13_fake_model_final_parses");
    req.tool_id = "not_registered";
    check(registry.invoke(req, {}).exit_code == 127, "14_unknown_tool_rejected");
    req.tool_id = "readFile";
    ToolContext cancelled;
    cancelled.cancelled = [] { return true; };
    check(registry.invoke(req, cancelled).exit_code == 130,
          "15_cancelled_tool_rejected");
    fs::remove_all(root);
    std::cout << "MOCK_E2E_CHECKS=" << checks << " FAILURES=" << failures << '\n';
    return failures ? 1 : 0;
}
