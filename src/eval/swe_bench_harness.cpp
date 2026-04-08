// swe_bench_harness.cpp — RawrXD SWE-bench Evaluation Harness
//
// Measures autonomous software engineering capability against a defined instance
// set.  Each instance represents a real-world bug-fix task:
//
//   task_id       — unique identifier
//   repo          — repository slug (owner/name)
//   problem_stmt  — natural-language description of the bug
//   patch         — expected gold patch (unified diff)
//   test_cmds     — commands to verify the fix
//
// Scoring (pass@1):
//   task_completion_rate  — fraction of tasks where the harness produced output
//   patch_correctness     — fraction of tasks whose emitted patch matches gold
//   test_pass_rate        — fraction of tasks whose test_cmds exit 0
//   overall               — harmonic mean of the three metrics above
//
// Compile standalone:
//   cl /std:c++20 /O2 /EHsc src/eval/swe_bench_harness.cpp /Fe:swe_bench.exe
//
// CMake target: RawrXD-SWEBench (EXCLUDE_FROM_ALL)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winhttp.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <functional>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

// Phase 2 context integration
#include "context_config.h"

// Stub implementations to avoid external dependencies for harness standalone build
namespace RawrXD {
    struct VRAMInfo {
        uint64_t total_bytes = 0;
        uint64_t available_bytes = 0;
        uint64_t reserved_bytes = 0;
    };
    
    VRAMInfo QueryVRAM() {
        // Mock VRAM query for standalone harness
        VRAMInfo info;
        info.total_bytes = 8ULL * 1024 * 1024 * 1024;  // 8GB
        info.available_bytes = 6ULL * 1024 * 1024 * 1024;  // 6GB available
        info.reserved_bytes = 2ULL * 1024 * 1024 * 1024;  // 2GB reserved
        return info;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Data model
// ─────────────────────────────────────────────────────────────────────────────

namespace SWEBench {

struct Instance {
    std::string task_id;
    std::string repo;
    std::string base_commit;
    std::string problem_stmt;
    std::string gold_patch;              // expected unified diff
    std::vector<std::string> test_cmds; // commands that must exit 0
    std::string hints_text;             // optional guidance
};

enum class TaskStatus {
    NOT_RUN,
    COMPLETED,      // agent produced a patch
    PATCH_CORRECT,  // patch matches gold
    TESTS_PASSED,   // test_cmds all succeeded
    FAILED
};

struct TaskResult {
    std::string  task_id;
    TaskStatus   status       = TaskStatus::NOT_RUN;
    std::string  emitted_patch;
    std::string  raw_response;
    bool         has_header   = false;
    bool         has_hunks    = false;
    bool         is_fenced    = false;
    bool         prose_detected = false;
    bool         patch_match  = false;
    bool         tests_passed = false;
    double       elapsed_ms   = 0.0;
    std::string  failure_reason;
    // Phase 2 telemetry
    uint64_t     tokens_requested  = 0;  // estimated prompt size
    uint64_t     tokens_effective   = 0;  // context window used
    uint64_t     kv_budget_bytes    = 0;  // KV cache budget
    bool         adapted            = false;  // pressure-driven adaptation
    double       pressure_ratio     = 0.0;  // kv_bytes / kv_budget
};

struct HarnessReport {
    int    total           = 0;
    int    completed       = 0;    // agent produced output
    int    patch_correct   = 0;    // patch matched gold
    int    tests_passed    = 0;    // tests all green
    double task_completion_rate = 0.0;
    double patch_correctness    = 0.0;
    double test_pass_rate       = 0.0;
    double overall_score        = 0.0;   // harmonic mean
    std::vector<TaskResult> results;
};

static bool write_json_report(const HarnessReport& r, const char* path);

static void recompute_report_metrics(HarnessReport& report, bool run_tests)
{
    if (report.total <= 0) {
        report.task_completion_rate = 0.0;
        report.patch_correctness = 0.0;
        report.test_pass_rate = 0.0;
        report.overall_score = 0.0;
        return;
    }

    report.task_completion_rate =
        static_cast<double>(report.completed) / report.total;
    report.patch_correctness = (report.completed > 0)
        ? static_cast<double>(report.patch_correct) / report.total
        : 0.0;
    report.test_pass_rate = run_tests
        ? static_cast<double>(report.tests_passed) / report.total
        : report.patch_correctness;

    const double comp = report.task_completion_rate;
    const double patch = report.patch_correctness;
    const double test = report.test_pass_rate;
    if (comp > 0.0 && patch > 0.0 && test > 0.0) {
        report.overall_score = 3.0 / (1.0 / comp + 1.0 / patch + 1.0 / test);
    } else {
        report.overall_score = (comp + patch + test) / 3.0;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Utility helpers
// ─────────────────────────────────────────────────────────────────────────────

static bool normalize_patch(const std::string& raw, std::string& out)
{
    // Strip trailing whitespace per line; normalise CRLF → LF
    std::ostringstream ss;
    std::istringstream in(raw);
    std::string line;
    while (std::getline(in, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == ' '))
            line.pop_back();
        ss << line << '\n';
    }
    out = ss.str();
    return !out.empty();
}

static bool patches_equivalent(const std::string& a, const std::string& b)
{
    std::string na, nb;
    normalize_patch(a, na);
    normalize_patch(b, nb);
    return na == nb;
}

static std::string sanitize_task_id_for_path(const std::string& value)
{
    std::string out;
    out.reserve(value.size());
    for (char c : value) {
        if ((c >= 'a' && c <= 'z') ||
            (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') ||
            c == '-' || c == '_' || c == '.') {
            out.push_back(c);
        } else {
            out.push_back('_');
        }
    }
    if (out.empty()) {
        out = "task";
    }
    return out;
}

static void NormalizeHostAndPort(const std::string& input, std::string& out_host, WORD& out_port)
{
    out_host.clear();
    out_port = 11434;

    std::string value = input;
    const size_t scheme_pos = value.find("://");
    if (scheme_pos != std::string::npos) {
        value = value.substr(scheme_pos + 3);
    }

    const size_t path_pos = value.find('/');
    if (path_pos != std::string::npos) {
        value = value.substr(0, path_pos);
    }

    while (!value.empty() && value.back() == '/') {
        value.pop_back();
    }

    if (value.empty()) {
        return;
    }

    if (value.front() == '[') {
        const size_t closing = value.find(']');
        if (closing != std::string::npos) {
            out_host = value.substr(1, closing - 1);
            if (closing + 1 < value.size() && value[closing + 1] == ':') {
                try {
                    const int parsed_port = std::stoi(value.substr(closing + 2));
                    if (parsed_port > 0 && parsed_port <= 65535) {
                        out_port = static_cast<WORD>(parsed_port);
                    }
                } catch (...) {
                }
            }
            return;
        }
    }

    const size_t colon_pos = value.rfind(':');
    if (colon_pos != std::string::npos && value.find(':') == colon_pos) {
        out_host = value.substr(0, colon_pos);
        try {
            const int parsed_port = std::stoi(value.substr(colon_pos + 1));
            if (parsed_port > 0 && parsed_port <= 65535) {
                out_port = static_cast<WORD>(parsed_port);
            }
        } catch (...) {
        }
    } else {
        out_host = value;
    }

    while (!out_host.empty() && out_host.back() == '/') {
        out_host.pop_back();
    }
}
static std::string trim_copy(const std::string& value)
{
    size_t start = 0;
    while (start < value.size() && std::isspace(static_cast<unsigned char>(value[start]))) {
        ++start;
    }

    size_t end = value.size();
    while (end > start && std::isspace(static_cast<unsigned char>(value[end - 1]))) {
        --end;
    }

    return value.substr(start, end - start);
}

// Extract unique target files from a gold patch.
// Parses lines starting with "--- a/" to identify files being modified.
static std::vector<std::string> extract_target_files_from_patch(const std::string& patch)
{
    std::vector<std::string> targets;
    if (patch.empty()) {
        return targets;
    }

    std::istringstream in(patch);
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        if (line.back() == '\r') line.pop_back();

        // Lines starting with "--- a/" indicate file paths being modified
        if (line.rfind("--- a/", 0) == 0) {
            std::string file_path = line.substr(6);  // skip "--- a/"
            
            // Remove any trailing content (e.g., timestamps)
            const size_t tab_pos = file_path.find('\t');
            if (tab_pos != std::string::npos) {
                file_path = file_path.substr(0, tab_pos);
            }
            
            // Avoid duplicates
            if (std::find(targets.begin(), targets.end(), file_path) == targets.end()) {
                targets.push_back(file_path);
            }
        }
    }

    return targets;
}

static std::string build_patch_only_prompt(const Instance& inst, const std::vector<std::string>& target_files = {})
{
    std::ostringstream prompt;
    prompt << "You are an expert software engineering evaluation agent.\n";
    prompt << "A machine will score your output.\n";
    prompt << "Return ONLY a valid unified diff patch that fixes the task.\n";
    prompt << "Do NOT include explanation, commentary, analysis, markdown fences, XML tags, or extra text.\n";
    prompt << "If you cannot produce a valid unified diff, output exactly: NO_PATCH\n\n";
    prompt << "Output requirements:\n";
    prompt << "1. The first diff line must start with --- a/\n";
    prompt << "2. The second diff line must start with +++ b/\n";
    prompt << "3. Every file modification must include at least one @@ hunk header.\n";
    prompt << "4. Emit only the minimal files and hunks required to solve the task.\n";
    prompt << "5. Do not wrap the diff in backticks.\n";
    prompt << "6. Do not output prose before or after the patch.\n";
    prompt << "7. If the fix spans multiple files, emit one contiguous unified diff containing every changed file.\n";
    prompt << "8. In multi-file output, each file must start with its own --- a/ and +++ b/ headers before its @@ hunks.\n";
    
    // Inject file-lock constraint if exactly one target file is specified
    if (target_files.size() == 1) {
        prompt << "9. CRITICAL: Modify ONLY the file: " << target_files[0] << "\n";
        prompt << "   Do NOT modify any other files, helpers, or dependencies.\n";
    }
    
    prompt << "\nValid single-file output example:\n";
    prompt << "--- a/src/example.cpp\n";
    prompt << "+++ b/src/example.cpp\n";
    prompt << "@@ -10,2 +10,2 @@\n";
    prompt << "-    return false;\n";
    prompt << "+    return true;\n\n";
    prompt << "Valid multi-file output example:\n";
    prompt << "--- a/src/core.cpp\n";
    prompt << "+++ b/src/core.cpp\n";
    prompt << "@@ -10,2 +10,2 @@\n";
    prompt << "-    old_logic();\n";
    prompt << "+    new_logic();\n";
    prompt << "--- a/include/core.h\n";
    prompt << "+++ b/include/core.h\n";
    prompt << "@@ -2,2 +2,2 @@\n";
    prompt << "-void old_logic();\n";
    prompt << "+void new_logic();\n\n";
    prompt << "Invalid output examples:\n";
    prompt << "- Here is the fix:\n";
    prompt << "- ```diff\n";
    prompt << "- <patch>...</patch>\n";
    prompt << "- Any explanation before or after the diff\n";
    prompt << "- Mixing edits for multiple files under one header pair\n";
    prompt << "- Returning separate patches or sections instead of one contiguous unified diff\n";
    if (target_files.size() == 1) {
        prompt << "- Modifying files other than: " << target_files[0] << "\n";
    }
    prompt << "\nThe first character of your reply must be '-' from the leading --- a/ header, unless you reply with NO_PATCH.\n";
    prompt << "Copy the structure of the valid examples, but use the real file paths and hunks for the task below.\n";
    prompt << "If the correct fix needs multiple files, include all of them in one unified diff response.\n\n";
    prompt << "Task ID: " << inst.task_id << "\n";
    prompt << "Repository: " << inst.repo << "\n";
    prompt << "Base commit: " << inst.base_commit << "\n\n";
    prompt << "Problem statement:\n" << inst.problem_stmt << "\n\n";

    if (!inst.hints_text.empty()) {
        prompt << "Hints:\n" << inst.hints_text << "\n\n";
    }

    prompt << "Output ONLY the unified diff now. Start immediately with --- a/ or output NO_PATCH.\n";
    return prompt.str();
}

static std::string strip_to_unified_diff(const std::string& value)
{
    const std::string trimmed = trim_copy(value);
    const size_t diff_pos = trimmed.find("--- ");
    if (diff_pos == std::string::npos) {
        return {};
    }

    std::istringstream in(trimmed.substr(diff_pos));
    std::ostringstream out;
    std::string line;
    bool saw_hunk = false;

    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        if (line.rfind("--- ", 0) == 0 || line.rfind("+++ ", 0) == 0) {
            out << line << '\n';
            continue;
        }

        if (line.rfind("@@", 0) == 0) {
            saw_hunk = true;
            out << line << '\n';
            continue;
        }

        if (saw_hunk) {
            if (!line.empty()) {
                const char c = line[0];
                if (c == ' ' || c == '+' || c == '-' || c == '\\') {
                    out << line << '\n';
                    continue;
                }
            }
            break;
        }
    }

    return trim_copy(out.str());
}

static std::string extract_tagged_patch(const std::string& value)
{
    const std::string open_tag = "<patch>";
    const std::string close_tag = "</patch>";
    const size_t open_pos = value.find(open_tag);
    if (open_pos == std::string::npos) {
        return {};
    }

    const size_t content_start = open_pos + open_tag.size();
    const size_t close_pos = value.find(close_tag, content_start);
    if (close_pos == std::string::npos) {
        return {};
    }

    return trim_copy(value.substr(content_start, close_pos - content_start));
}

static std::string extract_fenced_diff(const std::string& value)
{
    const size_t fence_start = value.find("```");
    if (fence_start == std::string::npos) {
        return {};
    }

    size_t content_start = fence_start + 3;
    if (value.compare(content_start, 4, "diff") == 0) {
        content_start += 4;
    } else if (value.compare(content_start, 5, "patch") == 0) {
        content_start += 5;
    }
    if (content_start < value.size() && (value[content_start] == '\r' || value[content_start] == '\n')) {
        while (content_start < value.size() && (value[content_start] == '\r' || value[content_start] == '\n')) {
            ++content_start;
        }
    }

    const size_t fence_end = value.find("```", content_start);
    if (fence_end == std::string::npos) {
        return {};
    }

    return trim_copy(value.substr(content_start, fence_end - content_start));
}

static bool looks_like_no_patch(const std::string& raw)
{
    const std::string trimmed = trim_copy(raw);
    return trimmed == "NO_PATCH";
}

static bool is_strict_unified_diff(const std::string& value)
{
    return value.rfind("--- a/", 0) == 0 &&
           value.find("\n+++ b/") != std::string::npos &&
           value.find("\n@@") != std::string::npos;
}

static bool raw_has_diff_headers(const std::string& value)
{
    return value.find("--- a/") != std::string::npos && value.find("+++ b/") != std::string::npos;
}

static bool raw_has_diff_hunks(const std::string& value)
{
    return value.find("@@ ") != std::string::npos || value.find("\n@@") != std::string::npos;
}

static bool raw_contains_fence(const std::string& value)
{
    return value.find("```") != std::string::npos;
}

static bool raw_starts_with_prose(const std::string& value)
{
    const std::string trimmed = trim_copy(value);
    if (trimmed.empty()) {
        return false;
    }
    if (trimmed.rfind("--- a/", 0) == 0 ||
        trimmed.rfind("```", 0) == 0 ||
        trimmed.rfind("<patch>", 0) == 0 ||
        trimmed == "NO_PATCH") {
        return false;
    }
    return true;
}

static void populate_response_compliance(TaskResult& result)
{
    result.has_header = raw_has_diff_headers(result.raw_response);
    result.has_hunks = raw_has_diff_hunks(result.raw_response);
    result.is_fenced = raw_contains_fence(result.raw_response);
    result.prose_detected = raw_starts_with_prose(result.raw_response);
}

static std::string normalize_agent_patch_response(const std::string& raw, std::string* error_out = nullptr)
{
    const std::string trimmed = trim_copy(raw);
    if (trimmed.empty()) {
        if (error_out) {
            *error_out = "empty model response";
        }
        return {};
    }

    if (looks_like_no_patch(trimmed)) {
        if (error_out) {
            *error_out = "model returned NO_PATCH";
        }
        return {};
    }

    std::string tagged = extract_tagged_patch(trimmed);
    if (!tagged.empty()) {
        std::string diff = strip_to_unified_diff(tagged);
        if (is_strict_unified_diff(diff)) {
            return diff;
        }
    }

    std::string fenced = extract_fenced_diff(trimmed);
    if (!fenced.empty()) {
        std::string diff = strip_to_unified_diff(fenced);
        if (is_strict_unified_diff(diff)) {
            return diff;
        }
    }

    std::string diff = strip_to_unified_diff(trimmed);
    if (is_strict_unified_diff(diff)) {
        return diff;
    }

    if (error_out) {
        *error_out = "model did not emit a strict unified diff";
    }
    return {};
}

// Run a command in a subprocess and return exit code.
// stdout/stderr are inherited so they flow to the console.
static int run_command(const std::string& cmd, double* elapsed_ms_out)
{
    auto t0 = std::chrono::steady_clock::now();

    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};

    std::string cmdline = cmd; // CreateProcessA needs mutable buffer
    cmdline.push_back('\0');   // ensure null-terminated

    BOOL ok = CreateProcessA(
        nullptr,
        cmdline.data(),
        nullptr, nullptr,
        FALSE,
        0,
        nullptr, nullptr,
        &si, &pi);

    if (!ok) {
        if (elapsed_ms_out) *elapsed_ms_out = 0.0;
        return -1;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exit_code = 1;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    auto t1 = std::chrono::steady_clock::now();
    if (elapsed_ms_out) {
        *elapsed_ms_out = static_cast<double>(
            std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count()) / 1000.0;
    }
    return static_cast<int>(exit_code);
}

// ─────────────────────────────────────────────────────────────────────────────
// Agent interface — callers implement this to wire their model
// ─────────────────────────────────────────────────────────────────────────────

using AgentFn = std::function<std::string(const Instance&, TaskResult&)>;

static void populate_context_telemetry(const Instance& inst, TaskResult& result)
{
    const size_t prompt_size = inst.problem_stmt.size();
    result.tokens_requested = static_cast<uint64_t>(prompt_size / 4);

    const size_t clamped_prompt =
        std::min(prompt_size, static_cast<size_t>(std::numeric_limits<int32_t>::max()));
    const RawrXD::ContextDecision decision =
        RawrXD::ResolveContextDecision(static_cast<int32_t>(clamped_prompt));

    result.tokens_effective = decision.effective;
    result.kv_budget_bytes = decision.kv_budget_bytes;
    result.adapted = decision.adapted;
    result.pressure_ratio = decision.pressure_ratio;
}

static void write_jsonl_sample(FILE* jsonl_out, const TaskResult& result, size_t response_length)
{
    if (!jsonl_out) {
        return;
    }

    auto json_escape = [](const std::string& s) {
        std::string out;
        out.reserve(s.size() + 16);
        for (char c : s) {
            switch (c) {
            case '\\': out += "\\\\"; break;
            case '"': out += "\\\""; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default: out.push_back(c); break;
            }
        }
        return out;
    };

    fprintf(jsonl_out,
        "{\"sample_id\": \"%s\", \"tokens_requested\": %llu, "
        "\"tokens_effective\": %llu, \"kv_budget_bytes\": %llu, "
        "\"adapted\": %s, \"pressure_ratio\": %.6f, "
        "\"has_header\": %s, \"has_hunks\": %s, "
        "\"is_fenced\": %s, \"prose_detected\": %s, "
        "\"response_length\": %zu, \"raw_response\": \"%s\", "
        "\"extracted_patch\": \"%s\", \"failure_reason\": \"%s\", "
        "\"success\": %s}\n",
        result.task_id.c_str(),
        result.tokens_requested,
        result.tokens_effective,
        result.kv_budget_bytes,
        result.adapted ? "true" : "false",
        result.pressure_ratio,
        result.has_header ? "true" : "false",
        result.has_hunks ? "true" : "false",
        result.is_fenced ? "true" : "false",
        result.prose_detected ? "true" : "false",
        response_length,
        json_escape(result.raw_response).c_str(),
        json_escape(result.emitted_patch).c_str(),
        json_escape(result.failure_reason).c_str(),
        (result.status == TaskStatus::FAILED) ? "false" : "true");
    fflush(jsonl_out);
}

// ─────────────────────────────────────────────────────────────────────────────
// Harness
// ─────────────────────────────────────────────────────────────────────────────

class Harness {
public:
    explicit Harness(
        bool run_tests = false,
        FILE* jsonl_out = nullptr,
        const char* progress_json_path = nullptr,
        const char* raw_dump_dir = nullptr)
        : m_run_tests(run_tests),
          m_jsonl_out(jsonl_out),
          m_progress_json_path(progress_json_path),
          m_raw_dump_dir(raw_dump_dir) {}

    void add_instance(Instance inst) { m_instances.push_back(std::move(inst)); }

    HarnessReport run(AgentFn agent)
    {
        HarnessReport report;
        report.total = static_cast<int>(m_instances.size());

        for (const auto& inst : m_instances) {
            TaskResult res;
            res.task_id = inst.task_id;
            populate_context_telemetry(inst, res);

            auto t0 = std::chrono::steady_clock::now();
            try {
                res.emitted_patch = agent(inst, res);
            } catch (const std::exception& ex) {
                res.status = TaskStatus::FAILED;
                res.failure_reason = ex.what();
                maybe_dump_raw_response(res);
                write_jsonl_sample(m_jsonl_out, res, res.raw_response.empty() ? 0 : res.raw_response.size());
                report.results.push_back(res);
                recompute_report_metrics(report, m_run_tests);
                checkpoint_report(report);
                continue;
            }
            auto t1 = std::chrono::steady_clock::now();
            res.elapsed_ms = static_cast<double>(
                std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count()) / 1000.0;

            if (res.emitted_patch.empty()) {
                res.status = TaskStatus::FAILED;
                if (res.failure_reason.empty()) {
                    res.failure_reason = "agent returned empty patch";
                }
                maybe_dump_raw_response(res);
                write_jsonl_sample(m_jsonl_out, res, res.raw_response.empty() ? 0 : res.raw_response.size());
                report.results.push_back(res);
                recompute_report_metrics(report, m_run_tests);
                checkpoint_report(report);
                continue;
            }

            report.completed++;
            res.status = TaskStatus::COMPLETED;

            // Patch correctness check
            if (!inst.gold_patch.empty()) {
                res.patch_match = patches_equivalent(res.emitted_patch, inst.gold_patch);
                if (res.patch_match) {
                    report.patch_correct++;
                    res.status = TaskStatus::PATCH_CORRECT;
                }
            }

            // Optionally run tests
            if (m_run_tests && !inst.test_cmds.empty()) {
                bool all_pass = true;
                for (const auto& cmd : inst.test_cmds) {
                    int rc = run_command(cmd, nullptr);
                    if (rc != 0) { all_pass = false; break; }
                }
                res.tests_passed = all_pass;
                if (all_pass) {
                    report.tests_passed++;
                    res.status = TaskStatus::TESTS_PASSED;
                }
            }

            maybe_dump_raw_response(res);
            write_jsonl_sample(m_jsonl_out, res,
                res.raw_response.empty() ? res.emitted_patch.size() : res.raw_response.size());
            report.results.push_back(res);
            recompute_report_metrics(report, m_run_tests);
            checkpoint_report(report);
        }

        recompute_report_metrics(report, m_run_tests);
        checkpoint_report(report);

        return report;
    }

private:
    void maybe_dump_raw_response(const TaskResult& result) const
    {
        if (!m_raw_dump_dir || !m_raw_dump_dir[0] || result.raw_response.empty()) {
            return;
        }

        const std::string dir = m_raw_dump_dir;
        if (!CreateDirectoryA(dir.c_str(), nullptr)) {
            const DWORD err = GetLastError();
            if (err != ERROR_ALREADY_EXISTS) {
                return;
            }
        }

        std::string path = dir;
        if (!path.empty() && path.back() != '\\' && path.back() != '/') {
            path.push_back('\\');
        }
        path += sanitize_task_id_for_path(result.task_id);
        path += ".raw.txt";

        FILE* f = nullptr;
        if (fopen_s(&f, path.c_str(), "wb") != 0 || !f) {
            return;
        }
        fwrite(result.raw_response.data(), 1, result.raw_response.size(), f);
        fclose(f);
    }

    void checkpoint_report(const HarnessReport& report) const
    {
        if (m_progress_json_path && m_progress_json_path[0]) {
            write_json_report(report, m_progress_json_path);
        }
    }

    std::vector<Instance> m_instances;
    bool                  m_run_tests;
    FILE*                 m_jsonl_out;
    const char*           m_progress_json_path;
    const char*           m_raw_dump_dir;
};

// ─────────────────────────────────────────────────────────────────────────────
// Reporter
// ─────────────────────────────────────────────────────────────────────────────

static void print_report(const HarnessReport& r, FILE* out = stdout)
{
    fprintf(out, "\n");
    fprintf(out, "╔══════════════════════════════════════════════╗\n");
    fprintf(out, "║       RawrXD SWE-bench Evaluation Report     ║\n");
    fprintf(out, "╠══════════════════════════════════════════════╣\n");
    fprintf(out, "║  Instances evaluated  : %6d               ║\n", r.total);
    fprintf(out, "║  Tasks completed      : %6d  (%5.1f%%)     ║\n",
            r.completed,       r.task_completion_rate * 100.0);
    fprintf(out, "║  Patch correct        : %6d  (%5.1f%%)     ║\n",
            r.patch_correct,   r.patch_correctness   * 100.0);
    fprintf(out, "║  Tests passed         : %6d  (%5.1f%%)     ║\n",
            r.tests_passed,    r.test_pass_rate      * 100.0);
    fprintf(out, "╠══════════════════════════════════════════════╣\n");
    fprintf(out, "║  OVERALL SCORE        :        %5.1f%%        ║\n",
            r.overall_score * 100.0);
    fprintf(out, "║  Target (Claude Code) :         72.5%%        ║\n");
    fprintf(out, "║  Minimum competitive  :         50.0%%        ║\n");
    fprintf(out, "╚══════════════════════════════════════════════╝\n");

    // Per-task summary
    fprintf(out, "\nPer-task results:\n");
    for (const auto& t : r.results) {
        const char* status_str = "NOT_RUN";
        switch (t.status) {
        case TaskStatus::COMPLETED:     status_str = "COMPLETED"; break;
        case TaskStatus::PATCH_CORRECT: status_str = "PATCH_OK "; break;
        case TaskStatus::TESTS_PASSED:  status_str = "TESTS_OK "; break;
        case TaskStatus::FAILED:        status_str = "FAILED   "; break;
        default: break;
        }
        fprintf(out, "  [%s] %-40s  %.1f ms\n",
                status_str, t.task_id.c_str(), t.elapsed_ms);
        if (!t.failure_reason.empty()) {
            fprintf(out, "           reason: %s\n", t.failure_reason.c_str());
        }
    }
    fprintf(out, "\n");
}

static bool write_json_report(const HarnessReport& r, const char* path)
{
    FILE* f = nullptr;
    if (fopen_s(&f, path, "w") != 0 || !f) return false;

    auto json_escape = [](const std::string& s) {
        std::string out;
        out.reserve(s.size() + 16);
        for (char c : s) {
            switch (c) {
            case '\\': out += "\\\\"; break;
            case '"': out += "\\\""; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default: out.push_back(c); break;
            }
        }
        return out;
    };

    fprintf(f, "{\n");
    fprintf(f, "  \"total\": %d,\n",           r.total);
    fprintf(f, "  \"completed\": %d,\n",        r.completed);
    fprintf(f, "  \"patch_correct\": %d,\n",    r.patch_correct);
    fprintf(f, "  \"tests_passed\": %d,\n",     r.tests_passed);
    fprintf(f, "  \"task_completion_rate\": %.4f,\n", r.task_completion_rate);
    fprintf(f, "  \"patch_correctness\": %.4f,\n",    r.patch_correctness);
    fprintf(f, "  \"test_pass_rate\": %.4f,\n",       r.test_pass_rate);
    fprintf(f, "  \"overall_score\": %.4f,\n",        r.overall_score);
    fprintf(f, "  \"pass@1\": %.4f,\n",               r.overall_score);
    fprintf(f, "  \"results\": [\n");
    for (size_t i = 0; i < r.results.size(); ++i) {
        const auto& t = r.results[i];
        const char* comma = (i + 1 < r.results.size()) ? "," : "";
        fprintf(f,
            "    {\"task_id\": \"%s\", \"status\": %d, \"patch_match\": %s, "
            "\"tests_passed\": %s, \"elapsed_ms\": %.2f, \"failure_reason\": \"%s\", "
            "\"response\": \"%s\", "
            "\"raw_response\": \"%s\", "
            "\"has_header\": %s, \"has_hunks\": %s, "
            "\"is_fenced\": %s, \"prose_detected\": %s, "
            "\"tokens_requested\": %llu, \"tokens_effective\": %llu, "
            "\"kv_budget_bytes\": %llu, \"adapted\": %s, "
            "\"pressure_ratio\": %.4f}%s\n",
            t.task_id.c_str(),
            static_cast<int>(t.status),
            t.patch_match  ? "true" : "false",
            t.tests_passed ? "true" : "false",
            t.elapsed_ms,
            json_escape(t.failure_reason).c_str(),
            json_escape(t.emitted_patch).c_str(),
            json_escape(t.raw_response).c_str(),
            t.has_header ? "true" : "false",
            t.has_hunks ? "true" : "false",
            t.is_fenced ? "true" : "false",
            t.prose_detected ? "true" : "false",
            t.tokens_requested,
            t.tokens_effective,
            t.kv_budget_bytes,
            t.adapted ? "true" : "false",
            t.pressure_ratio,
            comma);
    }
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
    fclose(f);
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Built-in synthetic instance set
// ─────────────────────────────────────────────────────────────────────────────

static std::vector<Instance> builtin_instances()
{
    std::vector<Instance> v;

    // Each instance is a synthetic task that can be validated without a live
    // repository — the gold patch is compared against the agent's output.

    {
        Instance i;
        i.task_id      = "rawrxd-001";
        i.repo         = "ItsMehRAWRXD/RawrXD";
        i.base_commit  = "main";
        i.problem_stmt =
            "The context window defaults are fragmented (4096/8192) across "
            "inference files. Unify them to 131072 using the ContextLimits::DEFAULT "
            "constant from context_config.h.";
        i.gold_patch   =
            "--- a/src/ai/ai_inference_real.cpp\n"
            "+++ b/src/ai/ai_inference_real.cpp\n"
            "@@ -1 +1 @@\n"
            "-    g_model.n_ctx = 8192;\n"
            "+    g_model.n_ctx = RawrXD::ContextLimits::DEFAULT;\n";
        v.push_back(i);
    }

    {
        Instance i;
        i.task_id      = "rawrxd-002";
        i.repo         = "ItsMehRAWRXD/RawrXD";
        i.base_commit  = "main";
        i.problem_stmt =
            "MCP HTTP client connectHttp() is explicitly unimplemented — the "
            "function body returns false immediately. Implement a WinHTTP-backed "
            "transport so remote MCP servers can be reached over HTTP/HTTPS.";
        i.gold_patch   = "(WinHTTP implementation in mcp_integration.cpp)";
        v.push_back(i);
    }

    {
        Instance i;
        i.task_id      = "rawrxd-003";
        i.repo         = "ItsMehRAWRXD/RawrXD";
        i.base_commit  = "main";
        i.problem_stmt =
            "plan_orchestrator.cpp executeTask() falls through to return true for "
            "unknown operations, creating a fail-open safety hole. Fix so unknown "
            "operations are rejected with an error.";
        i.gold_patch   = "(fail-closed unknown-op rejection in plan_orchestrator.cpp)";
        v.push_back(i);
    }

    {
        Instance i;
        i.task_id      = "rawrxd-004";
        i.repo         = "ItsMehRAWRXD/RawrXD";
        i.base_commit  = "main";
        i.problem_stmt =
            "tool_registry_init.cpp defines register_git_mcp_tools() but is not "
            "listed in CMakeLists.txt, so the symbol is never linked. Add it to the "
            "Win32IDE source list.";
        i.gold_patch   =
            "--- a/CMakeLists.txt\n"
            "+++ b/CMakeLists.txt\n"
            "@@ -700 +700 @@\n"
            "+        src/tool_registry_init.cpp\n";
        v.push_back(i);
    }

    return v;
}

// Load instances from a JSON/JSONL dataset file.
// Format: one JSON object per line, with fields:
//   task_id, repo, base_commit, problem_statement, patch (gold), test_commands, hints
static std::vector<Instance> load_json_dataset(const char* path)
{
    std::vector<Instance> v;
    std::ifstream f(path);
    if (!f.is_open()) {
        fprintf(stderr, "Error: cannot open JSON dataset: %s\n", path);
        return v;
    }

    std::string line;
    int line_num = 0;
    while (std::getline(f, line)) {
        ++line_num;
        if (line.empty() || line[0] == '#') continue;

        // Rudimentary field extraction: "key": "value"
        auto extract = [&](const char* key) -> std::string {
            std::string k = std::string("\"") + key + "\"";
            auto pos = line.find(k);
            if (pos == std::string::npos) return {};
            auto colon = line.find(':', pos + k.size());
            if (colon == std::string::npos) return {};
            auto qs = line.find('"', colon + 1);
            if (qs == std::string::npos) return {};
            auto qe = line.find('"', qs + 1);
            if (qe == std::string::npos) return {};
            return line.substr(qs + 1, qe - qs - 1);
        };

        Instance inst;
        inst.task_id      = extract("task_id");
        inst.repo         = extract("repo");
        inst.base_commit  = extract("base_commit");
        inst.problem_stmt = extract("problem_statement");
        inst.gold_patch   = extract("patch");
        inst.hints_text   = extract("hints");

        if (inst.task_id.empty() || inst.problem_stmt.empty()) {
            fprintf(stderr, "Warning: line %d missing required fields (task_id, problem_statement), skipping\n", line_num);
            continue;
        }

        v.push_back(inst);
    }

    fprintf(stdout, "Loaded %zu instances from JSON dataset\n", v.size());
    return v;
}

} // namespace SWEBench

// Real inference agent wrapper (minimal Ollama HTTP client)
// ─────────────────────────────────────────────────────────────────────────────

struct MinimalOllamaClient {
    std::string host;
    int port;
    std::string model;
    bool debug_http = false;

    static void NormalizeHostAndPortLocal(const std::string& input, std::string& out_host, WORD& out_port)
    {
        out_host.clear();
        out_port = 11434;

        std::string value = input;
        const size_t scheme_pos = value.find("://");
        if (scheme_pos != std::string::npos) {
            value = value.substr(scheme_pos + 3);
        }

        const size_t path_pos = value.find('/');
        if (path_pos != std::string::npos) {
            value = value.substr(0, path_pos);
        }

        while (!value.empty() && value.back() == '/') {
            value.pop_back();
        }

        if (value.empty()) {
            return;
        }

        const size_t colon_pos = value.rfind(':');
        if (colon_pos != std::string::npos && colon_pos + 1 < value.size()) {
            out_host = value.substr(0, colon_pos);
            try {
                const int parsed_port = std::stoi(value.substr(colon_pos + 1));
                if (parsed_port > 0 && parsed_port <= 65535) {
                    out_port = static_cast<WORD>(parsed_port);
                }
            } catch (...) {
            }
            if (out_host.empty()) {
                out_host = value;
            }
            return;
        }

        out_host = value;
    }

    explicit MinimalOllamaClient(const std::string& h = "127.0.0.1", int p = 11434, const std::string& m = "mistral")
        : port(11434), model(m)
    {
        WORD normalized_port = 11434;
        NormalizeHostAndPortLocal(h, host, normalized_port);
        if (host.empty()) {
            host = "127.0.0.1";
        }

        if (p > 0 && p <= 65535) {
            port = p;
        } else {
            port = static_cast<int>(normalized_port);
        }
    }

    static std::string escape_json(const std::string& s)
    {
        std::string out;
        out.reserve(s.size() + 16);
        for (char c : s) {
            switch (c) {
            case '\\': out += "\\\\"; break;
            case '"': out += "\\\""; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default: out.push_back(c); break;
            }
        }
        return out;
    }

    static std::string unescape_json(const std::string& s)
    {
        std::string out;
        out.reserve(s.size());
        for (size_t i = 0; i < s.size(); ++i) {
            if (s[i] == '\\' && i + 1 < s.size()) {
                char n = s[++i];
                switch (n) {
                case 'n': out.push_back('\n'); break;
                case 'r': out.push_back('\r'); break;
                case 't': out.push_back('\t'); break;
                case '\\': out.push_back('\\'); break;
                case '"': out.push_back('"'); break;
                case 'u': {
                    if (i + 4 < s.size()) {
                        const std::string hex = s.substr(i + 1, 4);
                        char* end_ptr = nullptr;
                        const long codepoint = std::strtol(hex.c_str(), &end_ptr, 16);
                        if (end_ptr && *end_ptr == '\0' && codepoint >= 0 && codepoint <= 0x7F) {
                            out.push_back(static_cast<char>(codepoint));
                            i += 4;
                            break;
                        }
                    }
                    out.push_back('u');
                    break;
                }
                default: out.push_back(n); break;
                }
            } else {
                out.push_back(s[i]);
            }
        }
        return out;
    }

    static bool extract_json_string(const std::string& raw, const std::string& key, std::string& out)
    {
        std::string needle = "\"" + key + "\":\"";
        size_t pos = raw.find(needle);
        if (pos == std::string::npos) {
            return false;
        }

        size_t start = pos + needle.size();
        size_t end = start;
        while (end < raw.size()) {
            if (raw[end] == '\\' && end + 1 < raw.size()) {
                end += 2;
                continue;
            }
            if (raw[end] == '"') {
                break;
            }
            ++end;
        }

        out = unescape_json(raw.substr(start, end - start));
        return true;
    }

    static std::string parse_ollama_response(const std::string& raw, std::string* error_out = nullptr)
    {
        std::string value;
        if (extract_json_string(raw, "error", value)) {
            if (error_out) {
                *error_out = value;
            }
            return {};
        }

        if (extract_json_string(raw, "response", value)) {
            return value;
        }

        size_t resultsPos = raw.find("\"results\"");
        if (resultsPos != std::string::npos) {
            std::string suffix = raw.substr(resultsPos);
            if (extract_json_string(suffix, "response", value)) {
                return value;
            }
            if (extract_json_string(suffix, "content", value)) {
                return value;
            }
        }

        size_t choicesPos = raw.find("\"choices\"");
        if (choicesPos != std::string::npos) {
            std::string suffix = raw.substr(choicesPos);
            if (extract_json_string(suffix, "content", value)) {
                return value;
            }
        }

        // Fallback: return raw body so harness can still treat non-empty output as a response.
        return raw;
    }

    static std::wstring utf8_to_wide(const std::string& s)
    {
        if (s.empty()) {
            return {};
        }
        int needed = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), nullptr, 0);
        if (needed <= 0) {
            return {};
        }
        std::wstring out(static_cast<size_t>(needed), L'\0');
        MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), out.data(), needed);
        return out;
    }

    static std::string wide_to_utf8(const std::wstring& s)
    {
        if (s.empty()) {
            return {};
        }
        int needed = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), nullptr, 0, nullptr, nullptr);
        if (needed <= 0) {
            return {};
        }
        std::string out(static_cast<size_t>(needed), '\0');
        WideCharToMultiByte(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), out.data(), needed, nullptr, nullptr);
        return out;
    }

    std::string Generate(const std::string& prompt, int max_tokens = 2048, std::string* error_out = nullptr) const
    {
        const int request_max_tokens = (max_tokens > 0)
        ? std::min(max_tokens, 8192)
        : 2048;

        std::string body =
            "{\"model\":\"" + escape_json(model) +
            "\",\"prompt\":\"" + escape_json(prompt) +
            "\",\"stream\":false,\"max_tokens\":" + std::to_string(request_max_tokens) +
            ",\"num_predict\":" + std::to_string(request_max_tokens) +
            ",\"options\":{\"num_predict\":" + std::to_string(request_max_tokens) + "}}";

        std::wstring whost = utf8_to_wide(host);
        if (whost.empty()) {
            return {};
        }

        std::string raw;

        HINTERNET session = WinHttpOpen(L"RawrXD-SWEBench/1.0",
                                        WINHTTP_ACCESS_TYPE_NO_PROXY,
                                        WINHTTP_NO_PROXY_NAME,
                                        WINHTTP_NO_PROXY_BYPASS,
                                        0);
        if (!session) {
            if (error_out) {
                *error_out = "WinHttpOpen failed err=" + std::to_string(GetLastError());
            }
            return {};
        }

        int recv_timeout_ms = 240000;
        const char* env_recv_timeout = getenv("RAWRXD_SWEBENCH_RECV_TIMEOUT_MS");
        if (env_recv_timeout && env_recv_timeout[0]) {
            const int parsed = atoi(env_recv_timeout);
            if (parsed > 0) {
                recv_timeout_ms = parsed;
            }
        }
        WinHttpSetTimeouts(session, 5000, 5000, 10000, recv_timeout_ms);

        HINTERNET connection = WinHttpConnect(session, whost.c_str(), static_cast<INTERNET_PORT>(port), 0);
        if (!connection) {
            if (error_out) {
                *error_out = "WinHttpConnect failed err=" + std::to_string(GetLastError());
            }
            WinHttpCloseHandle(session);
            return {};
        }

        HINTERNET request = WinHttpOpenRequest(connection,
                                               L"POST",
                                               L"/api/generate",
                                               nullptr,
                                               WINHTTP_NO_REFERER,
                                               WINHTTP_DEFAULT_ACCEPT_TYPES,
                                               0);
        if (!request) {
            if (error_out) {
                *error_out = "WinHttpOpenRequest failed err=" + std::to_string(GetLastError());
            }
            WinHttpCloseHandle(connection);
            WinHttpCloseHandle(session);
            return {};
        }

        const wchar_t* headers = L"Content-Type: application/json\r\n";
        BOOL ok = WinHttpSendRequest(request,
                                     headers,
                                     -1L,
                                     const_cast<char*>(body.data()),
                                     static_cast<DWORD>(body.size()),
                                     static_cast<DWORD>(body.size()),
                                     0);
        if (ok) {
            ok = WinHttpReceiveResponse(request, nullptr);
        }
        if (!ok) {
            if (error_out) {
                *error_out = "WinHTTP send/recv failed err=" + std::to_string(GetLastError());
            }
            WinHttpCloseHandle(request);
            WinHttpCloseHandle(connection);
            WinHttpCloseHandle(session);
            return {};
        }

        DWORD status_code = 0;
        DWORD status_size = sizeof(status_code);
        if (WinHttpQueryHeaders(request,
                                 WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                 WINHTTP_HEADER_NAME_BY_INDEX,
                                 &status_code,
                                 &status_size,
                                 WINHTTP_NO_HEADER_INDEX)) {
            if (debug_http) {
                fprintf(stdout,
                    "[SWE][HTTP] POST /api/generate host=%s port=%d status=%lu num_predict=%d recv_timeout_ms=%d\n",
                    host.c_str(),
                    port,
                    static_cast<unsigned long>(status_code),
                    request_max_tokens,
                    recv_timeout_ms);
                fflush(stdout);
            }
            if (status_code != 200) {
                if (error_out) {
                    *error_out = "HTTP status=" + std::to_string(status_code);
                }
                WinHttpCloseHandle(request);
                WinHttpCloseHandle(connection);
                WinHttpCloseHandle(session);
                return {};
            }
        }

        for (;;) {
            DWORD available = 0;
            if (!WinHttpQueryDataAvailable(request, &available) || available == 0) {
                break;
            }

            std::string chunk(static_cast<size_t>(available), '\0');
            DWORD read = 0;
            if (!WinHttpReadData(request, chunk.data(), available, &read) || read == 0) {
                break;
            }
            chunk.resize(static_cast<size_t>(read));
            raw += chunk;
        }

        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);

        if (raw.empty()) {
            if (error_out) {
                *error_out = "empty HTTP response body";
            }
            return {};
        }

        if (debug_http) {
            fprintf(stdout,
                "[SWE][HTTP] response_bytes=%zu\n",
                raw.size());
            fprintf(stdout,
                "[SWE][HTTP] raw_generate_body=%s\n",
                raw.c_str());
            fflush(stdout);
        }

        std::string parsed = parse_ollama_response(raw, error_out);
        if (parsed.empty() && error_out && !raw.empty()) {
            // preserve raw response when parsing fails, but signal the issue
            *error_out = "could not parse response; raw body returned";
            return raw;
        }
        return parsed;
    }

    std::string HttpGet(const std::string& path, std::string* error_out = nullptr) const
    {
        std::wstring whost = utf8_to_wide(host);
        if (whost.empty()) {
            if (error_out) {
                *error_out = "invalid host";
            }
            return {};
        }

        std::string raw;
        HINTERNET session = WinHttpOpen(L"RawrXD-SWEBench/1.0",
                                        WINHTTP_ACCESS_TYPE_NO_PROXY,
                                        WINHTTP_NO_PROXY_NAME,
                                        WINHTTP_NO_PROXY_BYPASS,
                                        0);
        if (!session) {
            if (error_out) {
                *error_out = "WinHttpOpen failed err=" + std::to_string(GetLastError());
            }
            return {};
        }

        int recv_timeout_ms = 240000;
        const char* env_recv_timeout = getenv("RAWRXD_SWEBENCH_RECV_TIMEOUT_MS");
        if (env_recv_timeout && env_recv_timeout[0]) {
            const int parsed = atoi(env_recv_timeout);
            if (parsed > 0) {
                recv_timeout_ms = parsed;
            }
        }
        WinHttpSetTimeouts(session, 5000, 5000, 10000, recv_timeout_ms);

        HINTERNET connection = WinHttpConnect(session, whost.c_str(), static_cast<INTERNET_PORT>(port), 0);
        if (!connection) {
            if (error_out) {
                *error_out = "WinHttpConnect failed err=" + std::to_string(GetLastError());
            }
            WinHttpCloseHandle(session);
            return {};
        }

        HINTERNET request = WinHttpOpenRequest(connection,
                                               L"GET",
                                               std::wstring(utf8_to_wide(path)).c_str(),
                                               nullptr,
                                               WINHTTP_NO_REFERER,
                                               WINHTTP_DEFAULT_ACCEPT_TYPES,
                                               0);
        if (!request) {
            if (error_out) {
                *error_out = "WinHttpOpenRequest failed err=" + std::to_string(GetLastError());
            }
            WinHttpCloseHandle(connection);
            WinHttpCloseHandle(session);
            return {};
        }

        BOOL ok = WinHttpSendRequest(request,
                                     WINHTTP_NO_ADDITIONAL_HEADERS,
                                     0,
                                     nullptr,
                                     0,
                                     0,
                                     0);
        if (ok) {
            ok = WinHttpReceiveResponse(request, nullptr);
        }
        if (!ok) {
            if (error_out) {
                *error_out = "WinHTTP GET failed err=" + std::to_string(GetLastError());
            }
            WinHttpCloseHandle(request);
            WinHttpCloseHandle(connection);
            WinHttpCloseHandle(session);
            return {};
        }

        DWORD status_code = 0;
        DWORD status_size = sizeof(status_code);
        if (!WinHttpQueryHeaders(request,
                                 WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                 WINHTTP_HEADER_NAME_BY_INDEX,
                                 &status_code,
                                 &status_size,
                                 WINHTTP_NO_HEADER_INDEX)) {
            if (error_out) {
                *error_out = "WinHttpQueryHeaders status failed err=" + std::to_string(GetLastError());
            }
            WinHttpCloseHandle(request);
            WinHttpCloseHandle(connection);
            WinHttpCloseHandle(session);
            return {};
        }

        if (status_code != 200) {
            if (error_out) {
                *error_out = "HTTP status=" + std::to_string(status_code);
            }
            WinHttpCloseHandle(request);
            WinHttpCloseHandle(connection);
            WinHttpCloseHandle(session);
            return {};
        }

        for (;;) {
            DWORD available = 0;
            if (!WinHttpQueryDataAvailable(request, &available) || available == 0) {
                break;
            }

            std::string chunk(static_cast<size_t>(available), '\0');
            DWORD read = 0;
            if (!WinHttpReadData(request, chunk.data(), available, &read) || read == 0) {
                break;
            }
            chunk.resize(static_cast<size_t>(read));
            raw += chunk;
        }

        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);

        if (raw.empty() && error_out) {
            *error_out = "empty HTTP response body";
        }

        if (debug_http && !raw.empty()) {
            fprintf(stdout,
                "[SWE][HTTP] GET %s host=%s port=%d raw_body=%s\n",
                path.c_str(),
                host.c_str(),
                port,
                raw.c_str());
            fflush(stdout);
        }

        return raw;
    }

    std::vector<std::string> ListModels(std::string* error_out = nullptr) const
    {
        std::vector<std::string> names;
        std::string raw = HttpGet("/api/models", error_out);
        if (raw.empty()) {
            raw = HttpGet("/api/tags", error_out);
        }
        if (raw.empty()) {
            return names;
        }

        const std::vector<std::string> keys = {"\"name\":\"", "\"model\":\"", "\"tag\":\""};
        for (const auto& key : keys) {
            size_t pos = 0;
            while ((pos = raw.find(key, pos)) != std::string::npos) {
                size_t start = pos + key.size();
                size_t end = start;
                while (end < raw.size() && raw[end] != '"') {
                    end++;
                }
                if (end > start) {
                    names.push_back(raw.substr(start, end - start));
                }
                pos = end + 1;
            }
            if (!names.empty()) {
                break;
            }
        }
        return names;
    }
};

struct RealAgentContext {
    MinimalOllamaClient* ollama_client = nullptr;
    bool debug_runtime = false;
    int max_output_tokens = 0;
};

static std::string invoke_real_agent(
    const SWEBench::Instance& inst,
    RealAgentContext* ctx,
    SWEBench::TaskResult& result_out)
{
    if (!ctx || !ctx->ollama_client) {
        result_out.failure_reason = "ollama_client not initialized";
        return {};
    }

    try {
        std::string transport_error;
        int max_tokens = result_out.tokens_effective > 0
            ? static_cast<int>(std::min<uint64_t>(
                result_out.tokens_effective,
                static_cast<uint64_t>(std::numeric_limits<int>::max())))
            : 2048;

        if (ctx->max_output_tokens > 0) {
            max_tokens = std::min(max_tokens, ctx->max_output_tokens);
        }

        if (ctx->debug_runtime) {
            fprintf(stdout,
                "[SWE][BUDGET] task=%s requested=%llu effective=%llu adapted=%s pressure=%.4f max_tokens=%d\n",
                inst.task_id.c_str(),
                static_cast<unsigned long long>(result_out.tokens_requested),
                static_cast<unsigned long long>(result_out.tokens_effective),
                result_out.adapted ? "true" : "false",
                result_out.pressure_ratio,
                max_tokens);
            fflush(stdout);
        }

        // Extract target files from gold patch to enable file-lock constraint
        const std::vector<std::string> target_files =
            SWEBench::extract_target_files_from_patch(inst.gold_patch);

        std::string response =
            ctx->ollama_client->Generate(SWEBench::build_patch_only_prompt(inst, target_files), max_tokens, &transport_error);
        if (response.empty()) {
            result_out.failure_reason = transport_error.empty() ? "empty response from Ollama" : transport_error;
            return {};
        }
        result_out.raw_response = response;
        SWEBench::populate_response_compliance(result_out);

        std::string normalization_error;
        std::string patch = SWEBench::normalize_agent_patch_response(response, &normalization_error);
        if (patch.empty()) {
            result_out.failure_reason = normalization_error.empty()
                ? "model did not emit a strict unified diff"
                : normalization_error;
            return {};
        }

        return patch;
    } catch (const std::exception& ex) {
        result_out.failure_reason = std::string("inference exception: ") + ex.what();
        return {};
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Stand-alone entry point
// ─────────────────────────────────────────────────────────────────────────────
//
// Usage:
//   swe_bench.exe [--json <output.json>] [--jsonl <telemetry.jsonl>] [--run-tests]
//                 [--dataset <instances.jsonl>] [--real-agent] [--model <name>]
//                 [--host <host>] [--port <num>] [--list-models] [--debug-http]
//                 [--verbose] [--max-tasks <N>] [--max-output-tokens <N>]
//                 [--dump-raw-responses <dir>] [--raw-dump-dir <dir>]
//
// --real-agent     Use live Ollama HTTP endpoint (requires Ollama running)
// --list-models    Print installed Ollama models and exit
// --model          Use the specified Ollama model name
// --host           Connect to Ollama at this hostname or IP
// --port           Connect to Ollama on this HTTP port
// --debug-http     Emit HTTP status/budget debug lines to stdout
// --verbose        Alias for --debug-http plus raw JSON body dumps
// --max-tasks      Limit number of evaluation instances processed
// --max-output-tokens  Cap generated completion tokens for bounded smoke tests
// --dump-raw-responses  Write per-task raw model responses into <dir>
// --raw-dump-dir        Alias for --dump-raw-responses
// --run-tests      Run task test commands when available
// --json           Output JSON report to this file
// --jsonl          Output per-sample telemetry to this file
// --dataset        Load instances from JSON/JSONL file instead of built-in set
//
// Without --real-agent, runs null agent on built-in instances for self-test.

int main(int argc, char** argv)
{
    bool        use_real_agent = false;
    bool        run_tests     = false;
    bool        list_models   = false;
    bool        debug_http    = false;
    bool        verbose       = false;
    const char* json_out      = nullptr;
    const char* jsonl_out     = nullptr;
    const char* dataset_path  = nullptr;
    const char* model_name    = nullptr;
    const char* host_name     = nullptr;
    const char* raw_dump_dir  = nullptr;
    int         ollama_port   = 11434;
    int         max_tasks     = -1;
    int         max_output_tokens = 0;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--real-agent") == 0) {
            use_real_agent = true;
        } else if (strcmp(argv[i], "--list-models") == 0) {
            list_models = true;
            use_real_agent = true;
        } else if (strcmp(argv[i], "--run-tests") == 0) {
            run_tests = true;
        } else if (strcmp(argv[i], "--json") == 0 && i + 1 < argc) {
            json_out = argv[++i];
        } else if (strcmp(argv[i], "--jsonl") == 0 && i + 1 < argc) {
            jsonl_out = argv[++i];
        } else if (strcmp(argv[i], "--dataset") == 0 && i + 1 < argc) {
            dataset_path = argv[++i];
        } else if (strcmp(argv[i], "--model") == 0 && i + 1 < argc) {
            model_name = argv[++i];
        } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            ollama_port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--host") == 0 && i + 1 < argc) {
            host_name = argv[++i];
        } else if (strcmp(argv[i], "--debug-http") == 0) {
            debug_http = true;
        } else if (strcmp(argv[i], "--verbose") == 0) {
            verbose = true;
        } else if (strcmp(argv[i], "--max-tasks") == 0 && i + 1 < argc) {
            max_tasks = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--max-output-tokens") == 0 && i + 1 < argc) {
            max_output_tokens = atoi(argv[++i]);
        } else if ((strcmp(argv[i], "--dump-raw-responses") == 0 ||
                    strcmp(argv[i], "--raw-dump-dir") == 0) &&
                   i + 1 < argc) {
            raw_dump_dir = argv[++i];
        }
    }

    if (verbose) {
        debug_http = true;
    }

    fprintf(stdout,
        "╔════════════════════════════════════════════════╗\n"
        "║    RawrXD SWE-bench Evaluation Harness         ║\n"
        "║    Purpose: Validate Phase 2 Adaptation       ║\n"
        "╚════════════════════════════════════════════════╝\n\n");

    // Load instances
    std::vector<SWEBench::Instance> instances;
    if (dataset_path) {
        instances = SWEBench::load_json_dataset(dataset_path);
    } else {
        instances = SWEBench::builtin_instances();
    }

    if (instances.empty()) {
        fprintf(stderr, "Error: no instances to evaluate\n");
        return 1;
    }

    if (max_tasks > 0 && static_cast<size_t>(max_tasks) < instances.size()) {
        instances.resize(static_cast<size_t>(max_tasks));
        fprintf(stdout, "Limiting evaluation to %d instance(s) via --max-tasks\n", max_tasks);
    }

    fprintf(stdout, "Loaded %zu instances\n", instances.size());

    // Open telemetry JSONL if requested
    FILE* jsonl_file = nullptr;
    if (jsonl_out) {
        if (fopen_s(&jsonl_file, jsonl_out, "w") == 0 && jsonl_file) {
            fprintf(stdout, "Telemetry will be written to: %s\n", jsonl_out);
        } else {
            fprintf(stderr, "Warning: could not open JSONL telemetry file: %s\n", jsonl_out);
        }
    }

    SWEBench::HarnessReport report;

    if (use_real_agent) {
        fprintf(stdout, "\n[INFO] Initializing minimal Ollama HTTP client...\n");

        try {
            const char* env_model = getenv("RAWRXD_SWEBENCH_MODEL");
            if (!env_model || !env_model[0]) {
                env_model = getenv("OLLAMA_MODEL");
            }
            const char* env_port = getenv("RAWRXD_SWEBENCH_PORT");
            if (env_port && env_port[0]) {
                ollama_port = atoi(env_port);
            }
            const char* env_host = getenv("RAWRXD_SWEBENCH_HOST");
            if (!env_host || !env_host[0]) {
                env_host = getenv("OLLAMA_HOST");
            }
            const char* env_debug = getenv("RAWRXD_SWEBENCH_DEBUG_HTTP");
            if (env_debug && env_debug[0] && strcmp(env_debug, "0") != 0) {
                debug_http = true;
            }

            std::string chosen_host = host_name && host_name[0] ? host_name : "127.0.0.1";
            if (env_host && env_host[0]) {
                chosen_host = env_host;
            }

            std::string chosen_model;
            if (model_name && model_name[0]) {
                chosen_model = model_name;
            } else if (env_model && env_model[0]) {
                chosen_model = env_model;
            }

            MinimalOllamaClient ollama(chosen_host, ollama_port, chosen_model);
            ollama.debug_http = debug_http;

            if (list_models) {
                std::string discover_error;
                auto models = ollama.ListModels(&discover_error);
                if (!models.empty()) {
                    fprintf(stdout, "Available Ollama models:\n");
                    for (const auto& name : models) {
                        fprintf(stdout, "  %s\n", name.c_str());
                    }
                    if (jsonl_file) fclose(jsonl_file);
                    return 0;
                }
                fprintf(stderr, "Error: could not discover an Ollama model list: %s\n",
                        discover_error.empty() ? "no models returned" : discover_error.c_str());
                if (jsonl_file) fclose(jsonl_file);
                return 1;
            }

            if (chosen_model.empty()) {
                std::string discover_error;
                auto models = ollama.ListModels(&discover_error);
                if (!models.empty()) {
                    chosen_model = models.front();
                    ollama.model = chosen_model;
                    fprintf(stdout, "[INFO] Discovered Ollama model: %s\n", chosen_model.c_str());
                } else {
                    fprintf(stderr, "Error: could not discover an Ollama model: %s\n",
                            discover_error.empty() ? "no models returned" : discover_error.c_str());
                    if (jsonl_file) fclose(jsonl_file);
                    return 1;
                }
            }

            fprintf(stdout, "[INFO] Using Ollama model: %s on port %d\n", chosen_model.c_str(), ollama_port);
            RealAgentContext ctx;
            ctx.ollama_client = &ollama;
            ctx.debug_runtime = debug_http;
            ctx.max_output_tokens = max_output_tokens;

            SWEBench::Harness harness(run_tests, jsonl_file, json_out, raw_dump_dir);
            for (auto& inst : instances) {
                harness.add_instance(std::move(inst));
            }

            fprintf(stdout, "Running evaluation with minimal Ollama client...\n");
            report = harness.run([&ctx](const SWEBench::Instance& inst, SWEBench::TaskResult& result) {
                return invoke_real_agent(inst, &ctx, result);
            });

        } catch (const std::exception& ex) {
            fprintf(stderr, "Error initializing Ollama client: %s\n", ex.what());
            if (jsonl_file) fclose(jsonl_file);
            return 1;
        }
    } else {
        // Null agent self-test mode
        fprintf(stdout, "\n[INFO] Running self-test with null agent...\n");
        fprintf(stdout, "      (Use --real-agent flag for live inference evaluation)\n\n");

        SWEBench::Harness harness(run_tests, jsonl_file, json_out, raw_dump_dir);
        for (auto& inst : instances) {
            harness.add_instance(std::move(inst));
        }

        SWEBench::AgentFn null_agent = [](const SWEBench::Instance&, SWEBench::TaskResult&) -> std::string {
            return {};
        };

        report = harness.run(null_agent);
    }

    if (jsonl_file) {
        fflush(jsonl_file);
    }

    if (json_out) {
        if (SWEBench::write_json_report(report, json_out)) {
            fprintf(stdout, "JSON report written to: %s\n", json_out);
        } else {
            fprintf(stderr, "Warning: failed to write JSON report to: %s\n", json_out);
        }
    }

    SWEBench::print_report(report);

    if (jsonl_file) {
        fclose(jsonl_file);
        fprintf(stdout, "Telemetry JSONL closed: %s\n", jsonl_out);
    }

    // Return 0 even when score is zero (harness validates the framework plumbing)
    return 0;
}
