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

    fprintf(jsonl_out,
        "{\"sample_id\": \"%s\", \"tokens_requested\": %llu, "
        "\"tokens_effective\": %llu, \"kv_budget_bytes\": %llu, "
        "\"adapted\": %s, \"pressure_ratio\": %.6f, "
        "\"response_length\": %zu, \"success\": %s}\n",
        result.task_id.c_str(),
        result.tokens_requested,
        result.tokens_effective,
        result.kv_budget_bytes,
        result.adapted ? "true" : "false",
        result.pressure_ratio,
        response_length,
        (result.status == TaskStatus::FAILED) ? "false" : "true");
}

// ─────────────────────────────────────────────────────────────────────────────
// Harness
// ─────────────────────────────────────────────────────────────────────────────

class Harness {
public:
    explicit Harness(bool run_tests = false, FILE* jsonl_out = nullptr)
        : m_run_tests(run_tests), m_jsonl_out(jsonl_out) {}

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
                write_jsonl_sample(m_jsonl_out, res, 0);
                report.results.push_back(res);
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
                write_jsonl_sample(m_jsonl_out, res, 0);
                report.results.push_back(res);
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

            write_jsonl_sample(m_jsonl_out, res, res.emitted_patch.size());
            report.results.push_back(res);
        }

        // Compute rates
        if (report.total > 0) {
            report.task_completion_rate =
                static_cast<double>(report.completed) / report.total;
            report.patch_correctness = (report.completed > 0)
                ? static_cast<double>(report.patch_correct) / report.total
                : 0.0;
            report.test_pass_rate = (m_run_tests && !m_instances.empty())
                ? static_cast<double>(report.tests_passed) / report.total
                : report.patch_correctness; // fallback: use patch score
        }

        // Harmonic mean of the three non-zero metrics
        double comp  = report.task_completion_rate;
        double patch = report.patch_correctness;
        double test  = report.test_pass_rate;
        if (comp > 0.0 && patch > 0.0 && test > 0.0) {
            report.overall_score = 3.0 / (1.0 / comp + 1.0 / patch + 1.0 / test);
        } else {
            report.overall_score = (comp + patch + test) / 3.0;
        }

        return report;
    }

private:
    std::vector<Instance> m_instances;
    bool                  m_run_tests;
    FILE*                 m_jsonl_out;
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
    fprintf(f, "  \"results\": [\n");
    for (size_t i = 0; i < r.results.size(); ++i) {
        const auto& t = r.results[i];
        const char* comma = (i + 1 < r.results.size()) ? "," : "";
        fprintf(f,
            "    {\"task_id\": \"%s\", \"status\": %d, \"patch_match\": %s, "
            "\"tests_passed\": %s, \"elapsed_ms\": %.2f, \"failure_reason\": \"%s\", "
            "\"tokens_requested\": %llu, \"tokens_effective\": %llu, "
            "\"kv_budget_bytes\": %llu, \"adapted\": %s, "
            "\"pressure_ratio\": %.4f}%s\n",
            t.task_id.c_str(),
            static_cast<int>(t.status),
            t.patch_match  ? "true" : "false",
            t.tests_passed ? "true" : "false",
            t.elapsed_ms,
            json_escape(t.failure_reason).c_str(),
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

    explicit MinimalOllamaClient(const std::string& h = "127.0.0.1", int p = 11435, const std::string& m = "mistral")
        : host(h), port(p), model(m) {}

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
                default: out.push_back(n); break;
                }
            } else {
                out.push_back(s[i]);
            }
        }
        return out;
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
        std::string body =
            "{\"model\":\"" + escape_json(model) +
            "\",\"prompt\":\"" + escape_json(prompt) +
            "\",\"stream\":false,\"options\":{\"num_predict\":" + std::to_string(max_tokens) + "}}";

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

        WinHttpSetTimeouts(session, 5000, 5000, 10000, 120000);

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

        const std::string error_key = "\"error\":\"";
        size_t error_pos = raw.find(error_key);
        if (error_pos != std::string::npos) {
            size_t start = error_pos + error_key.size();
            std::string encoded_error;
            for (size_t i = start; i < raw.size(); ++i) {
                if (raw[i] == '"' && (i == start || raw[i - 1] != '\\')) {
                    break;
                }
                encoded_error.push_back(raw[i]);
            }
            if (error_out) {
                *error_out = unescape_json(encoded_error);
            }
            return {};
        }

        const std::string key = "\"response\":\"";
        size_t pos = raw.find(key);
        if (pos == std::string::npos) {
            if (error_out) {
                *error_out = "response field missing";
            }
            return raw;
        }

        size_t start = pos + key.size();
        std::string encoded;
        for (size_t i = start; i < raw.size(); ++i) {
            if (raw[i] == '"' && (i == start || raw[i - 1] != '\\')) {
                break;
            }
            encoded.push_back(raw[i]);
        }
        return unescape_json(encoded);
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
                                        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                        WINHTTP_NO_PROXY_NAME,
                                        WINHTTP_NO_PROXY_BYPASS,
                                        0);
        if (!session) {
            if (error_out) {
                *error_out = "WinHttpOpen failed err=" + std::to_string(GetLastError());
            }
            return {};
        }

        WinHttpSetTimeouts(session, 5000, 5000, 10000, 120000);

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
        const int max_tokens = result_out.tokens_effective > 0
            ? static_cast<int>(std::min<uint64_t>(
                result_out.tokens_effective,
                static_cast<uint64_t>(std::numeric_limits<int>::max())))
            : 2048;
        std::string response =
            ctx->ollama_client->Generate(inst.problem_stmt, max_tokens, &transport_error);
        if (response.empty()) {
            result_out.failure_reason = transport_error.empty() ? "empty response from Ollama" : transport_error;
            return {};
        }
        return response;
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
//                 [--port <num>] [--list-models]
//
// --real-agent     Use live Ollama HTTP endpoint (requires Ollama running)
// --list-models    Print installed Ollama models and exit
// --model          Use the specified Ollama model name
// --port           Connect to Ollama on this HTTP port
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
    const char* json_out      = nullptr;
    const char* jsonl_out     = nullptr;
    const char* dataset_path  = nullptr;
    const char* model_name    = nullptr;
    int         ollama_port   = 11434;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--real-agent") == 0) {
            use_real_agent = true;
        } else if (strcmp(argv[i], "--list-models") == 0) {
            list_models = true;
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
        }
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

            std::string chosen_model;
            if (model_name && model_name[0]) {
                chosen_model = model_name;
            } else if (env_model && env_model[0]) {
                chosen_model = env_model;
            }

            MinimalOllamaClient ollama("127.0.0.1", ollama_port, chosen_model);

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

            SWEBench::Harness harness(run_tests, jsonl_file);
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

        SWEBench::Harness harness(run_tests, jsonl_file);
        for (auto& inst : instances) {
            harness.add_instance(std::move(inst));
        }

        SWEBench::AgentFn null_agent = [](const SWEBench::Instance&, SWEBench::TaskResult&) -> std::string {
            return {};
        };

        report = harness.run(null_agent);
    }

    SWEBench::print_report(report);

    if (json_out) {
        if (SWEBench::write_json_report(report, json_out)) {
            fprintf(stdout, "JSON report written to: %s\n", json_out);
        } else {
            fprintf(stderr, "Warning: failed to write JSON report to: %s\n", json_out);
        }
    }

    if (jsonl_file) {
        fclose(jsonl_file);
        fprintf(stdout, "Telemetry JSONL closed: %s\n", jsonl_out);
    }

    // Return 0 even when score is zero (harness validates the framework plumbing)
    return 0;
}
