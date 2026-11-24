// =============================================================================
// agent_security_smoke.cpp — executable certification for the P0 agent
// security contract (tool_security.hpp). No model, no GPU, no network.
//
// Verifies:
//   1. AuthorizeExecute: deny without host flag, allow with it.
//   2. CommandEscapesWorkspace: cd .. / cd / / cd \ / cd C:\ rejected,
//      ordinary commands accepted.
//   3. JobIsolation::RunIsolated: real child process, stdout captured, exit 0.
//   4. Timeout: whole process tree killed (timedOut=true, nonzero exit).
//   5. Cancel: KillAll() terminates an in-flight RunIsolated child.
//   6. ToolReceiptLog: durable JSONL receipt with required fields.
// =============================================================================
#include <atomic>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>

#include "agentic/tool_security.hpp"

using rawrxd::agentic::security::AuthorizeExecute;
using rawrxd::agentic::security::CommandEscapesWorkspace;
using rawrxd::agentic::security::JobIsolation;
using rawrxd::agentic::security::Receipt;
using rawrxd::agentic::security::ToolReceiptLog;

static int g_failures = 0;

static void Check(const char* name, bool ok, const std::string& detail = {})
{
    std::printf("[%s] %s%s%s\n", ok ? "PASS" : "FAIL", name,
                detail.empty() ? "" : " :: ", detail.c_str());
    if (!ok) ++g_failures;
}

int main()
{
    // 1. Authorization ---------------------------------------------------------
    {
        const auto deny = AuthorizeExecute(false, "smoke");
        Check("authz.deny_without_flag", !deny.allowed &&
            deny.reason.rfind("AUTHORIZATION_REQUIRED", 0) == 0, deny.reason);
        const auto allow = AuthorizeExecute(true, "smoke");
        Check("authz.allow_with_flag", allow.allowed &&
            allow.reason.rfind("AUTHORIZED_BY_HOST", 0) == 0, allow.reason);
    }

    // 2. Workspace escape detection -------------------------------------------
    Check("escape.cd_dotdot", CommandEscapesWorkspace("cd .. && dir"));
    Check("escape.cd_root", CommandEscapesWorkspace("cd /"));
    Check("escape.cd_backslash", CommandEscapesWorkspace("cd \\"));
    Check("escape.cd_drive", CommandEscapesWorkspace("cd C:\\Windows"));
    Check("escape.pushd", CommandEscapesWorkspace("pushd .."));
    Check("escape.ordinary_ok", !CommandEscapesWorkspace("dir /b"));
    Check("escape.nested_ok", !CommandEscapesWorkspace("cd sub && dir"));

    // 3. Real subprocess through the job --------------------------------------
    {
        std::string out, err;
        int code = -1;
        bool timedOut = false;
        const bool launched = JobIsolation::RunIsolated(
            "cmd.exe /d /c echo AGENT_SECURITY_SMOKE_OK", std::string(), 0ULL,
            out, err, code, timedOut);
        Check("job.echo_launched", launched);
        Check("job.echo_exit0", code == 0, "exit=" + std::to_string(code));
        Check("job.echo_output",
              out.find("AGENT_SECURITY_SMOKE_OK") != std::string::npos, out);
    }

    // 4. Timeout kills the tree ------------------------------------------------
    {
        std::string out, err;
        int code = -1;
        bool timedOut = false;
        const auto t0 = std::chrono::steady_clock::now();
        const bool launched = JobIsolation::RunIsolated(
            "cmd.exe /d /c ping -n 10 127.0.0.1 >nul", std::string(), 700ULL,
            out, err, code, timedOut);
        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0).count();
        Check("timeout.launched", launched);
        Check("timeout.timed_out", timedOut);
        Check("timeout.nonzero_exit", code != 0, "exit=" + std::to_string(code));
        Check("timeout.bounded", ms < 5000, "elapsed=" + std::to_string(ms) + "ms");
    }

    // 5. Cancel (KillAll) terminates an in-flight child ------------------------
    {
        std::atomic<bool> done{false};
        std::string out, err;
        int code = -1;
        bool timedOut = false;
        std::thread worker([&] {
            JobIsolation::RunIsolated(
                "cmd.exe /d /c ping -n 30 127.0.0.1 >nul", std::string(), 0ULL,
                out, err, code, timedOut);
            done.store(true);
        });
        std::this_thread::sleep_for(std::chrono::milliseconds(600));
        JobIsolation::KillAll();
        bool finished = false;
        for (int i = 0; i < 100 && !finished; ++i) {
            finished = done.load();
            if (!finished) std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        worker.join();
        Check("cancel.killall_terminates", finished && code != 0,
              "exit=" + std::to_string(code));
    }

    // 6. Durable receipts -------------------------------------------------------
    {
        const std::string path =
            std::string(getenv("TEMP") ? getenv("TEMP") : ".") +
            "/rawrxd_agent_security_smoke_receipts.jsonl";
        std::remove(path.c_str());
        ToolReceiptLog log(path);
        Receipt r;
        r.ts = "2026-11-24T00:00:00Z";
        r.tool = "runInTerminal";
        r.target = "smoke";
        r.risk = "Execute";
        r.decision = "DENY";
        r.authorizer = "motd-only";
        r.detail = "AUTHORIZATION_REQUIRED";
        r.exit_code = -1;
        r.bytes = 42;
        r.accepted = false;
        log.Write(r);
        std::ifstream in(path);
        std::stringstream ss;
        ss << in.rdbuf();
        const std::string body = ss.str();
        Check("receipt.file_written", !body.empty());
        Check("receipt.valid_jsonl",
              body.find("\"decision\":\"DENY\"") != std::string::npos &&
              body.find("\"tool\":\"runInTerminal\"") != std::string::npos &&
              body.find("\"exit_code\":-1") != std::string::npos, body);
        std::remove(path.c_str());
    }

    std::printf("AGENT_SECURITY_SMOKE %s (failures=%d)\n",
                g_failures == 0 ? "PASS" : "FAIL", g_failures);
    return g_failures == 0 ? 0 : 1;
}