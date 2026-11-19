// NativeActionExecutor acceptance test
//
// Exercises the full ActionExecutor runtime contract against the real
// NativeProcess implementation on Windows:
//   1. successful execution (exit 0)
//   2. nonzero exit propagation (exit 7)
//   3. stdout capture
//   4. stderr capture
//   5. timeout handling
//   6. pre-execution cancellation
//   7. async plan shutdown (join)
//   8. mid-flight cancellation of an async plan
//
// Exit code 0 => ACCEPTANCE=PASS, non-zero => ACCEPTANCE=FAIL.
// This is a regression test: it must remain green so the executor
// out-parameter contract (results written back into the caller's action)
// cannot silently regress.

#include "agent/native_action_executor.hpp"

#include <chrono>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

static int g_checks = 0;
static int g_failures = 0;

static void check(bool cond, const std::string& msg, int line) {
    ++g_checks;
    if (cond) {
        std::cout << "PASS: " << msg << "\n";
    } else {
        ++g_failures;
        std::cout << "FAIL: " << msg << " (line " << line << ")\n";
    }
}

#define CHECK(cond, msg) check((cond), (msg), __LINE__)

static bool contains(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

static NativeAction makeExit0() {
    NativeAction a;
    a.command = "cmd.exe";
    a.args = {"/c exit 0"};
    return a;
}

int main() {
    NativeExecutionContext ctx;
    ctx.commandTimeoutMs = 2000;
    ctx.planTimeoutMs = 15000;

    // 1. Successful execution ------------------------------------------------
    {
        NativeActionExecutor ex(ctx);
        NativeAction a = makeExit0();
        bool ok = ex.execute(a);
        CHECK(ok, "success: exit 0 returns true");
        CHECK(a.success, "success: success flag set");
        CHECK(a.error.empty(), "success: no error recorded");
    }

    // 2. Nonzero exit --------------------------------------------------------
    {
        NativeActionExecutor ex(ctx);
        NativeAction a;
        a.command = "cmd.exe";
        a.args = {"/c exit 7"};
        bool ok = ex.execute(a);
        CHECK(!ok, "nonzero: exit 7 returns false");
        CHECK(!a.success, "nonzero: success flag false");
        CHECK(!a.error.empty(), "nonzero: error populated");
        CHECK(contains(a.error, "7"), "nonzero: error mentions exit code 7");
    }

    // 3. stdout capture ------------------------------------------------------
    {
        NativeActionExecutor ex(ctx);
        NativeAction a;
        a.command = "cmd.exe";
        a.args = {"/c echo rawrxd_stdout"};
        ex.execute(a);
        CHECK(contains(a.output, "rawrxd_stdout"),
              "output: stdout captured");
    }

    // 4. stderr capture ------------------------------------------------------
    {
        NativeActionExecutor ex(ctx);
        NativeAction a;
        a.command = "cmd.exe";
        a.args = {"/c echo rawrxd_stderr 1>&2"};
        ex.execute(a);
        CHECK(contains(a.output, "rawrxd_stderr"),
              "output: stderr captured");
    }

    // 5. Timeout handling ----------------------------------------------------
    {
        NativeActionExecutor ex(ctx);
        NativeAction a;
        a.command = "cmd.exe";
        a.args = {"/c ping -n 10 127.0.0.1 > NUL"};
        auto t0 = std::chrono::steady_clock::now();
        bool ok = ex.execute(a);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::steady_clock::now() - t0).count();
        CHECK(!ok, "timeout: long command returns false");
        CHECK(contains(a.error, "TIMEOUT"),
              "timeout: error indicates COMMAND_TIMEOUT");
        CHECK(ms < 5000, "timeout: returned promptly (<5s)");
    }

    // 6. Pre-execution cancellation -----------------------------------------
    {
        NativeActionExecutor ex(ctx);
        ex.cancel();
        NativeAction a = makeExit0();
        bool ok = ex.execute(a);
        CHECK(!ok, "cancel: pre-cancelled returns false");
        CHECK(a.error == "CANCELLED", "cancel: error == CANCELLED");
    }

    // 7. Async plan shutdown (join) -----------------------------------------
    {
        NativeActionExecutor ex(ctx);
        std::vector<NativeAction> plan(3, makeExit0());
        ex.executePlanAsync(plan, /*stopOnError=*/true);
        ex.join();
        CHECK(!ex.running(), "shutdown: async plan joined, not running");
    }

    // 8. Mid-flight cancellation of async plan ------------------------------
    {
        NativeActionExecutor ex(ctx);
        std::vector<NativeAction> plan;
        for (int i = 0; i < 60; ++i) {
            NativeAction a;
            a.command = "cmd.exe";
            a.args = {"/c ping -n 2 127.0.0.1 > NUL"};
            plan.push_back(a);
        }
        ex.executePlanAsync(plan, /*stopOnError=*/true);
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
        ex.cancel();
        ex.join();
        CHECK(!ex.running(), "midcancel: joined after cancel");
    }

    std::cout << "\n==== ACCEPTANCE SUMMARY ====\n";
    std::cout << "checks=" << g_checks << " failures=" << g_failures << "\n";
    std::cout << (g_failures == 0 ? "ACCEPTANCE=PASS\n" : "ACCEPTANCE=FAIL\n");
    return g_failures == 0 ? 0 : 1;
}