#include "../src/win32app/Win32TerminalManager.h"
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <string>

struct RunResult {
    int exitCode = -1;
    std::string output;
    std::string error;
    bool finished = false;
};

static RunResult runCase(const std::string& commandLine)
{
    Win32TerminalManager manager;
    RunResult result;
    std::mutex mutex;
    std::condition_variable ready;
    manager.onOutput = [&](const std::string& text) {
        std::lock_guard<std::mutex> lock(mutex);
        result.output += text;
    };
    manager.onError = [&](const std::string& text) {
        std::lock_guard<std::mutex> lock(mutex);
        result.error += text;
    };
    manager.onFinished = [&](int code) {
        {
            std::lock_guard<std::mutex> lock(mutex);
            result.exitCode = code;
            result.finished = true;
        }
        ready.notify_one();
    };
    if (!manager.startCommandLine(Win32TerminalManager::CommandPrompt, commandLine)) {
        result.error = "START_FAILED";
        return result;
    }
    std::unique_lock<std::mutex> lock(mutex);
    if (!ready.wait_for(lock, std::chrono::seconds(15), [&] { return result.finished; })) {
        result.error += "TIMEOUT";
        manager.stop();
    }
    return result;
}

int main()
{
    struct Case { const char* name; const char* command; int expected; const char* expectedOut; const char* expectedErr; };
    const Case cases[] = {
        {"cmd_exit", "cmd.exe /d /c exit 7", 7, "", ""},
        {"cmd_stdout", "cmd.exe /d /c echo RAWRXD_OK", 0, "RAWRXD_OK", ""},
        {"ps_exit", "powershell.exe -NoProfile -NonInteractive -Command \"exit 7\"", 7, "", ""},
        {"ps_stdout", "powershell.exe -NoProfile -NonInteractive -Command \"Write-Output 'RAWRXD_OK'\"", 0, "RAWRXD_OK", ""},
        {"ps_stderr", "powershell.exe -NoProfile -NonInteractive -Command \"[Console]::Error.WriteLine('RAWRXD_ERR'); exit 7\"", 7, "", "RAWRXD_ERR"}
    };
    bool allPass = true;
    for (const auto& test : cases) {
        const RunResult result = runCase(test.command);
        const bool pass = result.exitCode == test.expected &&
            (std::string(test.expectedOut).empty() || result.output.find(test.expectedOut) != std::string::npos) &&
            (std::string(test.expectedErr).empty() || result.error.find(test.expectedErr) != std::string::npos);
        allPass = allPass && pass;
        std::cout << test.name << " status=" << (pass ? "PASS" : "FAIL")
                  << " exit=" << result.exitCode
                  << " stdout_bytes=" << result.output.size()
                  << " stderr_bytes=" << result.error.size() << "\n";
        if (!pass) {
            std::cout << "stdout=" << result.output << "\nstderr=" << result.error << "\n";
        }
    }
    return allPass ? 0 : 1;
}
