#pragma once
// Native Windows subprocess runner for compiler/linker commands.
// No shell expansion; stdout and stderr drained concurrently to avoid pipe deadlocks.
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <utility>
namespace rawrxd::build {
struct ProcessResult {
    DWORD exitCode = 0;
    bool launched = false;
    bool timedOut = false;
    std::string stdoutText, stderrText, error;
};
inline std::wstring quoteArg(const std::wstring& s) {
    std::wstring out = L"\"";
    unsigned slashes = 0;
    for (wchar_t c : s) {
        if (c == L'\\') { ++slashes; continue; }
        if (c == L'"') { out.append(slashes * 2 + 1, L'\\'); out += L'"'; slashes = 0; continue; }
        out.append(slashes, L'\\'); slashes = 0; out += c;
    }
    out.append(slashes * 2, L'\\'); out += L'"';
    return out;
}
inline ProcessResult runProcess(const std::wstring& executable,
                               const std::vector<std::wstring>& args,
                               DWORD timeoutMs = 60000,
                               const std::wstring& workingDirectory = {}) {
    ProcessResult r;
    if (executable.empty()) { r.error = "empty executable"; return r; }
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    HANDLE outRead = nullptr, outWrite = nullptr, errRead = nullptr, errWrite = nullptr;
    auto close = [](HANDLE& h) { if (h) { CloseHandle(h); h = nullptr; } };
    if (!CreatePipe(&outRead, &outWrite, &sa, 0) ||
        !CreatePipe(&errRead, &errWrite, &sa, 0)) {
        r.error = "CreatePipe failed"; close(outRead); close(outWrite); close(errRead); close(errWrite); return r;
    }
    SetHandleInformation(outRead, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(errRead, HANDLE_FLAG_INHERIT, 0);
    STARTUPINFOW si{}; si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = outWrite; si.hStdError = errWrite;
    HANDLE input = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               &sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    si.hStdInput = input == INVALID_HANDLE_VALUE ? nullptr : input;
    std::wstring cmd = quoteArg(executable);
    for (const auto& a : args) { cmd += L" "; cmd += quoteArg(a); }
    std::vector<wchar_t> mutableCmd(cmd.begin(), cmd.end()); mutableCmd.push_back(0);
    PROCESS_INFORMATION pi{};
    BOOL ok = CreateProcessW(executable.c_str(), mutableCmd.data(), nullptr, nullptr, TRUE,
                             CREATE_NO_WINDOW | CREATE_SUSPENDED, nullptr,
                             workingDirectory.empty() ? nullptr : workingDirectory.c_str(), &si, &pi);
    close(outWrite); close(errWrite);
    if (input != INVALID_HANDLE_VALUE) CloseHandle(input);
    if (!ok) {
        r.error = "CreateProcessW failed: " + std::to_string(GetLastError());
        close(outRead); close(errRead); return r;
    }
    r.launched = true;
    HANDLE job = CreateJobObjectW(nullptr, nullptr);
    bool jobAssigned = false;
    if (job) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)) &&
            AssignProcessToJobObject(job, pi.hProcess)) jobAssigned = true;
    }
    // Refuse to run a process that cannot be reliably terminated as a tree.
    if (!jobAssigned) {
        TerminateProcess(pi.hProcess, 1);
        r.error = "could not assign process to kill-on-close job";
        close(outRead); close(errRead); CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        if (job) CloseHandle(job); r.launched = false; return r;
    }
    auto drain = [](HANDLE h, std::string& dest) {
        char buf[8192]; DWORD n = 0;
        while (ReadFile(h, buf, sizeof(buf), &n, nullptr) && n) dest.append(buf, n);
    };
    std::thread stdoutThread(drain, outRead, std::ref(r.stdoutText));
    std::thread stderrThread(drain, errRead, std::ref(r.stderrText));
    ResumeThread(pi.hThread);
    DWORD wait = WaitForSingleObject(pi.hProcess, timeoutMs);
    if (wait == WAIT_TIMEOUT) {
        r.timedOut = true;
        TerminateJobObject(job, 124);
        WaitForSingleObject(pi.hProcess, INFINITE);
    } else if (wait == WAIT_FAILED) {
        r.error = "WaitForSingleObject failed: " + std::to_string(GetLastError());
        TerminateJobObject(job, 125);
        WaitForSingleObject(pi.hProcess, INFINITE);
    }
    GetExitCodeProcess(pi.hProcess, &r.exitCode);
    stdoutThread.join(); stderrThread.join();
    close(outRead); close(errRead);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess); CloseHandle(job);
    return r;
}
} // namespace rawrxd::build
#endif
