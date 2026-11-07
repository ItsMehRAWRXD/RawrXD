#pragma once
// Windows-only compiler subprocess runner. No model/runtime dependency.
// Concurrent stdout/stderr draining, process-tree termination and bounded waits.
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <chrono>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace rawrxd::build {
struct ProcessResult {
    DWORD exitCode = STILL_ACTIVE;
    bool timedOut = false;
    std::string stdoutText;
    std::string stderrText;
    std::string error;
};
namespace detail {
struct Handle {
    HANDLE h = nullptr;
    Handle() = default;
    explicit Handle(HANDLE value) : h(value) {}
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    ~Handle() { reset(); }
    void reset(HANDLE value = nullptr) {
        if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h);
        h = value;
    }
    HANDLE release() { HANDLE value = h; h = nullptr; return value; }
};
inline std::wstring quote(const std::wstring& arg) {
    if (arg.find_first_of(L" \t\"") == std::wstring::npos && !arg.empty()) return arg;
    std::wstring out = L"\"";
    unsigned slashes = 0;
    for (wchar_t c : arg) {
        if (c == L'\\') { ++slashes; continue; }
        if (c == L'\"') {
            out.append(slashes * 2 + 1, L'\\');
            out.push_back(L'\"');
            slashes = 0;
            continue;
        }
        out.append(slashes, L'\\');
        slashes = 0;
        out.push_back(c);
    }
    out.append(slashes * 2, L'\\');
    return out + L"\"";
}
inline void drain(HANDLE pipe, std::string& output) {
    char buffer[8192];
    DWORD read = 0;
    while (ReadFile(pipe, buffer, sizeof(buffer), &read, nullptr) && read)
        output.append(buffer, read);
}
}
inline ProcessResult run(const std::vector<std::wstring>& argv,
                         const std::wstring& workingDirectory = L"",
                         DWORD timeoutMs = 120000) {
    ProcessResult result;
    if (argv.empty() || argv[0].empty()) {
        result.error = "Missing executable";
        return result;
    }
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    detail::Handle outRead, outWrite, errRead, errWrite, nullInput;
    HANDLE r = nullptr, w = nullptr;
    if (!CreatePipe(&r, &w, &sa, 0)) { result.error = "stdout pipe failed"; return result; }
    outRead.reset(r); outWrite.reset(w);
    if (!SetHandleInformation(outRead.h, HANDLE_FLAG_INHERIT, 0)) { result.error = "stdout inheritance failed"; return result; }
    r = w = nullptr;
    if (!CreatePipe(&r, &w, &sa, 0)) { result.error = "stderr pipe failed"; return result; }
    errRead.reset(r); errWrite.reset(w);
    if (!SetHandleInformation(errRead.h, HANDLE_FLAG_INHERIT, 0)) { result.error = "stderr inheritance failed"; return result; }
    nullInput.reset(CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                &sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (nullInput.h == INVALID_HANDLE_VALUE) { result.error = "NUL input failed"; return result; }
    std::wstring command;
    for (const auto& arg : argv) {
        if (!command.empty()) command += L' ';
        command += detail::quote(arg);
    }
    std::vector<wchar_t> mutableCommand(command.begin(), command.end());
    mutableCommand.push_back(0);
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput = nullInput.h;
    si.hStdOutput = outWrite.h;
    si.hStdError = errWrite.h;
    PROCESS_INFORMATION pi{};
    detail::Handle job(CreateJobObjectW(nullptr, nullptr));
    if (!job.h) { result.error = "job creation failed"; return result; }
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(job.h, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) {
        result.error = "job configuration failed"; return result;
    }
    BOOL started = CreateProcessW(argv[0].c_str(), mutableCommand.data(), nullptr, nullptr,
                                  TRUE, CREATE_NO_WINDOW | CREATE_SUSPENDED,
                                  nullptr, workingDirectory.empty() ? nullptr : workingDirectory.c_str(),
                                  &si, &pi);
    if (!started) { result.error = "CreateProcessW failed: " + std::to_string(GetLastError()); return result; }
    detail::Handle process(pi.hProcess), primaryThread(pi.hThread);
    if (!AssignProcessToJobObject(job.h, process.h)) {
        result.error = "AssignProcessToJobObject failed: " + std::to_string(GetLastError());
        TerminateProcess(process.h, 1);
        WaitForSingleObject(process.h, INFINITE);
        return result;
    }
    outWrite.reset();
    errWrite.reset();
    std::thread outThread(detail::drain, outRead.h, std::ref(result.stdoutText));
    std::thread errThread(detail::drain, errRead.h, std::ref(result.stderrText));
    if (ResumeThread(primaryThread.h) == static_cast<DWORD>(-1)) {
        result.error = "ResumeThread failed";
        TerminateJobObject(job.h, 1);
    } else {
        DWORD wait = WaitForSingleObject(process.h, timeoutMs);
        if (wait == WAIT_TIMEOUT) {
            result.timedOut = true;
            TerminateJobObject(job.h, 124);
        } else if (wait != WAIT_OBJECT_0) {
            result.error = "WaitForSingleObject failed";
            TerminateJobObject(job.h, 1);
        }
    }
    WaitForSingleObject(process.h, INFINITE);
    GetExitCodeProcess(process.h, &result.exitCode);
    // Closing job kills any surviving descendants holding the pipe handles.
    job.reset();
    outThread.join();
    errThread.join();
    return result;
}
} // namespace rawrxd::build
#else
#error windows_subprocess_runner.h requires Windows
#endif
