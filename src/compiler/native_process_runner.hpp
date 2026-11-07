#pragma once
// Native Windows subprocess runner for the RawrXD compiler/linker pipeline.
// No shell invocation: arguments are passed directly to CreateProcessW.
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <string>
#include <thread>
#include <vector>

namespace rawrxd::build {
struct ProcessResult {
    DWORD exitCode = STILL_ACTIVE;
    bool started = false;
    bool timedOut = false;
    bool outputTruncated = false;
    std::string stdoutText, stderrText;
    std::string error;
};
struct ProcessSpec {
    std::wstring executable;
    std::vector<std::wstring> args;
    std::wstring workingDirectory;
    DWORD timeoutMs = 60000;
    size_t maxOutputBytes = 4 * 1024 * 1024;
};
inline std::wstring quoteWindowsArg(const std::wstring& arg) {
    if (arg.empty()) return L"\"\"";
    if (arg.find_first_of(L" \t\n\v\"") == std::wstring::npos) return arg;
    std::wstring out = L"\"";
    size_t slashes = 0;
    for (wchar_t c : arg) {
        if (c == L'\\') { ++slashes; continue; }
        if (c == L'"') {
            out.append(slashes * 2 + 1, L'\\');
            out += L'"';
            slashes = 0;
            continue;
        }
        out.append(slashes, L'\\');
        slashes = 0;
        out += c;
    }
    out.append(slashes * 2, L'\\');
    out += L'"';
    return out;
}
class Handle {
public:
    explicit Handle(HANDLE h = nullptr) : h_(h) {}
    ~Handle() { reset(); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    HANDLE get() const { return h_; }
    HANDLE release() { HANDLE h = h_; h_ = nullptr; return h; }
    void reset(HANDLE h = nullptr) {
        if (h_ && h_ != INVALID_HANDLE_VALUE) CloseHandle(h_);
        h_ = h;
    }
private:
    HANDLE h_;
};
inline ProcessResult runProcess(const ProcessSpec& spec) {
    ProcessResult result;
    if (spec.executable.empty() || spec.timeoutMs == 0) {
        result.error = "executable and nonzero timeout required";
        return result;
    }
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    HANDLE outReadRaw = nullptr, outWriteRaw = nullptr;
    HANDLE errReadRaw = nullptr, errWriteRaw = nullptr;
    if (!CreatePipe(&outReadRaw, &outWriteRaw, &sa, 0)) {
        result.error = "stdout pipe creation failed"; return result;
    }
    Handle outRead(outReadRaw), outWrite(outWriteRaw);
    if (!CreatePipe(&errReadRaw, &errWriteRaw, &sa, 0)) {
        result.error = "stderr pipe creation failed"; return result;
    }
    Handle errRead(errReadRaw), errWrite(errWriteRaw);
    if (!SetHandleInformation(outRead.get(), HANDLE_FLAG_INHERIT, 0) ||
        !SetHandleInformation(errRead.get(), HANDLE_FLAG_INHERIT, 0)) {
        result.error = "pipe inheritance configuration failed"; return result;
    }
    // Prevent the child from reading IDE console input.
    Handle input(CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                             &sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (input.get() == INVALID_HANDLE_VALUE) {
        result.error = "NUL input open failed"; return result;
    }
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = input.get();
    si.hStdOutput = outWrite.get();
    si.hStdError = errWrite.get();
    std::wstring command = quoteWindowsArg(spec.executable);
    for (const auto& arg : spec.args) command += L" " + quoteWindowsArg(arg);
    std::vector<wchar_t> mutableCommand(command.begin(), command.end());
    mutableCommand.push_back(L'\0');
    PROCESS_INFORMATION pi{};
    // CREATE_SUSPENDED permits assigning the job before user code runs.
    if (!CreateProcessW(spec.executable.c_str(), mutableCommand.data(), nullptr, nullptr,
                        TRUE, CREATE_NO_WINDOW | CREATE_SUSPENDED, nullptr,
                        spec.workingDirectory.empty() ? nullptr : spec.workingDirectory.c_str(),
                        &si, &pi)) {
        result.error = "CreateProcessW failed: " + std::to_string(GetLastError());
        return result;
    }
    Handle process(pi.hProcess), primaryThread(pi.hThread);
    Handle job(CreateJobObjectW(nullptr, nullptr));
    if (!job.get()) {
        TerminateProcess(process.get(), 1);
        WaitForSingleObject(process.get(), INFINITE);
        result.error = "CreateJobObjectW failed"; return result;
    }
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(job.get(), JobObjectExtendedLimitInformation,
                                 &limits, sizeof(limits)) ||
        !AssignProcessToJobObject(job.get(), process.get())) {
        TerminateProcess(process.get(), 1);
        WaitForSingleObject(process.get(), INFINITE);
        result.error = "job assignment failed (nested job restrictions?)";
        return result;
    }
    result.started = true;
    // Parent must close its write ends so readers can observe EOF.
    outWrite.reset();
    errWrite.reset();
    auto reader = [&](HANDLE pipe, std::string& destination) {
        char buffer[8192];
        DWORD count = 0;
        while (ReadFile(pipe, buffer, sizeof(buffer), &count, nullptr) && count) {
            const size_t remaining = spec.maxOutputBytes > destination.size()
                ? spec.maxOutputBytes - destination.size() : 0;
            const size_t copy = std::min(remaining, static_cast<size_t>(count));
            destination.append(buffer, copy);
            if (copy != count) result.outputTruncated = true;
        }
    };
    // Each pipe must be drained concurrently to avoid compiler deadlocks.
    std::thread stdoutReader(reader, outRead.get(), std::ref(result.stdoutText));
    std::thread stderrReader(reader, errRead.get(), std::ref(result.stderrText));
    if (ResumeThread(primaryThread.get()) == static_cast<DWORD>(-1)) {
        TerminateJobObject(job.get(), 1);
        result.error = "ResumeThread failed";
    } else {
        const DWORD wait = WaitForSingleObject(process.get(), spec.timeoutMs);
        if (wait == WAIT_TIMEOUT) {
            result.timedOut = true;
            TerminateJobObject(job.get(), 1);
        } else if (wait != WAIT_OBJECT_0) {
            result.error = "process wait failed: " + std::to_string(GetLastError());
            TerminateJobObject(job.get(), 1);
        }
    }
    WaitForSingleObject(process.get(), INFINITE);
    GetExitCodeProcess(process.get(), &result.exitCode);
    // TerminateJobObject ensures descendants do not retain inherited pipe writers.
    // Successful builds may launch descendants; the job remains alive until process
    // completion, and normal EOF requires all descendants to close inherited handles.
    stdoutReader.join();
    stderrReader.join();
    return result;
}
} // namespace rawrxd::build
