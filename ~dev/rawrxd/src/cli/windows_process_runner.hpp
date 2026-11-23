#pragma once
// Windows-only subprocess runner for compiler and linker tools.
// No shell: caller supplies executable and already-tokenized arguments.
#ifndef _WIN32
#error WindowsProcessRunner requires Windows
#endif
#define NOMINMAX
#include <windows.h>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <stdexcept>
#include <utility>

namespace rawrxd::build {
struct ProcessResult {
    DWORD exit_code = 0;
    bool timed_out = false;
    bool started = false;
    std::string stdout_text;
    std::string stderr_text;
};

inline std::wstring quote_argument(const std::wstring& arg) {
    if (arg.find_first_of(L" \t\n\v\"") == std::wstring::npos && !arg.empty()) return arg;
    std::wstring out = L"\"";
    size_t slashes = 0;
    for (wchar_t c : arg) {
        if (c == L'\\') { ++slashes; continue; }
        if (c == L'"') {
            out.append(slashes * 2 + 1, L'\\');
            out.push_back(L'"');
            slashes = 0;
            continue;
        }
        out.append(slashes, L'\\');
        slashes = 0;
        out.push_back(c);
    }
    out.append(slashes * 2, L'\\');
    out.push_back(L'"');
    return out;
}

class Handle {
public:
    explicit Handle(HANDLE h = nullptr) : h_(h) {}
    ~Handle() { reset(); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    Handle(Handle&& other) noexcept : h_(std::exchange(other.h_, nullptr)) {}
    Handle& operator=(Handle&& other) noexcept {
        if (this != &other) { reset(); h_ = std::exchange(other.h_, nullptr); }
        return *this;
    }
    HANDLE get() const { return h_; }
    HANDLE release() { return std::exchange(h_, nullptr); }
    void reset(HANDLE h = nullptr) {
        if (h_ && h_ != INVALID_HANDLE_VALUE) CloseHandle(h_);
        h_ = h;
    }
private:
    HANDLE h_;
};

inline void drain_pipe(HANDLE pipe, std::string& output) {
    char buffer[8192];
    DWORD count = 0;
    while (ReadFile(pipe, buffer, sizeof(buffer), &count, nullptr) && count)
        output.append(buffer, count);
}

inline ProcessResult run_process(const std::wstring& exe,
                                 const std::vector<std::wstring>& args,
                                 DWORD timeout_ms = 30000,
                                 const std::wstring& working_directory = L"") {
    if (exe.empty()) throw std::invalid_argument("executable is empty");
    ProcessResult result;
    SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
    HANDLE out_read = nullptr, out_write = nullptr;
    HANDLE err_read = nullptr, err_write = nullptr;
    if (!CreatePipe(&out_read, &out_write, &security, 0))
        throw std::runtime_error("stdout pipe creation failed");
    Handle stdout_read(out_read), stdout_write(out_write);
    if (!SetHandleInformation(stdout_read.get(), HANDLE_FLAG_INHERIT, 0))
        throw std::runtime_error("stdout handle inheritance setup failed");
    if (!CreatePipe(&err_read, &err_write, &security, 0))
        throw std::runtime_error("stderr pipe creation failed");
    Handle stderr_read(err_read), stderr_write(err_write);
    if (!SetHandleInformation(stderr_read.get(), HANDLE_FLAG_INHERIT, 0))
        throw std::runtime_error("stderr handle inheritance setup failed");

    Handle job(CreateJobObjectW(nullptr, nullptr));
    if (!job.get()) throw std::runtime_error("job object creation failed");
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(job.get(), JobObjectExtendedLimitInformation,
                                 &limits, sizeof(limits)))
        throw std::runtime_error("job object setup failed");

    std::wstring command = quote_argument(exe);
    for (const auto& arg : args) { command += L" "; command += quote_argument(arg); }
    std::vector<wchar_t> mutable_command(command.begin(), command.end());
    mutable_command.push_back(L'\0');
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    startup.wShowWindow = SW_HIDE;
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startup.hStdOutput = stdout_write.get();
    startup.hStdError = stderr_write.get();
    PROCESS_INFORMATION info{};
    const BOOL created = CreateProcessW(exe.c_str(), mutable_command.data(),
        nullptr, nullptr, TRUE, CREATE_NO_WINDOW | CREATE_SUSPENDED,
        nullptr, working_directory.empty() ? nullptr : working_directory.c_str(),
        &startup, &info);
    if (!created) {
        result.exit_code = GetLastError();
        return result;
    }
    Handle process(info.hProcess), primary_thread(info.hThread);
    result.started = true;
    if (!AssignProcessToJobObject(job.get(), process.get())) {
        TerminateProcess(process.get(), 1);
        WaitForSingleObject(process.get(), INFINITE);
        throw std::runtime_error("job assignment failed (nested job restrictions?)");
    }
    if (ResumeThread(primary_thread.get()) == static_cast<DWORD>(-1)) {
        TerminateJobObject(job.get(), 1);
        WaitForSingleObject(process.get(), INFINITE);
        throw std::runtime_error("process resume failed");
    }
    stdout_write.reset();
    stderr_write.reset();
    std::thread out_thread([&] { drain_pipe(stdout_read.get(), result.stdout_text); });
    std::thread err_thread([&] { drain_pipe(stderr_read.get(), result.stderr_text); });
    const DWORD wait = WaitForSingleObject(process.get(), timeout_ms);
    if (wait != WAIT_OBJECT_0) {
        result.timed_out = (wait == WAIT_TIMEOUT);
        TerminateJobObject(job.get(), 1);
        WaitForSingleObject(process.get(), INFINITE);
    }
    GetExitCodeProcess(process.get(), &result.exit_code);
    // Closing the job kills any descendants that still hold pipe write handles.
    job.reset();
    out_thread.join();
    err_thread.join();
    if (wait == WAIT_FAILED) throw std::runtime_error("process wait failed");
    return result;
}
} // namespace rawrxd::build
