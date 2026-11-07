#pragma once
// Model-independent Windows subprocess runner for native compiler/linker tools.
// Uses argv (no shell), drains stdout/stderr concurrently, and kills the process
// tree through a job object on timeout. Windows-only; header-only for IDE reuse.
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <algorithm>
#include <cstdint>
#include <string>
#include <thread>
#include <vector>

namespace rawrxd::build {
struct ProcessResult {
    DWORD exit_code = STILL_ACTIVE;
    bool launched = false;
    bool timed_out = false;
    DWORD win32_error = ERROR_SUCCESS;
    std::string stdout_text, stderr_text;
};
inline std::wstring quoteArgument(const std::wstring& arg) {
    if (arg.find_first_of(L" \t\n\v\"") == std::wstring::npos && !arg.empty()) return arg;
    std::wstring out = L"\"";
    size_t slashes = 0;
    for (wchar_t c : arg) {
        if (c == L'\\') { ++slashes; continue; }
        if (c == L'"') { out.append(slashes * 2 + 1, L'\\'); out.push_back(L'"'); slashes = 0; continue; }
        out.append(slashes, L'\\'); slashes = 0; out.push_back(c);
    }
    out.append(slashes * 2, L'\\');
    out.push_back(L'"');
    return out;
}
inline ProcessResult runProcess(const std::wstring& executable,
                                const std::vector<std::wstring>& args,
                                DWORD timeout_ms,
                                const std::wstring& working_directory = L"") {
    ProcessResult result;
    if (executable.empty()) { result.win32_error = ERROR_INVALID_PARAMETER; return result; }
    struct Handle {
        HANDLE h = nullptr;
        ~Handle() { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); }
        Handle() = default;
        explicit Handle(HANDLE value) : h(value) {}
        Handle(const Handle&) = delete;
        Handle& operator=(const Handle&) = delete;
    };
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    HANDLE out_read_raw = nullptr, out_write_raw = nullptr;
    HANDLE err_read_raw = nullptr, err_write_raw = nullptr;
    if (!CreatePipe(&out_read_raw, &out_write_raw, &sa, 0)) { result.win32_error = GetLastError(); return result; }
    Handle out_read(out_read_raw), out_write(out_write_raw);
    if (!CreatePipe(&err_read_raw, &err_write_raw, &sa, 0)) { result.win32_error = GetLastError(); return result; }
    Handle err_read(err_read_raw), err_write(err_write_raw);
    if (!SetHandleInformation(out_read.h, HANDLE_FLAG_INHERIT, 0) ||
        !SetHandleInformation(err_read.h, HANDLE_FLAG_INHERIT, 0)) {
        result.win32_error = GetLastError(); return result;
    }
    Handle job(CreateJobObjectW(nullptr, nullptr));
    if (!job.h) { result.win32_error = GetLastError(); return result; }
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(job.h, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) {
        result.win32_error = GetLastError(); return result;
    }
    std::wstring command = quoteArgument(executable);
    for (const auto& arg : args) { command.push_back(L' '); command += quoteArgument(arg); }
    std::vector<wchar_t> mutable_command(command.begin(), command.end());
    mutable_command.push_back(0);
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdOutput = out_write.h;
    startup.hStdError = err_write.h;
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    PROCESS_INFORMATION pi{};
    // CREATE_SUSPENDED avoids child work escaping before job assignment.
    const DWORD flags = CREATE_SUSPENDED | CREATE_NO_WINDOW;
    if (!CreateProcessW(executable.c_str(), mutable_command.data(), nullptr, nullptr, TRUE,
                        flags, nullptr, working_directory.empty() ? nullptr : working_directory.c_str(),
                        &startup, &pi)) {
        result.win32_error = GetLastError(); return result;
    }
    result.launched = true;
    Handle process(pi.hProcess), primary_thread(pi.hThread);
    if (!AssignProcessToJobObject(job.h, process.h)) {
        result.win32_error = GetLastError();
        TerminateProcess(process.h, 1);
        WaitForSingleObject(process.h, INFINITE);
        return result;
    }
    if (ResumeThread(primary_thread.h) == static_cast<DWORD>(-1)) {
        result.win32_error = GetLastError();
        TerminateJobObject(job.h, 1);
        WaitForSingleObject(process.h, INFINITE);
        return result;
    }
    // Parent must release its write ends before readers can observe EOF.
    CloseHandle(out_write.h); out_write.h = nullptr;
    CloseHandle(err_write.h); err_write.h = nullptr;
    auto drain = [](HANDLE pipe, std::string& destination) {
        char buffer[8192];
        DWORD count = 0;
        while (ReadFile(pipe, buffer, sizeof(buffer), &count, nullptr) && count)
            destination.append(buffer, count);
    };
    std::thread stdout_reader(drain, out_read.h, std::ref(result.stdout_text));
    std::thread stderr_reader(drain, err_read.h, std::ref(result.stderr_text));
    const DWORD wait = WaitForSingleObject(process.h, timeout_ms);
    if (wait != WAIT_OBJECT_0) {
        result.timed_out = wait == WAIT_TIMEOUT;
        if (wait == WAIT_FAILED) result.win32_error = GetLastError();
        TerminateJobObject(job.h, 1);
        WaitForSingleObject(process.h, INFINITE);
    }
    if (!GetExitCodeProcess(process.h, &result.exit_code) && !result.win32_error)
        result.win32_error = GetLastError();
    stdout_reader.join();
    stderr_reader.join();
    return result;
}
} // namespace rawrxd::build
#endif
