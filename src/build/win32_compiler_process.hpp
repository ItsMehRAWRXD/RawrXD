#pragma once
// Windows compiler subprocess primitive: no shell, concurrent stdout/stderr,
// bounded capture, process-tree timeout and explicit exit status.
// Include in Win32 IDE compiler/build adapters; does not require a model.
#ifndef _WIN32
#error This runner requires Windows
#endif
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

namespace RawrXD::Build {
struct ProcessResult {
    bool launched = false;
    bool timed_out = false;
    bool stdout_truncated = false;
    bool stderr_truncated = false;
    DWORD exit_code = 0xffffffffu;
    DWORD win32_error = 0;
    std::string stdout_text;
    std::string stderr_text;
};
struct ProcessOptions {
    std::wstring executable;
    std::vector<std::wstring> arguments;
    std::wstring working_directory;
    DWORD timeout_ms = 60000;
    size_t max_output_bytes_per_stream = 4 * 1024 * 1024;
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
    HANDLE release() { HANDLE v = h; h = nullptr; return v; }
};
inline std::wstring quote(const std::wstring& arg) {
    if (arg.find_first_of(L" \t\n\v\"") == std::wstring::npos && !arg.empty()) return arg;
    std::wstring out = L"\"";
    size_t slashes = 0;
    for (wchar_t c : arg) {
        if (c == L'\\') { ++slashes; continue; }
        if (c == L'"') {
            out.append(slashes * 2 + 1, L'\\');
            out.push_back(c);
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
inline void drain(HANDLE pipe, std::string& out, size_t cap, bool& truncated) {
    char buffer[8192];
    DWORD read = 0;
    while (ReadFile(pipe, buffer, sizeof(buffer), &read, nullptr) && read) {
        const size_t available = cap > out.size() ? cap - out.size() : 0;
        const size_t take = (std::min)(available, static_cast<size_t>(read));
        out.append(buffer, take);
        if (take < read) truncated = true;
    }
}
} // namespace detail
inline ProcessResult run_process(const ProcessOptions& opt) {
    ProcessResult result;
    if (opt.executable.empty() || opt.executable.find(L'\0') != std::wstring::npos ||
        opt.working_directory.find(L'\0') != std::wstring::npos) {
        result.win32_error = ERROR_INVALID_PARAMETER;
        return result;
    }
    for (const auto& a : opt.arguments) if (a.find(L'\0') != std::wstring::npos) {
        result.win32_error = ERROR_INVALID_PARAMETER;
        return result;
    }
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    HANDLE out_read = nullptr, out_write = nullptr, err_read = nullptr, err_write = nullptr;
    if (!CreatePipe(&out_read, &out_write, &sa, 0)) {
        result.win32_error = GetLastError(); return result;
    }
    detail::Handle ro(out_read), wo(out_write);
    if (!CreatePipe(&err_read, &err_write, &sa, 0)) {
        result.win32_error = GetLastError(); return result;
    }
    detail::Handle re(err_read), we(err_write);
    if (!SetHandleInformation(ro.h, HANDLE_FLAG_INHERIT, 0) ||
        !SetHandleInformation(re.h, HANDLE_FLAG_INHERIT, 0)) {
        result.win32_error = GetLastError(); return result;
    }
    detail::Handle nul(CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                   &sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (nul.h == INVALID_HANDLE_VALUE) {
        result.win32_error = GetLastError(); return result;
    }
    detail::Handle job(CreateJobObjectW(nullptr, nullptr));
    if (!job.h) { result.win32_error = GetLastError(); return result; }
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(job.h, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) {
        result.win32_error = GetLastError(); return result;
    }
    std::wstring cmd = detail::quote(opt.executable);
    for (const auto& a : opt.arguments) { cmd += L" "; cmd += detail::quote(a); }
    std::vector<wchar_t> command(cmd.begin(), cmd.end());
    command.push_back(0);
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = nul.h;
    si.hStdOutput = wo.h;
    si.hStdError = we.h;
    PROCESS_INFORMATION pi{};
    const wchar_t* cwd = opt.working_directory.empty() ? nullptr : opt.working_directory.c_str();
    if (!CreateProcessW(opt.executable.c_str(), command.data(), nullptr, nullptr, TRUE,
                        CREATE_NO_WINDOW | CREATE_SUSPENDED, nullptr, cwd, &si, &pi)) {
        result.win32_error = GetLastError(); return result;
    }
    result.launched = true;
    detail::Handle process(pi.hProcess), thread(pi.hThread);
    // Assign before resuming so descendants are subject to job termination.
    if (!AssignProcessToJobObject(job.h, process.h)) {
        result.win32_error = GetLastError();
        TerminateProcess(process.h, 1);
        WaitForSingleObject(process.h, INFINITE);
        return result;
    }
    if (ResumeThread(thread.h) == static_cast<DWORD>(-1)) {
        result.win32_error = GetLastError();
        TerminateJobObject(job.h, 1);
        WaitForSingleObject(process.h, INFINITE);
        return result;
    }
    wo.reset(); we.reset(); nul.reset();
    std::thread out_reader([&] { detail::drain(ro.h, result.stdout_text,
        opt.max_output_bytes_per_stream, result.stdout_truncated); });
    std::thread err_reader([&] { detail::drain(re.h, result.stderr_text,
        opt.max_output_bytes_per_stream, result.stderr_truncated); });
    const DWORD wait = WaitForSingleObject(process.h, opt.timeout_ms);
    if (wait != WAIT_OBJECT_0) {
        result.timed_out = wait == WAIT_TIMEOUT;
        if (wait == WAIT_FAILED) result.win32_error = GetLastError();
        TerminateJobObject(job.h, 1);
        WaitForSingleObject(process.h, INFINITE);
    }
    GetExitCodeProcess(process.h, &result.exit_code);
    // Closing the job prevents descendants from retaining pipe handles.
    job.reset();
    out_reader.join();
    err_reader.join();
    return result;
}
} // namespace RawrXD::Build
