#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "native_process_runner.hpp"
#include <algorithm>
#include <string>
#include <thread>
#include <vector>

namespace RawrXD::Build {
namespace {
struct Handle {
    HANDLE h = nullptr;
    ~Handle() { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); }
    Handle() = default;
    explicit Handle(HANDLE value) : h(value) {}
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    HANDLE* out() { return &h; }
    void reset(HANDLE value = nullptr) {
        if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h);
        h = value;
    }
};

std::wstring quote(const std::wstring& value) {
    if (value.empty()) return L"\"\"";
    if (value.find_first_of(L" \t\n\v\"") == std::wstring::npos) return value;
    std::wstring result = L"\"";
    unsigned slashes = 0;
    for (wchar_t ch : value) {
        if (ch == L'\\') { ++slashes; continue; }
        if (ch == L'"') {
            result.append(slashes * 2 + 1, L'\\');
            result.push_back(L'"');
            slashes = 0;
            continue;
        }
        result.append(slashes, L'\\');
        slashes = 0;
        result.push_back(ch);
    }
    result.append(slashes * 2, L'\\');
    result.push_back(L'"');
    return result;
}

void drain(HANDLE pipe, std::string& output) {
    constexpr size_t max_capture = 8 * 1024 * 1024;
    char buffer[8192];
    DWORD read = 0;
    while (ReadFile(pipe, buffer, sizeof(buffer), &read, nullptr) && read) {
        const size_t remaining = max_capture - output.size();
        output.append(buffer, std::min(static_cast<size_t>(read), remaining));
    }
}
}

ProcessResult RunProcess(const std::vector<std::wstring>& argv,
                         const std::wstring& working_directory,
                         std::uint32_t timeout_ms) {
    ProcessResult result;
    if (argv.empty() || argv[0].empty() || timeout_ms == 0) {
        result.error = "Executable and nonzero timeout required";
        return result;
    }

    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    Handle out_read, out_write, err_read, err_write;
    if (!CreatePipe(out_read.out(), out_write.out(), &sa, 0) ||
        !CreatePipe(err_read.out(), err_write.out(), &sa, 0)) {
        result.error = "CreatePipe failed";
        return result;
    }
    if (!SetHandleInformation(out_read.h, HANDLE_FLAG_INHERIT, 0) ||
        !SetHandleInformation(err_read.h, HANDLE_FLAG_INHERIT, 0)) {
        result.error = "SetHandleInformation failed";
        return result;
    }

    Handle job(CreateJobObjectW(nullptr, nullptr));
    if (!job.h) {
        result.error = "CreateJobObject failed";
        return result;
    }
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(job.h, JobObjectExtendedLimitInformation,
                                 &limits, sizeof(limits))) {
        result.error = "SetInformationJobObject failed";
        return result;
    }

    std::wstring command;
    for (const auto& arg : argv) {
        if (!command.empty()) command.push_back(L' ');
        command += quote(arg);
    }
    std::vector<wchar_t> command_buffer(command.begin(), command.end());
    command_buffer.push_back(L'\0');

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdOutput = out_write.h;
    startup.hStdError = err_write.h;
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

    PROCESS_INFORMATION pi{};
    const wchar_t* cwd = working_directory.empty() ? nullptr : working_directory.c_str();
    // Suspended launch closes the race between process creation and job assignment.
    if (!CreateProcessW(nullptr, command_buffer.data(), nullptr, nullptr, TRUE,
                        CREATE_NO_WINDOW | CREATE_SUSPENDED, nullptr, cwd,
                        &startup, &pi)) {
        result.error = "CreateProcessW failed: " + std::to_string(GetLastError());
        return result;
    }
    Handle process(pi.hProcess), primary_thread(pi.hThread);
    if (!AssignProcessToJobObject(job.h, process.h)) {
        result.error = "AssignProcessToJobObject failed: " + std::to_string(GetLastError());
        TerminateProcess(process.h, 1);
        WaitForSingleObject(process.h, INFINITE);
        return result;
    }
    result.launched = true;

    // Parent must close its copies of write handles or readers never see EOF.
    out_write.reset();
    err_write.reset();
    std::thread out_thread(drain, out_read.h, std::ref(result.stdout_text));
    std::thread err_thread(drain, err_read.h, std::ref(result.stderr_text));

    if (ResumeThread(primary_thread.h) == static_cast<DWORD>(-1)) {
        result.error = "ResumeThread failed";
        TerminateJobObject(job.h, 1);
        WaitForSingleObject(process.h, INFINITE);
    } else {
        const DWORD wait = WaitForSingleObject(process.h, timeout_ms);
        if (wait == WAIT_TIMEOUT) {
            result.timed_out = true;
            result.error = "Process timeout";
            TerminateJobObject(job.h, 1);
            WaitForSingleObject(process.h, INFINITE);
        } else if (wait != WAIT_OBJECT_0) {
            result.error = "WaitForSingleObject failed";
            TerminateJobObject(job.h, 1);
            WaitForSingleObject(process.h, INFINITE);
        }
    }
    GetExitCodeProcess(process.h, &result.exit_code);
    // Kill any surviving descendants that inherited stdout/stderr handles so
    // both drain threads receive EOF even when the direct child has exited.
    job.reset();
    out_thread.join();
    err_thread.join();
    return result;
}
} // namespace RawrXD::Build
#endif
