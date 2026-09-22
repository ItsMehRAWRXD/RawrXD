#include "rawrxd/closure/ProcessRunner.hpp"
#include <algorithm>
#include <array>
#include <cstdio>
#include <thread>
#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#endif

namespace rawrxd::closure {

#ifdef _WIN32
namespace {
std::wstring widen(std::string_view s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring out(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n);
    return out;
}
}
#endif

ProcessResult NativeProcessRunner::run(const ProcessSpec& spec) {
    ProcessResult r;
    const auto start = std::chrono::steady_clock::now();
#ifdef _WIN32
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    HANDLE readPipe = nullptr, writePipe = nullptr;
    if (!CreatePipe(&readPipe, &writePipe, &sa, 0)) return r;
    SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0);

    HANDLE job = CreateJobObjectW(nullptr, nullptr);
    if (job) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION info{};
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(job, JobObjectExtendedLimitInformation, &info, sizeof(info));
    }

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = writePipe;
    si.hStdError = writePipe;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    PROCESS_INFORMATION pi{};

    auto cmd = widen(spec.command_line);
    std::wstring cwd = spec.working_directory.empty() ? L"" : spec.working_directory.wstring();
    BOOL ok = CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, TRUE,
                             CREATE_NO_WINDOW, nullptr,
                             cwd.empty() ? nullptr : cwd.c_str(), &si, &pi);
    CloseHandle(writePipe);
    if (!ok) {
        CloseHandle(readPipe);
        if (job) CloseHandle(job);
        return r;
    }
    r.launched = true;
    if (job) AssignProcessToJobObject(job, pi.hProcess);

    std::string output;
    std::array<char, 4096> buf{};
    bool done = false;
    while (!done) {
        DWORD available = 0;
        if (PeekNamedPipe(readPipe, nullptr, 0, nullptr, &available, nullptr) && available) {
            DWORD got = 0;
            if (ReadFile(readPipe, buf.data(),
                         static_cast<DWORD>(std::min<size_t>(buf.size(), available)),
                         &got, nullptr) && got) output.append(buf.data(), got);
        }
        DWORD wait = WaitForSingleObject(pi.hProcess, 10);
        if (wait == WAIT_OBJECT_0) done = true;
        if (std::chrono::steady_clock::now() - start > spec.timeout) {
            r.timed_out = true;
            if (job) TerminateJobObject(job, 124);
            else TerminateProcess(pi.hProcess, 124);
            WaitForSingleObject(pi.hProcess, INFINITE);
            done = true;
        }
    }
    for (;;) {
        DWORD got = 0;
        if (!ReadFile(readPipe, buf.data(), static_cast<DWORD>(buf.size()), &got, nullptr) || !got) break;
        output.append(buf.data(), got);
    }
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    r.exit_code = static_cast<int>(code);
    r.output = std::move(output);

    CloseHandle(readPipe);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    if (job) CloseHandle(job);
#else
    // Non-Windows fallback exists only so this closure pack can be unit-built elsewhere.
    // RawrXD shipping on Win32 uses CreateProcessW above.
    std::string command = spec.command_line + " 2>&1";
    if (!spec.working_directory.empty())
        command = "cd \"" + spec.working_directory.string() + "\" && " + command;
    FILE* p = popen(command.c_str(), "r");
    if (!p) return r;
    r.launched = true;
    std::array<char, 4096> b{};
    while (fgets(b.data(), static_cast<int>(b.size()), p)) r.output += b.data();
    int code = pclose(p);
    r.exit_code = code;
#endif
    r.elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start);
    return r;
}

} // namespace rawrxd::closure
