// Windows-only subprocess runner: concurrent pipe draining, deadline and process-tree kill.
// Standalone adapter for the IDE build system; no model, Ollama or Qt dependencies.
#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <functional>
#include <string>
#include <thread>
#include <vector>
#include <utility>

namespace RawrXD { namespace Build {
struct ProcessResult {
    DWORD exitCode = 0;
    bool launched = false, timedOut = false;
    std::string stdoutText, stderrText;
    std::string error;
};
inline std::wstring Quote(const std::wstring& s) {
    std::wstring out = L"\"";
    unsigned slash = 0;
    for (wchar_t c : s) {
        if (c == L'\\') { ++slash; continue; }
        if (c == L'"') { out.append(slash * 2 + 1, L'\\'); out += c; slash = 0; continue; }
        out.append(slash, L'\\'); slash = 0; out += c;
    }
    out.append(slash * 2, L'\\'); return out + L"\"";
}
inline void Drain(HANDLE pipe, std::string& dst) {
    char buf[8192]; DWORD n;
    while (ReadFile(pipe, buf, sizeof(buf), &n, nullptr) && n) dst.append(buf, n);
    CloseHandle(pipe);
}
inline ProcessResult Run(const std::wstring& exe, const std::vector<std::wstring>& args,
                         const std::wstring& cwd, DWORD timeoutMs) {
    ProcessResult result;
    if (exe.empty()) { result.error = "empty executable"; return result; }
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    HANDLE outRead = nullptr, outWrite = nullptr, errRead = nullptr, errWrite = nullptr;
    auto close = [](HANDLE& h) { if (h) { CloseHandle(h); h = nullptr; } };
    if (!CreatePipe(&outRead, &outWrite, &sa, 0) ||
        !CreatePipe(&errRead, &errWrite, &sa, 0)) {
        result.error = "CreatePipe failed";
        close(outRead); close(outWrite); close(errRead); close(errWrite); return result;
    }
    if (!SetHandleInformation(outRead, HANDLE_FLAG_INHERIT, 0) ||
        !SetHandleInformation(errRead, HANDLE_FLAG_INHERIT, 0)) {
        result.error = "SetHandleInformation failed";
        close(outRead); close(outWrite); close(errRead); close(errWrite); return result;
    }
    HANDLE job = CreateJobObjectW(nullptr, nullptr);
    if (!job) {
        result.error = "CreateJobObject failed";
        close(outRead); close(outWrite); close(errRead); close(errWrite); return result;
    }
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) {
        result.error = "SetInformationJobObject failed";
        CloseHandle(job); close(outRead); close(outWrite); close(errRead); close(errWrite); return result;
    }
    // CreateProcessW with a non-null application name does not search PATH.
    // Resolve cl.exe/link.exe explicitly while preserving absolute paths.
    std::wstring resolvedExe = exe;
    if (exe.find(L'\\\\') == std::wstring::npos &&
        exe.find(L'/') == std::wstring::npos) {
        DWORD required = SearchPathW(nullptr, exe.c_str(), nullptr, 0, nullptr, nullptr);
        if (!required) {
            result.error = "executable not found on PATH";
            CloseHandle(job); close(outRead); close(outWrite); close(errRead); close(errWrite);
            return result;
        }
        std::vector<wchar_t> resolved(required);
        DWORD actual = SearchPathW(nullptr, exe.c_str(), nullptr, required, resolved.data(), nullptr);
        if (!actual || actual >= required) {
            result.error = "SearchPathW failed";
            CloseHandle(job); close(outRead); close(outWrite); close(errRead); close(errWrite);
            return result;
        }
        resolvedExe.assign(resolved.data(), actual);
    }
    std::wstring command = Quote(resolvedExe);
    for (const auto& a : args) command += L" " + Quote(a);
    std::vector<wchar_t> mutableCmd(command.begin(), command.end());
    mutableCmd.push_back(0);
    STARTUPINFOW si{}; si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = outWrite; si.hStdError = errWrite;
    PROCESS_INFORMATION pi{};
    // CREATE_SUSPENDED prevents descendants escaping the job before assignment.
    BOOL ok = CreateProcessW(resolvedExe.c_str(), mutableCmd.data(), nullptr, nullptr, TRUE,
                              CREATE_NO_WINDOW | CREATE_SUSPENDED, nullptr,
                              cwd.empty() ? nullptr : cwd.c_str(), &si, &pi);
    close(outWrite); close(errWrite);
    if (!ok) {
        result.error = "CreateProcessW failed: " + std::to_string(GetLastError());
        CloseHandle(job); close(outRead); close(errRead); return result;
    }
    result.launched = true;
    if (!AssignProcessToJobObject(job, pi.hProcess)) {
        result.error = "AssignProcessToJobObject failed: " + std::to_string(GetLastError());
        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess); CloseHandle(job);
        close(outRead); close(errRead); return result;
    }
    std::thread stdoutThread(Drain, outRead, std::ref(result.stdoutText));
    std::thread stderrThread(Drain, errRead, std::ref(result.stderrText));
    ResumeThread(pi.hThread);
    DWORD wait = WaitForSingleObject(pi.hProcess, timeoutMs);
    if (wait == WAIT_TIMEOUT || wait == WAIT_FAILED) {
        result.timedOut = wait == WAIT_TIMEOUT;
        if (wait == WAIT_FAILED) result.error = "WaitForSingleObject failed";
        TerminateJobObject(job, 1);
        WaitForSingleObject(pi.hProcess, INFINITE);
    }
    GetExitCodeProcess(pi.hProcess, &result.exitCode);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    CloseHandle(job);
    stdoutThread.join(); stderrThread.join();
    return result;
}
}} // namespace RawrXD::Build
#else
#error Windows-only process runner
#endif
