// RawrXD native build runner: argv-only, no shell expansion.
// Usage: rawrxd_msvc_runner <configure|build|test> <build-dir> [source-dir|target]
// configure <build-dir> <source-dir> [generator] (generator optional)
// build <build-dir> [target]
// test <build-dir> [ctest-regex]
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <vector>
#include <iostream>
#include <filesystem>
#include <thread>
#include <cwchar>

static std::wstring quote(const std::wstring& s) {
    std::wstring out = L"\"";
    size_t slashes = 0;
    for (wchar_t c : s) {
        if (c == L'\\') { ++slashes; continue; }
        if (c == L'"') { out.append(slashes * 2 + 1, L'\\'); out += L'"'; slashes = 0; continue; }
        out.append(slashes, L'\\'); slashes = 0; out += c;
    }
    out.append(slashes * 2, L'\\');
    return out + L"\"";
}
struct OwnedHandle {
    HANDLE h = nullptr;
    explicit OwnedHandle(HANDLE v = nullptr) : h(v) {}
    ~OwnedHandle() { close(); }
    OwnedHandle(const OwnedHandle&) = delete;
    OwnedHandle& operator=(const OwnedHandle&) = delete;
    void close() { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); h = nullptr; }
};
static void copyPipe(HANDLE pipe, HANDLE destination) {
    char buffer[8192];
    DWORD n = 0;
    while (ReadFile(pipe, buffer, sizeof(buffer), &n, nullptr) && n) {
        DWORD offset = 0;
        while (offset < n) {
            DWORD written = 0;
            if (!WriteFile(destination, buffer + offset, n - offset, &written, nullptr) || !written) break;
            offset += written;
        }
    }
}
static int execute(const std::vector<std::wstring>& args, DWORD timeoutMs) {
    if (args.empty() || args[0].empty()) return 2;
    std::wstring command;
    for (const auto& a : args) {
        if (!command.empty()) command += L' ';
        command += quote(a);
    }
    std::vector<wchar_t> buffer(command.begin(), command.end());
    buffer.push_back(0);
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    HANDLE readOut = nullptr, writeOut = nullptr, readErr = nullptr, writeErr = nullptr;
    if (!CreatePipe(&readOut, &writeOut, &sa, 0)) return 127;
    OwnedHandle outRead(readOut), outWrite(writeOut);
    if (!CreatePipe(&readErr, &writeErr, &sa, 0)) return 127;
    OwnedHandle errRead(readErr), errWrite(writeErr);
    if (!SetHandleInformation(outRead.h, HANDLE_FLAG_INHERIT, 0) ||
        !SetHandleInformation(errRead.h, HANDLE_FLAG_INHERIT, 0)) return 127;
    OwnedHandle job(CreateJobObjectW(nullptr, nullptr));
    if (!job.h) return 127;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limit{};
    limit.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(job.h, JobObjectExtendedLimitInformation, &limit, sizeof(limit))) return 127;
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startup.hStdOutput = outWrite.h;
    startup.hStdError = errWrite.h;
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(nullptr, buffer.data(), nullptr, nullptr, TRUE,
                        CREATE_SUSPENDED | CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process)) {
        std::wcerr << L"CreateProcessW failed: " << GetLastError() << L"\n";
        return 127;
    }
    OwnedHandle proc(process.hProcess), thread(process.hThread);
    if (!AssignProcessToJobObject(job.h, proc.h)) {
        std::wcerr << L"AssignProcessToJobObject failed: " << GetLastError() << L"\n";
        TerminateProcess(proc.h, 127);
        return 127;
    }
    outWrite.close();
    errWrite.close();
    std::thread stdoutReader(copyPipe, outRead.h, GetStdHandle(STD_OUTPUT_HANDLE));
    std::thread stderrReader(copyPipe, errRead.h, GetStdHandle(STD_ERROR_HANDLE));
    if (ResumeThread(thread.h) == static_cast<DWORD>(-1)) TerminateJobObject(job.h, 127);
    DWORD wait = WaitForSingleObject(proc.h, timeoutMs);
    DWORD code = 127;
    if (wait == WAIT_TIMEOUT) {
        TerminateJobObject(job.h, 124);
        code = 124;
        std::wcerr << L"Process timed out after " << timeoutMs << L" ms\n";
    } else if (wait == WAIT_OBJECT_0) {
        if (!GetExitCodeProcess(proc.h, &code)) code = 127;
    } else {
        TerminateJobObject(job.h, 127);
    }
    if (wait != WAIT_OBJECT_0) WaitForSingleObject(proc.h, INFINITE);
    job.close(); // Terminate lingering descendants before waiting for pipe EOF.
    stdoutReader.join();
    stderrReader.join();
    return static_cast<int>(code);
}
static bool parseTimeout(const wchar_t* value, DWORD& result) {
    if (!value || !*value || *value == L'-') return false;
    wchar_t* end = nullptr;
    unsigned long long n = std::wcstoull(value, &end, 10);
    if (!end || *end || n < 1 || n > 3600000) return false;
    result = static_cast<DWORD>(n);
    return true;
}
int wmain(int argc, wchar_t** argv) {
    DWORD timeoutMs = 120000;
    int pos = 1;
    if (argc > 2 && std::wstring(argv[1]) == L"--timeout-ms") {
        if (!parseTimeout(argv[2], timeoutMs)) return 2;
        pos = 3;
    }
    if (pos >= argc) return 2;
    const std::wstring action = argv[pos++];
    std::vector<std::wstring> args;
    if (action == L"exec") {
        if (pos >= argc) return 2;
        for (; pos < argc; ++pos) args.emplace_back(argv[pos]);
    } else if (action == L"configure") {
        if (argc - pos < 2 || argc - pos > 3) return 2;
        args = {L"cmake", L"-S", argv[pos+1], L"-B", argv[pos]};
        if (argc - pos == 3) { args.push_back(L"-G"); args.push_back(argv[pos+2]); }
    } else if (action == L"build") {
        if (argc - pos < 1 || argc - pos > 2) return 2;
        args = {L"cmake", L"--build", argv[pos]};
        if (argc - pos == 2) { args.push_back(L"--target"); args.push_back(argv[pos+1]); }
    } else if (action == L"test") {
        if (argc - pos < 1 || argc - pos > 2) return 2;
        args = {L"ctest", L"--test-dir", argv[pos], L"--output-on-failure"};
        if (argc - pos == 2) { args.push_back(L"-R"); args.push_back(argv[pos+1]); }
    } else return 2;
    return execute(args, timeoutMs);
}
