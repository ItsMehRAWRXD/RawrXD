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
static int execute(const std::vector<std::wstring>& args) {
    std::wstring command;
    for (const auto& a : args) {
        if (!command.empty()) command += L' ';
        command += quote(a);
    }
    std::vector<wchar_t> buffer(command.begin(), command.end());
    buffer.push_back(0);
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    // No cmd.exe: arguments are passed directly to the executable.
    if (!CreateProcessW(nullptr, buffer.data(), nullptr, nullptr, FALSE, 0,
                        nullptr, nullptr, &startup, &process)) {
        std::wcerr << L"Could not start tool, Win32 error " << GetLastError() << L"\n";
        return 127;
    }
    CloseHandle(process.hThread);
    DWORD wait = WaitForSingleObject(process.hProcess, INFINITE);
    DWORD code = 1;
    if (wait != WAIT_OBJECT_0 || !GetExitCodeProcess(process.hProcess, &code)) {
        std::wcerr << L"Could not obtain tool exit status\n";
    }
    CloseHandle(process.hProcess);
    return static_cast<int>(code);
}
int wmain(int argc, wchar_t** argv) {
    if (argc < 3 || argc > 5) {
        std::wcerr << L"Usage: rawrxd_msvc_runner configure <build-dir> <source-dir> [generator]\n"
                      L"       rawrxd_msvc_runner build <build-dir> [target]\n"
                      L"       rawrxd_msvc_runner test <build-dir> [regex]\n";
        return 2;
    }
    const std::wstring action = argv[1];
    const std::filesystem::path build = argv[2];
    if (build.empty()) return 2;
    std::vector<std::wstring> args;
    if (action == L"configure") {
        if (argc < 4) return 2;
        args = {L"cmake", L"-S", argv[3], L"-B", build.wstring()};
        if (argc == 5) { args.push_back(L"-G"); args.push_back(argv[4]); }
    } else if (action == L"build") {
        if (argc > 4) return 2;
        args = {L"cmake", L"--build", build.wstring()};
        if (argc == 4) { args.push_back(L"--target"); args.push_back(argv[3]); }
    } else if (action == L"test") {
        if (argc > 4) return 2;
        args = {L"ctest", L"--test-dir", build.wstring(), L"--output-on-failure"};
        if (argc == 4) { args.push_back(L"-R"); args.push_back(argv[3]); }
    } else {
        std::wcerr << L"Unknown action\n";
        return 2;
    }
    return execute(args);
}
