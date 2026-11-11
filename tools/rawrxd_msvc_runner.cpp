#define NOMINMAX
#include <windows.h>

#include <cstdio>
#include <string>
#include <vector>

namespace {

std::string JsonEscape(const std::string& value) {
    std::string out;
    out.reserve(value.size() + 16);
    for (unsigned char c : value) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char hex[8]; std::snprintf(hex, sizeof(hex), "\\u%04x", c); out += hex;
                } else out.push_back(static_cast<char>(c));
        }
    }
    return out;
}

std::wstring Quote(const std::wstring& arg) {
    if (arg.find_first_of(L" \t\"") == std::wstring::npos) return arg;
    std::wstring out = L"\"";
    size_t slashes = 0;
    for (wchar_t c : arg) {
        if (c == L'\\') { ++slashes; continue; }
        if (c == L'"') {
            out.append(slashes * 2 + 1, L'\\'); out.push_back(L'"'); slashes = 0; continue;
        }
        out.append(slashes, L'\\'); slashes = 0; out.push_back(c);
    }
    out.append(slashes * 2, L'\\'); out.push_back(L'"');
    return out;
}

std::string Run(const std::wstring& cwd, const std::vector<std::wstring>& args, DWORD& exitCode) {
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE readPipe = nullptr, writePipe = nullptr;
    if (!CreatePipe(&readPipe, &writePipe, &sa, 0)) return "CreatePipe failed";
    SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0);

    std::wstring command;
    for (size_t i = 0; i < args.size(); ++i) {
        if (i) command.push_back(L' ');
        command += Quote(args[i]);
    }
    std::vector<wchar_t> mutableCommand(command.begin(), command.end());
    mutableCommand.push_back(L'\0');

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = writePipe;
    si.hStdError = writePipe;
    PROCESS_INFORMATION pi{};
    const BOOL created = CreateProcessW(nullptr, mutableCommand.data(), nullptr, nullptr, TRUE,
                                        CREATE_NO_WINDOW, nullptr,
                                        cwd.empty() ? nullptr : cwd.c_str(), &si, &pi);
    CloseHandle(writePipe);
    if (!created) {
        CloseHandle(readPipe);
        return "CreateProcess failed: " + std::to_string(GetLastError());
    }

    std::string output;
    char buffer[8192];
    DWORD got = 0;
    while (ReadFile(readPipe, buffer, sizeof(buffer), &got, nullptr) && got != 0)
        output.append(buffer, buffer + got);
    CloseHandle(readPipe);
    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return output;
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    std::wstring cwd;
    std::vector<std::wstring> command;
    bool afterSeparator = false;
    for (int i = 1; i < argc; ++i) {
        const std::wstring arg(argv[i]);
        if (!afterSeparator && arg == L"--cwd" && i + 1 < argc) { cwd = argv[++i]; continue; }
        if (!afterSeparator && arg == L"--") { afterSeparator = true; continue; }
        command.push_back(arg);
    }
    if (command.empty()) {
        std::fprintf(stderr, "usage: rawrxd_msvc_runner --cwd <dir> -- <program> [args...]\n");
        return 2;
    }
    DWORD exitCode = 1;
    const std::string output = Run(cwd, command, exitCode);
    std::printf("{\"exit_code\":%lu,\"succeeded\":%s,\"output\":\"%s\"}\n",
                static_cast<unsigned long>(exitCode), exitCode == 0 ? "true" : "false",
                JsonEscape(output).c_str());
    return exitCode == 0 ? 0 : 1;
}
