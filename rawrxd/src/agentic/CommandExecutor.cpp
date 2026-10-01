// ============================================================================
// CommandExecutor.cpp — RAWRXD_AGENTIC_COMMAND_EXECUTOR_001
// ============================================================================
#include "agentic/CommandExecutor.h"

#include <windows.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

namespace rawrxd {
namespace agentic {
namespace {

struct StreamCapture {
    std::string text;
    std::size_t dropped = 0;
    bool overflowed = false;
};

// Drains a pipe until EOF, appending up to `cap` bytes and counting the rest.
// Runs on its own thread so the child never blocks on a full pipe buffer.
void DrainPipe(HANDLE pipe, StreamCapture& capture, std::size_t cap) {
    char buffer[8192];
    for (;;) {
        DWORD read = 0;
        if (!ReadFile(pipe, buffer, sizeof(buffer), &read, nullptr) || read == 0) break;
        if (capture.text.size() < cap) {
            const std::size_t room = cap - capture.text.size();
            const std::size_t take = (read < room) ? read : room;
            capture.text.append(buffer, take);
            if (take < read) {
                capture.dropped += read - take;
                capture.overflowed = true;
            }
        } else {
            capture.dropped += read;
            capture.overflowed = true;
        }
    }
}

std::string Win32ErrorText(const char* prefix) {
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%lu", static_cast<unsigned long>(GetLastError()));
    return std::string(prefix) + " (win32=" + buf + ")";
}

std::wstring Widen(const std::string& s) {
    if (s.empty()) return std::wstring();
    const int needed =
        MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), nullptr, 0);
    if (needed <= 0) return std::wstring();
    std::wstring out(static_cast<std::size_t>(needed), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), &out[0], needed);
    return out;
}

} // namespace

std::wstring CommandExecutor::QuoteArg(const std::wstring& arg) {
    // CommandLineToArgvW rules: backslashes are literal unless they precede a
    // double quote, in which case they are doubled and the quote is escaped.
    if (!arg.empty() &&
        arg.find_first_of(L" \t\n\v\"") == std::wstring::npos) {
        return arg;
    }
    std::wstring out;
    out.push_back(L'"');
    for (std::size_t i = 0; i < arg.size(); ++i) {
        std::size_t backslashes = 0;
        while (i < arg.size() && arg[i] == L'\\') {
            ++i;
            ++backslashes;
        }
        if (i == arg.size()) {
            out.append(backslashes * 2, L'\\');
            break;
        }
        if (arg[i] == L'"') {
            out.append(backslashes * 2 + 1, L'\\');
            out.push_back(L'"');
        } else {
            out.append(backslashes, L'\\');
            out.push_back(arg[i]);
        }
    }
    out.push_back(L'"');
    return out;
}

std::vector<std::wstring> CommandExecutor::SplitCommand(const std::string& command) {
    std::vector<std::wstring> argv;
    std::wstring current;
    bool inQuotes = false;
    bool started = false;

    for (std::size_t i = 0; i < command.size(); ++i) {
        const char c = command[i];
        if (c == '\\') {
            std::size_t backslashes = 0;
            while (i < command.size() && command[i] == '\\') {
                ++i;
                ++backslashes;
            }
            if (i < command.size() && command[i] == '"') {
                current.append(backslashes / 2, L'\\');
                if ((backslashes % 2) == 0) {
                    inQuotes = !inQuotes;
                } else {
                    current.push_back(L'"');
                }
                started = true;
            } else {
                current.append(backslashes, L'\\');
                started = true;
                if (i < command.size()) {
                    current.push_back(static_cast<wchar_t>(command[i]));
                    ++i;
                    started = true;
                }
            }
            continue;
        }
        if (c == '"') {
            inQuotes = !inQuotes;
            started = true;
            continue;
        }
        if (!inQuotes && (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f')) {
            if (started) {
                argv.push_back(current);
                current.clear();
                started = false;
            }
            continue;
        }
        if (c == '\0') continue;  // a NUL cannot cross into a command line
        current.push_back(static_cast<wchar_t>(c));
        started = true;
    }
    if (started) argv.push_back(current);
    return argv;
}

bool CommandExecutor::PathExists(const std::string& path) {
    const std::wstring wide = Widen(path);
    if (wide.empty()) return false;
    return GetFileAttributesW(wide.c_str()) != INVALID_FILE_ATTRIBUTES;
}

bool CommandExecutor::IsDirectory(const std::string& path) {
    const std::wstring wide = Widen(path);
    if (wide.empty()) return false;
    const DWORD attrs = GetFileAttributesW(wide.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

std::uint64_t CommandExecutor::FileSizeBytes(const std::string& path) {
    const std::wstring wide = Widen(path);
    if (wide.empty()) return 0;
    WIN32_FILE_ATTRIBUTE_DATA data{};
    if (!GetFileAttributesExW(wide.c_str(), GetFileExInfoStandard, &data)) return 0;
    return (static_cast<std::uint64_t>(data.nFileSizeHigh) << 32) |
           static_cast<std::uint64_t>(data.nFileSizeLow);
}

CommandExecutor::Result CommandExecutor::RunArgv(const std::vector<std::wstring>& argv,
                                                 const Options& options) {
    Result result;
    if (argv.empty()) {
        result.error = "empty command";
        return result;
    }

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE outRead = nullptr;
    HANDLE outWrite = nullptr;
    HANDLE errRead = nullptr;
    HANDLE errWrite = nullptr;
    if (!CreatePipe(&outRead, &outWrite, &sa, 0) || !CreatePipe(&errRead, &errWrite, &sa, 0)) {
        result.error = Win32ErrorText("CreatePipe failed");
        if (outRead) CloseHandle(outRead);
        if (errRead) CloseHandle(errRead);
        return result;
    }
    // The child must not inherit the read ends, or EOF is never observed.
    SetHandleInformation(outRead, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(errRead, HANDLE_FLAG_INHERIT, 0);

    std::wstring mutableCommandLine;
    for (const auto& arg : argv) {
        if (!mutableCommandLine.empty()) mutableCommandLine.push_back(L' ');
        mutableCommandLine += QuoteArg(arg);
    }
    std::vector<wchar_t> commandBuffer(mutableCommandLine.begin(), mutableCommandLine.end());
    commandBuffer.push_back(L'\0');

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = outWrite;
    si.hStdError = errWrite;
    si.hStdInput = nullptr;  // no console input; children must not block on read

    PROCESS_INFORMATION pi{};
    const ULONGLONG startTick = GetTickCount64();
    const BOOL created =
        CreateProcessW(nullptr, commandBuffer.data(), nullptr, nullptr, TRUE,
                       CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT, nullptr,
                       options.workingDir.empty() ? nullptr : options.workingDir.c_str(), &si,
                       &pi);
    if (!created) {
        result.error = Win32ErrorText("CreateProcessW failed");
        CloseHandle(outRead);
        CloseHandle(outWrite);
        CloseHandle(errRead);
        CloseHandle(errWrite);
        return result;
    }

    // Parent no longer needs the write ends; the child holds its own copies.
    CloseHandle(outWrite);
    CloseHandle(errWrite);

    StreamCapture outCapture;
    StreamCapture errCapture;
    std::thread outThread(DrainPipe, outRead, std::ref(outCapture), options.maxCaptureBytes);
    std::thread errThread(DrainPipe, errRead, std::ref(errCapture), options.maxCaptureBytes);

    const DWORD waitResult = WaitForSingleObject(pi.hProcess, options.timeoutMs);
    if (waitResult == WAIT_TIMEOUT) {
        result.timedOut = true;
        // Kill the whole tree so a child that spawned grandchildren cannot keep
        // the pipes open and stall the drain threads.
        TerminateProcess(pi.hProcess, 1246);
        WaitForSingleObject(pi.hProcess, 5000);
    }

    if (outThread.joinable()) outThread.join();
    if (errThread.joinable()) errThread.join();
    result.elapsedMicros = (GetTickCount64() - startTick) * 1000ULL;

    DWORD exitCode = 0;
    if (GetExitCodeProcess(pi.hProcess, &exitCode)) {
        result.exitCode = exitCode;
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(outRead);
    CloseHandle(errRead);

    result.stdoutText = std::move(outCapture.text);
    result.stdoutBytesDropped = outCapture.dropped;
    result.stderrText = std::move(errCapture.text);
    result.stderrBytesDropped = errCapture.dropped;
    if (outCapture.overflowed) {
        result.stdoutText += "\n...[stdout capture cap reached]";
    }
    if (errCapture.overflowed) {
        result.stderrText += "\n...[stderr capture cap reached]";
    }

    if (result.timedOut) {
        result.error = "process timed out after " + std::to_string(options.timeoutMs) + "ms";
        result.success = false;
    } else {
        result.success = (exitCode == 0);
        if (!result.success && result.exitCode != 0) {
            result.error = "exit code " + std::to_string(result.exitCode);
        }
    }
    return result;
}

CommandExecutor::Result CommandExecutor::Run(const std::string& command, const Options& options) {
    if (command.empty()) {
        Result result;
        result.error = "empty command";
        return result;
    }

    if (!options.allowShell) {
        return RunArgv(SplitCommand(command), options);
    }

    // Explicitly permitted shell path. cmd.exe is used as the program so the
    // command string is not re-parsed by CreateProcess.
    std::vector<std::wstring> argv;
    argv.push_back(L"cmd.exe");
    argv.push_back(L"/d");  // no AutoRun commands from the registry
    argv.push_back(L"/c");
    argv.push_back(Widen(command));
    Options shellOptions = options;
    shellOptions.allowShell = false;  // already resolved to an explicit argv
    return RunArgv(argv, shellOptions);
}

} // namespace agentic
} // namespace rawrxd
