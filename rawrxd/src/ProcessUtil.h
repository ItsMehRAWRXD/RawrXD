// ProcessUtil.h — shared primitives for RAWRXD_LOCAL_AGENT_E2E_001,
// RAWRXD_RESPONSE_CODED_AGENT_001 and RAWRXD_SINGLE_WRITER_AUTHORITY_001
//
// Four defects were duplicated across three subsystems, each copy fixed in
// isolation and each copy still wrong somewhere. They live here once instead:
//
//   1. Shell execution. Both agent cores built a command STRING and handed it
//      to _popen, and WriterLeaseAuthority did the same for `git -C "<root>"`
//      and for `git commit -m "<message>"`. A quote, & or | in any of those
//      values escaped into the shell. runProcessNoShell passes an argument
//      vector to CreateProcess; no shell parses it.
//
//   2. Path confinement. Both agent cores tested containment with a raw
//      string prefix, so <root>_backup/secret.txt satisfied "is inside
//      <root>". The test is component-wise and requires a separator boundary.
//
//   3. Bounded reads. ResponseCodedAgent.cpp carried the precedence bug
//      `total < kMax && in.read(...) || in.gcount() > 0`, which never
//      terminates. readBounded is the single correct form.
//
//   4. Truncated observations. AgentCore's runner broke out of the read loop
//      at the byte cap, closing the pipe while the child was still writing,
//      so a large `git status --porcelain` made git die of a broken pipe and
//      its non-zero exit was reported as a genuine tool failure.
#pragma once

#ifdef _WIN32
// A header that includes <windows.h> has to neutralise the min/max macros
// itself. Without this, every translation unit that pulls this in inherits
// function-like `max`/`min` macros and its own `std::max(...)` calls stop
// compiling with C2589 "illegal token on right side of '::'".
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <system_error>
#include <vector>

namespace rawrxd { namespace procutil {

namespace fs = std::filesystem;

enum class RunResult { Ok, SpawnFailed, TimedOut };

// Run a fixed executable with a fixed argument vector. No shell is involved, so
// nothing in any argument can be reinterpreted as a metacharacter, redirection
// or pipeline. Output is fully drained from the pipe — truncating the retained
// buffer rather than closing the read end — so the child sees a normal
// completion and its exit code means what it says.
inline RunResult runProcessNoShell(const std::string& exe,
                                   const std::vector<std::string>& args,
                                   std::string& out,
                                   int32_t&    exitCode,
                                   size_t      capBytes = 8000,
                                   DWORD       timeoutMs = 15000) {
    out.clear();
    exitCode = -1;
#ifdef _WIN32
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof sa;
    sa.bInheritHandle = TRUE;
    HANDLE rd = nullptr, wr = nullptr;
    if (!CreatePipe(&rd, &wr, &sa, 0)) return RunResult::SpawnFailed;
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);   // read end not inherited

    std::string cmdLine = "\"" + exe + "\"";
    for (const auto& a : args) cmdLine += " \"" + a + "\"";

    std::vector<char> mutableCmd(cmdLine.begin(), cmdLine.end());
    mutableCmd.push_back('\0');

    STARTUPINFOA si{};
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = wr;
    si.hStdError  = wr;
    si.hStdInput  = nullptr;

    PROCESS_INFORMATION pi{};
    const BOOL created = CreateProcessA(nullptr, mutableCmd.data(), nullptr, nullptr, TRUE,
                                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(wr);
    if (!created) { CloseHandle(rd); return RunResult::SpawnFailed; }

    char buf[4096];
    DWORD n = 0;
    while (ReadFile(rd, buf, sizeof buf, &n, nullptr) && n > 0) {
        if (out.size() < capBytes) {
            const size_t room = capBytes - out.size();
            out.append(buf, (n < room) ? n : room);   // retain up to the cap
        }
        // Keep draining past the cap. Breaking here would close the pipe while
        // the child is still writing, which makes it exit non-zero and turns a
        // truncated observation into a reported tool failure.
    }
    CloseHandle(rd);

    const DWORD waited = WaitForSingleObject(pi.hProcess, timeoutMs);
    DWORD code = 0;
    if (waited == WAIT_OBJECT_0) {
        GetExitCodeProcess(pi.hProcess, &code);
        exitCode = static_cast<int32_t>(code);
    } else if (waited == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, 2000);
        // 259 is STILL_ACTIVE. Reporting it as a tool exit code reads as a
        // genuine failure of the command, which is a different fact.
        exitCode = static_cast<int32_t>(STILL_ACTIVE);
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return (waited == WAIT_TIMEOUT) ? RunResult::TimedOut : RunResult::Ok;
#else
    (void)exe; (void)args; (void)out; (void)exitCode; (void)capBytes; (void)timeoutMs;
    return RunResult::SpawnFailed;
#endif
}

// True when `canon` is `root` itself or a descendant of it.
//
// The comparison is component-wise on purpose. A prefix test admits
// F:\~dev\rawrxd_backup\keys.txt for root F:\~dev\rawrxd, because the string
// "f:\~dev\rawrxd_backup\keys.txt" does start with "f:\~dev\rawrxd".
inline bool isInsideRoot(const fs::path& canon, const fs::path& root) {
    std::error_code ec;
    const fs::path c = fs::weakly_canonical(canon, ec);
    if (ec) return false;
    const fs::path r = fs::weakly_canonical(root, ec);
    if (ec) return false;

    std::error_code relEc;
    const fs::path rel = c.lexically_relative(r);
    if (relEc) return false;

    const std::string relStr = rel.string();
    if (relStr.empty()) return true;                 // the root itself
    if (relStr == "..") return false;
    // Any leading ".." component means the target escapes the root.
    if (relStr.rfind("..", 0) == 0) {
        const size_t after = 2;
        if (relStr.size() == after || relStr[after] == '/' || relStr[after] == '\\')
            return false;
    }
    return true;
}

// Read at most kMax bytes. Terminates on a short read and on reaching the cap.
inline std::string readBounded(const fs::path& p, size_t kMax) {
    std::ifstream in(p, std::ios::binary);
    if (!in) return {};
    std::ostringstream os;
    char buf[1024];
    size_t total = 0;
    // The parenthesisation is the whole point. The old unparenthesised form
    // parsed as `(total < kMax && in.read(..)) || (in.gcount() > 0)`: once
    // total hit kMax the read short-circuited, gcount() kept its stale
    // non-zero value, and `kMax - total` underflowed as size_t.
    while (total < kMax && (in.read(buf, sizeof buf) || in.gcount() > 0)) {
        const size_t got = static_cast<size_t>(in.gcount());
        if (got == 0) break;
        const size_t room = kMax - total;             // total < kMax: no underflow
        const size_t take = (got < room) ? got : room;
        os.write(buf, static_cast<std::streamsize>(take));
        total += take;
        if (got < sizeof buf) break;                  // short read: end of file
    }
    return os.str();
}

}} // namespace rawrxd::procutil
