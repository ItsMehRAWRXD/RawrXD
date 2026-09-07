// rawr_terminal_session.cpp
#include "rawr_terminal_session.hpp"
#include <cstdio>

namespace rawr::term {

void EnsureTermRoot() {
    CreateDirectoryA("G:\\~dev\\rawrxd\\.rawrxd", nullptr);
    CreateDirectoryA(TermRoot().c_str(), nullptr);
}

bool AppendTermLog(const std::string& name, const char* p, size_t n) {
    if (!p || !n) return true;
    EnsureTermRoot();
    FILE* f = fopen((TermRoot() + "\\" + name + ".log").c_str(), "ab");
    if (!f) return false;
    fwrite(p, 1, n, f);
    fclose(f);
    return true;
}

std::string ReadTermLogTail(const std::string& name, size_t maxBytes) {
    FILE* f = fopen((TermRoot() + "\\" + name + ".log").c_str(), "rb");
    if (!f) return {};
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    if (sz <= 0) { fclose(f); return {}; }
    size_t n = (size_t)sz > maxBytes ? maxBytes : (size_t)sz;
    fseek(f, (long)((size_t)sz - n), SEEK_SET);
    std::string out(n, '\0');
    fread(&out[0], 1, n, f);
    fclose(f);
    return out;
}

bool WriteTermMeta(const std::string& name, DWORD pid, int alive, int exitCode,
                   const std::string& cmd) {
    EnsureTermRoot();
    FILE* f = fopen((TermRoot() + "\\" + name + ".meta").c_str(), "wb");
    if (!f) return false;
    fprintf(f, "name=%s\npid=%lu\nalive=%d\nexit=%d\ncmd=%s\n", name.c_str(),
            (unsigned long)pid, alive, exitCode, cmd.c_str());
    fclose(f);
    return true;
}

void TermSession::stopReader() {
    stopReq = true;
    if (reader.joinable()) reader.join();
}

void TermSession::appendRing(const char* p, size_t n) {
    std::lock_guard<std::mutex> g(ringMu);
    ring.append(p, n);
    if (ring.size() > 262144) ring.erase(0, ring.size() - 262144);
}

std::string TermSession::tail(size_t maxBytes) {
    std::lock_guard<std::mutex> g(ringMu);
    if (ring.size() <= maxBytes) return ring;
    return ring.substr(ring.size() - maxBytes);
}

static void readerMain(TermSession* sp) {
    TermSession& s = *sp;
    char buf[4096];
    while (!s.stopReq.load()) {
        DWORD n = WinProcessPeekRead(s.proc.hOutR, buf, sizeof(buf));
        if (n) {
            s.appendRing(buf, n);
            AppendTermLog(s.name, buf, n);
            s.outBytes += n;
        }
        n = WinProcessPeekRead(s.proc.hErrR, buf, sizeof(buf));
        if (n) {
            s.appendRing(buf, n);
            AppendTermLog(s.name, buf, n);
            s.errBytes += n;
        }
        if (!WinProcessAlive(s.proc)) {
            n = WinProcessPeekRead(s.proc.hOutR, buf, sizeof(buf));
            if (n) { s.appendRing(buf, n); AppendTermLog(s.name, buf, n); s.outBytes += n; }
            n = WinProcessPeekRead(s.proc.hErrR, buf, sizeof(buf));
            if (n) { s.appendRing(buf, n); AppendTermLog(s.name, buf, n); s.errBytes += n; }
            s.exitCode = WinProcessExitCode(s.proc);
            s.alive = false;
            WriteTermMeta(s.name, s.proc.pid, 0, s.exitCode, s.cmd);
            break;
        }
        Sleep(15);
    }
}

bool SessionStart(TermSession& s, const std::string& name,
                  const std::string& cmd) {
    s.name = name;
    s.cmd = cmd;
    s.exitCode = -1;
    s.stopReq = false;
    s.outBytes = s.errBytes = 0;
    { std::lock_guard<std::mutex> g(s.ringMu); s.ring.clear(); }
    EnsureTermRoot();
    DeleteFileA((TermRoot() + "\\" + name + ".log").c_str());
    if (!WinProcessSpawn(s.proc, Utf8ToWide(cmd))) return false;
    s.alive = true;
    WriteTermMeta(s.name, s.proc.pid, 1, -1, s.cmd);
    s.reader = std::thread(readerMain, &s);
    return true;
}

bool SessionSend(TermSession& s, const std::string& input) {
    if (!s.alive.load()) return false;
    std::string line = input;
    if (line.empty() || line.back() != '\n') line.push_back('\n');
    return WinProcessWriteStdin(s.proc, line.data(), (DWORD)line.size());
}

bool SessionStop(TermSession& s) {
    s.stopReq = true;
    bool ok = WinProcessTerminate(s.proc, 1);
    if (s.reader.joinable()) s.reader.join();
    s.exitCode = WinProcessExitCode(s.proc);
    s.alive = false;
    WriteTermMeta(s.name, s.proc.pid, 0, s.exitCode, s.cmd);
    return ok;
}

void SessionPoll(TermSession& s) {
    if (s.alive.load() && !WinProcessAlive(s.proc)) {
        s.exitCode = WinProcessExitCode(s.proc);
        s.alive = false;
        WriteTermMeta(s.name, s.proc.pid, 0, s.exitCode, s.cmd);
    }
}

} // namespace rawr::term
