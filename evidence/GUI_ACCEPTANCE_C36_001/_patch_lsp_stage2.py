from pathlib import Path

p = Path(r"g:\~dev\rawrxd\src\win32app\Win32IDE_LSPClient.cpp")
text = p.read_text(encoding="utf-8", errors="replace")
orig = text
n = 0

def repl(old, new, label):
    global text, n
    if old not in text:
        raise SystemExit(f"MISSING: {label}")
    text = text.replace(old, new, 1)
    n += 1
    print("patched", label)

# Track last canonical stage
repl(
    "char g_c36LastPhase[96] = \"none\";\n",
    "char g_c36LastPhase[96] = \"none\";\n"
    "std::atomic<int> g_lspLastStage{0};  // 1=PIPE 2=PROC 3=INIT_SEND 4=INIT_WAIT\n"
    "constexpr const char* kLspStageTelem =\n"
    "    \"G:\\\\~dev\\\\rawrxd\\\\evidence\\\\GUI_ACCEPTANCE_C36_001\\\\LSP_STAGE_TELEMETRY.log\";\n",
    "g_lspLastStage",
)

# Emit LSP_STAGE from c36Phase
old_phase_body = r'''void c36Phase(const char* phase, const char* detail)
{
    if (!phase)
        phase = "?";
    strncpy_s(g_c36LastPhase, phase, _TRUNCATE);
    const uint64_t hb = g_c36Hb[0].load();
    const uint64_t by = g_c36Bytes[0].load();
    char line[768];
    _snprintf_s(line, _TRUNCATE,
                "t_ms=%llu phase=%s detail=%s reader_hb=%llu reader_bytes=%llu\n",
                (unsigned long long)c36SteadyMs(), phase,
                detail ? detail : "-", (unsigned long long)hb,
                (unsigned long long)by);
    std::fputs(line, stderr);
    std::fflush(stderr);'''

new_phase_body = r'''void c36Phase(const char* phase, const char* detail)
{
    if (!phase)
        phase = "?";
    strncpy_s(g_c36LastPhase, phase, _TRUNCATE);
    /* Canonical LSP_STAGE=PROC|PIPE|INIT_SEND|INIT_WAIT OK/FAIL + errno crumbs. */
    const char* stage = nullptr;
    const char* verd = "BEGIN";
    if (std::strncmp(phase, "pipe", 4) == 0 || std::strncmp(phase, "PIPE", 4) == 0) {
        stage = "PIPE";
        verd = (std::strstr(phase, "fail") || (detail && std::strstr(detail, "FAIL")))
                   ? "FAIL"
                   : ((detail && std::strstr(detail, "ok")) ? "OK" : "BEGIN");
        g_lspLastStage.store(1);
    } else if (std::strncmp(phase, "proc", 4) == 0 || std::strncmp(phase, "PROC", 4) == 0 ||
               std::strncmp(phase, "create", 6) == 0) {
        stage = "PROC";
        verd = (std::strstr(phase, "fail") || (detail && std::strstr(detail, "FAIL")))
                   ? "FAIL"
                   : ((detail && (std::strstr(detail, "pid=") || std::strstr(detail, "ok")))
                          ? "OK"
                          : "BEGIN");
        g_lspLastStage.store(2);
    } else if (std::strncmp(phase, "init_send", 9) == 0 ||
               std::strncmp(phase, "INIT_SEND", 9) == 0) {
        stage = "INIT_SEND";
        if (std::strstr(phase, "fail") || std::strstr(phase, "FAIL"))
            verd = "FAIL";
        else if (std::strstr(phase, "ok") || std::strstr(phase, "OK"))
            verd = "OK";
        g_lspLastStage.store(3);
    } else if (std::strncmp(phase, "init_wait", 9) == 0 ||
               std::strncmp(phase, "INIT_WAIT", 9) == 0 ||
               std::strncmp(phase, "response_", 9) == 0 ||
               std::strncmp(phase, "deadlock", 8) == 0 ||
               std::strncmp(phase, "init_fail", 9) == 0 ||
               std::strncmp(phase, "init_pass", 9) == 0) {
        stage = "INIT_WAIT";
        if (std::strstr(phase, "fail") || std::strstr(phase, "TIMEOUT") ||
            std::strstr(phase, "deadlock"))
            verd = "FAIL";
        else if (std::strstr(phase, "ok") || std::strstr(phase, "pass") ||
                 std::strstr(phase, "OK") || std::strstr(phase, "PASS"))
            verd = "OK";
        g_lspLastStage.store(4);
    }
    if (stage) {
        char sline[960];
        _snprintf_s(sline, _TRUNCATE, "LSP_STAGE=%s %s err=0 detail=%s\n", stage, verd,
                    detail ? detail : "-");
        std::fputs(sline, stderr);
        std::fflush(stderr);
        FILE* sf = nullptr;
        if (fopen_s(&sf, kLspStageTelem, "a") == 0 && sf) {
            fputs(sline, sf);
            fclose(sf);
        }
    }
    const uint64_t hb = g_c36Hb[0].load();
    const uint64_t by = g_c36Bytes[0].load();
    char line[768];
    _snprintf_s(line, _TRUNCATE,
                "t_ms=%llu phase=%s detail=%s reader_hb=%llu reader_bytes=%llu\n",
                (unsigned long long)c36SteadyMs(), phase,
                detail ? detail : "-", (unsigned long long)hb,
                (unsigned long long)by);
    std::fputs(line, stderr);
    std::fflush(stderr);'''

repl(old_phase_body, new_phase_body, "c36Phase emit LSP_STAGE")

# Fix classify per user law
old_cls = r'''    /* Both sides blocked, zero pipe progress ⇒ DEADLOCK. */
    if (timedOut && bytes == 0 && readerUp && hb == 0) {
        strncpy_s(g_c36Class, "DEADLOCK", _TRUNCATE);
        return g_c36Class;
    }
    strncpy_s(g_c36Class, "HANDSHAKE_UNFULFILLED", _TRUNCATE);
    return g_c36Class;
}'''

new_cls = r'''    const int last = g_lspLastStage.load();
    /* Hang with no progress before INIT_WAIT ⇒ possible DEADLOCK (lock/pipe full). */
    if (last < 4 && !timedOut) {
        strncpy_s(g_c36Class, "DEADLOCK", _TRUNCATE);
        return g_c36Class;
    }
    /* Hang after INIT_SEND with no bytes ⇒ UNFULFILLED_HANDSHAKE. */
    if (timedOut && bytes == 0) {
        strncpy_s(g_c36Class, "UNFULFILLED_HANDSHAKE", _TRUNCATE);
        return g_c36Class;
    }
    /* Reader up but heartbeat frozen through wait ⇒ DEADLOCK suspect. */
    if (timedOut && readerUp && hb == 0 && bytes == 0) {
        strncpy_s(g_c36Class, "DEADLOCK", _TRUNCATE);
        return g_c36Class;
    }
    strncpy_s(g_c36Class, "HANDSHAKE_PARTIAL", _TRUNCATE);
    return g_c36Class;
}'''

repl(old_cls, new_cls, "c36Classify")

# Pipe setup stamps + SetHandleInformation
old_pipe = r'''    if (!CreatePipe(&hStdinRead, &hStdinWrite, &sa, 0) || !CreatePipe(&hStdoutRead, &hStdoutWrite, &sa, 0))
    {
        status.state = LSPServerState::Error;
        status.lastError = "Failed to create pipes: " + std::to_string(GetLastError());
        logError("startLSPServer", status.lastError);
        c36Phase("pipe_setup", status.lastError.c_str());
        return false;
    }
    {
        char d[256];
        snprintf(d, sizeof(d),
                 "ok duplex parent_stdinW=%p parent_stdoutR=%p",
                 (void*)hStdinWrite, (void*)hStdoutRead);
        c36Phase("pipe_setup", d);
    }

    // Ensure our ends of the pipes are not inherited
    SetHandleInformation(hStdinWrite, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(hStdoutRead, HANDLE_FLAG_INHERIT, 0);'''

new_pipe = r'''    BOOL pipeInOk = CreatePipe(&hStdinRead, &hStdinWrite, &sa, 0);
    DWORD pipeInErr = pipeInOk ? 0 : GetLastError();
    BOOL pipeOutOk = pipeInOk ? CreatePipe(&hStdoutRead, &hStdoutWrite, &sa, 0) : FALSE;
    DWORD pipeOutErr = pipeOutOk ? 0 : GetLastError();
    if (!(pipeInOk && pipeOutOk))
    {
        status.state = LSPServerState::Error;
        status.lastError = "Failed to create pipes: " + std::to_string(pipeOutErr ? pipeOutErr : pipeInErr);
        logError("startLSPServer", status.lastError);
        char d[192];
        snprintf(d, sizeof(d), "FAIL CreatePipe_in=%d/%lu CreatePipe_out=%d/%lu",
                 (int)pipeInOk, (unsigned long)pipeInErr, (int)pipeOutOk,
                 (unsigned long)pipeOutErr);
        c36Phase("pipe_fail", d);
        return false;
    }
    BOOL hiIn = SetHandleInformation(hStdinWrite, HANDLE_FLAG_INHERIT, 0);
    DWORD hiInErr = hiIn ? 0 : GetLastError();
    BOOL hiOut = SetHandleInformation(hStdoutRead, HANDLE_FLAG_INHERIT, 0);
    DWORD hiOutErr = hiOut ? 0 : GetLastError();
    {
        char d[320];
        snprintf(d, sizeof(d),
                 "ok CreatePipe_in=1/0 CreatePipe_out=1/0 SetHandleInfo_in=%d/%lu "
                 "SetHandleInfo_out=%d/%lu parent_stdinW=%p parent_stdoutR=%p "
                 "(no DuplicateHandle)",
                 (int)hiIn, (unsigned long)hiInErr, (int)hiOut,
                 (unsigned long)hiOutErr, (void*)hStdinWrite, (void*)hStdoutRead);
        if (!(hiIn && hiOut)) {
            status.state = LSPServerState::Error;
            status.lastError = d;
            c36Phase("pipe_fail", d);
            return false;
        }
        c36Phase("pipe_ok", d);
    }'''

repl(old_pipe, new_pipe, "pipe")

# PROC stages — find CreateProcess fail/ok phase names
# dump nearby if needed
if 'c36Phase("process' in text or 'c36Phase("proc' in text:
    pass

# Normalize CreateProcess phases if present
for a, b in [
    ('c36Phase("createprocess_fail"', 'c36Phase("proc_fail"'),
    ('c36Phase("CREATEPROCESS_FAIL"', 'c36Phase("proc_fail"'),
    ('c36Phase("process_ok"', 'c36Phase("proc_ok"'),
    ('c36Phase("PROCESS_OK"', 'c36Phase("proc_ok"'),
]:
    if a in text:
        text = text.replace(a, b, 1)
        n += 1
        print("renamed", a, "->", b)

# If CreateProcess still uses generic names, patch common pattern
old_cp_fail = None
# Try to find and upgrade CreateProcess instrumentation
import re
m = re.search(r'if \(!created\)\s*\{.*?return false;\s*\}', text, re.S)
if m:
    block = m.group(0)
    if 'c36Phase' in block and 'proc_fail' not in block and 'PROC' not in block:
        # inject/replace last c36Phase in fail path
        block2 = re.sub(
            r'c36Phase\("[^"]+",\s*d\);',
            'c36Phase("proc_fail", d);',
            block,
            count=1,
        )
        if 'pid=' in block or 'cmd=' in block or 'err=' in block:
            text = text.replace(block, block2, 1)
            n += 1
            print("patched CreateProcess fail phase")

# Ensure PROCESS_OK becomes proc_ok after spawn
text2 = text
# Look for successful spawn stage
for pat in [
    ('c36Phase("process_ok"', 'c36Phase("proc_ok"'),
    ('c36Phase("spawn_ok"', 'c36Phase("proc_ok"'),
]:
    if pat[0] in text:
        text = text.replace(pat[0], pat[1], 1)
        n += 1

# If no proc_ok yet, find snprintf with pid= after CreateProcess success
if 'c36Phase("proc_ok"' not in text:
    m2 = re.search(
        r'(logInfo\("\[LSP\] " \+ cfg\.name \+ " spawned.*?\n)(\s*\{.*?\n\s*\})',
        text,
        re.S,
    )
    # simpler: after status.pid = pi.dwProcessId
    needle = 'status.pid = pi.dwProcessId;'
    idx = text.find(needle)
    if idx > 0:
        # find next c36Phase after this
        j = text.find('c36Phase(', idx)
        if j > 0 and j < idx + 500:
            k = text.find(';', j)
            # replace that call's stage string
            chunk = text[j:j+80]
            chunk2 = re.sub(r'c36Phase\("[^"]+"', 'c36Phase("proc_ok"', chunk, count=1)
            text = text[:j] + chunk2 + text[j+len(chunk):]
            n += 1
            print("forced proc_ok", chunk, "->", chunk2)
        else:
            insert = '''
    {
        char d[512];
        snprintf(d, sizeof(d), "ok pid=%lu cmdline=%s", (unsigned long)status.pid,
                 cmdLine.c_str());
        c36Phase("proc_ok", d);
    }
'''
            # insert after startedEpochMs line
            mark = 'status.startedEpochMs = currentEpochMs();'
            if mark in text:
                text = text.replace(mark, mark + insert, 1)
                n += 1
                print("inserted proc_ok")

# Also stamp PROC begin before CreateProcess
if 'c36Phase("proc_begin"' not in text and 'CreateProcessA' in text:
    text = text.replace(
        'PROCESS_INFORMATION pi = {};\n\n    BOOL created = CreateProcessA',
        'PROCESS_INFORMATION pi = {};\n'
        '    c36Phase("proc_begin", cmdLine.c_str());\n\n'
        '    BOOL created = CreateProcessA',
        1,
    )
    n += 1
    print("inserted proc_begin")

# WriteFile INIT_SEND instrumentation
old_wf = r'''    DWORD written = 0;
    BOOL ok = WriteFile(status.hStdinWrite, packet.c_str(), (DWORD)packet.size(), &written, nullptr);
    if (!ok || written != (DWORD)packet.size())
    {
        logError("sendLSPRequest", "WriteFile failed for " + m_lspConfigs[(size_t)lang].name);
        return -1;
    }

    status.requestCount++;
    return id;
}'''

new_wf = r'''    const bool isInit = (method == "initialize");
    if (isInit) {
        char d[192];
        snprintf(d, sizeof(d), "method=initialize Content-Length=%zu packet=%zu",
                 body.size(), packet.size());
        c36Phase("init_send_begin", d);
    }
    DWORD written = 0;
    const auto t0 = std::chrono::steady_clock::now();
    BOOL ok = WriteFile(status.hStdinWrite, packet.c_str(), (DWORD)packet.size(), &written, nullptr);
    const auto wallMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - t0)
                            .count();
    if (isInit) {
        char d[256];
        snprintf(d, sizeof(d),
                 "method=initialize Content-Length=%zu bytes_written=%lu wall_ms=%lld ok=%d",
                 body.size(), (unsigned long)written, (long long)wallMs, (int)ok);
        c36Phase((ok && written == (DWORD)packet.size()) ? "init_send_ok" : "init_send_fail",
                 d);
    }
    if (!ok || written != (DWORD)packet.size())
    {
        logError("sendLSPRequest", "WriteFile failed for " + m_lspConfigs[(size_t)lang].name);
        return -1;
    }

    status.requestCount++;
    return id;
}'''

repl(old_wf, new_wf, "WriteFile INIT_SEND")

# sendInitialize
old_si = r'''    int id = sendLSPRequest(lang, "initialize", params);
    if (id < 0) {
        m_lspStatuses[(size_t)lang].lastError =
            "Initialize send failed (server not Starting/Running)";
        std::fprintf(stderr, "C36_LSP_STAGE=INIT_SEND_FAIL\n");
        std::fflush(stderr);
        return false;
    }
    std::fprintf(stderr, "C36_LSP_STAGE=INIT_SEND_OK id=%d\n", id);
    std::fflush(stderr);

    // Floor 15s / cap 60s — never wait unbounded; fail closed for tipbound C36.
    int timeoutMs = cfg.initTimeoutMs;
    if (timeoutMs < 15000)
        timeoutMs = 15000;
    if (timeoutMs > 60000)
        timeoutMs = 60000;
    std::fprintf(stderr, "C36_LSP_STAGE=INIT_WAIT_ENTER timeout_ms=%d\n",
                 timeoutMs);
    std::fflush(stderr);
    nlohmann::json resp = readLSPResponse(lang, id, timeoutMs);
    if (resp.contains("error"))
    {
        const std::string em =
            resp["error"].value("message", std::string("unknown"));
        m_lspStatuses[(size_t)lang].lastError = "Initialize error: " + em;
        const bool timed = em.find("Timeout") != std::string::npos ||
                           em.find("timeout") != std::string::npos;
        /* Timed wait returned ⇒ HANDSHAKE_UNFULFILLED (not deadlock). */
        std::fprintf(stderr,
                     "C36_LSP_STAGE=INIT_WAIT_DONE class=%s msg=%s\n",
                     timed ? "HANDSHAKE_UNFULFILLED" : "INIT_ERROR",
                     em.c_str());
        std::fflush(stderr);
        return false;
    }

    const bool ok = resp.contains("result");
    std::fprintf(stderr, "C36_LSP_STAGE=INIT_WAIT_DONE class=%s\n",
                 ok ? "INIT_OK" : "HANDSHAKE_UNFULFILLED");
    std::fflush(stderr);
    return ok;
}'''

new_si = r'''    int id = sendLSPRequest(lang, "initialize", params);
    if (id < 0) {
        m_lspStatuses[(size_t)lang].lastError =
            "Initialize send failed (server not Starting/Running)";
        /* Send never completed ⇒ possible DEADLOCK (lock/pipe full). */
        c36Phase("init_send_fail", "disp=DEADLOCK send_failed");
        return false;
    }

    // Floor 15s / cap 60s — never wait unbounded; fail closed for tipbound C36.
    int timeoutMs = cfg.initTimeoutMs;
    if (timeoutMs < 15000)
        timeoutMs = 15000;
    if (timeoutMs > 60000)
        timeoutMs = 60000;
    g_c36InitWaitLang.store((int)lang);
    {
        char d[128];
        snprintf(d, sizeof(d), "timeout_ms=%d id=%d", timeoutMs, id);
        c36Phase("init_wait_begin", d);
    }
    nlohmann::json resp = readLSPResponse(lang, id, timeoutMs);
    g_c36InitWaitLang.store(-1);
    const size_t li = (size_t)lang;
    const uint64_t bytes = (li < kC36N) ? g_c36Bytes[li].load() : 0;
    if (resp.contains("error"))
    {
        const std::string em =
            resp["error"].value("message", std::string("unknown"));
        m_lspStatuses[(size_t)lang].lastError = "Initialize error: " + em;
        const bool timed = em.find("Timeout") != std::string::npos ||
                           em.find("timeout") != std::string::npos;
        const char* cls = c36Classify(li, m_lspStatuses[li].hProcess, timed);
        int rpcId = resp.contains("id") ? resp["id"].get<int>() : id;
        char d[448];
        snprintf(d, sizeof(d),
                 "disp=%s jsonrpc_id=%d bytes_read=%llu WaitFor=cv_timeout "
                 "ReadFile=via_reader has_result=0 has_error=1 error=%s",
                 cls, rpcId, (unsigned long long)bytes, em.c_str());
        c36Phase("init_wait_fail", d);
        return false;
    }

    const bool ok = resp.contains("result");
    char d[288];
    if (ok) {
        int rpcId = resp.contains("id") ? resp["id"].get<int>() : id;
        snprintf(d, sizeof(d),
                 "disp=HANDSHAKE_OK jsonrpc_id=%d bytes_read=%llu has_result=1 has_error=0",
                 rpcId, (unsigned long long)bytes);
        c36Phase("init_wait_ok", d);
    } else {
        snprintf(d, sizeof(d),
                 "disp=UNFULFILLED_HANDSHAKE id=%d bytes_read=%llu has_result=0",
                 id, (unsigned long long)bytes);
        c36Phase("init_wait_fail", d);
    }
    return ok;
}'''

repl(old_si, new_si, "sendInitialize")

# ensure cstring for strncmp
if '#include <cstring>' not in text:
    text = text.replace('#include <cstdio>\n', '#include <cstdio>\n#include <cstring>\n', 1)
    n += 1
    print("added cstring")
elif 'cstring' not in text[:80]:
    # may already exist elsewhere
    pass

if text == orig:
    raise SystemExit("no net changes")
p.write_text(text, encoding="utf-8")
print("DONE patches=", n, "delta=", len(text) - len(orig))
