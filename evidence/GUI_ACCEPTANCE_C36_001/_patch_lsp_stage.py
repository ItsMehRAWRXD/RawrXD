from pathlib import Path

p = Path(r"g:\~dev\rawrxd\src\win32app\Win32IDE_LSPClient.cpp")
text = p.read_text(encoding="utf-8", errors="replace")
orig = text

old_c36 = r'''static void c36Stage(const char* stage, const char* detail)
{
    if (!stage)
        stage = "?";
    strncpy_s(g_c36LastStage, stage, _TRUNCATE);
    std::fprintf(stderr, "C36_LSP_STAGE=%s %s ts=%llu\n", stage,
                 detail ? detail : "-", (unsigned long long)c36SteadyMs());
    std::fflush(stderr);'''

new_c36 = r'''static void c36Stage(const char* stage, const char* detail)
{
    if (!stage)
        stage = "?";
    strncpy_s(g_c36LastStage, stage, _TRUNCATE);
    /* Canonical LSP_STAGE stamps for hang classification. */
    const char* canon = nullptr;
    const char* verd = "BEGIN";
    DWORD err = 0;
    if (std::strncmp(stage, "PIPE", 4) == 0) {
        canon = "PIPE";
        verd = (std::strstr(stage, "FAIL")) ? "FAIL" : "OK";
    } else if (std::strncmp(stage, "PROC", 4) == 0 ||
               std::strncmp(stage, "PROCESS", 7) == 0 ||
               std::strncmp(stage, "CREATEPROCESS", 13) == 0) {
        canon = "PROC";
        verd = (std::strstr(stage, "FAIL")) ? "FAIL" : "OK";
    } else if (std::strncmp(stage, "INIT_SEND", 9) == 0) {
        canon = "INIT_SEND";
        if (std::strstr(stage, "FAIL"))
            verd = "FAIL";
        else if (std::strstr(stage, "OK") || std::strstr(stage, "DONE"))
            verd = "OK";
        else
            verd = "BEGIN";
    } else if (std::strncmp(stage, "INIT_WAIT", 9) == 0 ||
               std::strncmp(stage, "RESPONSE_", 9) == 0 ||
               std::strncmp(stage, "INIT_FAIL", 9) == 0 ||
               std::strncmp(stage, "INIT_PASS", 9) == 0) {
        canon = "INIT_WAIT";
        if (std::strstr(stage, "FAIL") || std::strstr(stage, "TIMEOUT"))
            verd = "FAIL";
        else if (std::strstr(stage, "OK") || std::strstr(stage, "PASS") ||
                 std::strstr(stage, "DONE"))
            verd = "OK";
        else
            verd = "BEGIN";
    }
    if (canon)
        lspStageEmit(canon, verd, err, detail);
    std::fprintf(stderr, "C36_LSP_STAGE=%s %s ts=%llu\n", stage,
                 detail ? detail : "-", (unsigned long long)c36SteadyMs());
    std::fflush(stderr);'''

if old_c36 not in text:
    raise SystemExit("c36Stage block not found")
text = text.replace(old_c36, new_c36, 1)

old_cls = r'''static const char* c36Classify(size_t li, HANDLE hProc, bool timedOut)
{
    DWORD live = hProc ? WaitForSingleObject(hProc, 0) : WAIT_FAILED;
    const uint64_t bytes = (li < kC36N) ? g_c36Bytes[li].load() : 0;
    const int readerUp = (li < kC36N) ? g_c36ReaderUp[li].load() : 0;
    if (live != WAIT_TIMEOUT) {
        strncpy_s(g_c36Class, "PROCESS_EXITED", _TRUNCATE);
        return g_c36Class;
    }
    /* Both sides blocked, zero pipe progress ⇒ DEADLOCK. */
    if (timedOut && bytes == 0 && readerUp) {
        strncpy_s(g_c36Class, "DEADLOCK", _TRUNCATE);
        return g_c36Class;
    }
    strncpy_s(g_c36Class, "HANDSHAKE_UNFULFILLED", _TRUNCATE);
    return g_c36Class;
}'''

new_cls = r'''static const char* c36Classify(size_t li, HANDLE hProc, bool timedOut)
{
    DWORD live = hProc ? WaitForSingleObject(hProc, 0) : WAIT_FAILED;
    const uint64_t bytes = (li < kC36N) ? g_c36Bytes[li].load() : 0;
    const int last = g_lspLastStage.load();
    if (live != WAIT_TIMEOUT) {
        strncpy_s(g_c36Class, "PROCESS_EXITED", _TRUNCATE);
        return g_c36Class;
    }
    /* Hang with no INIT_SEND progress before wait ⇒ possible DEADLOCK. */
    if (last < 4 || (last == 3 && !timedOut && bytes == 0)) {
        strncpy_s(g_c36Class, "DEADLOCK", _TRUNCATE);
        return g_c36Class;
    }
    /* Hang after INIT_SEND with no response bytes ⇒ UNFULFILLED_HANDSHAKE. */
    if (timedOut && bytes == 0) {
        strncpy_s(g_c36Class, "UNFULFILLED_HANDSHAKE", _TRUNCATE);
        return g_c36Class;
    }
    strncpy_s(g_c36Class, "HANDSHAKE_PARTIAL", _TRUNCATE);
    return g_c36Class;
}'''

if old_cls not in text:
    raise SystemExit("c36Classify block not found")
text = text.replace(old_cls, new_cls, 1)

old_pipe = r'''    if (!CreatePipe(&hStdinRead, &hStdinWrite, &sa, 0) || !CreatePipe(&hStdoutRead, &hStdoutWrite, &sa, 0))
    {
        status.state = LSPServerState::Error;
        status.lastError = "Failed to create pipes: " + std::to_string(GetLastError());
        logError("startLSPServer", status.lastError);
        c36Stage("PIPE_FAIL", status.lastError.c_str());
        return false;
    }
    {
        char d[256];
        snprintf(d, sizeof(d),
                 "duplex parent_stdinW=%p parent_stdoutR=%p "
                 "child_stdinR=%p child_stdoutW=%p",
                 (void*)hStdinWrite, (void*)hStdoutRead, (void*)hStdinRead,
                 (void*)hStdoutWrite);
        c36Stage("PIPE_OK", d);
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
        snprintf(d, sizeof(d), "CreatePipe_in=%d/%lu CreatePipe_out=%d/%lu",
                 (int)pipeInOk, (unsigned long)pipeInErr, (int)pipeOutOk,
                 (unsigned long)pipeOutErr);
        c36Stage("PIPE_FAIL", d);
        return false;
    }
    BOOL hiIn = SetHandleInformation(hStdinWrite, HANDLE_FLAG_INHERIT, 0);
    DWORD hiInErr = hiIn ? 0 : GetLastError();
    BOOL hiOut = SetHandleInformation(hStdoutRead, HANDLE_FLAG_INHERIT, 0);
    DWORD hiOutErr = hiOut ? 0 : GetLastError();
    {
        char d[320];
        snprintf(d, sizeof(d),
                 "CreatePipe_in=1/0 CreatePipe_out=1/0 SetHandleInfo_in=%d/%lu "
                 "SetHandleInfo_out=%d/%lu parent_stdinW=%p parent_stdoutR=%p "
                 "(no DuplicateHandle)",
                 (int)hiIn, (unsigned long)hiInErr, (int)hiOut,
                 (unsigned long)hiOutErr, (void*)hStdinWrite, (void*)hStdoutRead);
        if (!(hiIn && hiOut)) {
            status.state = LSPServerState::Error;
            status.lastError = d;
            c36Stage("PIPE_FAIL", d);
            return false;
        }
        c36Stage("PIPE_OK", d);
    }'''

if old_pipe not in text:
    raise SystemExit("pipe block not found")
text = text.replace(old_pipe, new_pipe, 1)

text = text.replace('c36Stage("CREATEPROCESS_FAIL", d);', 'c36Stage("PROC_FAIL", d);', 1)
text = text.replace('c36Stage("PROCESS_OK", d);', 'c36Stage("PROC_OK", d);', 1)

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
        c36Stage("INIT_SEND_BEGIN", d);
    }
    DWORD written = 0;
    const auto t0 = std::chrono::steady_clock::now();
    BOOL ok = WriteFile(status.hStdinWrite, packet.c_str(), (DWORD)packet.size(), &written, nullptr);
    const auto wallMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - t0)
                            .count();
    DWORD gle = ok ? 0 : GetLastError();
    if (isInit) {
        char d[256];
        snprintf(d, sizeof(d),
                 "method=initialize Content-Length=%zu bytes_written=%lu wall_ms=%lld ok=%d",
                 body.size(), (unsigned long)written, (long long)wallMs, (int)ok);
        c36Stage((ok && written == (DWORD)packet.size()) ? "INIT_SEND_OK" : "INIT_SEND_FAIL",
                 d);
        if (!ok)
            lspStageEmit("INIT_SEND", "FAIL", gle, d);
    }
    if (!ok || written != (DWORD)packet.size())
    {
        logError("sendLSPRequest", "WriteFile failed for " + m_lspConfigs[(size_t)lang].name);
        return -1;
    }

    status.requestCount++;
    return id;
}'''

if old_wf not in text:
    raise SystemExit("WriteFile block not found")
text = text.replace(old_wf, new_wf, 1)

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
        c36Stage("INIT_SEND_FAIL", "disp=DEADLOCK send_failed");
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
        c36Stage("INIT_WAIT_BEGIN", d);
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
        char d[384];
        snprintf(d, sizeof(d),
                 "disp=%s id=%d bytes_read=%llu WaitFor=cv_timeout ReadFile=via_reader "
                 "error=%s",
                 cls, id, (unsigned long long)bytes, em.c_str());
        c36Stage("INIT_WAIT_FAIL", d);
        return false;
    }

    const bool ok = resp.contains("result");
    char d[256];
    if (ok) {
        snprintf(d, sizeof(d),
                 "disp=HANDSHAKE_OK id=%d bytes_read=%llu has_result=1 has_error=0",
                 id, (unsigned long long)bytes);
        c36Stage("INIT_WAIT_OK", d);
    } else {
        snprintf(d, sizeof(d),
                 "disp=UNFULFILLED_HANDSHAKE id=%d bytes_read=%llu has_result=0",
                 id, (unsigned long long)bytes);
        c36Stage("INIT_WAIT_FAIL", d);
    }
    return ok;
}'''

if old_si not in text:
    raise SystemExit("sendInitialize tail not found")
text = text.replace(old_si, new_si, 1)

old_start = r'''        c36Stage("START", d);
    }'''
new_start = r'''        c36Stage("START", d);
        lspStageResetLog();
    }'''
if old_start not in text:
    raise SystemExit("START block not found")
text = text.replace(old_start, new_start, 1)

if text == orig:
    raise SystemExit("no changes applied")
p.write_text(text, encoding="utf-8")
print("OK patched", p)
print("len delta", len(text) - len(orig))
