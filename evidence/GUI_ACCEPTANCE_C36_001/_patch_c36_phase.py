# -*- coding: utf-8 -*-
import re
import pathlib

p = pathlib.Path(r"G:\~dev\rawrxd\src\win32app\Win32IDE_LSPClient.cpp")
t = p.read_text(encoding="utf-8", errors="replace")
orig = t

pat_rr = re.compile(
    r"nlohmann::json Win32IDE::readLSPResponse\(LSPLanguage lang, int requestId, int timeoutMs\)\s*\{.*?\n\}",
    re.S,
)
new_rr = r"""nlohmann::json Win32IDE::readLSPResponse(LSPLanguage lang, int requestId, int timeoutMs)
{
    // Wait for the reader thread to deposit the response
    std::unique_lock<std::mutex> lock(m_lspResponseMutex);
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    const size_t li = (size_t)lang;
    const bool c36Wait = (g_c36InitWaitLang.load() == (int)lang);
    if (c36Wait) {
        char d[160];
        snprintf(d, sizeof(d),
                 "deadline_ms=%d id=%d bytes=%llu hb=%llu", timeoutMs, requestId,
                 (unsigned long long)((li < kC36N) ? g_c36Bytes[li].load() : 0),
                 (unsigned long long)((li < kC36N) ? g_c36Hb[li].load() : 0));
        c36Phase("response_wait", d);
    }

    while (true)
    {
        auto it = m_lspPendingResponses.find(requestId);
        if (it != m_lspPendingResponses.end())
        {
            nlohmann::json resp = std::move(it->second);
            m_lspPendingResponses.erase(it);
            return resp;
        }
        if (m_lspResponseCV.wait_until(lock, deadline) == std::cv_status::timeout)
        {
            nlohmann::json err_obj;
            err_obj["code"] = -1;
            err_obj["message"] = "Timeout waiting for response";
            nlohmann::json root;
            root["error"] = err_obj;
            return root;
        }
    }
}"""
m = pat_rr.search(t)
if not m:
    raise SystemExit("readLSPResponse not found")
t = t[: m.start()] + new_rr + t[m.end() :]

pat_si = re.compile(
    r'    int id = sendLSPRequest\(lang, "initialize", params\);\n.*?    return ok;\n\}',
    re.S,
)
new_si = r"""    int id = sendLSPRequest(lang, "initialize", params);
    if (id < 0) {
        m_lspStatuses[(size_t)lang].lastError =
            "Initialize send failed (server not Starting/Running)";
        c36Phase("init_request", "send_fail");
        return false;
    }
    {
        char d[64];
        snprintf(d, sizeof(d), "ok id=%d", id);
        c36Phase("init_request", d);
    }

    // Floor 15s / cap 60s — never wait unbounded; fail closed for tipbound C36.
    int timeoutMs = cfg.initTimeoutMs;
    if (timeoutMs < 15000)
        timeoutMs = 15000;
    if (timeoutMs > 60000)
        timeoutMs = 60000;

    g_c36InitWaitLang.store((int)lang);
    const uint32_t waitGen = g_c36WaitGen.fetch_add(1u) + 1u;
    g_c36WaitGen.store(waitGen);
    c36ArmDeadlockWatch(waitGen, timeoutMs);

    nlohmann::json resp = readLSPResponse(lang, id, timeoutMs);

    /* Invalidate watchdog before terminal crumb — clean return != deadlock. */
    g_c36WaitGen.fetch_add(1u);
    g_c36InitWaitLang.store(-1);

    const size_t li = (size_t)lang;
    const uint64_t bytes = (li < kC36N) ? g_c36Bytes[li].load() : 0;
    const uint64_t hb = (li < kC36N) ? g_c36Hb[li].load() : 0;
    if (resp.contains("error"))
    {
        const std::string em =
            resp["error"].value("message", std::string("unknown"));
        m_lspStatuses[(size_t)lang].lastError = "Initialize error: " + em;
        const bool timed = em.find("Timeout") != std::string::npos ||
                           em.find("timeout") != std::string::npos;
        char d[320];
        snprintf(d, sizeof(d),
                 "class=%s bytes=%llu hb=%llu msg=%s",
                 timed ? "HANDSHAKE_UNFULFILLED" : "INIT_ERROR",
                 (unsigned long long)bytes, (unsigned long long)hb, em.c_str());
        c36Phase("init_timeout", d);
        return false;
    }

    const bool ok = resp.contains("result");
    if (ok) {
        char d[160];
        snprintf(d, sizeof(d), "bytes=%llu hb=%llu", (unsigned long long)bytes,
                 (unsigned long long)hb);
        c36Phase("init_ok", d);
    } else {
        char d[160];
        snprintf(d, sizeof(d), "class=HANDSHAKE_UNFULFILLED_no_result bytes=%llu",
                 (unsigned long long)bytes);
        c36Phase("init_timeout", d);
    }
    return ok;
}"""
m2 = pat_si.search(t)
if not m2:
    raise SystemExit("sendInitialize tail not found")
t = t[: m2.start()] + new_si + t[m2.end() :]

if "g_c36Hb[li].fetch_add(1)" not in t:
    needle = (
        "g_c36Bytes[li].fetch_add((uint64_t)bytesRead);\n"
        "            g_c36Partial[li].store((uint64_t)buffer.size());"
    )
    repl = needle + "\n            g_c36Hb[li].fetch_add(1);"
    if needle not in t:
        raise SystemExit("reader byte bump needle missing")
    t = t.replace(needle, repl, 1)

old_map = (
    '               std::strncmp(phase, "response_", 9) == 0 ||\n'
    '               std::strncmp(phase, "deadlock", 8) == 0 ||\n'
    '               std::strncmp(phase, "init_fail", 9) == 0 ||\n'
    '               std::strncmp(phase, "init_pass", 9) == 0) {'
)
new_map = (
    '               std::strncmp(phase, "response_", 9) == 0 ||\n'
    '               std::strncmp(phase, "deadlock", 8) == 0 ||\n'
    '               std::strncmp(phase, "init_fail", 9) == 0 ||\n'
    '               std::strncmp(phase, "init_pass", 9) == 0 ||\n'
    '               std::strncmp(phase, "init_ok", 7) == 0 ||\n'
    '               std::strncmp(phase, "init_timeout", 12) == 0 ||\n'
    '               std::strncmp(phase, "init_request", 12) == 0) {'
)
if old_map in t:
    t = t.replace(old_map, new_map)

if t == orig:
    raise SystemExit("no changes applied")

p.write_text(t, encoding="utf-8")
print("OK", len(t) - len(orig))
print("response_wait", 'c36Phase("response_wait"' in t)
print("init_request", 'c36Phase("init_request"' in t)
print("init_ok", 'c36Phase("init_ok"' in t)
print("init_timeout", 'c36Phase("init_timeout"' in t)
print("hb", "g_c36Hb[li].fetch_add(1)" in t)
print("RESPONSE_WAIT_gone", "RESPONSE_WAIT" not in t)
