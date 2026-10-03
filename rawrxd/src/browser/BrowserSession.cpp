// ============================================================================
// BrowserSession.cpp -- launch and verify a REAL browser process.
//
// See BrowserSession.hpp for the evidence law.
// ============================================================================

#include "browser/BrowserSession.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shellapi.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>

#pragma comment(lib, "ws2_32.lib")

namespace rawrxd::browser {

namespace {

std::uint64_t nowMs() {
    return static_cast<std::uint64_t>(GetTickCount64());
}

bool fileExists(const std::string& p) {
    return !p.empty() && std::filesystem::exists(p);
}

// Quote an argument for CreateProcessW.
//
// The MSVC parsing rule is precise: inside a quoted argument, a run of
// backslashes must be doubled ONLY when it precedes a quote character, and the
// quote itself is escaped. Backslashes anywhere else are literal.
//
// An earlier version doubled EVERY backslash, which turned
//     C:\Program Files (x86)\Microsoft\Edge\...
// into
//     C:"\"Program Files (x86)...
// and CreateProcessW answered ERROR_ACCESS_DENIED (5) for a path that plainly
// exists. A quoting bug that produces "access denied" is worse than one that
// produces a syntax error, because it points the reader at permissions instead
// of at the string.
std::wstring quoteArg(const std::string& s) {
    std::wstring out = L"\"";
    std::size_t i = 0;
    while (i < s.size()) {
        if (s[i] == '\\') {
            std::size_t run = 0;
            while (i + run < s.size() && s[i + run] == '\\') ++run;
            const bool nextIsQuote = (i + run < s.size() && s[i + run] == '"');
            out.append(run * (nextIsQuote ? 2 : 1), L'\\');
            i += run;
        } else if (s[i] == '"') {
            out += L'\\';
            out += L'"';
            ++i;
        } else {
            out += static_cast<unsigned char>(s[i]);
            ++i;
        }
    }
    out += L'"';
    return out;
}

std::wstring widen(const std::string& s) {
    if (s.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(),
                                      static_cast<int>(s.size()), nullptr, 0);
    std::wstring w(static_cast<std::size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()),
                        w.data(), n);
    return w;
}

} // namespace

BrowserSession::~BrowserSession() { close(); }

std::string BrowserSession::findBrowser() {
    // Probed in a deliberate order: an explicit override first, then the
    // architecture-matched installs. Existence is checked, not assumed.
    //
    // NOTE: there is deliberately no ShellExecute / registry fallback here. An
    // earlier version of this function probed the registry and then called
    // ShellExecuteW -- which meant that merely ASKING where a browser was would
    // LAUNCH one. Discovery must never mutate the machine it is inspecting.
    wchar_t envBuf[MAX_PATH] = {};
    const DWORD envLen = ::GetEnvironmentVariableW(L"RAWRXD_BROWSER_PATH",
                                                   envBuf, MAX_PATH);
    if (envLen > 0 && envLen < MAX_PATH) {
        // Narrow explicitly. Constructing std::string from wchar_t* would
        // truncate each unit to char and silently mangle any non-ASCII path.
        const int n = WideCharToMultiByte(CP_UTF8, 0, envBuf,
                                          static_cast<int>(envLen), nullptr, 0,
                                          nullptr, nullptr);
        if (n > 0) {
            std::string p(static_cast<std::size_t>(n), '\0');
            WideCharToMultiByte(CP_UTF8, 0, envBuf, static_cast<int>(envLen),
                                p.data(), n, nullptr, nullptr);
            if (fileExists(p)) return p;
        }
    }

    const char* kCandidates[] = {
        "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
    };
    for (const char* c : kCandidates)
        if (fileExists(c)) return c;

    // No browser on this host is a legitimate, reportable state. Returning ""
    // forces the caller to treat it as UNAVAILABLE rather than to proceed with
    // something that is not a browser.
    return {};
}

bool BrowserSession::httpGet(const std::string& host, std::uint16_t port,
                             const std::string& path, std::string& body,
                             std::string& err) {
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        err = "WSAStartup failed";
        return false;
    }
    SOCKET s = ::socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) { err = "socket failed"; WSACleanup(); return false; }

    DWORD tv = 1500;
    ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO,
                 reinterpret_cast<const char*>(&tv), sizeof(tv));

    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    if (::inet_pton(AF_INET, host.c_str(), &a.sin_addr) != 1) {
        ::closesocket(s);
        WSACleanup();
        err = "devtools host must be a loopback IPv4 literal, got '" + host + "'";
        return false;
    }

    bool ok = false;
    if (::connect(s, reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0) {
        std::ostringstream req;
        req << "GET " << path << " HTTP/1.1\r\nHost: 127.0.0.1:" << port
            << "\r\nConnection: close\r\nAccept: */*\r\n\r\n";
        const std::string r = req.str();
        ::send(s, r.data(), static_cast<int>(r.size()), 0);

        char buf[4096];
        for (;;) {
            const int n = ::recv(s, buf, sizeof(buf), 0);
            if (n <= 0) break;
            body.append(buf, static_cast<std::size_t>(n));
            if (body.size() > 4u * 1024 * 1024) break;   // refuse unbounded reply
        }
        ok = !body.empty();
        if (!ok) err = "devtools HTTP endpoint returned nothing";
    } else {
        err = "devtools HTTP connect refused (browser not listening yet?)";
    }
    ::closesocket(s);
    WSACleanup();
    return ok;
}

bool BrowserSession::ready() const noexcept {
    return ev_.processCreated && ev_.devtoolsEndpointOpen
        && ev_.debuggerUrlPresent && ev_.websocketHandshake
        && cdp_.connected();
}

bool BrowserSession::launch(const std::string& browserPath,
                            std::string profileDir,
                            bool headless,
                            std::uint16_t port,
                            std::string& err) {
    close();
    ev_ = SessionLaunchEvidence{};
    ev_.browserPath = browserPath;
    ev_.port = port;
    ev_.profileDir = profileDir;

    if (!fileExists(browserPath)) {
        ev_.failureStages.push_back("BROWSER_BINARY_ABSENT:" + browserPath);
        err = "no browser binary at " + browserPath;
        return false;
    }

    std::error_code ec;
    // CANONICALISE THE PROFILE PATH BEFORE HANDING IT TO THE BROWSER.
    //
    // A relative --user-data-dir is resolved by the browser against ITS OWN
    // working directory, which is not necessarily ours. The browser then writes
    // DevToolsActivePort somewhere this process does not look, and the launch
    // fails with the misleading "devtools endpoint never answered on port 0" --
    // which names the port when the real fault is the path. The browser lane
    // passed an absolute path and worked; the shell lane passed a relative one
    // and did not. Same code, same browser, opposite outcome: exactly the kind
    // of luck-dependent behaviour this class exists to remove.
    std::filesystem::create_directories(profileDir, ec);
    if (ec) {
        ev_.failureStages.push_back("PROFILE_DIR_CREATE_FAILED");
        err = "could not create profile dir " + profileDir + ": " + ec.message();
        return false;
    }
    {
        const std::filesystem::path abs =
            std::filesystem::weakly_canonical(profileDir, ec);
        if (!ec && !abs.empty()) profileDir = abs.string();
    }

    // --remote-debugging-port is what makes this a drivable browser rather than
    // a window. --user-data-dir is what makes the session persistent and
    // authenticated-state-capable. --no-first-run and --no-default-browser-check
    // suppress first-run UI that would otherwise block automation.
    //
    // PORT SELECTION. Passing 0 to --remote-debugging-port does NOT serve on
    // port 0: the browser picks an ephemeral port itself and records it in
    // <user-data-dir>/DevToolsActivePort (first line = port, second = ws path).
    // An earlier version passed the caller's 0 straight through and then polled
    // 127.0.0.1:0, which of course never answers. Reading the file is also
    // race-free, whereas binding a socket to find a free port and handing it to
    // the browser leaves a window in which something else can take it.
    const std::string activePortFile =
        (std::filesystem::path(profileDir) / "DevToolsActivePort").string();

    std::wostringstream cmd;
    cmd << quoteArg(browserPath)
        << L" --remote-debugging-port=" << port
        << L" --remote-allow-origins=*"
        << L" --user-data-dir=" << quoteArg(profileDir)
        << L" --no-first-run --no-default-browser-check"
        << L" --disable-background-networking"
        << L" --disable-features=Translate,MediaRouter"
        << L" --disable-popup-blocking"
        << L" about:blank";
    if (headless) cmd << L" --headless=new";

    // CreateProcessW is given a writable command line, and every argument that
    // can contain a space is already quoted by quoteArg.
    std::wstring wcmd = cmd.str();

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    std::vector<wchar_t> mutableCmd(wcmd.begin(), wcmd.end());
    mutableCmd.push_back(L'\0');

    // CREATE_NO_WINDOW: the browser is a child of a headless tool, and a
    // console window for it would be noise in every receipt run.
    if (::CreateProcessW(nullptr, mutableCmd.data(), nullptr, nullptr, FALSE,
                         CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi) == 0) {
        ev_.failureStages.push_back("CREATE_PROCESS_FAILED");
        std::ostringstream e;
        e << "CreateProcessW failed, error=" << ::GetLastError();
        err = e.str();
        return false;
    }
    processHandle_ = pi.hProcess;
    processId_ = pi.dwProcessId;
    ev_.processId = pi.dwProcessId;
    ev_.processCreated = true;

    std::uint16_t effectivePort = port;

    // ---- poll the devtools endpoint until it answers or we give up --------
    // A spawned browser is not yet a reachable one. The wait is a measurement
    // with a bound, not a sleep: if the port never opens the session reports
    // NOT READY rather than hanging or claiming success.
    const std::uint64_t deadline = nowMs() + 30000;
    std::string versionDoc;
    while (nowMs() < deadline) {
        if (::WaitForSingleObject(pi.hProcess, 0) == WAIT_OBJECT_0) {
            ev_.failureStages.push_back("BROWSER_EXITED_BEFORE_DEVTOOLS");
            err = "browser process exited before its devtools port opened";
            close();
            return false;
        }

        // Resolve the port the browser actually chose.
        if (port == 0) {
            std::ifstream af(activePortFile);
            std::string line;
            if (af && std::getline(af, line)) {
                try {
                    const int parsed = std::stoi(line);
                    if (parsed > 0 && parsed <= 65535) {
                        effectivePort = static_cast<std::uint16_t>(parsed);
                        ev_.port = effectivePort;
                    }
                } catch (...) {
                    // A partially written file is expected on the first poll;
                    // the next iteration re-reads it.
                }
            }
        }

        if (effectivePort != 0 &&
            httpGet("127.0.0.1", effectivePort, "/json/version",
                    versionDoc, err)) {
            ev_.devtoolsEndpointOpen = true;
            break;
        }
        ::Sleep(150);
    }
    if (!ev_.devtoolsEndpointOpen) {
        ev_.failureStages.push_back("DEVTOOLS_ENDPOINT_NEVER_OPENED");
        err = "devtools endpoint never answered on port "
            + std::to_string(effectivePort) + ": " + err;
        close();
        return false;
    }
    const std::uint16_t wsPort = effectivePort;

    ev_.browserVersion = json::findString(versionDoc, "Browser");
    const std::string wsUrl = json::findString(versionDoc, "webSocketDebuggerUrl");
    if (wsUrl.empty()) {
        ev_.failureStages.push_back("NO_DEBUGGER_URL_IN_VERSION_RESPONSE");
        err = "devtools answered but carried no webSocketDebuggerUrl";
        close();
        return false;
    }
    ev_.debuggerUrlPresent = true;
    ev_.webSocketDebuggerUrl = wsUrl;

    // ws://127.0.0.1:PORT/devtools/page/<id>
    const std::string prefix = "ws://";
    if (wsUrl.rfind(prefix, 0) != 0) {
        ev_.failureStages.push_back("DEBUGGER_URL_NOT_WS_SCHEME");
        err = "unexpected debugger url scheme: " + wsUrl;
        close();
        return false;
    }
    std::string rest = wsUrl.substr(prefix.size());
    const std::size_t slash = rest.find('/');
    const std::string hostport = rest.substr(0, slash);
    const std::string wspath = slash == std::string::npos ? "/" : rest.substr(slash);
    const std::size_t colon = hostport.find(':');
    const std::string host = colon == std::string::npos ? hostport
                                                        : hostport.substr(0, colon);

    std::string wsErr;
    if (!cdp_.connect(host, wsPort, wspath, wsErr)) {
        ev_.failureStages.push_back("WEBSOCKET_HANDSHAKE_FAILED");
        err = "websocket handshake failed: " + wsErr;
        close();
        return false;
    }
    ev_.websocketHandshake = true;

    // ---- prove the connection actually commands the browser ---------------
    // A completed WebSocket upgrade proves a socket, not a working protocol.
    // One real command whose result the browser returns is the difference.
    const long long id = cdp_.send("Target.getTargets", "{}", wsErr);
    if (id < 0) {
        ev_.failureStages.push_back("CDP_COMMAND_SEND_FAILED");
        err = "could not send Target.getTargets: " + wsErr;
        close();
        return false;
    }
    std::string result, cdpErr;
    if (!cdp_.awaitResponse(id, result, cdpErr, 10000, wsErr) || result.empty()) {
        ev_.failureStages.push_back("CDP_COMMAND_NOT_ANSWERED");
        err = "browser did not answer Target.getTargets: " + wsErr
            + (cdpErr.empty() ? "" : (" / " + cdpErr));
        close();
        return false;
    }

    err.clear();
    return true;
}

bool BrowserSession::openTab(const std::string& url, std::string& wsPath,
                             std::string& targetId, std::string& err) {
    if (!cdp_.connected()) { err = "session not ready"; return false; }

    std::string cdpErr;
    const long long id = cdp_.send(
        "Target.createTarget",
        json::obj({{"url", "\"" + json::escape(url) + "\""}}),
        err);
    if (id < 0) { err = "Target.createTarget send failed: " + err; return false; }

    std::string result;
    if (!cdp_.awaitResponse(id, result, cdpErr, 15000, err)) {
        err = "Target.createTarget not answered: " + err;
        return false;
    }
    if (!cdpErr.empty()) { err = "Target.createTarget refused: " + cdpErr; return false; }

    targetId = json::findString(result, "targetId");
    if (targetId.empty()) { err = "createTarget returned no targetId"; return false; }

    wsPath = "/devtools/page/" + targetId;

    std::string r2, e2;
    const long long id2 = cdp_.send("Target.attachToTarget",
                                    json::obj({{"targetId", "\"" + json::escape(targetId) + "\""},
                                               {"flatten", "true"}}),
                                    err);
    if (id2 < 0) { err = "attachToTarget send failed: " + err; return false; }
    if (!cdp_.awaitResponse(id2, r2, e2, 15000, err) || !e2.empty()) {
        err = "attachToTarget failed: " + (e2.empty() ? err : e2);
        return false;
    }
    return true;
}

std::vector<std::string> BrowserSession::listTargets() {
    std::vector<std::string> out;
    std::string err;
    const long long id = cdp_.send("Target.getTargets", "{}", err);
    if (id < 0) return out;
    std::string result, cdpErr;
    if (!cdp_.awaitResponse(id, result, cdpErr, 10000, err)) return out;

    // Minimal scan of targetInfos[]. Each entry contributes an id and a url.
    std::size_t p = 0;
    while ((p = result.find("\"targetId\"", p)) != std::string::npos) {
        const std::string tid = json::findString(result.substr(p), "targetId");
        const std::string url = json::findString(result.substr(p), "url");
        if (!tid.empty()) out.push_back(tid + "<TAB>" + url);
        p += 11;
    }
    return out;
}

void BrowserSession::close() {
    if (cdp_.connected()) {
        // Ask the browser to close cleanly so the profile is flushed. A killed
        // browser can leave the profile locked, which is exactly the failure
        // that makes a "persistent" session fail on its second launch.
        std::string err;
        const long long id = cdp_.send("Browser.close", "{}", err);
        if (id >= 0) {
            std::string r, e;
            cdp_.awaitResponse(id, r, e, 2000, err);
        }
    }
    cdp_.close();

    if (processHandle_) {
        const HANDLE h = static_cast<HANDLE>(processHandle_);
        if (::WaitForSingleObject(h, 3000) == WAIT_TIMEOUT) {
            // The browser did not exit on request. Tear it down rather than
            // returning, because a session that cannot be closed leaves the
            // profile locked and makes every later launch fail for a reason
            // that has nothing to do with the later launch.
            ev_.failureStages.push_back("BROWSER_IGNORED_BROWSER_CLOSE_FORCE_KILLED");
            ::TerminateProcess(h, 0);
            ::WaitForSingleObject(h, 2000);
        }
        ::CloseHandle(h);
        processHandle_ = nullptr;
    }
    processId_ = 0;
}

} // namespace rawrxd::browser