// ============================================================================
// BrowserSession.hpp
//
// RAWRXD_BROWSER_SESSION_001 -- a REAL browser process, with a persistent
// profile, launched and verified.
//
// ---------------------------------------------------------------------------
// WHY THIS IS NOT A HANDLE TO SOMETHING THAT MAY NOT EXIST
// ---------------------------------------------------------------------------
// The tree already contains five browser-shaped files that contain no browser:
//
//     src/win32app/AgenticBrowserLayer.cpp        11 lines
//     src/win32app/Win32IDE_AgenticBrowser.cpp     11 lines
//     src/sovereign/puppeteer/AutonomousPuppeteer.hpp  2 lines
//     src/sovereign/puppeteer/PuppeteerAPI.hpp         2 lines
//     src/collab/websocket_hub.cpp                     1 line
//
// So the first obligation of this class is to be unable to report a browser
// that did not start. `launch()` returns success only when all of the
// following have been MEASURED:
//
//   1. CreateProcessW returned a live process handle
//   2. the devtools HTTP endpoint answered /json/version
//   3. that response carried a webSocketDebuggerUrl
//   4. the WebSocket handshake against it completed and its
//      Sec-WebSocket-Accept validated
//
// Steps 2-4 are what separate "spawned a process" from "reached a browser".
// A browser that starts but whose devtools port never opens is a browser this
// authority must report as NOT READY, because an agent handed that handle would
// discover the failure mid-task with the page half-loaded.
//
// ---------------------------------------------------------------------------
// PERSISTENCE
// ---------------------------------------------------------------------------
// The profile directory is supplied by the caller and is NOT deleted on close.
// That is what makes authenticated sessions survive the process: cookies,
// localStorage and permission grants live in the profile, so reusing the same
// directory is the whole mechanism. A session that wiped its profile on close
// could never satisfy AUTHENTICATED_SESSION_PERSISTENCE, so this class makes no
// such option available.
// ============================================================================

#ifndef RAWRXD_BROWSER_BROWSER_SESSION_HPP
#define RAWRXD_BROWSER_BROWSER_SESSION_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "browser/CdpTransport.hpp"

namespace rawrxd::browser {

// What was actually verified at launch. Every field is measured; none is
// inferred from the fact that launch was requested.
struct SessionLaunchEvidence {
    bool processCreated       = false;  // CreateProcessW returned a live handle
    bool devtoolsEndpointOpen = false;  // HTTP /json/version answered
    bool debuggerUrlPresent   = false;  // that response carried a WS url
    bool websocketHandshake   = false;  // RFC6455 upgrade + accept validated

    std::string browserPath;
    std::uint16_t port = 0;
    std::string profileDir;
    std::string browserVersion;         // from /json/version "Browser"
    std::string webSocketDebuggerUrl;
    std::uint32_t processId = 0;

    // One line per failed stage, so a failure names its cause rather than
    // collapsing into a single "launch failed".
    std::vector<std::string> failureStages;
};

class BrowserSession {
public:
    BrowserSession() = default;
    ~BrowserSession();
    BrowserSession(const BrowserSession&) = delete;
    BrowserSession& operator=(const BrowserSession&) = delete;

    // Launches a real browser.
    //
    // `profileDir` must persist across launches for authenticated state to
    // survive. It is created if absent and never removed.
    //
    // `headless` selects headless mode. Headless is still a REAL browser: it
    // loads pages, runs JS and exposes the same DOM. It is not a simulation,
    // and the evidence fields are identical either way.
    //
    // `profileDir` is taken BY VALUE and canonicalised to an absolute path
    // before it reaches the browser. A relative --user-data-dir is resolved by
    // the browser against ITS OWN working directory, so DevToolsActivePort is
    // written where this process does not look and the launch fails while
    // reporting the wrong cause.
    bool launch(const std::string& browserPath,
                std::string profileDir,
                bool headless,
                std::uint16_t port,
                std::string& err);

    // Closes the browser and its devtools socket. The profile is preserved.
    void close();

    // Opens a NEW target (tab) and returns its devtools websocket path.
    // Fails when the browser reports no target, which is a browser-side fact
    // and not a client-side assumption.
    bool openTab(const std::string& url, std::string& wsPath,
                 std::string& targetId, std::string& err);

    // Lists currently open targets as "targetId<TAB>url".
    // Non-const because it issues a real CDP command; a listing that did not
    // ask the browser would be a guess about what is open.
    std::vector<std::string> listTargets();

    const SessionLaunchEvidence& evidence() const noexcept { return ev_; }
    CdpConnection& cdp() noexcept { return cdp_; }
    bool ready() const noexcept;

    // Locates a Chromium-family browser. Returns "" when none exists, which
    // callers must treat as NOT_AVAILABLE rather than as a stub browser.
    static std::string findBrowser();

private:
    SessionLaunchEvidence ev_;
    CdpConnection cdp_;
    std::uint32_t processId_ = 0;
    void* processHandle_ = nullptr;
    std::uint64_t lastTargetFetchMs_ = 0;

    bool httpGet(const std::string& host, std::uint16_t port,
                 const std::string& path, std::string& body, std::string& err);
};

} // namespace rawrxd::browser

#endif // RAWRXD_BROWSER_BROWSER_SESSION_HPP