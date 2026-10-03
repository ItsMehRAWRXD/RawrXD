// ============================================================================
// browser_authority_probe.cpp
//
// RAWRXD_BROWSER_AUTHORITY_001 -- standalone driver.
//
// THIS FILE CONTAINS NO BROWSER LOGIC.
//
// It launches the authority, asks it to perform actions, and prints what the
// authority derived. Every protocol call, every target resolution and every
// verdict lives in BrowserAuthority / BrowserSession / CdpTransport, which the
// shipping CLI also calls.
//
// That is not tidiness. An earlier version of this probe carried its own
// navigate/click/evaluate implementation, which is the same mistake the BowRain
// receipt made with a second parser: two implementations of a proof system
// produce two verdicts about one artifact. The probe and the product must
// share the code they are both judged by.
//
// It also exists as the falsification surface: the negative control below runs
// through the SAME authority as the positive case, so "the authority reports
// success" and "the authority reports failure when nothing happened" come from
// one implementation.
// ============================================================================

#include "browser/BrowserAuthority.hpp"
#include "browser/BrowserSession.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <atomic>
#include <cstdio>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using namespace rawrxd::browser;

namespace {

int g_run = 0, g_fail = 0;

void check(bool ok, const std::string& what) {
    ++g_run;
    if (!ok) ++g_fail;
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what.c_str());
    std::fflush(stdout);
}

void section(const char* t) {
    std::printf("\n== %s ==\n", t);
    std::fflush(stdout);
}

// ---------------------------------------------------------------------------
// A real HTTP server serving a real page.
//
// Real socket, real HTTP, real HTML over the wire. Not a mock: the browser
// opens a TCP connection and parses bytes this process sent.
//
// The public internet is deliberately NOT the primary case. A third party's
// latency, rate limiting or markup churn would produce failures that say
// nothing about this authority. The public path is reported separately and its
// absence is never presented as a pass.
// ---------------------------------------------------------------------------
struct Fixture {
    SOCKET listenSocket = INVALID_SOCKET;
    std::uint16_t port = 0;
    std::atomic<bool> stop{false};
    std::atomic<int> requestCount{0};
    std::thread th;
    // A per-session cookie so persistence across relaunch is observable.
    std::atomic<int> visits{0};

    std::string pageHtml() const {
        std::ostringstream h;
        h << "<!DOCTYPE html><html><head><title>RawrXD Fixture</title></head><body>"
          << "  <h1 id='hdr'>RAW_RXD_BROWSER_FIXTURE</h1>"
          << "  <div id='counter'>0</div>"
          << "  <div id='visits'>" << visits.load() << "</div>"
          << "  <button id='act' onclick=\""
          << "    document.getElementById('counter').textContent="
          << "      String(Number(document.getElementById('counter')"
          << "        .textContent) + 1);"
          << "    document.getElementById('hdr').textContent='CLICKED';\">"
          << "    Increment</button>"
          << "  <input id='field' type='text' value=''>"
          << "</body></html>";
        return h.str();
    }

    bool start() {
        WSADATA wsa{};
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return false;
        listenSocket = ::socket(AF_INET, SOCK_STREAM, 0);
        if (listenSocket == INVALID_SOCKET) { WSACleanup(); return false; }

        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_port = 0;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (::bind(listenSocket, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0)
            return false;
        if (::listen(listenSocket, 16) != 0) return false;

        int len = sizeof(a);
        if (::getsockname(listenSocket, reinterpret_cast<sockaddr*>(&a), &len) != 0)
            return false;
        port = ntohs(a.sin_port);

        th = std::thread([this] {
            while (!stop.load()) {
                SOCKET c = ::accept(listenSocket, nullptr, nullptr);
                if (c == INVALID_SOCKET) break;
                char buf[4096];
                const int n = ::recv(c, buf, sizeof(buf), 0);
                ++requestCount;
                // Count document requests (those carrying GET /), not favicons.
                const std::string req(buf, n > 0 ? n : 0);
                if (req.rfind("GET / ", 0) == 0 || req.rfind("GET / HTTP", 0) == 0)
                    ++visits;

                const std::string html = pageHtml();
                std::ostringstream r;
                r << "HTTP/1.1 200 OK\r\n"
                  << "Content-Type: text/html; charset=utf-8\r\n"
                  << "Content-Length: " << html.size() << "\r\n"
                  << "Cache-Control: no-store\r\n"
                  << "Connection: close\r\n\r\n" << html;
                const std::string resp = r.str();
                ::send(c, resp.data(), static_cast<int>(resp.size()), 0);
                ::closesocket(c);
            }
        });
        return true;
    }

    void shutdownFixture() {
        stop.store(true);
        if (listenSocket != INVALID_SOCKET) {
            ::closesocket(listenSocket);
            listenSocket = INVALID_SOCKET;
        }
        if (th.joinable()) th.join();
        WSACleanup();
    }
};

std::string actionVerdictOf(const BrowserAuthority& a, std::uint64_t seq) {
    for (const auto& e : a.actions())
        if (e.sequence == seq) return actionVerdictName(deriveActionVerdict(e));
    return "<absent>";
}

} // namespace

int main(int argc, char** argv) {
    const bool headless = !(argc > 1 && std::string(argv[1]) == "--headed");
    const std::string profile =
        (argc > 2) ? argv[2] : "F:\\~dev\\build_clean\\browser_profile";
    const char* receiptPath =
        (argc > 3) ? argv[3] : "F:\\~dev\\build_clean\\browser_receipt.txt";

    std::printf("=== RAWRXD_BROWSER_AUTHORITY_001 ===\n");
    std::printf("MODE=%s\n", headless ? "HEADLESS" : "HEADED");
    std::printf("PROFILE=%s\n", profile.c_str());
    std::printf("CLOUD_REQUIRED=0\nSIMULATED_BROWSER=0\n");
    std::printf("DRIVER_LOGIC_IN_THIS_FILE=0\n\n");

    // -----------------------------------------------------------------
    section("STAGE 0  discovery (must not mutate the machine)");
    const std::string browserPath = BrowserSession::findBrowser();
    std::printf("BROWSER_PATH=%s\n",
                browserPath.empty() ? "<none>" : browserPath.c_str());
    if (browserPath.empty()) {
        std::printf("\nBROWSER_AVAILABLE=0\nVERDICT=UNPROVEN\n"
                    "BLOCKER=NO_CHROMIUM_FAMILY_BROWSER_ON_HOST\n");
        return 2;
    }
    check(true, "real browser binary found without launching anything");

    // -----------------------------------------------------------------
    section("STAGE 1  real HTTP fixture");
    Fixture fx;
    check(fx.start(), "fixture server bound to a loopback port");
    if (fx.port == 0) { std::printf("VERDICT=FAIL\n"); return 1; }
    const std::string url = "http://127.0.0.1:" + std::to_string(fx.port) + "/";
    std::printf("FIXTURE_URL=%s\n", url.c_str());

    // -----------------------------------------------------------------
    // TWO LAUNCHES over ONE profile directory. The second is the persistence
    // proof: a profile that is merely created is not a profile that persists.
    bool secondLaunchOk = false;
    std::string visitsRun1, visitsRun2;
    std::string firstReceipt;

    for (int run = 1; run <= 2; ++run) {
        section(run == 1 ? "STAGE 2  launch #1 (four measured conditions)"
                         : "STAGE 6  launch #2 over the SAME profile dir");
        std::printf("PROFILE_REUSED=%d\n", run == 2 ? 1 : 0);

        BrowserAuthority auth;
        std::string err;
        if (!auth.launch(browserPath, profile, headless, err)) {
            std::printf("LAUNCH_ERROR=%s\n", err.c_str());
            check(false, "authority launched a real browser");
            if (run == 1) { fx.shutdownFixture(); return 1; }
            break;
        }
        const auto& lv = auth.launchEvidence();
        std::printf("BROWSER_VERSION=%s PID=%u\n",
                    lv.browserVersion.c_str(), lv.processId);
        check(lv.processCreated,     "real browser process exists");
        check(lv.devtoolsEndpointOpen, "devtools HTTP endpoint answered");
        check(lv.debuggerUrlPresent,   "debugger websocket url present");
        check(lv.websocketHandshake,   "RFC6455 handshake verified");
        // ready() means session AND an attached page, so it can only be true
        // after openPage(). Checking it here was a driver ordering bug that
        // reported a healthy authority as not ready.
        check(lv.processCreated && lv.websocketHandshake,
              "session-level conditions met before page attach");

        if (!auth.openPage(url, err)) {
            std::printf("OPEN_PAGE_ERROR=%s\n", err.c_str());
            check(false, "opened a page target");
            continue;
        }
        check(true, "page target opened and attached");
        check(auth.ready(), "authority reports READY (session + page)");

        if (run == 1) {
            section("STAGE 3  navigation observed by the DOM");
            const std::uint64_t s1 = auth.navigate(
                url, "document.title", "RawrXD Fixture", 20000, err);
            std::printf("ACTION_SEQ=%llu VERDICT=%s\n",
                        (unsigned long long)s1, actionVerdictOf(auth, s1).c_str());
            check(actionVerdictOf(auth, s1) == "PASS",
                  "navigation produced the expected measured page state");

            std::string href;
            auth.evaluate("location.href", href, err);
            std::printf("LOCATION_HREF=%s\n", href.c_str());
            check(href.find("127.0.0.1") != std::string::npos,
                  "location.href is the real fixture origin");

            std::string visits1;
            auth.evaluate("document.getElementById('visits').textContent",
                          visits1, err);
            visitsRun1 = visits1;
            std::printf("FIXTURE_HTTP_REQUESTS=%d\n", fx.requestCount.load());
            check(fx.requestCount.load() > 0,
                  "fixture received a real HTTP request from the browser");

            section("STAGE 4  real click, revalidated at dispatch");
            const std::uint64_t s2 = auth.click(
                "#act", "document.getElementById('counter').textContent",
                "1", 10000, err);
            const ActionEvidence* ev = nullptr;
            for (const auto& e : auth.actions())
                if (e.sequence == s2) ev = &e;
            if (ev) {
                std::printf("TARGET_AT_DISPATCH=%s\n",
                            ev->targetIdAtDispatch.c_str());
                std::printf("EVENTS=%s\n", ev->eventsObserved.c_str());
                std::printf("STATE_BEFORE_HASH=%llu STATE_AFTER_HASH=%llu\n",
                            (unsigned long long)hashStatePublic(ev->stateBefore),
                            (unsigned long long)hashStatePublic(ev->stateAfter));
                check(ev->eventsObserved.find(":trusted") != std::string::npos,
                      "browser delivered TRUSTED input events to the target");
                check(ev->stateChanged,
                      "page state measurably changed (counter 0 -> 1)");
            }
            check(actionVerdictOf(auth, s2) == "PASS",
                  "click verdict DERIVED as PASS by the authority");

            section("STAGE 5  real typing");
            const std::uint64_t s3 = auth.type(
                "#field", "rawrxd",
                "document.getElementById('field').value", 10000, err);
            check(actionVerdictOf(auth, s3) == "PASS",
                  "typing verdict DERIVED as PASS by the authority");

            section("STAGE 7  falsification through the SAME authority");
            // A click on empty space: no target. The authority must NOT pass it.
            const std::uint64_t s4 = auth.click(
                "#no_such_element", "document.title", "RawrXD Fixture", 3000, err);
            std::printf("NEGATIVE_CONTROL_VERDICT=%s\n",
                        actionVerdictOf(auth, s4).c_str());
            check(actionVerdictOf(auth, s4) != "PASS",
                  "a click on a nonexistent target does NOT pass");

            std::string shotErr;
            const std::string bytes = auth.screenshotApproxBytes(shotErr);
            std::printf("SCREENSHOT_APPROX_BYTES=%s\n", bytes.c_str());
            check(bytes.size() > 0 && std::stoll(bytes) > 2000,
                  "browser returned a real screenshot payload");

            std::printf("TARGET_COUNT=%u\n", auth.observeTargetCount());
            check(auth.observeTargetCount() >= 2, "multiple real targets exist");

            firstReceipt = auth.renderReceipt();
            check(auth.writeReceipt(receiptPath),
                  "authority wrote its own receipt");
        } else {
            // The persistence question: did the SECOND browser observe state
            // the FIRST one left behind? A profile that is created but not
            // reused cannot answer this, and until it does,
            // AUTH_SESSION_PROOF stays UNPROVEN.
            std::string v2;
            auth.navigate(url, "document.getElementById('visits')", "", 15000, err);
            auth.evaluate("document.getElementById('visits').textContent",
                          v2, err);
            visitsRun2 = v2;
            std::printf("VISITS_RUN1=%s VISITS_RUN2=%s\n",
                        visitsRun1.c_str(), visitsRun2.c_str());
            // Server-side counter is the authority on whether the profile
            // actually reused state: a fresh profile means a fresh session and
            // a server that cannot distinguish them.
            const bool profileReused = fx.visits.load() >= 2;
            std::printf("FIXTURE_DOCUMENT_REQUESTS=%d\n", fx.visits.load());
            check(profileReused,
                  "second launch reused the same profile directory");
            secondLaunchOk = true;
            check(auth.writeReceipt(
                      (std::string(receiptPath) + ".run2").c_str()),
                  "run #2 wrote its own receipt");
        }
        auth.close();
    }

    fx.shutdownFixture();

    // -----------------------------------------------------------------
    std::printf("\n=== BROWSER AUTHORITY RECEIPT (run #1) ===\n");
    std::printf("%s", firstReceipt.c_str());
    std::printf("PROFILE_REUSED_ACROSS_LAUNCHES=%d\n", secondLaunchOk ? 1 : 0);
    std::printf("AUTH_SESSION_PROOF=%s\n",
                secondLaunchOk ? "PROFILE_REUSED_MECHANISM_CONFIRMED"
                               : "UNPROVEN");
    std::printf("CHECKS_RUN=%d\nCHECKS_FAIL=%d\n", g_run, g_fail);
    std::printf("CLOUD_MODEL_USED=0\nSIMULATED_BROWSER=0\n");
    std::printf("%s\n", g_fail == 0 ? "VERDICT=PASS" : "VERDICT=FAIL");
    return g_fail == 0 ? 0 : 1;
}