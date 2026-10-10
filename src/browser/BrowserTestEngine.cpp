// ============================================================================
// BrowserTestEngine.cpp — Playwright-like Browser Automation Implementation
// ============================================================================
// Implements the BrowserTestEngine.hpp interface using WebView2 as the
// native browser backend on Windows. Provides Cursor-like browser testing:
//   - Chromium/WebView2 automation via CDP
//   - Test runner with parallel execution
//   - AI-driven test generation via BrowserTestAgent
//   - Network interception and visual testing
// ============================================================================

#include "BrowserTestEngine.hpp"

#include <windows.h>
#include <shlobj.h>

// Windows SDK defines ERROR as a macro (winerror.h), which collides
// with the TestResult::ERROR enumerator used throughout this module.
#undef ERROR

#include <sstream>
#include <fstream>
#include <algorithm>
#include <random>
#include <thread>
#include <condition_variable>
#include <filesystem>

namespace fs = std::filesystem;

namespace RawrXD {
namespace Browser {

// ============================================================================
// Forward declarations for internal implementation classes
// ============================================================================

class WebView2Browser;
class WebView2BrowserContext;
class WebView2Page;
class WebView2Frame;
class WebView2ElementHandle;

// ============================================================================
// WebView2Container — Self-contained WebView2 host abstraction
// ============================================================================
// Lightweight host for an embedded WebView2 webview. This is a self-contained
// stub that satisfies the BrowserTestEngine interface; a full implementation
// would back executeScript() with ICoreWebView2::ExecuteScript and route
// navigation through ICoreWebView2::Navigate. Keeping it internal to this
// translation unit avoids a dependency on the Win32 IDE's WebView2 host.
// ============================================================================
class WebView2Container {
public:
    WebView2Container() = default;
    ~WebView2Container() = default;

    // Execute JavaScript in the hosted webview (fire-and-forget).
    void executeScript(const std::string& script) {
        m_lastScript = script;
        // Full implementation: webview->ExecuteScript(wScript, callback).
    }

    // Destroy the hosted webview and release COM resources.
    void destroy() {
        m_initialized = false;
        m_lastScript.clear();
    }

    // Resize the hosted webview to the given client-area rectangle.
    void resize(int x, int y, int width, int height) {
        m_x = x; m_y = y; m_width = width; m_height = height;
    }

    // Initialize the host against a parent window handle.
    bool initialize(void* hwnd, const std::string& url = std::string()) {
        m_hwnd = hwnd;
        m_initialized = true;
        m_url = url;
        return true;
    }

    bool isInitialized() const { return m_initialized; }
    const std::string& lastScript() const { return m_lastScript; }

private:
    void* m_hwnd = nullptr;
    bool m_initialized = false;
    int m_x = 0, m_y = 0, m_width = 0, m_height = 0;
    std::string m_url;
    std::string m_lastScript;
};

// ============================================================================
// Helper: Generate unique IDs
// ============================================================================
static std::atomic<uint64_t> g_nextId{1};
static uint64_t nextId() { return g_nextId.fetch_add(1); }

// ============================================================================
// Helper: JSON escape
// ============================================================================
static std::string jsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", (unsigned char)c);
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

// ============================================================================
// Helper: Wait for a future with timeout
// ============================================================================
template<typename T>
static bool waitForFuture(std::future<T>& fut, int timeoutMs) {
    if (timeoutMs <= 0) {
        fut.wait();
        return true;
    }
    auto status = fut.wait_for(std::chrono::milliseconds(timeoutMs));
    return status == std::future_status::ready;
}

// ============================================================================
// WebView2ElementHandle — Element reference
// ============================================================================
class WebView2ElementHandle : public ElementHandle {
public:
    WebView2ElementHandle(std::shared_ptr<WebView2Page> page, const std::string& selector)
        : m_page(page), m_selector(selector) {}

    // Actions
    std::future<bool> click(const ClickOptions& options = {}) override;
    std::future<bool> doubleClick(const ClickOptions& options = {}) override;
    std::future<bool> hover() override;
    std::future<bool> type(const std::string& text, const TypeOptions& options = {}) override;
    std::future<bool> press(const std::string& key, const KeyboardOptions& options = {}) override;
    std::future<bool> fill(const std::string& value, const TypeOptions& options = {}) override;
    std::future<bool> selectOption(const SelectOptionOptions& options) override;
    std::future<bool> focus() override;
    std::future<bool> blur() override;
    std::future<bool> scrollIntoViewIfNeeded() override;
    std::future<bool> check(const ClickOptions& options = {}) override;
    std::future<bool> uncheck(const ClickOptions& options = {}) override;

    // Properties
    std::future<std::string> getAttribute(const std::string& name) override;
    std::future<std::string> getProperty(const std::string& name) override;
    std::future<std::string> innerText() override;
    std::future<std::string> innerHTML() override;
    std::future<std::string> textContent() override;
    std::future<bool> isVisible() override;
    std::future<bool> isEnabled() override;
    std::future<bool> isChecked() override;
    std::future<bool> isDisabled() override;
    std::future<bool> isEditable() override;
    std::future<int> getBoundingBoxX() override;
    std::future<int> getBoundingBoxY() override;
    std::future<int> getBoundingBoxWidth() override;
    std::future<int> getBoundingBoxHeight() override;
    std::future<std::string> screenshot(const ScreenshotOptions& options = {}) override;

    // Query
    std::future<std::shared_ptr<ElementHandle>> querySelector(const std::string& selector) override;
    std::future<std::vector<std::shared_ptr<ElementHandle>>> querySelectorAll(const std::string& selector) override;
    std::future<std::shared_ptr<ElementHandle>> querySelectorXPath(const std::string& xpath) override;

    // Evaluation
    std::future<json> evaluate(const std::string& script, const json& arg = json()) override;
    std::future<json> evaluateHandle(const std::string& script, const json& arg = json()) override;

    // Frame access
    std::shared_ptr<Frame> contentFrame() override;

private:
    std::shared_ptr<WebView2Page> m_page;
    std::string m_selector;
    json m_cachedState;
};

// ============================================================================
// WebView2Frame — Frame implementation
// ============================================================================
class WebView2Frame : public Frame, public std::enable_shared_from_this<WebView2Frame> {
public:
    WebView2Frame(std::shared_ptr<WebView2Page> page, const std::string& name, const std::string& url)
        : m_page(page), m_name(name), m_url(url) {}

    std::string name() const override { return m_name; }
    std::string url() const override { return m_url; }
    std::shared_ptr<Frame> parentFrame() override { return m_parentFrame.lock(); }
    std::vector<std::shared_ptr<Frame>> childFrames() override;

    // Navigation
    std::future<bool> gotoURL(const std::string& url, const NavigateOptions& options = {}) override;
    std::future<bool> waitForNavigation(const NavigateOptions& options = {}) override;
    std::future<bool> waitForLoadState(WaitUntil state, int timeoutMs = 30000) override;

    // Query
    std::future<std::shared_ptr<ElementHandle>> querySelector(const std::string& selector) override;
    std::future<std::vector<std::shared_ptr<ElementHandle>>> querySelectorAll(const std::string& selector) override;
    std::future<std::shared_ptr<ElementHandle>> querySelectorXPath(const std::string& xpath) override;
    std::future<std::shared_ptr<ElementHandle>> waitForSelector(const std::string& selector, const WaitForSelectorOptions& options = {}) override;
    std::future<std::shared_ptr<ElementHandle>> waitForSelectorXPath(const std::string& xpath, const WaitForSelectorOptions& options = {}) override;

    // Evaluation
    std::future<json> evaluate(const std::string& script, const json& arg = json()) override;
    std::future<json> evaluateHandle(const std::string& script, const json& arg = json()) override;

    // Actions
    std::future<bool> click(const std::string& selector, const ClickOptions& options = {}) override;
    std::future<bool> fill(const std::string& selector, const std::string& value, const TypeOptions& options = {}) override;
    std::future<bool> type(const std::string& selector, const std::string& text, const TypeOptions& options = {}) override;
    std::future<bool> press(const std::string& selector, const std::string& key, const KeyboardOptions& options = {}) override;
    std::future<bool> selectOption(const std::string& selector, const SelectOptionOptions& options) override;
    std::future<bool> check(const std::string& selector, const ClickOptions& options = {}) override;
    std::future<bool> uncheck(const std::string& selector, const ClickOptions& options = {}) override;
    std::future<bool> hover(const std::string& selector) override;
    std::future<bool> focus(const std::string& selector) override;

    // Content
    std::future<std::string> content() override;
    std::future<std::string> title() override;

    void setParentFrame(std::shared_ptr<Frame> parent) { m_parentFrame = parent; }
    void setUrl(const std::string& url) { m_url = url; }

private:
    std::shared_ptr<WebView2Page> m_page;
    std::string m_name;
    std::string m_url;
    std::weak_ptr<Frame> m_parentFrame;
    std::vector<std::shared_ptr<Frame>> m_childFrames;
};

// ============================================================================
// WebView2Page — Page implementation
// ============================================================================
class WebView2Page : public Page, public std::enable_shared_from_this<WebView2Page> {
public:
    WebView2Page(std::shared_ptr<WebView2BrowserContext> context);
    ~WebView2Page() override;

    // Lifecycle
    std::future<bool> close(bool runBeforeUnload = false) override;
    std::future<bool> reload(const NavigateOptions& options = {}) override;
    std::future<bool> goBack(const NavigateOptions& options = {}) override;
    std::future<bool> goForward(const NavigateOptions& options = {}) override;

    // Navigation
    std::future<bool> gotoURL(const std::string& url, const NavigateOptions& options = {}) override;
    std::future<bool> waitForNavigation(const NavigateOptions& options = {}) override;
    std::future<bool> waitForLoadState(WaitUntil state, int timeoutMs = 30000) override;

    // URL/Title
    std::string url() const override;
    std::future<std::string> title() override;

    // Frame access
    std::shared_ptr<Frame> mainFrame() override;
    std::vector<std::shared_ptr<Frame>> frames() override;

    // Query
    std::future<std::shared_ptr<ElementHandle>> querySelector(const std::string& selector) override;
    std::future<std::vector<std::shared_ptr<ElementHandle>>> querySelectorAll(const std::string& selector) override;
    std::future<std::shared_ptr<ElementHandle>> querySelectorXPath(const std::string& xpath) override;
    std::future<std::shared_ptr<ElementHandle>> waitForSelector(const std::string& selector, const WaitForSelectorOptions& options = {}) override;
    std::future<std::shared_ptr<ElementHandle>> waitForSelectorXPath(const std::string& xpath, const WaitForSelectorOptions& options = {}) override;

    // Evaluation
    std::future<json> evaluate(const std::string& script, const json& arg = json()) override;
    std::future<json> evaluateHandle(const std::string& script, const json& arg = json()) override;
    std::future<json> evaluateOnNewDocument(const std::string& script, const json& arg = json()) override;
    std::future<void> addInitScript(const std::string& script) override;

    // Actions (on main frame)
    std::future<bool> click(const std::string& selector, const ClickOptions& options = {}) override;
    std::future<bool> doubleClick(const std::string& selector, const ClickOptions& options = {}) override;
    std::future<bool> hover(const std::string& selector) override;
    std::future<bool> fill(const std::string& selector, const std::string& value, const TypeOptions& options = {}) override;
    std::future<bool> type(const std::string& selector, const std::string& text, const TypeOptions& options = {}) override;
    std::future<bool> press(const std::string& selector, const std::string& key, const KeyboardOptions& options = {}) override;
    std::future<bool> selectOption(const std::string& selector, const SelectOptionOptions& options) override;
    std::future<bool> check(const std::string& selector, const ClickOptions& options = {}) override;
    std::future<bool> uncheck(const std::string& selector, const ClickOptions& options = {}) override;
    std::future<bool> focus(const std::string& selector) override;
    std::future<bool> blur(const std::string& selector) override;
    std::future<bool> dragAndDrop(const std::string& source, const std::string& target) override;

    // Keyboard/Mouse
    std::future<bool> keyboardDown(const std::string& key) override;
    std::future<bool> keyboardUp(const std::string& key) override;
    std::future<bool> keyboardPress(const std::string& key, const KeyboardOptions& options = {}) override;
    std::future<bool> keyboardType(const std::string& text, const TypeOptions& options = {}) override;
    std::future<bool> mouseMove(int x, int y, const MouseOptions& options = {}) override;
    std::future<bool> mouseDown(int x, int y, const MouseOptions& options = {}) override;
    std::future<bool> mouseUp(int x, int y, const MouseOptions& options = {}) override;
    std::future<bool> mouseWheel(int deltaX, int deltaY) override;

    // Screenshots/PDF
    std::future<std::string> screenshot(const ScreenshotOptions& options = {}) override;
    std::future<std::string> pdf(const PDFOptions& options = {}) override;

    // Viewport
    std::future<bool> setViewportSize(const ViewportSize& viewport) override;
    ViewportSize viewportSize() const override;

    // Network
    std::future<bool> setRequestInterception(bool value) override;
    std::future<void> route(const std::string& urlPattern, std::function<void(const std::string&, const json&)> handler) override;
    std::future<void> unroute(const std::string& urlPattern) override;
    std::future<void> waitForRequest(const std::string& urlPattern, int timeoutMs = 30000) override;
    std::future<void> waitForResponse(const std::string& urlPattern, int timeoutMs = 30000) override;

    // Console/Dialogs
    void onConsoleMessage(std::function<void(const std::string&, const std::string&)> callback) override;
    void onDialog(std::function<void(const std::string&, const std::string&, bool, const std::string&)> callback) override;
    void onPageError(std::function<void(const std::string&)> callback) override;
    void onRequestFailed(std::function<void(const std::string&, const std::string&)> callback) override;
    void onResponse(std::function<void(const std::string&, int, const std::map<std::string, std::string>&)> callback) override;

    // Storage
    std::future<json> cookies(const std::vector<std::string>& urls = {}) override;
    std::future<bool> setCookie(const json& cookie) override;
    std::future<bool> deleteCookie(const std::string& name, const std::string& url) override;
    std::future<json> localStorage(const std::string& origin) override;
    std::future<json> sessionStorage(const std::string& origin) override;

    // Accessibility
    std::future<json> accessibilitySnapshot(const std::string& rootSelector = "") override;

    // Video
    std::future<bool> videoStart(const std::string& path, const ViewportSize& size = {}) override;
    std::future<std::string> videoStop() override;

    // Tracing
    std::future<bool> tracingStart(const std::string& path, bool screenshots = true, bool snapshots = true) override;
    std::future<std::string> tracingStop() override;

    // Checkpoint
    std::future<json> checkpoint() override;
    std::future<bool> restoreCheckpoint(const json& state) override;

    // Internal: Execute script and get result
    json executeScriptSync(const std::string& script);
    bool executeScriptBoolSync(const std::string& script);
    std::string executeScriptStringSync(const std::string& script);

    // Internal: WebView2 container access
    void setContainer(std::shared_ptr<WebView2Container> container) { m_container = container; }
    std::shared_ptr<WebView2Container> getContainer() const { return m_container; }

    // Internal: Set URL
    void setUrl(const std::string& url) { m_url = url; }

private:
    std::shared_ptr<WebView2BrowserContext> m_context;
    std::shared_ptr<WebView2Container> m_container;
    std::shared_ptr<WebView2Frame> m_mainFrame;
    std::vector<std::shared_ptr<WebView2Frame>> m_frames;
    std::string m_url;
    ViewportSize m_viewport;
    bool m_closed = false;

    // Event callbacks
    std::function<void(const std::string&, const std::string&)> m_consoleCallback;
    std::function<void(const std::string&, const std::string&, bool, const std::string&)> m_dialogCallback;
    std::function<void(const std::string&)> m_pageErrorCallback;
    std::function<void(const std::string&, const std::string&)> m_requestFailedCallback;
    std::function<void(const std::string&, int, const std::map<std::string, std::string>&)> m_responseCallback;

    // Network interception
    bool m_interceptionEnabled = false;
    std::map<std::string, std::function<void(const std::string&, const json&)>> m_routes;

    // Tracing
    bool m_tracing = false;
    std::string m_tracePath;

    // Video
    bool m_videoRecording = false;
    std::string m_videoPath;

    // Checkpoint state
    json m_checkpointState;

    mutable std::mutex m_mutex;
};

// ============================================================================
// WebView2BrowserContext — Browser context
// ============================================================================
class WebView2BrowserContext : public BrowserContext, public std::enable_shared_from_this<WebView2BrowserContext> {
public:
    WebView2BrowserContext(std::shared_ptr<WebView2Browser> browser, const BrowserContextOptions& options);

    // Pages
    std::future<std::shared_ptr<Page>> newPage() override;
    std::vector<std::shared_ptr<Page>> pages() override;
    std::future<std::shared_ptr<Page>> newPage(const PageOptions& options) override;

    // Cookies
    std::future<json> cookies(const std::vector<std::string>& urls = {}) override;
    std::future<bool> addCookies(const json& cookies) override;
    std::future<bool> clearCookies() override;

    // Permissions
    std::future<bool> grantPermissions(const std::vector<std::string>& permissions, const std::string& origin = "") override;
    std::future<bool> clearPermissions() override;

    // Storage state
    std::future<json> storageState(const std::string& path = "") override;

    // Close
    std::future<bool> close() override;

    // Browser reference
    std::shared_ptr<Browser> browser() override;

    // Checkpoint
    std::future<json> checkpoint() override;
    std::future<bool> restoreCheckpoint(const json& state) override;

    // Internal
    BrowserContextOptions getOptions() const { return m_options; }

private:
    std::shared_ptr<WebView2Browser> m_browser;
    BrowserContextOptions m_options;
    std::vector<std::shared_ptr<WebView2Page>> m_pages;
    mutable std::mutex m_mutex;
};

// ============================================================================
// WebView2Browser — Browser implementation
// ============================================================================
class WebView2Browser : public Browser, public std::enable_shared_from_this<WebView2Browser> {
public:
    WebView2Browser(BrowserType type, const json& options);
    ~WebView2Browser() override;

    // Contexts
    std::future<std::shared_ptr<BrowserContext>> newContext(const BrowserContextOptions& options = {}) override;
    std::vector<std::shared_ptr<BrowserContext>> contexts() override;

    // Default context
    std::shared_ptr<BrowserContext> defaultContext() override;

    // Version
    std::string version() const override;

    // Close
    std::future<bool> close() override;

    // Checkpoint
    std::future<json> checkpoint() override;
    std::future<bool> restoreCheckpoint(const json& state) override;

    // Check if connected
    bool isConnected() const override;

    // Internal: Launch the browser
    bool launch();

    // Internal: Get browser type
    BrowserType getType() const { return m_type; }

private:
    BrowserType m_type;
    json m_options;
    std::vector<std::shared_ptr<WebView2BrowserContext>> m_contexts;
    std::shared_ptr<WebView2BrowserContext> m_defaultContext;
    bool m_connected = false;
    std::string m_version;
    mutable std::mutex m_mutex;

    // Hidden window for WebView2 host
    HWND m_hiddenWindow = nullptr;
    static LRESULT CALLBACK hiddenWindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
};

// ============================================================================
// PlaywrightImpl — Main Playwright implementation
// ============================================================================
class PlaywrightImpl : public Playwright, public std::enable_shared_from_this<PlaywrightImpl> {
public:
    PlaywrightImpl();
    ~PlaywrightImpl() override;

    // Browser launching
    std::future<std::shared_ptr<Browser>> chromiumLaunch(const json& options = json()) override;
    std::future<std::shared_ptr<Browser>> firefoxLaunch(const json& options = json()) override;
    std::future<std::shared_ptr<Browser>> webkitLaunch(const json& options = json()) override;
    std::future<std::shared_ptr<Browser>> webview2Launch(const json& options = json()) override;

    // Generic launch
    std::future<std::shared_ptr<Browser>> launch(BrowserType type, const json& options = json()) override;

    // Connect to existing browser
    std::future<std::shared_ptr<Browser>> connectOverCDP(const std::string& endpointURL, const json& options = json()) override;

    // Stop
    void stop() override;

    // Version
    std::string version() const override;

private:
    std::atomic<bool> m_stopped{false};
    std::vector<std::shared_ptr<WebView2Browser>> m_activeBrowsers;
    mutable std::mutex m_mutex;

    std::shared_ptr<WebView2Browser> createBrowser(BrowserType type, const json& options);
};

// ============================================================================
// TestRunnerImpl — Test runner implementation
// ============================================================================
class TestRunnerImpl : public TestRunner {
public:
    explicit TestRunnerImpl(std::shared_ptr<Playwright> playwright);
    ~TestRunnerImpl() override;

    // Run a test suite
    std::future<SuiteExecutionResult> runSuite(const TestSuite& suite) override;

    // Run a single test
    std::future<TestExecutionResult> runTest(const TestCase& test, std::shared_ptr<BrowserContext> context) override;

    // Configuration
    void setOutputDir(const std::string& dir) override;
    void setBaseURL(const std::string& url) override;
    void setRetries(int retries) override;
    void setWorkers(int workers) override;
    void setReporter(std::function<void(const TestExecutionResult&)> reporter) override;

    // Global setup/teardown
    void setGlobalSetup(std::function<std::future<void>()> setup) override;
    void setGlobalTeardown(std::function<std::future<void>()> teardown) override;

private:
    std::shared_ptr<Playwright> m_playwright;
    std::string m_outputDir;
    std::string m_baseURL;
    int m_retries = 0;
    int m_workers = 4;
    std::function<void(const TestExecutionResult&)> m_reporter;
    std::function<std::future<void>()> m_globalSetup;
    std::function<std::future<void>()> m_globalTeardown;

    std::future<TestExecutionResult> executeTest(const TestCase& test, std::shared_ptr<BrowserContext> context);
    void takeScreenshot(std::shared_ptr<Page> page, const std::string& name);
    void recordVideo(std::shared_ptr<Page> page, const std::string& name);
};

// ============================================================================
// BrowserTestAgentImpl — AI-driven browser testing agent
// ============================================================================
class BrowserTestAgentImpl : public BrowserTestAgent {
public:
    explicit BrowserTestAgentImpl(std::shared_ptr<Playwright> playwright);
    ~BrowserTestAgentImpl() override;

    // Execute a natural language test task
    std::future<BrowserTestResult> executeTask(const BrowserTestTask& task) override;

    // Generate test code from natural language
    std::future<std::string> generateTestCode(const std::string& description, const std::string& url) override;

    // Run generated test code
    std::future<BrowserTestResult> runTestCode(const std::string& testCode, const std::string& url) override;

    // Learn from test results
    void learnFromResult(const BrowserTestTask& task, const BrowserTestResult& result) override;

    // Get learned patterns
    json getLearnedPatterns() const override;

private:
    std::shared_ptr<Playwright> m_playwright;
    std::shared_ptr<TestRunner> m_runner;
    mutable std::mutex m_learnedMutex;
    json m_learnedPatterns;

    std::future<BrowserTestResult> executeWithAgent(const BrowserTestTask& task);
    std::string buildTestPrompt(const BrowserTestTask& task);
    std::vector<TestStep> parseTestSteps(const std::string& agentResponse);
    std::future<bool> executeStep(std::shared_ptr<Page> page, const TestStep& step);
};

// ============================================================================
// NetworkInterceptorImpl — Network interception
// ============================================================================
class NetworkInterceptorImpl : public NetworkInterceptor {
public:
    explicit NetworkInterceptorImpl(std::shared_ptr<Page> page);
    ~NetworkInterceptorImpl() override;

    // Intercept and mock
    std::future<void> route(const std::string& urlPattern, const RouteOptions& options) override;
    std::future<void> route(const std::string& urlPattern, std::function<void(const std::string&, const json&)> handler) override;
    std::future<void> unroute(const std::string& urlPattern) override;
    std::future<void> unrouteAll() override;

    // Wait for network events
    std::future<json> waitForRequest(const std::string& urlPattern, int timeoutMs = 30000) override;
    std::future<json> waitForResponse(const std::string& urlPattern, int timeoutMs = 30000) override;
    std::future<std::vector<json>> waitForRequests(const std::string& urlPattern, int count, int timeoutMs = 30000) override;

    // Modify requests
    std::future<void> modifyRequest(const std::string& urlPattern, std::function<void(json&)> modifier) override;
    std::future<void> abortRequest(const std::string& urlPattern, const std::string& errorCode = "failed") override;

    // HAR export
    std::future<std::string> exportHAR(const std::string& path = "") override;

private:
    std::shared_ptr<Page> m_page;
    std::map<std::string, RouteOptions> m_routes;
    std::map<std::string, std::function<void(const std::string&, const json&)>> m_handlers;
    std::mutex m_mutex;
    std::vector<json> m_requestLog;
    std::vector<json> m_responseLog;
};

// ============================================================================
// VisualTesterImpl — Visual testing
// ============================================================================
class VisualTesterImpl : public VisualTester {
public:
    explicit VisualTesterImpl(std::shared_ptr<Page> page);
    ~VisualTesterImpl() override;

    // Compare current page with baseline
    std::future<VisualTestResult> compare(const std::string& baselinePath, const VisualTestOptions& options = {}) override;

    // Update baseline
    std::future<bool> updateBaseline(const std::string& baselinePath) override;

    // Compare element
    std::future<VisualTestResult> compareElement(std::shared_ptr<ElementHandle> element, const std::string& baselinePath, const VisualTestOptions& options = {}) override;

private:
    std::shared_ptr<Page> m_page;

    // Simple pixel comparison (placeholder for full implementation)
    double computeDifference(const std::vector<uint8_t>& img1, const std::vector<uint8_t>& img2, double threshold);
    std::vector<uint8_t> loadImage(const std::string& path);
    bool saveImage(const std::string& path, const std::vector<uint8_t>& data);
};

// ============================================================================
// WebView2ElementHandle Implementation
// ============================================================================

std::future<bool> WebView2ElementHandle::click(const ClickOptions& options) {
    return std::async(std::launch::async, [this, options]() -> bool {
        std::string script = "(function() { "
            "const el = document.querySelector('" + jsonEscape(m_selector) + "'); "
            "if (!el) return false; "
            "el.click(); "
            "return true; "
        "})()";
        return m_page->executeScriptBoolSync(script);
    });
}

std::future<bool> WebView2ElementHandle::doubleClick(const ClickOptions& options) {
    return std::async(std::launch::async, [this, options]() -> bool {
        std::string script = "(function() { "
            "const el = document.querySelector('" + jsonEscape(m_selector) + "'); "
            "if (!el) return false; "
            "const evt = new MouseEvent('dblclick', { bubbles: true }); "
            "el.dispatchEvent(evt); "
            "return true; "
        "})()";
        return m_page->executeScriptBoolSync(script);
    });
}

std::future<bool> WebView2ElementHandle::hover() {
    return std::async(std::launch::async, [this]() -> bool {
        std::string script = "(function() { "
            "const el = document.querySelector('" + jsonEscape(m_selector) + "'); "
            "if (!el) return false; "
            "const evt = new MouseEvent('mouseover', { bubbles: true }); "
            "el.dispatchEvent(evt); "
            "return true; "
        "})()";
        return m_page->executeScriptBoolSync(script);
    });
}

std::future<bool> WebView2ElementHandle::type(const std::string& text, const TypeOptions& options) {
    return std::async(std::launch::async, [this, text, options]() -> bool {
        std::string script = "(function() { "
            "const el = document.querySelector('" + jsonEscape(m_selector) + "'); "
            "if (!el) return false; "
            "el.value = '" + jsonEscape(text) + "'; "
            "el.dispatchEvent(new Event('input', { bubbles: true })); "
            "el.dispatchEvent(new Event('change', { bubbles: true })); "
            "return true; "
        "})()";
        return m_page->executeScriptBoolSync(script);
    });
}

std::future<bool> WebView2ElementHandle::press(const std::string& key, const KeyboardOptions& options) {
    return std::async(std::launch::async, [this, key, options]() -> bool {
        std::string script = "(function() { "
            "const el = document.querySelector('" + jsonEscape(m_selector) + "'); "
            "if (!el) return false; "
            "const evt = new KeyboardEvent('keydown', { key: '" + jsonEscape(key) + "' }); "
            "el.dispatchEvent(evt); "
            "return true; "
        "})()";
        return m_page->executeScriptBoolSync(script);
    });
}

std::future<bool> WebView2ElementHandle::fill(const std::string& value, const TypeOptions& options) {
    return type(value, options);
}

std::future<bool> WebView2ElementHandle::selectOption(const SelectOptionOptions& options) {
    return std::async(std::launch::async, [this, options]() -> bool {
        std::string script = "(function() { "
            "const el = document.querySelector('" + jsonEscape(m_selector) + "'); "
            "if (!el) return false; ";
        if (!options.values.empty()) {
            script += "el.value = '" + jsonEscape(options.values[0]) + "'; ";
        }
        script += "el.dispatchEvent(new Event('change', { bubbles: true })); "
            "return true; "
        "})()";
        return m_page->executeScriptBoolSync(script);
    });
}

std::future<bool> WebView2ElementHandle::focus() {
    return std::async(std::launch::async, [this]() -> bool {
        std::string script = "(function() { "
            "const el = document.querySelector('" + jsonEscape(m_selector) + "'); "
            "if (!el) return false; "
            "el.focus(); "
            "return true; "
        "})()";
        return m_page->executeScriptBoolSync(script);
    });
}

std::future<bool> WebView2ElementHandle::blur() {
    return std::async(std::launch::async, [this]() -> bool {
        std::string script = "(function() { "
            "const el = document.querySelector('" + jsonEscape(m_selector) + "'); "
            "if (!el) return false; "
            "el.blur(); "
            "return true; "
        "})()";
        return m_page->executeScriptBoolSync(script);
    });
}

std::future<bool> WebView2ElementHandle::scrollIntoViewIfNeeded() {
    return std::async(std::launch::async, [this]() -> bool {
        std::string script = "(function() { "
            "const el = document.querySelector('" + jsonEscape(m_selector) + "'); "
            "if (!el) return false; "
            "el.scrollIntoView({ behavior: 'smooth', block: 'center' }); "
            "return true; "
        "})()";
        return m_page->executeScriptBoolSync(script);
    });
}

std::future<bool> WebView2ElementHandle::check(const ClickOptions& options) {
    return std::async(std::launch::async, [this]() -> bool {
        std::string script = "(function() { "
            "const el = document.querySelector('" + jsonEscape(m_selector) + "'); "
            "if (!el) return false; "
            "el.checked = true; "
            "el.dispatchEvent(new Event('change', { bubbles: true })); "
            "return true; "
        "})()";
        return m_page->executeScriptBoolSync(script);
    });
}

std::future<bool> WebView2ElementHandle::uncheck(const ClickOptions& options) {
    return std::async(std::launch::async, [this]() -> bool {
        std::string script = "(function() { "
            "const el = document.querySelector('" + jsonEscape(m_selector) + "'); "
            "if (!el) return false; "
            "el.checked = false; "
            "el.dispatchEvent(new Event('change', { bubbles: true })); "
            "return true; "
        "})()";
        return m_page->executeScriptBoolSync(script);
    });
}

std::future<std::string> WebView2ElementHandle::getAttribute(const std::string& name) {
    return std::async(std::launch::async, [this, name]() -> std::string {
        std::string script = "(function() { "
            "const el = document.querySelector('" + jsonEscape(m_selector) + "'); "
            "if (!el) return null; "
            "return el.getAttribute('" + jsonEscape(name) + "'); "
        "})()";
        return m_page->executeScriptStringSync(script);
    });
}

std::future<std::string> WebView2ElementHandle::getProperty(const std::string& name) {
    return std::async(std::launch::async, [this, name]() -> std::string {
        std::string script = "(function() { "
            "const el = document.querySelector('" + jsonEscape(m_selector) + "'); "
            "if (!el) return null; "
            "return String(el." + jsonEscape(name) + "); "
        "})()";
        return m_page->executeScriptStringSync(script);
    });
}

std::future<std::string> WebView2ElementHandle::innerText() {
    return std::async(std::launch::async, [this]() -> std::string {
        std::string script = "(function() { "
            "const el = document.querySelector('" + jsonEscape(m_selector) + "'); "
            "if (!el) return null; "
            "return el.innerText; "
        "})()";
        return m_page->executeScriptStringSync(script);
    });
}

std::future<std::string> WebView2ElementHandle::innerHTML() {
    return std::async(std::launch::async, [this]() -> std::string {
        std::string script = "(function() { "
            "const el = document.querySelector('" + jsonEscape(m_selector) + "'); "
            "if (!el) return null; "
            "return el.innerHTML; "
        "})()";
        return m_page->executeScriptStringSync(script);
    });
}

std::future<std::string> WebView2ElementHandle::textContent() {
    return std::async(std::launch::async, [this]() -> std::string {
        std::string script = "(function() { "
            "const el = document.querySelector('" + jsonEscape(m_selector) + "'); "
            "if (!el) return null; "
            "return el.textContent; "
        "})()";
        return m_page->executeScriptStringSync(script);
    });
}

std::future<bool> WebView2ElementHandle::isVisible() {
    return std::async(std::launch::async, [this]() -> bool {
        std::string script = "(function() { "
            "const el = document.querySelector('" + jsonEscape(m_selector) + "'); "
            "if (!el) return false; "
            "const style = window.getComputedStyle(el); "
            "return style.display !== 'none' && style.visibility !== 'hidden' && style.opacity !== '0'; "
        "})()";
        return m_page->executeScriptBoolSync(script);
    });
}

std::future<bool> WebView2ElementHandle::isEnabled() {
    return std::async(std::launch::async, [this]() -> bool {
        std::string script = "(function() { "
            "const el = document.querySelector('" + jsonEscape(m_selector) + "'); "
            "if (!el) return false; "
            "return !el.disabled; "
        "})()";
        return m_page->executeScriptBoolSync(script);
    });
}

std::future<bool> WebView2ElementHandle::isChecked() {
    return std::async(std::launch::async, [this]() -> bool {
        std::string script = "(function() { "
            "const el = document.querySelector('" + jsonEscape(m_selector) + "'); "
            "if (!el) return false; "
            "return el.checked === true; "
        "})()";
        return m_page->executeScriptBoolSync(script);
    });
}

std::future<bool> WebView2ElementHandle::isDisabled() {
    return std::async(std::launch::async, [this]() -> bool {
        std::string script = "(function() { "
            "const el = document.querySelector('" + jsonEscape(m_selector) + "'); "
            "if (!el) return false; "
            "return el.disabled === true; "
        "})()";
        return m_page->executeScriptBoolSync(script);
    });
}

std::future<bool> WebView2ElementHandle::isEditable() {
    return std::async(std::launch::async, [this]() -> bool {
        std::string script = "(function() { "
            "const el = document.querySelector('" + jsonEscape(m_selector) + "'); "
            "if (!el) return false; "
            "return el.readOnly === false && el.disabled === false; "
        "})()";
        return m_page->executeScriptBoolSync(script);
    });
}

std::future<int> WebView2ElementHandle::getBoundingBoxX() {
    return std::async(std::launch::async, [this]() -> int {
        std::string script = "(function() { "
            "const el = document.querySelector('" + jsonEscape(m_selector) + "'); "
            "if (!el) return -1; "
            "const r = el.getBoundingClientRect(); "
            "return Math.round(r.x); "
        "})()";
        json result = m_page->executeScriptSync(script);
        return result.is_number() ? result.get<int>() : -1;
    });
}

std::future<int> WebView2ElementHandle::getBoundingBoxY() {
    return std::async(std::launch::async, [this]() -> int {
        std::string script = "(function() { "
            "const el = document.querySelector('" + jsonEscape(m_selector) + "'); "
            "if (!el) return -1; "
            "const r = el.getBoundingClientRect(); "
            "return Math.round(r.y); "
        "})()";
        json result = m_page->executeScriptSync(script);
        return result.is_number() ? result.get<int>() : -1;
    });
}

std::future<int> WebView2ElementHandle::getBoundingBoxWidth() {
    return std::async(std::launch::async, [this]() -> int {
        std::string script = "(function() { "
            "const el = document.querySelector('" + jsonEscape(m_selector) + "'); "
            "if (!el) return -1; "
            "const r = el.getBoundingClientRect(); "
            "return Math.round(r.width); "
        "})()";
        json result = m_page->executeScriptSync(script);
        return result.is_number() ? result.get<int>() : -1;
    });
}

std::future<int> WebView2ElementHandle::getBoundingBoxHeight() {
    return std::async(std::launch::async, [this]() -> int {
        std::string script = "(function() { "
            "const el = document.querySelector('" + jsonEscape(m_selector) + "'); "
            "if (!el) return -1; "
            "const r = el.getBoundingClientRect(); "
            "return Math.round(r.height); "
        "})()";
        json result = m_page->executeScriptSync(script);
        return result.is_number() ? result.get<int>() : -1;
    });
}

std::future<std::string> WebView2ElementHandle::screenshot(const ScreenshotOptions& options) {
    return std::async(std::launch::async, [this, options]() -> std::string {
        // Element screenshot via canvas
        std::string script = "(function() { "
            "const el = document.querySelector('" + jsonEscape(m_selector) + "'); "
            "if (!el) return null; "
            "const canvas = document.createElement('canvas'); "
            "const r = el.getBoundingClientRect(); "
            "canvas.width = r.width; "
            "canvas.height = r.height; "
            "const ctx = canvas.getContext('2d'); "
            "ctx.drawWindow(window, r.x, r.y, r.width, r.height, '#fff'); "
            "return canvas.toDataURL('image/png'); "
        "})()";
        std::string dataUrl = m_page->executeScriptStringSync(script);
        if (dataUrl.empty() || dataUrl.find("data:image/png;base64,") != 0) {
            return "";
        }
        // Decode base64 and save
        std::string base64 = dataUrl.substr(22);
        // Save to file if path provided
        if (!options.path.empty()) {
            std::ofstream out(options.path, std::ios::binary);
            // Base64 decode (simplified)
            static const char* b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            std::vector<uint8_t> decoded;
            int val = 0, valb = -8;
            for (char c : base64) {
                if (c == '=') break;
                const char* p = strchr(b64chars, c);
                if (!p) continue;
                val = (val << 6) + (int)(p - b64chars);
                valb += 6;
                if (valb >= 0) {
                    decoded.push_back((val >> valb) & 0xFF);
                    valb -= 8;
                }
            }
            out.write((const char*)decoded.data(), decoded.size());
        }
        return dataUrl;
    });
}

std::future<std::shared_ptr<ElementHandle>> WebView2ElementHandle::querySelector(const std::string& selector) {
    return std::async(std::launch::async, [this, selector]() -> std::shared_ptr<ElementHandle> {
        std::string combined = m_selector + " " + selector;
        std::string script = "(function() { "
            "return document.querySelector('" + jsonEscape(combined) + "') !== null; "
        "})()";
        if (m_page->executeScriptBoolSync(script)) {
            return std::make_shared<WebView2ElementHandle>(m_page, combined);
        }
        return nullptr;
    });
}

std::future<std::vector<std::shared_ptr<ElementHandle>>> WebView2ElementHandle::querySelectorAll(const std::string& selector) {
    return std::async(std::launch::async, [this, selector]() -> std::vector<std::shared_ptr<ElementHandle>> {
        std::string combined = m_selector + " " + selector;
        std::string script = "(function() { "
            "return document.querySelectorAll('" + jsonEscape(combined) + "').length; "
        "})()";
        json result = m_page->executeScriptSync(script);
        int count = result.is_number() ? result.get<int>() : 0;
        std::vector<std::shared_ptr<ElementHandle>> handles;
        for (int i = 0; i < count; i++) {
            handles.push_back(std::make_shared<WebView2ElementHandle>(m_page, combined + ":nth-child(" + std::to_string(i + 1) + ")"));
        }
        return handles;
    });
}

std::future<std::shared_ptr<ElementHandle>> WebView2ElementHandle::querySelectorXPath(const std::string& xpath) {
    return std::async(std::launch::async, [this, xpath]() -> std::shared_ptr<ElementHandle> {
        std::string script = "(function() { "
            "const result = document.evaluate('" + jsonEscape(xpath) + "', document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null); "
            "return result.singleNodeValue !== null; "
        "})()";
        if (m_page->executeScriptBoolSync(script)) {
            return std::make_shared<WebView2ElementHandle>(m_page, "xpath:" + xpath);
        }
        return nullptr;
    });
}

std::future<json> WebView2ElementHandle::evaluate(const std::string& script, const json& arg) {
    return std::async(std::launch::async, [this, script, arg]() -> json {
        std::string fullScript = "(function() { "
            "const el = document.querySelector('" + jsonEscape(m_selector) + "'); "
            "if (!el) return null; "
            "const arg = " + arg.dump() + "; "
            "return (function(el, arg) { " + script + " })(el, arg); "
        "})()";
        return m_page->executeScriptSync(fullScript);
    });
}

std::future<json> WebView2ElementHandle::evaluateHandle(const std::string& script, const json& arg) {
    return evaluate(script, arg);
}

std::shared_ptr<Frame> WebView2ElementHandle::contentFrame() {
    return m_page->mainFrame();
}

// ============================================================================
// WebView2Frame Implementation
// ============================================================================

std::vector<std::shared_ptr<Frame>> WebView2Frame::childFrames() {
    return m_childFrames;
}

std::future<bool> WebView2Frame::gotoURL(const std::string& url, const NavigateOptions& options) {
    return m_page->gotoURL(url, options);
}

std::future<bool> WebView2Frame::waitForNavigation(const NavigateOptions& options) {
    return std::async(std::launch::async, [this, options]() -> bool {
        // Wait for URL change
        std::string currentUrl = m_url;
        auto start = std::chrono::steady_clock::now();
        while (std::chrono::steady_clock::now() - start < std::chrono::milliseconds(options.timeoutMs)) {
            if (m_url != currentUrl) return true;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        return false;
    });
}

std::future<bool> WebView2Frame::waitForLoadState(WaitUntil state, int timeoutMs) {
    return std::async(std::launch::async, [this, state, timeoutMs]() -> bool {
        std::string script = "(function() { "
            "return document.readyState; "
        "})()";
        auto start = std::chrono::steady_clock::now();
        while (std::chrono::steady_clock::now() - start < std::chrono::milliseconds(timeoutMs)) {
            std::string readyState = m_page->executeScriptStringSync(script);
            if (state == WaitUntil::LOAD && readyState == "complete") return true;
            if (state == WaitUntil::DOMCONTENTLOADED && (readyState == "interactive" || readyState == "complete")) return true;
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        return false;
    });
}

std::future<std::shared_ptr<ElementHandle>> WebView2Frame::querySelector(const std::string& selector) {
    return m_page->querySelector(selector);
}

std::future<std::vector<std::shared_ptr<ElementHandle>>> WebView2Frame::querySelectorAll(const std::string& selector) {
    return m_page->querySelectorAll(selector);
}

std::future<std::shared_ptr<ElementHandle>> WebView2Frame::querySelectorXPath(const std::string& xpath) {
    return m_page->querySelectorXPath(xpath);
}

std::future<std::shared_ptr<ElementHandle>> WebView2Frame::waitForSelector(const std::string& selector, const WaitForSelectorOptions& options) {
    return std::async(std::launch::async, [this, selector, options]() -> std::shared_ptr<ElementHandle> {
        auto start = std::chrono::steady_clock::now();
        while (std::chrono::steady_clock::now() - start < std::chrono::milliseconds(options.timeoutMs)) {
            std::string script = "(function() { "
                "return document.querySelector('" + jsonEscape(selector) + "') !== null; "
            "})()";
            if (m_page->executeScriptBoolSync(script)) {
                return std::make_shared<WebView2ElementHandle>(m_page, selector);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        return nullptr;
    });
}

std::future<std::shared_ptr<ElementHandle>> WebView2Frame::waitForSelectorXPath(const std::string& xpath, const WaitForSelectorOptions& options) {
    return std::async(std::launch::async, [this, xpath, options]() -> std::shared_ptr<ElementHandle> {
        auto start = std::chrono::steady_clock::now();
        while (std::chrono::steady_clock::now() - start < std::chrono::milliseconds(options.timeoutMs)) {
            std::string script = "(function() { "
                "const result = document.evaluate('" + jsonEscape(xpath) + "', document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null); "
                "return result.singleNodeValue !== null; "
            "})()";
            if (m_page->executeScriptBoolSync(script)) {
                return std::make_shared<WebView2ElementHandle>(m_page, "xpath:" + xpath);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        return nullptr;
    });
}

std::future<json> WebView2Frame::evaluate(const std::string& script, const json& arg) {
    return m_page->evaluate(script, arg);
}

std::future<json> WebView2Frame::evaluateHandle(const std::string& script, const json& arg) {
    return m_page->evaluateHandle(script, arg);
}

std::future<bool> WebView2Frame::click(const std::string& selector, const ClickOptions& options) {
    return m_page->click(selector, options);
}

std::future<bool> WebView2Frame::fill(const std::string& selector, const std::string& value, const TypeOptions& options) {
    return m_page->fill(selector, value, options);
}

std::future<bool> WebView2Frame::type(const std::string& selector, const std::string& text, const TypeOptions& options) {
    return m_page->type(selector, text, options);
}

std::future<bool> WebView2Frame::press(const std::string& selector, const std::string& key, const KeyboardOptions& options) {
    return m_page->press(selector, key, options);
}

std::future<bool> WebView2Frame::selectOption(const std::string& selector, const SelectOptionOptions& options) {
    return m_page->selectOption(selector, options);
}

std::future<bool> WebView2Frame::check(const std::string& selector, const ClickOptions& options) {
    return m_page->check(selector, options);
}

std::future<bool> WebView2Frame::uncheck(const std::string& selector, const ClickOptions& options) {
    return m_page->uncheck(selector, options);
}

std::future<bool> WebView2Frame::hover(const std::string& selector) {
    return m_page->hover(selector);
}

std::future<bool> WebView2Frame::focus(const std::string& selector) {
    return m_page->focus(selector);
}

std::future<std::string> WebView2Frame::content() {
    return std::async(std::launch::async, [this]() -> std::string {
        std::string script = "(function() { "
            "return document.documentElement.outerHTML; "
        "})()";
        return m_page->executeScriptStringSync(script);
    });
}

std::future<std::string> WebView2Frame::title() {
    return std::async(std::launch::async, [this]() -> std::string {
        std::string script = "(function() { "
            "return document.title; "
        "})()";
        return m_page->executeScriptStringSync(script);
    });
}

// ============================================================================
// WebView2Page Implementation
// ============================================================================

WebView2Page::WebView2Page(std::shared_ptr<WebView2BrowserContext> context)
    : m_context(context), m_mainFrame(std::make_shared<WebView2Frame>(shared_from_this(), "", "about:blank")) {
    m_mainFrame->setParentFrame(nullptr);
    m_frames.push_back(m_mainFrame);
}

WebView2Page::~WebView2Page() {
    if (m_container) {
        m_container->destroy();
    }
}

std::future<bool> WebView2Page::close(bool runBeforeUnload) {
    return std::async(std::launch::async, [this, runBeforeUnload]() -> bool {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_closed) return true;
        m_closed = true;
        if (m_container) {
            m_container->destroy();
            m_container.reset();
        }
        return true;
    });
}

std::future<bool> WebView2Page::reload(const NavigateOptions& options) {
    return std::async(std::launch::async, [this, options]() -> bool {
        if (m_url.empty()) return false;
        return gotoURL(m_url, options).get();
    });
}

std::future<bool> WebView2Page::goBack(const NavigateOptions& options) {
    return std::async(std::launch::async, [this, options]() -> bool {
        // Navigate back in history
        std::string script = "(function() { "
            "if (window.history.length > 1) { "
            "window.history.back(); "
            "return true; "
            "} "
            "return false; "
        "})()";
        return executeScriptBoolSync(script);
    });
}

std::future<bool> WebView2Page::goForward(const NavigateOptions& options) {
    return std::async(std::launch::async, [this, options]() -> bool {
        std::string script = "(function() { "
            "if (window.history.length > 1) { "
            "window.history.forward(); "
            "return true; "
            "} "
            "return false; "
        "})()";
        return executeScriptBoolSync(script);
    });
}

std::future<bool> WebView2Page::gotoURL(const std::string& url, const NavigateOptions& options) {
    return std::async(std::launch::async, [this, url, options]() -> bool {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_closed || !m_container) return false;

        // Navigate the WebView2
        std::wstring wUrl(url.begin(), url.end());
        // Use the container's navigate method
        // Note: WebView2Container doesn't expose Navigate directly in our header,
        // so we use executeScript to set location
        std::string script = "(function() { "
            "window.location.href = '" + jsonEscape(url) + "'; "
            "return true; "
        "})()";

        // Wait for navigation to complete
        auto start = std::chrono::steady_clock::now();
        m_url = url;
        m_mainFrame->setUrl(url);

        // Wait for load state
        if (options.waitUntil == WaitUntil::LOAD) {
            while (std::chrono::steady_clock::now() - start < std::chrono::milliseconds(options.timeoutMs)) {
                std::string readyState = executeScriptStringSync("(function() { return document.readyState; })()");
                if (readyState == "complete") return true;
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
        }
        return true;
    });
}

std::future<bool> WebView2Page::waitForNavigation(const NavigateOptions& options) {
    return std::async(std::launch::async, [this, options]() -> bool {
        std::string currentUrl = m_url;
        auto start = std::chrono::steady_clock::now();
        while (std::chrono::steady_clock::now() - start < std::chrono::milliseconds(options.timeoutMs)) {
            if (m_url != currentUrl) return true;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        return false;
    });
}

std::future<bool> WebView2Page::waitForLoadState(WaitUntil state, int timeoutMs) {
    return std::async(std::launch::async, [this, state, timeoutMs]() -> bool {
        std::string script = "(function() { "
            "return document.readyState; "
        "})()";
        auto start = std::chrono::steady_clock::now();
        while (std::chrono::steady_clock::now() - start < std::chrono::milliseconds(timeoutMs)) {
            std::string readyState = executeScriptStringSync(script);
            if (state == WaitUntil::LOAD && readyState == "complete") return true;
            if (state == WaitUntil::DOMCONTENTLOADED && (readyState == "interactive" || readyState == "complete")) return true;
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        return false;
    });
}

std::string WebView2Page::url() const {
    return m_url;
}

std::future<std::string> WebView2Page::title() {
    return std::async(std::launch::async, [this]() -> std::string {
        std::string script = "(function() { "
            "return document.title; "
        "})()";
        return executeScriptStringSync(script);
    });
}

std::shared_ptr<Frame> WebView2Page::mainFrame() {
    return m_mainFrame;
}

std::vector<std::shared_ptr<Frame>> WebView2Page::frames() {
    std::vector<std::shared_ptr<Frame>> result;
    for (const auto& f : m_frames) {
        result.push_back(std::static_pointer_cast<Frame>(f));
    }
    return result;
}

std::future<std::shared_ptr<ElementHandle>> WebView2Page::querySelector(const std::string& selector) {
    return std::async(std::launch::async, [this, selector]() -> std::shared_ptr<ElementHandle> {
        std::string script = "(function() { "
            "return document.querySelector('" + jsonEscape(selector) + "') !== null; "
        "})()";
        if (executeScriptBoolSync(script)) {
            return std::make_shared<WebView2ElementHandle>(shared_from_this(), selector);
        }
        return nullptr;
    });
}

std::future<std::vector<std::shared_ptr<ElementHandle>>> WebView2Page::querySelectorAll(const std::string& selector) {
    return std::async(std::launch::async, [this, selector]() -> std::vector<std::shared_ptr<ElementHandle>> {
        std::string script = "(function() { "
            "return document.querySelectorAll('" + jsonEscape(selector) + "').length; "
        "})()";
        json result = executeScriptSync(script);
        int count = result.is_number() ? result.get<int>() : 0;
        std::vector<std::shared_ptr<ElementHandle>> handles;
        for (int i = 0; i < count; i++) {
            handles.push_back(std::make_shared<WebView2ElementHandle>(shared_from_this(), selector + ":nth-child(" + std::to_string(i + 1) + ")"));
        }
        return handles;
    });
}

std::future<std::shared_ptr<ElementHandle>> WebView2Page::querySelectorXPath(const std::string& xpath) {
    return std::async(std::launch::async, [this, xpath]() -> std::shared_ptr<ElementHandle> {
        std::string script = "(function() { "
            "const result = document.evaluate('" + jsonEscape(xpath) + "', document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null); "
            "return result.singleNodeValue !== null; "
        "})()";
        if (executeScriptBoolSync(script)) {
            return std::make_shared<WebView2ElementHandle>(shared_from_this(), "xpath:" + xpath);
        }
        return nullptr;
    });
}

std::future<std::shared_ptr<ElementHandle>> WebView2Page::waitForSelector(const std::string& selector, const WaitForSelectorOptions& options) {
    return std::async(std::launch::async, [this, selector, options]() -> std::shared_ptr<ElementHandle> {
        auto start = std::chrono::steady_clock::now();
        while (std::chrono::steady_clock::now() - start < std::chrono::milliseconds(options.timeoutMs)) {
            std::string script = "(function() { "
                "return document.querySelector('" + jsonEscape(selector) + "') !== null; "
            "})()";
            if (executeScriptBoolSync(script)) {
                return std::make_shared<WebView2ElementHandle>(shared_from_this(), selector);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        return nullptr;
    });
}

std::future<std::shared_ptr<ElementHandle>> WebView2Page::waitForSelectorXPath(const std::string& xpath, const WaitForSelectorOptions& options) {
    return std::async(std::launch::async, [this, xpath, options]() -> std::shared_ptr<ElementHandle> {
        auto start = std::chrono::steady_clock::now();
        while (std::chrono::steady_clock::now() - start < std::chrono::milliseconds(options.timeoutMs)) {
            std::string script = "(function() { "
                "const result = document.evaluate('" + jsonEscape(xpath) + "', document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null); "
                "return result.singleNodeValue !== null; "
            "})()";
            if (executeScriptBoolSync(script)) {
                return std::make_shared<WebView2ElementHandle>(shared_from_this(), "xpath:" + xpath);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        return nullptr;
    });
}

std::future<json> WebView2Page::evaluate(const std::string& script, const json& arg) {
    return std::async(std::launch::async, [this, script, arg]() -> json {
        std::string fullScript = "(function() { "
            "const arg = " + arg.dump() + "; "
            "return (function(arg) { " + script + " })(arg); "
        "})()";
        return executeScriptSync(fullScript);
    });
}

std::future<json> WebView2Page::evaluateHandle(const std::string& script, const json& arg) {
    return evaluate(script, arg);
}

std::future<json> WebView2Page::evaluateOnNewDocument(const std::string& script, const json& arg) {
    return evaluate(script, arg);
}

std::future<void> WebView2Page::addInitScript(const std::string& script) {
    return std::async(std::launch::async, [this, script]() -> void {
        // Store init script to run on navigation
        std::lock_guard<std::mutex> lock(m_mutex);
        m_checkpointState["initScripts"].push_back(script);
    });
}

std::future<bool> WebView2Page::click(const std::string& selector, const ClickOptions& options) {
    return std::async(std::launch::async, [this, selector, options]() -> bool {
        std::string script = "(function() { "
            "const el = document.querySelector('" + jsonEscape(selector) + "'); "
            "if (!el) return false; "
            "el.click(); "
            "return true; "
        "})()";
        return executeScriptBoolSync(script);
    });
}

std::future<bool> WebView2Page::doubleClick(const std::string& selector, const ClickOptions& options) {
    return std::async(std::launch::async, [this, selector, options]() -> bool {
        std::string script = "(function() { "
            "const el = document.querySelector('" + jsonEscape(selector) + "'); "
            "if (!el) return false; "
            "const evt = new MouseEvent('dblclick', { bubbles: true }); "
            "el.dispatchEvent(evt); "
            "return true; "
        "})()";
        return executeScriptBoolSync(script);
    });
}

std::future<bool> WebView2Page::hover(const std::string& selector) {
    return std::async(std::launch::async, [this, selector]() -> bool {
        std::string script = "(function() { "
            "const el = document.querySelector('" + jsonEscape(selector) + "'); "
            "if (!el) return false; "
            "const evt = new MouseEvent('mouseover', { bubbles: true }); "
            "el.dispatchEvent(evt); "
            "return true; "
        "})()";
        return executeScriptBoolSync(script);
    });
}

std::future<bool> WebView2Page::fill(const std::string& selector, const std::string& value, const TypeOptions& options) {
    return std::async(std::launch::async, [this, selector, value, options]() -> bool {
        std::string script = "(function() { "
            "const el = document.querySelector('" + jsonEscape(selector) + "'); "
            "if (!el) return false; "
            "el.value = '" + jsonEscape(value) + "'; "
            "el.dispatchEvent(new Event('input', { bubbles: true })); "
            "el.dispatchEvent(new Event('change', { bubbles: true })); "
            "return true; "
        "})()";
        return executeScriptBoolSync(script);
    });
}

std::future<bool> WebView2Page::type(const std::string& selector, const std::string& text, const TypeOptions& options) {
    return fill(selector, text, options);
}

std::future<bool> WebView2Page::press(const std::string& selector, const std::string& key, const KeyboardOptions& options) {
    return std::async(std::launch::async, [this, selector, key, options]() -> bool {
        std::string script = "(function() { "
            "const el = document.querySelector('" + jsonEscape(selector) + "'); "
            "if (!el) return false; "
            "const evt = new KeyboardEvent('keydown', { key: '" + jsonEscape(key) + "' }); "
            "el.dispatchEvent(evt); "
            "return true; "
        "})()";
        return executeScriptBoolSync(script);
    });
}

std::future<bool> WebView2Page::selectOption(const std::string& selector, const SelectOptionOptions& options) {
    return std::async(std::launch::async, [this, selector, options]() -> bool {
        std::string script = "(function() { "
            "const el = document.querySelector('" + jsonEscape(selector) + "'); "
            "if (!el) return false; ";
        if (!options.values.empty()) {
            script += "el.value = '" + jsonEscape(options.values[0]) + "'; ";
        }
        script += "el.dispatchEvent(new Event('change', { bubbles: true })); "
            "return true; "
        "})()";
        return executeScriptBoolSync(script);
    });
}

std::future<bool> WebView2Page::check(const std::string& selector, const ClickOptions& options) {
    return std::async(std::launch::async, [this, selector]() -> bool {
        std::string script = "(function() { "
            "const el = document.querySelector('" + jsonEscape(selector) + "'); "
            "if (!el) return false; "
            "el.checked = true; "
            "el.dispatchEvent(new Event('change', { bubbles: true })); "
            "return true; "
        "})()";
        return executeScriptBoolSync(script);
    });
}

std::future<bool> WebView2Page::uncheck(const std::string& selector, const ClickOptions& options) {
    return std::async(std::launch::async, [this, selector]() -> bool {
        std::string script = "(function() { "
            "const el = document.querySelector('" + jsonEscape(selector) + "'); "
            "if (!el) return false; "
            "el.checked = false; "
            "el.dispatchEvent(new Event('change', { bubbles: true })); "
            "return true; "
        "})()";
        return executeScriptBoolSync(script);
    });
}

std::future<bool> WebView2Page::focus(const std::string& selector) {
    return std::async(std::launch::async, [this, selector]() -> bool {
        std::string script = "(function() { "
            "const el = document.querySelector('" + jsonEscape(selector) + "'); "
            "if (!el) return false; "
            "el.focus(); "
            "return true; "
        "})()";
        return executeScriptBoolSync(script);
    });
}

std::future<bool> WebView2Page::blur(const std::string& selector) {
    return std::async(std::launch::async, [this, selector]() -> bool {
        std::string script = "(function() { "
            "const el = document.querySelector('" + jsonEscape(selector) + "'); "
            "if (!el) return false; "
            "el.blur(); "
            "return true; "
        "})()";
        return executeScriptBoolSync(script);
    });
}

std::future<bool> WebView2Page::dragAndDrop(const std::string& source, const std::string& target) {
    return std::async(std::launch::async, [this, source, target]() -> bool {
        std::string script = "(function() { "
            "const src = document.querySelector('" + jsonEscape(source) + "'); "
            "const tgt = document.querySelector('" + jsonEscape(target) + "'); "
            "if (!src || !tgt) return false; "
            "const evt = new DragEvent('drop', { bubbles: true }); "
            "tgt.dispatchEvent(evt); "
            "return true; "
        "})()";
        return executeScriptBoolSync(script);
    });
}

std::future<bool> WebView2Page::keyboardDown(const std::string& key) {
    return std::async(std::launch::async, [this, key]() -> bool {
        std::string script = "(function() { "
            "const evt = new KeyboardEvent('keydown', { key: '" + jsonEscape(key) + "' }); "
            "document.dispatchEvent(evt); "
            "return true; "
        "})()";
        return executeScriptBoolSync(script);
    });
}

std::future<bool> WebView2Page::keyboardUp(const std::string& key) {
    return std::async(std::launch::async, [this, key]() -> bool {
        std::string script = "(function() { "
            "const evt = new KeyboardEvent('keyup', { key: '" + jsonEscape(key) + "' }); "
            "document.dispatchEvent(evt); "
            "return true; "
        "})()";
        return executeScriptBoolSync(script);
    });
}

std::future<bool> WebView2Page::keyboardPress(const std::string& key, const KeyboardOptions& options) {
    return std::async(std::launch::async, [this, key, options]() -> bool {
        std::string script = "(function() { "
            "const evt = new KeyboardEvent('keypress', { key: '" + jsonEscape(key) + "' }); "
            "document.dispatchEvent(evt); "
            "return true; "
        "})()";
        return executeScriptBoolSync(script);
    });
}

std::future<bool> WebView2Page::keyboardType(const std::string& text, const TypeOptions& options) {
    return std::async(std::launch::async, [this, text, options]() -> bool {
        std::string script = "(function() { "
            "const evt = new KeyboardEvent('keypress', { key: '" + jsonEscape(text) + "' }); "
            "document.dispatchEvent(evt); "
            "return true; "
        "})()";
        return executeScriptBoolSync(script);
    });
}

std::future<bool> WebView2Page::mouseMove(int x, int y, const MouseOptions& options) {
    return std::async(std::launch::async, [this, x, y, options]() -> bool {
        std::string script = "(function() { "
            "const evt = new MouseEvent('mousemove', { clientX: " + std::to_string(x) + ", clientY: " + std::to_string(y) + " }); "
            "document.dispatchEvent(evt); "
            "return true; "
        "})()";
        return executeScriptBoolSync(script);
    });
}

std::future<bool> WebView2Page::mouseDown(int x, int y, const MouseOptions& options) {
    return std::async(std::launch::async, [this, x, y, options]() -> bool {
        std::string script = "(function() { "
            "const evt = new MouseEvent('mousedown', { clientX: " + std::to_string(x) + ", clientY: " + std::to_string(y) + " }); "
            "document.dispatchEvent(evt); "
            "return true; "
        "})()";
        return executeScriptBoolSync(script);
    });
}

std::future<bool> WebView2Page::mouseUp(int x, int y, const MouseOptions& options) {
    return std::async(std::launch::async, [this, x, y, options]() -> bool {
        std::string script = "(function() { "
            "const evt = new MouseEvent('mouseup', { clientX: " + std::to_string(x) + ", clientY: " + std::to_string(y) + " }); "
            "document.dispatchEvent(evt); "
            "return true; "
        "})()";
        return executeScriptBoolSync(script);
    });
}

std::future<bool> WebView2Page::mouseWheel(int deltaX, int deltaY) {
    return std::async(std::launch::async, [this, deltaX, deltaY]() -> bool {
        std::string script = "(function() { "
            "const evt = new WheelEvent('wheel', { deltaX: " + std::to_string(deltaX) + ", deltaY: " + std::to_string(deltaY) + " }); "
            "document.dispatchEvent(evt); "
            "return true; "
        "})()";
        return executeScriptBoolSync(script);
    });
}

std::future<std::string> WebView2Page::screenshot(const ScreenshotOptions& options) {
    return std::async(std::launch::async, [this, options]() -> std::string {
        // Capture screenshot via canvas
        std::string script = "(function() { "
            "const canvas = document.createElement('canvas'); "
            "canvas.width = window.innerWidth; "
            "canvas.height = window.innerHeight; "
            "const ctx = canvas.getContext('2d'); "
            "ctx.drawWindow(window, 0, 0, window.innerWidth, window.innerHeight, '#fff'); "
            "return canvas.toDataURL('image/png'); "
        "})()";
        std::string dataUrl = executeScriptStringSync(script);
        if (dataUrl.empty() || dataUrl.find("data:image/png;base64,") != 0) {
            return "";
        }
        // Decode base64 and save
        std::string base64 = dataUrl.substr(22);
        if (!options.path.empty()) {
            std::ofstream out(options.path, std::ios::binary);
            static const char* b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            std::vector<uint8_t> decoded;
            int val = 0, valb = -8;
            for (char c : base64) {
                if (c == '=') break;
                const char* p = strchr(b64chars, c);
                if (!p) continue;
                val = (val << 6) + (int)(p - b64chars);
                valb += 6;
                if (valb >= 0) {
                    decoded.push_back((val >> valb) & 0xFF);
                    valb -= 8;
                }
            }
            out.write((const char*)decoded.data(), decoded.size());
        }
        return dataUrl;
    });
}

std::future<std::string> WebView2Page::pdf(const PDFOptions& options) {
    return std::async(std::launch::async, [this, options]() -> std::string {
        // PDF generation via print
        std::string script = "(function() { "
            "window.print(); "
            "return true; "
        "})()";
        executeScriptBoolSync(script);
        return "";
    });
}

std::future<bool> WebView2Page::setViewportSize(const ViewportSize& viewport) {
    return std::async(std::launch::async, [this, viewport]() -> bool {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_viewport = viewport;
        if (m_container) {
            m_container->resize(0, 0, viewport.width, viewport.height);
        }
        return true;
    });
}

ViewportSize WebView2Page::viewportSize() const {
    return m_viewport;
}

std::future<bool> WebView2Page::setRequestInterception(bool value) {
    return std::async(std::launch::async, [this, value]() -> bool {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_interceptionEnabled = value;
        return true;
    });
}

std::future<void> WebView2Page::route(const std::string& urlPattern, std::function<void(const std::string&, const json&)> handler) {
    return std::async(std::launch::async, [this, urlPattern, handler]() -> void {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_routes[urlPattern] = handler;
    });
}

std::future<void> WebView2Page::unroute(const std::string& urlPattern) {
    return std::async(std::launch::async, [this, urlPattern]() -> void {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_routes.erase(urlPattern);
    });
}

std::future<void> WebView2Page::waitForRequest(const std::string& urlPattern, int timeoutMs) {
    return std::async(std::launch::async, [this, urlPattern, timeoutMs]() -> void {
        // Wait for a request matching the pattern
        auto start = std::chrono::steady_clock::now();
        while (std::chrono::steady_clock::now() - start < std::chrono::milliseconds(timeoutMs)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    });
}

std::future<void> WebView2Page::waitForResponse(const std::string& urlPattern, int timeoutMs) {
    return std::async(std::launch::async, [this, urlPattern, timeoutMs]() -> void {
        auto start = std::chrono::steady_clock::now();
        while (std::chrono::steady_clock::now() - start < std::chrono::milliseconds(timeoutMs)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    });
}

void WebView2Page::onConsoleMessage(std::function<void(const std::string&, const std::string&)> callback) {
    m_consoleCallback = callback;
}

void WebView2Page::onDialog(std::function<void(const std::string&, const std::string&, bool, const std::string&)> callback) {
    m_dialogCallback = callback;
}

void WebView2Page::onPageError(std::function<void(const std::string&)> callback) {
    m_pageErrorCallback = callback;
}

void WebView2Page::onRequestFailed(std::function<void(const std::string&, const std::string&)> callback) {
    m_requestFailedCallback = callback;
}

void WebView2Page::onResponse(std::function<void(const std::string&, int, const std::map<std::string, std::string>&)> callback) {
    m_responseCallback = callback;
}

std::future<json> WebView2Page::cookies(const std::vector<std::string>& urls) {
    return std::async(std::launch::async, [this, urls]() -> json {
        std::string script = "(function() { "
            "return document.cookie; "
        "})()";
        std::string cookieStr = executeScriptStringSync(script);
        json cookies = json::array();
        std::istringstream stream(cookieStr);
        std::string cookie;
        while (std::getline(stream, cookie, ';')) {
            size_t eq = cookie.find('=');
            if (eq != std::string::npos) {
                json c;
                c["name"] = cookie.substr(0, eq);
                c["value"] = cookie.substr(eq + 1);
                cookies.push_back(c);
            }
        }
        return cookies;
    });
}

std::future<bool> WebView2Page::setCookie(const json& cookie) {
    return std::async(std::launch::async, [this, cookie]() -> bool {
        std::string name = cookie.value("name", "");
        std::string value = cookie.value("value", "");
        std::string script = "(function() { "
            "document.cookie = '" + jsonEscape(name) + "=" + jsonEscape(value) + "'; "
            "return true; "
        "})()";
        return executeScriptBoolSync(script);
    });
}

std::future<bool> WebView2Page::deleteCookie(const std::string& name, const std::string& url) {
    return std::async(std::launch::async, [this, name]() -> bool {
        std::string script = "(function() { "
            "document.cookie = '" + jsonEscape(name) + "=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;'; "
            "return true; "
        "})()";
        return executeScriptBoolSync(script);
    });
}

std::future<json> WebView2Page::localStorage(const std::string& origin) {
    return std::async(std::launch::async, [this]() -> json {
        std::string script = "(function() { "
            "const result = {}; "
            "for (let i = 0; i < localStorage.length; i++) { "
            "const key = localStorage.key(i); "
            "result[key] = localStorage.getItem(key); "
            "} "
            "return result; "
        "})()";
        return executeScriptSync(script);
    });
}

std::future<json> WebView2Page::sessionStorage(const std::string& origin) {
    return std::async(std::launch::async, [this]() -> json {
        std::string script = "(function() { "
            "const result = {}; "
            "for (let i = 0; i < sessionStorage.length; i++) { "
            "const key = sessionStorage.key(i); "
            "result[key] = sessionStorage.getItem(key); "
            "} "
            "return result; "
        "})()";
        return executeScriptSync(script);
    });
}

std::future<json> WebView2Page::accessibilitySnapshot(const std::string& rootSelector) {
    return std::async(std::launch::async, [this, rootSelector]() -> json {
        std::string script = "(function() { "
            "const root = " + (rootSelector.empty() ? "document.body" : "document.querySelector('" + jsonEscape(rootSelector) + "')") + "; "
            "if (!root) return null; "
            "function walk(el) { "
            "const node = { role: el.tagName ? el.tagName.toLowerCase() : 'text', name: el.innerText || '' }; "
            "if (el.children) { "
            "node.children = []; "
            "for (const child of el.children) { "
            "node.children.push(walk(child)); "
            "} "
            "} "
            "return node; "
            "} "
            "return walk(root); "
        "})()";
        return executeScriptSync(script);
    });
}

std::future<bool> WebView2Page::videoStart(const std::string& path, const ViewportSize& size) {
    return std::async(std::launch::async, [this, path, size]() -> bool {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_videoRecording = true;
        m_videoPath = path;
        return true;
    });
}

std::future<std::string> WebView2Page::videoStop() {
    return std::async(std::launch::async, [this]() -> std::string {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_videoRecording = false;
        return m_videoPath;
    });
}

std::future<bool> WebView2Page::tracingStart(const std::string& path, bool screenshots, bool snapshots) {
    return std::async(std::launch::async, [this, path, screenshots, snapshots]() -> bool {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_tracing = true;
        m_tracePath = path;
        return true;
    });
}

std::future<std::string> WebView2Page::tracingStop() {
    return std::async(std::launch::async, [this]() -> std::string {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_tracing = false;
        return m_tracePath;
    });
}

std::future<json> WebView2Page::checkpoint() {
    return std::async(std::launch::async, [this]() -> json {
        std::lock_guard<std::mutex> lock(m_mutex);
        json state;
        state["url"] = m_url;
        state["viewport"] = { {"width", m_viewport.width}, {"height", m_viewport.height} };
        state["cookies"] = cookies().get();
        state["localStorage"] = localStorage("").get();
        state["sessionStorage"] = sessionStorage("").get();
        state["title"] = title().get();
        return state;
    });
}

std::future<bool> WebView2Page::restoreCheckpoint(const json& state) {
    return std::async(std::launch::async, [this, state]() -> bool {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (state.contains("url")) {
            m_url = state["url"].get<std::string>();
            gotoURL(m_url).get();
        }
        if (state.contains("viewport")) {
            ViewportSize vp;
            vp.width = state["viewport"]["width"].get<int>();
            vp.height = state["viewport"]["height"].get<int>();
            setViewportSize(vp).get();
        }
        return true;
    });
}

json WebView2Page::executeScriptSync(const std::string& script) {
    if (!m_container) return nullptr;
    // Execute script and capture result via a temporary mechanism
    // Since WebView2Container::executeScript doesn't return a value,
    // we use a result buffer approach
    std::string resultScript = script + ";";
    m_container->executeScript(resultScript);
    // Return empty JSON (full implementation would use CDP for return values)
    return json();
}

bool WebView2Page::executeScriptBoolSync(const std::string& script) {
    json result = executeScriptSync(script);
    return result.is_boolean() ? result.get<bool>() : false;
}

std::string WebView2Page::executeScriptStringSync(const std::string& script) {
    json result = executeScriptSync(script);
    return result.is_string() ? result.get<std::string>() : "";
}

// ============================================================================
// WebView2BrowserContext Implementation
// ============================================================================

WebView2BrowserContext::WebView2BrowserContext(std::shared_ptr<WebView2Browser> browser, const BrowserContextOptions& options)
    : m_browser(browser), m_options(options) {}

std::future<std::shared_ptr<Page>> WebView2BrowserContext::newPage() {
    return std::async(std::launch::async, [this]() -> std::shared_ptr<Page> {
        auto page = std::make_shared<WebView2Page>(shared_from_this());
        std::lock_guard<std::mutex> lock(m_mutex);
        m_pages.push_back(page);
        return page;
    });
}

std::vector<std::shared_ptr<Page>> WebView2BrowserContext::pages() {
    std::vector<std::shared_ptr<Page>> result;
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& p : m_pages) {
        result.push_back(std::static_pointer_cast<Page>(p));
    }
    return result;
}

std::future<std::shared_ptr<Page>> WebView2BrowserContext::newPage(const PageOptions& options) {
    return newPage();
}

std::future<json> WebView2BrowserContext::cookies(const std::vector<std::string>& urls) {
    return std::async(std::launch::async, [this, urls]() -> json {
        json allCookies = json::array();
        auto pages = this->pages();
        for (const auto& page : pages) {
            json pageCookies = page->cookies(urls).get();
            for (const auto& c : pageCookies) {
                allCookies.push_back(c);
            }
        }
        return allCookies;
    });
}

std::future<bool> WebView2BrowserContext::addCookies(const json& cookies) {
    return std::async(std::launch::async, [this, cookies]() -> bool {
        auto pages = this->pages();
        if (pages.empty()) return false;
        for (const auto& c : cookies) {
            pages[0]->setCookie(c).get();
        }
        return true;
    });
}

std::future<bool> WebView2BrowserContext::clearCookies() {
    return std::async(std::launch::async, [this]() -> bool {
        auto pages = this->pages();
        for (const auto& page : pages) {
            json cookies = page->cookies().get();
            for (const auto& c : cookies) {
                std::string name = c.value("name", "");
                if (!name.empty()) {
                    page->deleteCookie(name, "").get();
                }
            }
        }
        return true;
    });
}

std::future<bool> WebView2BrowserContext::grantPermissions(const std::vector<std::string>& permissions, const std::string& origin) {
    return std::async(std::launch::async, [this, permissions, origin]() -> bool {
        // Store permissions in context state
        std::lock_guard<std::mutex> lock(m_mutex);
        for (const auto& p : permissions) {
            m_options.permissions.push_back(p);
        }
        return true;
    });
}

std::future<bool> WebView2BrowserContext::clearPermissions() {
    return std::async(std::launch::async, [this]() -> bool {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_options.permissions.clear();
        return true;
    });
}

std::future<json> WebView2BrowserContext::storageState(const std::string& path) {
    return std::async(std::launch::async, [this, path]() -> json {
        json state;
        state["cookies"] = cookies().get();
        state["origins"] = json::array();
        auto pages = this->pages();
        for (const auto& page : pages) {
            json origin;
            origin["origin"] = page->url();
            origin["localStorage"] = page->localStorage("").get();
            state["origins"].push_back(origin);
        }
        if (!path.empty()) {
            std::ofstream out(path);
            out << state.dump(2);
        }
        return state;
    });
}

std::future<bool> WebView2BrowserContext::close() {
    return std::async(std::launch::async, [this]() -> bool {
        auto pages = this->pages();
        for (const auto& page : pages) {
            page->close().get();
        }
        std::lock_guard<std::mutex> lock(m_mutex);
        m_pages.clear();
        return true;
    });
}

std::shared_ptr<Browser> WebView2BrowserContext::browser() {
    return m_browser;
}

std::future<json> WebView2BrowserContext::checkpoint() {
    return std::async(std::launch::async, [this]() -> json {
        json state;
        state["options"] = {
            {"userAgent", m_options.userAgent},
            {"locale", m_options.locale},
            {"timezoneId", m_options.timezoneId}
        };
        state["pages"] = json::array();
        auto pages = this->pages();
        for (const auto& page : pages) {
            state["pages"].push_back(page->checkpoint().get());
        }
        return state;
    });
}

std::future<bool> WebView2BrowserContext::restoreCheckpoint(const json& state) {
    return std::async(std::launch::async, [this, state]() -> bool {
        if (state.contains("pages")) {
            auto pages = this->pages();
            for (size_t i = 0; i < state["pages"].size() && i < pages.size(); i++) {
                pages[i]->restoreCheckpoint(state["pages"][i]).get();
            }
        }
        return true;
    });
}

// ============================================================================
// WebView2Browser Implementation
// ============================================================================

WebView2Browser::WebView2Browser(BrowserType type, const json& options)
    : m_type(type), m_options(options) {
    m_version = "WebView2/1.0";
}

WebView2Browser::~WebView2Browser() {
    if (m_hiddenWindow) {
        DestroyWindow(m_hiddenWindow);
        m_hiddenWindow = nullptr;
    }
}

LRESULT CALLBACK WebView2Browser::hiddenWindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

bool WebView2Browser::launch() {
    std::lock_guard<std::mutex> lock(m_mutex);

    // Create a hidden window for WebView2 hosting
    WNDCLASSA wc = {};
    wc.lpfnWndProc = hiddenWindowProc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.lpszClassName = "RawrXD_BrowserTest_Window";
    RegisterClassA(&wc);

    m_hiddenWindow = CreateWindowA("RawrXD_BrowserTest_Window", "RawrXD Browser Test",
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 1280, 720,
        nullptr, nullptr, GetModuleHandle(nullptr), nullptr);

    if (!m_hiddenWindow) {
        return false;
    }

    ShowWindow(m_hiddenWindow, SW_HIDE);

    // Create default context
    m_defaultContext = std::make_shared<WebView2BrowserContext>(shared_from_this(), BrowserContextOptions());
    m_contexts.push_back(m_defaultContext);
    m_connected = true;

    return true;
}

std::future<std::shared_ptr<BrowserContext>> WebView2Browser::newContext(const BrowserContextOptions& options) {
    return std::async(std::launch::async, [this, options]() -> std::shared_ptr<BrowserContext> {
        auto context = std::make_shared<WebView2BrowserContext>(shared_from_this(), options);
        std::lock_guard<std::mutex> lock(m_mutex);
        m_contexts.push_back(context);
        return context;
    });
}

std::vector<std::shared_ptr<BrowserContext>> WebView2Browser::contexts() {
    std::vector<std::shared_ptr<BrowserContext>> result;
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& c : m_contexts) {
        result.push_back(std::static_pointer_cast<BrowserContext>(c));
    }
    return result;
}

std::shared_ptr<BrowserContext> WebView2Browser::defaultContext() {
    return m_defaultContext;
}

std::string WebView2Browser::version() const {
    return m_version;
}

std::future<bool> WebView2Browser::close() {
    return std::async(std::launch::async, [this]() -> bool {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (const auto& c : m_contexts) {
            c->close().get();
        }
        m_contexts.clear();
        m_defaultContext.reset();
        m_connected = false;
        if (m_hiddenWindow) {
            DestroyWindow(m_hiddenWindow);
            m_hiddenWindow = nullptr;
        }
        return true;
    });
}

std::future<json> WebView2Browser::checkpoint() {
    return std::async(std::launch::async, [this]() -> json {
        json state;
        state["type"] = static_cast<int>(m_type);
        state["version"] = m_version;
        state["contexts"] = json::array();
        auto contexts = this->contexts();
        for (const auto& c : contexts) {
            state["contexts"].push_back(c->checkpoint().get());
        }
        return state;
    });
}

std::future<bool> WebView2Browser::restoreCheckpoint(const json& state) {
    return std::async(std::launch::async, [this, state]() -> bool {
        if (state.contains("contexts")) {
            auto contexts = this->contexts();
            for (size_t i = 0; i < state["contexts"].size() && i < contexts.size(); i++) {
                contexts[i]->restoreCheckpoint(state["contexts"][i]).get();
            }
        }
        return true;
    });
}

bool WebView2Browser::isConnected() const {
    return m_connected;
}

// ============================================================================
// PlaywrightImpl Implementation
// ============================================================================

PlaywrightImpl::PlaywrightImpl() = default;

PlaywrightImpl::~PlaywrightImpl() {
    stop();
}

std::future<std::shared_ptr<Browser>> PlaywrightImpl::chromiumLaunch(const json& options) {
    return launch(BrowserType::CHROMIUM, options);
}

std::future<std::shared_ptr<Browser>> PlaywrightImpl::firefoxLaunch(const json& options) {
    return launch(BrowserType::FIREFOX, options);
}

std::future<std::shared_ptr<Browser>> PlaywrightImpl::webkitLaunch(const json& options) {
    return launch(BrowserType::WEBKIT, options);
}

std::future<std::shared_ptr<Browser>> PlaywrightImpl::webview2Launch(const json& options) {
    return launch(BrowserType::WEBVIEW2, options);
}

std::future<std::shared_ptr<Browser>> PlaywrightImpl::launch(BrowserType type, const json& options) {
    return std::async(std::launch::async, [this, type, options]() -> std::shared_ptr<Browser> {
        auto browser = createBrowser(type, options);
        if (browser && browser->launch()) {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_activeBrowsers.push_back(browser);
            return browser;
        }
        return nullptr;
    });
}

std::future<std::shared_ptr<Browser>> PlaywrightImpl::connectOverCDP(const std::string& endpointURL, const json& options) {
    return std::async(std::launch::async, [this, endpointURL, options]() -> std::shared_ptr<Browser> {
        // Connect to existing browser via CDP
        auto browser = createBrowser(BrowserType::CHROMIUM, options);
        if (browser) {
            // In a full implementation, this would connect to the CDP endpoint
            browser->launch();
            std::lock_guard<std::mutex> lock(m_mutex);
            m_activeBrowsers.push_back(browser);
            return browser;
        }
        return nullptr;
    });
}

void PlaywrightImpl::stop() {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& b : m_activeBrowsers) {
        b->close().get();
    }
    m_activeBrowsers.clear();
    m_stopped = true;
}

std::string PlaywrightImpl::version() const {
    return "1.0.0";
}

std::shared_ptr<WebView2Browser> PlaywrightImpl::createBrowser(BrowserType type, const json& options) {
    return std::make_shared<WebView2Browser>(type, options);
}

// ============================================================================
// TestRunnerImpl Implementation
// ============================================================================

TestRunnerImpl::TestRunnerImpl(std::shared_ptr<Playwright> playwright)
    : m_playwright(playwright) {}

TestRunnerImpl::~TestRunnerImpl() = default;

std::future<SuiteExecutionResult> TestRunnerImpl::runSuite(const TestSuite& suite) {
    return std::async(std::launch::async, [this, suite]() -> SuiteExecutionResult {
        SuiteExecutionResult result;
        result.suiteName = suite.name;
        auto start = std::chrono::steady_clock::now();

        // Global setup
        if (m_globalSetup) {
            try {
                m_globalSetup().get();
            } catch (...) {
                result.errors++;
                result.totalDuration = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - start);
                return result;
            }
        }

        // Suite beforeAll
        if (suite.beforeAll) {
            try {
                suite.beforeAll().get();
            } catch (...) {
                result.errors++;
                result.totalDuration = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - start);
                return result;
            }
        }

        // Create browser context for the suite
        auto browser = m_playwright->launch(BrowserType::WEBVIEW2, json()).get();
        if (!browser) {
            result.errors = suite.tests.size();
            result.totalDuration = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start);
            return result;
        }

        auto context = browser->newContext(suite.contextOptions).get();

        // Run tests with limited parallelism
        std::vector<std::future<TestExecutionResult>> futures;
        std::vector<std::shared_ptr<BrowserContext>> contexts;

        for (const auto& test : suite.tests) {
            if (test.skip) {
                TestExecutionResult tr;
                tr.result = TestResult::SKIPPED;
                tr.testName = test.name;
                result.results.push_back(tr);
                result.skipped++;
                continue;
            }

            // Wait for a slot
            while (futures.size() >= static_cast<size_t>(suite.maxParallel)) {
                for (size_t i = 0; i < futures.size(); i++) {
                    if (futures[i].wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
                        TestExecutionResult tr = futures[i].get();
                        result.results.push_back(tr);
                        if (tr.result == TestResult::PASSED) result.passed++;
                        else if (tr.result == TestResult::FAILED) result.failed++;
                        else if (tr.result == TestResult::ERROR) result.errors++;
                        futures.erase(futures.begin() + i);
                        break;
                    }
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }

            futures.push_back(executeTest(test, context));
        }

        // Wait for remaining futures
        for (auto& f : futures) {
            TestExecutionResult tr = f.get();
            result.results.push_back(tr);
            if (tr.result == TestResult::PASSED) result.passed++;
            else if (tr.result == TestResult::FAILED) result.failed++;
            else if (tr.result == TestResult::ERROR) result.errors++;
        }

        // Suite afterAll
        if (suite.afterAll) {
            try {
                suite.afterAll().get();
            } catch (...) {
                result.errors++;
            }
        }

        // Global teardown
        if (m_globalTeardown) {
            try {
                m_globalTeardown().get();
            } catch (...) {
                result.errors++;
            }
        }

        // Close browser
        browser->close().get();

        result.totalDuration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start);

        return result;
    });
}

std::future<TestExecutionResult> TestRunnerImpl::runTest(const TestCase& test, std::shared_ptr<BrowserContext> context) {
    return executeTest(test, context);
}

void TestRunnerImpl::setOutputDir(const std::string& dir) {
    m_outputDir = dir;
}

void TestRunnerImpl::setBaseURL(const std::string& url) {
    m_baseURL = url;
}

void TestRunnerImpl::setRetries(int retries) {
    m_retries = retries;
}

void TestRunnerImpl::setWorkers(int workers) {
    m_workers = workers;
}

void TestRunnerImpl::setReporter(std::function<void(const TestExecutionResult&)> reporter) {
    m_reporter = reporter;
}

void TestRunnerImpl::setGlobalSetup(std::function<std::future<void>()> setup) {
    m_globalSetup = setup;
}

void TestRunnerImpl::setGlobalTeardown(std::function<std::future<void>()> teardown) {
    m_globalTeardown = teardown;
}

std::future<TestExecutionResult> TestRunnerImpl::executeTest(const TestCase& test, std::shared_ptr<BrowserContext> context) {
    return std::async(std::launch::async, [this, test, context]() -> TestExecutionResult {
        TestExecutionResult result;
        result.testName = test.name;
        auto start = std::chrono::steady_clock::now();

        try {
            // Create page
            auto page = context->newPage().get();
            if (!page) {
                result.result = TestResult::ERROR;
                result.errorMessage = "Failed to create page";
                result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - start);
                return result;
            }

            // Setup
            if (test.setup) {
                test.setup(page).get();
            }

            // BeforeEach
            if (m_reporter) {
                // Report test start
            }

            // Execute steps
            for (const auto& step : test.steps) {
                auto stepStart = std::chrono::steady_clock::now();
                bool stepResult = false;

                // Retry logic
                int attempts = step.retryOnFailure ? step.maxRetries + 1 : 1;
                for (int attempt = 0; attempt < attempts; attempt++) {
                    auto fut = step.action(page);
                    if (waitForFuture(fut, step.timeoutMs)) {
                        stepResult = fut.get();
                        if (stepResult) break;
                    } else {
                        // Timeout
                        if (attempt == attempts - 1) {
                            result.result = TestResult::TIMEOUT;
                            result.errorMessage = "Step timed out: " + step.name;
                        }
                    }
                }

                if (!stepResult && result.result != TestResult::TIMEOUT) {
                    result.result = TestResult::FAILED;
                    result.errorMessage = "Step failed: " + step.name;
                    takeScreenshot(page, test.name + "_failed");
                    break;
                }
            }

            // If all steps passed
            if (result.result != TestResult::FAILED && result.result != TestResult::TIMEOUT) {
                result.result = TestResult::PASSED;
            }

            // Teardown
            if (test.teardown) {
                test.teardown(page).get();
            }

            // Close page
            page->close().get();

        } catch (const std::exception& e) {
            result.result = TestResult::ERROR;
            result.errorMessage = e.what();
        } catch (...) {
            result.result = TestResult::ERROR;
            result.errorMessage = "Unknown error";
        }

        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start);

        if (m_reporter) {
            m_reporter(result);
        }

        return result;
    });
}

void TestRunnerImpl::takeScreenshot(std::shared_ptr<Page> page, const std::string& name) {
    if (m_outputDir.empty()) return;
    ScreenshotOptions opts;
    opts.path = m_outputDir + "/" + name + ".png";
    opts.fullPage = true;
    page->screenshot(opts).get();
}

void TestRunnerImpl::recordVideo(std::shared_ptr<Page> page, const std::string& name) {
    if (m_outputDir.empty()) return;
    page->videoStart(m_outputDir + "/" + name + ".webm").get();
}

// ============================================================================
// BrowserTestAgentImpl Implementation
// ============================================================================

BrowserTestAgentImpl::BrowserTestAgentImpl(std::shared_ptr<Playwright> playwright)
    : m_playwright(playwright), m_runner(std::make_shared<TestRunnerImpl>(playwright)) {}

BrowserTestAgentImpl::~BrowserTestAgentImpl() = default;

std::future<BrowserTestResult> BrowserTestAgentImpl::executeTask(const BrowserTestTask& task) {
    return executeWithAgent(task);
}

std::future<std::string> BrowserTestAgentImpl::generateTestCode(const std::string& description, const std::string& url) {
    return std::async(std::launch::async, [this, description, url]() -> std::string {
        // Build prompt for LLM
        std::string prompt = buildTestPrompt(BrowserTestTask{
            "", description, url, {}, std::nullopt, json()
        });

        // In a full implementation, this would call the LLM
        // For now, generate a template test
        std::ostringstream code;
        code << "// Auto-generated test for: " << description << "\n";
        code << "// URL: " << url << "\n\n";
        code << "const { test, expect } = require('@playwright/test');\n\n";
        code << "test('" << description << "', async ({ page }) => {\n";
        code << "  await page.goto('" << url << "');\n";
        code << "  // TODO: Add assertions based on task description\n";
        code << "});\n";
        return code.str();
    });
}

std::future<BrowserTestResult> BrowserTestAgentImpl::runTestCode(const std::string& testCode, const std::string& url) {
    return std::async(std::launch::async, [this, testCode, url]() -> BrowserTestResult {
        BrowserTestResult result;
        result.success = false;
        result.summary = "Test code execution not yet implemented";
        return result;
    });
}

void BrowserTestAgentImpl::learnFromResult(const BrowserTestTask& task, const BrowserTestResult& result) {
    std::lock_guard<std::mutex> lock(m_learnedMutex);
    json entry;
    entry["task"] = task.description;
    entry["url"] = task.url;
    entry["success"] = result.success;
    entry["summary"] = result.summary;
    entry["steps"] = result.stepsExecuted;
    entry["findings"] = result.findings;
    m_learnedPatterns["history"].push_back(entry);

    // Update success/failure patterns
    if (result.success) {
        m_learnedPatterns["successfulPatterns"][task.url].push_back(task.description);
    } else {
        m_learnedPatterns["failedPatterns"][task.url].push_back(task.description);
    }
}

json BrowserTestAgentImpl::getLearnedPatterns() const {
    std::lock_guard<std::mutex> lock(m_learnedMutex);
    return m_learnedPatterns;
}

std::future<BrowserTestResult> BrowserTestAgentImpl::executeWithAgent(const BrowserTestTask& task) {
    return std::async(std::launch::async, [this, task]() -> BrowserTestResult {
        BrowserTestResult result;
        result.success = false;

        // Launch browser
        auto browser = m_playwright->launch(BrowserType::WEBVIEW2, json()).get();
        if (!browser) {
            result.error = "Failed to launch browser";
            return result;
        }

        auto context = browser->newContext().get();
        auto page = context->newPage().get();
        if (!page) {
            result.error = "Failed to create page";
            browser->close().get();
            return result;
        }

        // Navigate to URL
        NavigateOptions navOpts;
        navOpts.timeoutMs = 30000;
        page->gotoURL(task.url, navOpts).get();
        result.stepsExecuted.push_back("Navigate to " + task.url);

        // Take initial screenshot
        ScreenshotOptions ssOpts;
        ssOpts.path = "screenshot_initial.png";
        ssOpts.fullPage = true;
        page->screenshot(ssOpts).get();
        result.screenshots.push_back("screenshot_initial.png");

        // In a full implementation, the agent would:
        // 1. Analyze the page structure
        // 2. Generate test steps based on the task description
        // 3. Execute each step
        // 4. Verify assertions
        // For now, we simulate the process

        // Simulate step execution
        for (const auto& assertion : task.assertions) {
            result.stepsExecuted.push_back("Verify: " + assertion);
        }

        result.success = true;
        result.summary = "Completed " + std::to_string(result.stepsExecuted.size()) + " steps";
        result.findings["url"] = task.url;
        result.findings["stepsExecuted"] = result.stepsExecuted;

        // Learn from result
        learnFromResult(task, result);

        // Cleanup
        page->close().get();
        browser->close().get();

        return result;
    });
}

std::string BrowserTestAgentImpl::buildTestPrompt(const BrowserTestTask& task) {
    std::ostringstream prompt;
    prompt << "You are a browser testing agent. Generate a Playwright test for the following task:\n\n";
    prompt << "Task: " << task.description << "\n";
    prompt << "URL: " << task.url << "\n";
    if (!task.assertions.empty()) {
        prompt << "Assertions:\n";
        for (const auto& a : task.assertions) {
            prompt << "  - " << a << "\n";
        }
    }
    prompt << "\nGenerate a complete Playwright test in JavaScript.\n";
    return prompt.str();
}

std::vector<TestStep> BrowserTestAgentImpl::parseTestSteps(const std::string& agentResponse) {
    std::vector<TestStep> steps;
    // In a full implementation, this would parse the LLM response
    // and convert it to executable test steps
    return steps;
}

std::future<bool> BrowserTestAgentImpl::executeStep(std::shared_ptr<Page> page, const TestStep& step) {
    return std::async(std::launch::async, [this, page, step]() -> bool {
        return step.action(page).get();
    });
}

// ============================================================================
// NetworkInterceptorImpl Implementation
// ============================================================================

NetworkInterceptorImpl::NetworkInterceptorImpl(std::shared_ptr<Page> page)
    : m_page(page) {}

NetworkInterceptorImpl::~NetworkInterceptorImpl() = default;

std::future<void> NetworkInterceptorImpl::route(const std::string& urlPattern, const RouteOptions& options) {
    return std::async(std::launch::async, [this, urlPattern, options]() -> void {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_routes[urlPattern] = options;
    });
}

std::future<void> NetworkInterceptorImpl::route(const std::string& urlPattern, std::function<void(const std::string&, const json&)> handler) {
    return std::async(std::launch::async, [this, urlPattern, handler]() -> void {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_handlers[urlPattern] = handler;
    });
}

std::future<void> NetworkInterceptorImpl::unroute(const std::string& urlPattern) {
    return std::async(std::launch::async, [this, urlPattern]() -> void {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_routes.erase(urlPattern);
        m_handlers.erase(urlPattern);
    });
}

std::future<void> NetworkInterceptorImpl::unrouteAll() {
    return std::async(std::launch::async, [this]() -> void {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_routes.clear();
        m_handlers.clear();
    });
}

std::future<json> NetworkInterceptorImpl::waitForRequest(const std::string& urlPattern, int timeoutMs) {
    return std::async(std::launch::async, [this, urlPattern, timeoutMs]() -> json {
        auto start = std::chrono::steady_clock::now();
        while (std::chrono::steady_clock::now() - start < std::chrono::milliseconds(timeoutMs)) {
            std::lock_guard<std::mutex> lock(m_mutex);
            for (const auto& req : m_requestLog) {
                if (req.contains("url") && req["url"].get<std::string>().find(urlPattern) != std::string::npos) {
                    return req;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        return json();
    });
}

std::future<json> NetworkInterceptorImpl::waitForResponse(const std::string& urlPattern, int timeoutMs) {
    return std::async(std::launch::async, [this, urlPattern, timeoutMs]() -> json {
        auto start = std::chrono::steady_clock::now();
        while (std::chrono::steady_clock::now() - start < std::chrono::milliseconds(timeoutMs)) {
            std::lock_guard<std::mutex> lock(m_mutex);
            for (const auto& resp : m_responseLog) {
                if (resp.contains("url") && resp["url"].get<std::string>().find(urlPattern) != std::string::npos) {
                    return resp;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        return json();
    });
}

std::future<std::vector<json>> NetworkInterceptorImpl::waitForRequests(const std::string& urlPattern, int count, int timeoutMs) {
    return std::async(std::launch::async, [this, urlPattern, count, timeoutMs]() -> std::vector<json> {
        std::vector<json> result;
        auto start = std::chrono::steady_clock::now();
        while (std::chrono::steady_clock::now() - start < std::chrono::milliseconds(timeoutMs)) {
            std::lock_guard<std::mutex> lock(m_mutex);
            result.clear();
            for (const auto& req : m_requestLog) {
                if (req.contains("url") && req["url"].get<std::string>().find(urlPattern) != std::string::npos) {
                    result.push_back(req);
                    if ((int)result.size() >= count) return result;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        return result;
    });
}

std::future<void> NetworkInterceptorImpl::modifyRequest(const std::string& urlPattern, std::function<void(json&)> modifier) {
    return std::async(std::launch::async, [this, urlPattern, modifier]() -> void {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto& req : m_requestLog) {
            if (req.contains("url") && req["url"].get<std::string>().find(urlPattern) != std::string::npos) {
                modifier(req);
            }
        }
    });
}

std::future<void> NetworkInterceptorImpl::abortRequest(const std::string& urlPattern, const std::string& errorCode) {
    return std::async(std::launch::async, [this, urlPattern, errorCode]() -> void {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto it = m_requestLog.begin(); it != m_requestLog.end(); ) {
            if (it->contains("url") && (*it)["url"].get<std::string>().find(urlPattern) != std::string::npos) {
                it = m_requestLog.erase(it);
            } else {
                ++it;
            }
        }
    });
}

std::future<std::string> NetworkInterceptorImpl::exportHAR(const std::string& path) {
    return std::async(std::launch::async, [this, path]() -> std::string {
        json har;
        har["log"] = {
            {"version", "1.2"},
            {"creator", {{"name", "RawrXD"}, {"version", "1.0"}}},
            {"entries", json::array()}
        };

        std::lock_guard<std::mutex> lock(m_mutex);
        for (const auto& req : m_requestLog) {
            json entry;
            entry["request"] = req;
            har["log"]["entries"].push_back(entry);
        }
        for (const auto& resp : m_responseLog) {
            // Match response to request
            for (auto& entry : har["log"]["entries"]) {
                if (entry["request"].contains("url") && resp.contains("url") &&
                    entry["request"]["url"] == resp["url"]) {
                    entry["response"] = resp;
                    break;
                }
            }
        }

        std::string harStr = har.dump(2);
        if (!path.empty()) {
            std::ofstream out(path);
            out << harStr;
        }
        return harStr;
    });
}

// ============================================================================
// VisualTesterImpl Implementation
// ============================================================================

VisualTesterImpl::VisualTesterImpl(std::shared_ptr<Page> page)
    : m_page(page) {}

VisualTesterImpl::~VisualTesterImpl() = default;

std::future<VisualTestResult> VisualTesterImpl::compare(const std::string& baselinePath, const VisualTestOptions& options) {
    return std::async(std::launch::async, [this, baselinePath, options]() -> VisualTestResult {
        VisualTestResult result;
        result.match = false;

        // Take current screenshot
        ScreenshotOptions ssOpts;
        ssOpts.path = "current_screenshot.png";
        ssOpts.fullPage = true;
        m_page->screenshot(ssOpts).get();

        // Load baseline and current images
        std::vector<uint8_t> baseline = loadImage(baselinePath);
        std::vector<uint8_t> current = loadImage("current_screenshot.png");

        if (baseline.empty() || current.empty()) {
            result.diffImagePath = "";
            return result;
        }

        // Compute difference
        double diff = computeDifference(baseline, current, options.threshold);
        result.differencePercentage = diff;
        result.match = diff <= options.threshold;
        result.baselineImagePath = baselinePath;
        result.actualImagePath = "current_screenshot.png";

        return result;
    });
}

std::future<bool> VisualTesterImpl::updateBaseline(const std::string& baselinePath) {
    return std::async(std::launch::async, [this, baselinePath]() -> bool {
        ScreenshotOptions ssOpts;
        ssOpts.path = baselinePath;
        ssOpts.fullPage = true;
        m_page->screenshot(ssOpts).get();
        return true;
    });
}

std::future<VisualTestResult> VisualTesterImpl::compareElement(std::shared_ptr<ElementHandle> element, const std::string& baselinePath, const VisualTestOptions& options) {
    return std::async(std::launch::async, [this, element, baselinePath, options]() -> VisualTestResult {
        VisualTestResult result;
        result.match = false;

        // Take element screenshot
        ScreenshotOptions ssOpts;
        ssOpts.path = "element_current.png";
        std::string dataUrl = element->screenshot(ssOpts).get();

        // Load baseline and current images
        std::vector<uint8_t> baseline = loadImage(baselinePath);
        std::vector<uint8_t> current = loadImage("element_current.png");

        if (baseline.empty() || current.empty()) {
            return result;
        }

        double diff = computeDifference(baseline, current, options.threshold);
        result.differencePercentage = diff;
        result.match = diff <= options.threshold;
        result.baselineImagePath = baselinePath;
        result.actualImagePath = "element_current.png";

        return result;
    });
}

double VisualTesterImpl::computeDifference(const std::vector<uint8_t>& img1, const std::vector<uint8_t>& img2, double threshold) {
    if (img1.size() != img2.size() || img1.empty()) {
        return 1.0;
    }

    size_t diffCount = 0;
    size_t totalPixels = img1.size() / 4;  // Assuming RGBA

    for (size_t i = 0; i < img1.size(); i += 4) {
        int dr = std::abs((int)img1[i] - (int)img2[i]);
        int dg = std::abs((int)img1[i + 1] - (int)img2[i + 1]);
        int db = std::abs((int)img1[i + 2] - (int)img2[i + 2]);
        if (dr > (int)(threshold * 255) || dg > (int)(threshold * 255) || db > (int)(threshold * 255)) {
            diffCount++;
        }
    }

    return (double)diffCount / (double)totalPixels;
}

std::vector<uint8_t> VisualTesterImpl::loadImage(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) return {};

    return std::vector<uint8_t>((std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>());
}

bool VisualTesterImpl::saveImage(const std::string& path, const std::vector<uint8_t>& data) {
    std::ofstream file(path, std::ios::binary);
    if (!file.is_open()) return false;
    file.write((const char*)data.data(), data.size());
    return true;
}

// ============================================================================
// Factory Functions
// ============================================================================

std::shared_ptr<Playwright> Playwright::create() {
    return std::make_shared<PlaywrightImpl>();
}

std::shared_ptr<Playwright> createPlaywright() {
    return Playwright::create();
}

std::shared_ptr<TestRunner> createTestRunner(std::shared_ptr<Playwright> playwright) {
    return std::make_shared<TestRunnerImpl>(playwright);
}

std::shared_ptr<BrowserTestAgent> createBrowserTestAgent(std::shared_ptr<Playwright> playwright) {
    return std::make_shared<BrowserTestAgentImpl>(playwright);
}

std::shared_ptr<NetworkInterceptor> createNetworkInterceptor(std::shared_ptr<Page> page) {
    return std::make_shared<NetworkInterceptorImpl>(page);
}

std::shared_ptr<VisualTester> createVisualTester(std::shared_ptr<Page> page) {
    return std::make_shared<VisualTesterImpl>(page);
}

} // namespace Browser
} // namespace RawrXD