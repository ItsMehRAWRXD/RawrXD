// ============================================================================
// BrowserTestEngine.hpp — Playwright-like Browser Automation Framework
// ============================================================================
// Provides Cursor-like browser testing capabilities:
//   - Multi-browser support (Chromium, Firefox, WebKit via WebView2)
//   - Page automation: click, type, navigate, wait, screenshot
//   - Network interception and mocking
//   - Test runner with parallel execution
//   - Integration with Agent framework for AI-driven testing
//   - Checkpoint/resume for long-running test suites
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <future>
#include <chrono>
#include <atomic>
#include <mutex>
#include <queue>
#include <condition_variable>
#include <optional>
#include <variant>
#include <nlohmann/json.hpp>

namespace RawrXD {
namespace Browser {

using json = nlohmann::json;

// ============================================================================
// Core Types
// ============================================================================

enum class BrowserType {
    CHROMIUM,
    FIREFOX,
    WEBKIT,
    WEBVIEW2  // Native Windows WebView2
};

enum class WaitUntil {
    LOAD,
    DOMCONTENTLOADED,
    NETWORKIDLE,
    COMMIT
};

struct ViewportSize {
    int width = 1280;
    int height = 720;
    bool isMobile = false;
    bool hasTouch = false;
    double deviceScaleFactor = 1.0;
};

struct BrowserContextOptions {
    ViewportSize viewport;
    std::string userAgent;
    std::string locale;
    std::string timezoneId;
    std::map<std::string, std::string> extraHTTPHeaders;
    bool ignoreHTTPSErrors = false;
    bool javaScriptEnabled = true;
    bool bypassCSP = false;
    std::optional<std::string> storageStatePath;
    std::vector<std::string> permissions;  // "geolocation", "notifications", etc.
    std::map<std::string, std::string> offline;
};

struct PageOptions {
    WaitUntil waitUntil = WaitUntil::LOAD;
    int timeoutMs = 30000;
};

struct NavigateOptions {
    WaitUntil waitUntil = WaitUntil::LOAD;
    int timeoutMs = 30000;
    std::string referer;
    std::map<std::string, std::string> headers;
};

struct ClickOptions {
    int delayMs = 0;
    int button = 0;  // 0=left, 1=middle, 2=right
    int clickCount = 1;
    std::vector<std::string> modifiers;  // "Alt", "Control", "Meta", "Shift"
    int positionX = -1;
    int positionY = -1;
    bool force = false;
    bool noWaitAfter = false;
    bool trial = false;
};

struct TypeOptions {
    int delayMs = 0;
    bool noWaitAfter = false;
};

struct WaitForSelectorOptions {
    int timeoutMs = 30000;
    enum class State { ATTACHED, DETACHED, VISIBLE, HIDDEN } state = State::VISIBLE;
};

struct ScreenshotOptions {
    std::string path;
    enum class Type { PNG, JPEG } type = Type::PNG;
    int quality = 90;  // For JPEG
    bool fullPage = false;
    std::optional<ViewportSize> clip;
    bool omitBackground = false;
    bool animations = false;  // "disabled" or "allow"
    int timeoutMs = 30000;
};

struct PDFOptions {
    std::string path;
    bool printBackground = false;
    std::string format = "A4";  // A4, A3, Letter, Legal, Tabloid
    double width = 0;
    double height = 0;
    double marginTop = 0;
    double marginRight = 0;
    double marginBottom = 0;
    double marginLeft = 0;
    bool preferCSSPageSize = false;
    bool displayHeaderFooter = false;
    std::string headerTemplate;
    std::string footerTemplate;
    int timeoutMs = 30000;
};

struct SelectOptionOptions {
    std::vector<std::string> values;
    std::vector<std::string> labels;
    std::vector<int> indices;
    bool noWaitAfter = false;
};

struct KeyboardOptions {
    int delayMs = 0;
    std::string text;
};

struct MouseOptions {
    int button = 0;
    int clickCount = 1;
    std::vector<std::string> modifiers;
};

// ============================================================================
// Element Handle — Reference to a DOM element
// ============================================================================

class ElementHandle {
public:
    virtual ~ElementHandle() = default;

    // Actions
    virtual std::future<bool> click(const ClickOptions& options = {}) = 0;
    virtual std::future<bool> doubleClick(const ClickOptions& options = {}) = 0;
    virtual std::future<bool> hover() = 0;
    virtual std::future<bool> type(const std::string& text, const TypeOptions& options = {}) = 0;
    virtual std::future<bool> press(const std::string& key, const KeyboardOptions& options = {}) = 0;
    virtual std::future<bool> fill(const std::string& value, const TypeOptions& options = {}) = 0;
    virtual std::future<bool> selectOption(const SelectOptionOptions& options) = 0;
    virtual std::future<bool> focus() = 0;
    virtual std::future<bool> blur() = 0;
    virtual std::future<bool> scrollIntoViewIfNeeded() = 0;
    virtual std::future<bool> check(const ClickOptions& options = {}) = 0;
    virtual std::future<bool> uncheck(const ClickOptions& options = {}) = 0;

    // Properties
    virtual std::future<std::string> getAttribute(const std::string& name) = 0;
    virtual std::future<std::string> getProperty(const std::string& name) = 0;
    virtual std::future<std::string> innerText() = 0;
    virtual std::future<std::string> innerHTML() = 0;
    virtual std::future<std::string> textContent() = 0;
    virtual std::future<bool> isVisible() = 0;
    virtual std::future<bool> isEnabled() = 0;
    virtual std::future<bool> isChecked() = 0;
    virtual std::future<bool> isDisabled() = 0;
    virtual std::future<bool> isEditable() = 0;
    virtual std::future<int> getBoundingBoxX() = 0;
    virtual std::future<int> getBoundingBoxY() = 0;
    virtual std::future<int> getBoundingBoxWidth() = 0;
    virtual std::future<int> getBoundingBoxHeight() = 0;
    virtual std::future<std::string> screenshot(const ScreenshotOptions& options = {}) = 0;

    // Query
    virtual std::future<std::shared_ptr<ElementHandle>> querySelector(const std::string& selector) = 0;
    virtual std::future<std::vector<std::shared_ptr<ElementHandle>>> querySelectorAll(const std::string& selector) = 0;
    virtual std::future<std::shared_ptr<ElementHandle>> querySelectorXPath(const std::string& xpath) = 0;

    // Evaluation
    virtual std::future<json> evaluate(const std::string& script, const json& arg = json()) = 0;
    virtual std::future<json> evaluateHandle(const std::string& script, const json& arg = json()) = 0;

    // Frame access
    virtual std::shared_ptr<class Frame> contentFrame() = 0;
};

// ============================================================================
// Frame — Page frame
// ============================================================================

class Frame {
public:
    virtual ~Frame() = default;

    virtual std::string name() const = 0;
    virtual std::string url() const = 0;
    virtual std::shared_ptr<Frame> parentFrame() = 0;
    virtual std::vector<std::shared_ptr<Frame>> childFrames() = 0;

    // Navigation
    virtual std::future<bool> gotoURL(const std::string& url, const NavigateOptions& options = {}) = 0;
    virtual std::future<bool> waitForNavigation(const NavigateOptions& options = {}) = 0;
    virtual std::future<bool> waitForLoadState(WaitUntil state, int timeoutMs = 30000) = 0;

    // Query
    virtual std::future<std::shared_ptr<ElementHandle>> querySelector(const std::string& selector) = 0;
    virtual std::future<std::vector<std::shared_ptr<ElementHandle>>> querySelectorAll(const std::string& selector) = 0;
    virtual std::future<std::shared_ptr<ElementHandle>> querySelectorXPath(const std::string& xpath) = 0;
    virtual std::future<std::shared_ptr<ElementHandle>> waitForSelector(const std::string& selector, const WaitForSelectorOptions& options = {}) = 0;
    virtual std::future<std::shared_ptr<ElementHandle>> waitForSelectorXPath(const std::string& xpath, const WaitForSelectorOptions& options = {}) = 0;

    // Evaluation
    virtual std::future<json> evaluate(const std::string& script, const json& arg = json()) = 0;
    virtual std::future<json> evaluateHandle(const std::string& script, const json& arg = json()) = 0;

    // Actions
    virtual std::future<bool> click(const std::string& selector, const ClickOptions& options = {}) = 0;
    virtual std::future<bool> fill(const std::string& selector, const std::string& value, const TypeOptions& options = {}) = 0;
    virtual std::future<bool> type(const std::string& selector, const std::string& text, const TypeOptions& options = {}) = 0;
    virtual std::future<bool> press(const std::string& selector, const std::string& key, const KeyboardOptions& options = {}) = 0;
    virtual std::future<bool> selectOption(const std::string& selector, const SelectOptionOptions& options) = 0;
    virtual std::future<bool> check(const std::string& selector, const ClickOptions& options = {}) = 0;
    virtual std::future<bool> uncheck(const std::string& selector, const ClickOptions& options = {}) = 0;
    virtual std::future<bool> hover(const std::string& selector) = 0;
    virtual std::future<bool> focus(const std::string& selector) = 0;

    // Content
    virtual std::future<std::string> content() = 0;
    virtual std::future<std::string> title() = 0;
};

// ============================================================================
// Page — Browser page/tab
// ============================================================================

class Page {
public:
    virtual ~Page() = default;

    // Lifecycle
    virtual std::future<bool> close(bool runBeforeUnload = false) = 0;
    virtual std::future<bool> reload(const NavigateOptions& options = {}) = 0;
    virtual std::future<bool> goBack(const NavigateOptions& options = {}) = 0;
    virtual std::future<bool> goForward(const NavigateOptions& options = {}) = 0;

    // Navigation
    virtual std::future<bool> gotoURL(const std::string& url, const NavigateOptions& options = {}) = 0;
    virtual std::future<bool> waitForNavigation(const NavigateOptions& options = {}) = 0;
    virtual std::future<bool> waitForLoadState(WaitUntil state, int timeoutMs = 30000) = 0;

    // URL/Title
    virtual std::string url() const = 0;
    virtual std::future<std::string> title() = 0;

    // Frame access
    virtual std::shared_ptr<Frame> mainFrame() = 0;
    virtual std::vector<std::shared_ptr<Frame>> frames() = 0;

    // Query
    virtual std::future<std::shared_ptr<ElementHandle>> querySelector(const std::string& selector) = 0;
    virtual std::future<std::vector<std::shared_ptr<ElementHandle>>> querySelectorAll(const std::string& selector) = 0;
    virtual std::future<std::shared_ptr<ElementHandle>> querySelectorXPath(const std::string& xpath) = 0;
    virtual std::future<std::shared_ptr<ElementHandle>> waitForSelector(const std::string& selector, const WaitForSelectorOptions& options = {}) = 0;
    virtual std::future<std::shared_ptr<ElementHandle>> waitForSelectorXPath(const std::string& xpath, const WaitForSelectorOptions& options = {}) = 0;

    // Evaluation
    virtual std::future<json> evaluate(const std::string& script, const json& arg = json()) = 0;
    virtual std::future<json> evaluateHandle(const std::string& script, const json& arg = json()) = 0;
    virtual std::future<json> evaluateOnNewDocument(const std::string& script, const json& arg = json()) = 0;
    virtual std::future<void> addInitScript(const std::string& script) = 0;

    // Actions (on main frame)
    virtual std::future<bool> click(const std::string& selector, const ClickOptions& options = {}) = 0;
    virtual std::future<bool> doubleClick(const std::string& selector, const ClickOptions& options = {}) = 0;
    virtual std::future<bool> hover(const std::string& selector) = 0;
    virtual std::future<bool> fill(const std::string& selector, const std::string& value, const TypeOptions& options = {}) = 0;
    virtual std::future<bool> type(const std::string& selector, const std::string& text, const TypeOptions& options = {}) = 0;
    virtual std::future<bool> press(const std::string& selector, const std::string& key, const KeyboardOptions& options = {}) = 0;
    virtual std::future<bool> selectOption(const std::string& selector, const SelectOptionOptions& options) = 0;
    virtual std::future<bool> check(const std::string& selector, const ClickOptions& options = {}) = 0;
    virtual std::future<bool> uncheck(const std::string& selector, const ClickOptions& options = {}) = 0;
    virtual std::future<bool> focus(const std::string& selector) = 0;
    virtual std::future<bool> blur(const std::string& selector) = 0;
    virtual std::future<bool> dragAndDrop(const std::string& source, const std::string& target) = 0;

    // Keyboard/Mouse
    virtual std::future<bool> keyboardDown(const std::string& key) = 0;
    virtual std::future<bool> keyboardUp(const std::string& key) = 0;
    virtual std::future<bool> keyboardPress(const std::string& key, const KeyboardOptions& options = {}) = 0;
    virtual std::future<bool> keyboardType(const std::string& text, const TypeOptions& options = {}) = 0;
    virtual std::future<bool> mouseMove(int x, int y, const MouseOptions& options = {}) = 0;
    virtual std::future<bool> mouseDown(int x, int y, const MouseOptions& options = {}) = 0;
    virtual std::future<bool> mouseUp(int x, int y, const MouseOptions& options = {}) = 0;
    virtual std::future<bool> mouseWheel(int deltaX, int deltaY) = 0;

    // Screenshots/PDF
    virtual std::future<std::string> screenshot(const ScreenshotOptions& options = {}) = 0;
    virtual std::future<std::string> pdf(const PDFOptions& options = {}) = 0;

    // Viewport
    virtual std::future<bool> setViewportSize(const ViewportSize& viewport) = 0;
    virtual ViewportSize viewportSize() const = 0;

    // Network
    virtual std::future<bool> setRequestInterception(bool value) = 0;
    virtual std::future<void> route(const std::string& urlPattern, std::function<void(const std::string&, const json&)> handler) = 0;
    virtual std::future<void> unroute(const std::string& urlPattern) = 0;
    virtual std::future<void> waitForRequest(const std::string& urlPattern, int timeoutMs = 30000) = 0;
    virtual std::future<void> waitForResponse(const std::string& urlPattern, int timeoutMs = 30000) = 0;

    // Console/Dialogs
    virtual void onConsoleMessage(std::function<void(const std::string&, const std::string&)> callback) = 0;
    virtual void onDialog(std::function<void(const std::string&, const std::string&, bool, const std::string&)> callback) = 0;
    virtual void onPageError(std::function<void(const std::string&)> callback) = 0;
    virtual void onRequestFailed(std::function<void(const std::string&, const std::string&)> callback) = 0;
    virtual void onResponse(std::function<void(const std::string&, int, const std::map<std::string, std::string>&)> callback) = 0;

    // Storage
    virtual std::future<json> cookies(const std::vector<std::string>& urls = {}) = 0;
    virtual std::future<bool> setCookie(const json& cookie) = 0;
    virtual std::future<bool> deleteCookie(const std::string& name, const std::string& url) = 0;
    virtual std::future<json> localStorage(const std::string& origin) = 0;
    virtual std::future<json> sessionStorage(const std::string& origin) = 0;

    // Accessibility
    virtual std::future<json> accessibilitySnapshot(const std::string& rootSelector = "") = 0;

    // Video
    virtual std::future<bool> videoStart(const std::string& path, const ViewportSize& size = {}) = 0;
    virtual std::future<std::string> videoStop() = 0;

    // Tracing
    virtual std::future<bool> tracingStart(const std::string& path, bool screenshots = true, bool snapshots = true) = 0;
    virtual std::future<std::string> tracingStop() = 0;

    // Checkpoint
    virtual std::future<json> checkpoint() = 0;
    virtual std::future<bool> restoreCheckpoint(const json& state) = 0;
};

// ============================================================================
// BrowserContext — Incognito-like context
// ============================================================================

class BrowserContext {
public:
    virtual ~BrowserContext() = default;

    // Pages
    virtual std::future<std::shared_ptr<Page>> newPage() = 0;
    virtual std::vector<std::shared_ptr<Page>> pages() = 0;
    virtual std::future<std::shared_ptr<Page>> newPage(const PageOptions& options) = 0;

    // Cookies
    virtual std::future<json> cookies(const std::vector<std::string>& urls = {}) = 0;
    virtual std::future<bool> addCookies(const json& cookies) = 0;
    virtual std::future<bool> clearCookies() = 0;

    // Permissions
    virtual std::future<bool> grantPermissions(const std::vector<std::string>& permissions, const std::string& origin = "") = 0;
    virtual std::future<bool> clearPermissions() = 0;

    // Storage state
    virtual std::future<json> storageState(const std::string& path = "") = 0;

    // Close
    virtual std::future<bool> close() = 0;

    // Browser reference
    virtual std::shared_ptr<class Browser> browser() = 0;

    // Checkpoint
    virtual std::future<json> checkpoint() = 0;
    virtual std::future<bool> restoreCheckpoint(const json& state) = 0;
};

// ============================================================================
// Browser — Browser instance
// ============================================================================

class Browser {
public:
    virtual ~Browser() = default;

    // Contexts
    virtual std::future<std::shared_ptr<BrowserContext>> newContext(const BrowserContextOptions& options = {}) = 0;
    virtual std::vector<std::shared_ptr<BrowserContext>> contexts() = 0;

    // Default context
    virtual std::shared_ptr<BrowserContext> defaultContext() = 0;

    // Version
    virtual std::string version() const = 0;

    // Close
    virtual std::future<bool> close() = 0;

    // Checkpoint
    virtual std::future<json> checkpoint() = 0;
    virtual std::future<bool> restoreCheckpoint(const json& state) = 0;

    // Check if connected
    virtual bool isConnected() const = 0;
};

// ============================================================================
// Playwright — Main entry point
// ============================================================================

class Playwright {
public:
    static std::shared_ptr<Playwright> create();

    virtual ~Playwright() = default;

    // Browser launching
    virtual std::future<std::shared_ptr<Browser>> chromiumLaunch(const json& options = json()) = 0;
    virtual std::future<std::shared_ptr<Browser>> firefoxLaunch(const json& options = json()) = 0;
    virtual std::future<std::shared_ptr<Browser>> webkitLaunch(const json& options = json()) = 0;
    virtual std::future<std::shared_ptr<Browser>> webview2Launch(const json& options = json()) = 0;

    // Generic launch
    virtual std::future<std::shared_ptr<Browser>> launch(BrowserType type, const json& options = json()) = 0;

    // Connect to existing browser
    virtual std::future<std::shared_ptr<Browser>> connectOverCDP(const std::string& endpointURL, const json& options = json()) = 0;

    // Stop
    virtual void stop() = 0;

    // Version
    virtual std::string version() const = 0;
};

// ============================================================================
// Test Runner — For test suite execution
// ============================================================================

struct TestStep {
    std::string name;
    std::function<std::future<bool>(std::shared_ptr<Page>)> action;
    int timeoutMs = 30000;
    bool retryOnFailure = false;
    int maxRetries = 2;
};

struct TestCase {
    std::string name;
    std::string description;
    std::vector<TestStep> steps;
    std::function<std::future<void>(std::shared_ptr<Page>)> setup;
    std::function<std::future<void>(std::shared_ptr<Page>)> teardown;
    std::vector<std::string> tags;
    bool skip = false;
    int timeoutMs = 60000;
};

struct TestSuite {
    std::string name;
    std::string description;
    std::vector<TestCase> tests;
    std::function<std::future<void>()> beforeAll;
    std::function<std::future<void>()> afterAll;
    std::function<std::future<void>(std::shared_ptr<Page>)> beforeEach;
    std::function<std::future<void>(std::shared_ptr<Page>)> afterEach;
    BrowserContextOptions contextOptions;
    int maxParallel = 4;
};

enum class TestResult {
    PASSED,
    FAILED,
    SKIPPED,
    TIMEOUT,
    ERROR
};

struct TestExecutionResult {
    TestResult result;
    std::string testName;
    std::string errorMessage;
    std::chrono::milliseconds duration;
    std::vector<std::string> screenshots;
    std::vector<std::string> videos;
    std::string tracePath;
    json metadata;
};

struct SuiteExecutionResult {
    std::string suiteName;
    std::vector<TestExecutionResult> results;
    std::chrono::milliseconds totalDuration;
    int passed = 0;
    int failed = 0;
    int skipped = 0;
    int errors = 0;
};

class TestRunner {
public:
    virtual ~TestRunner() = default;

    // Run a test suite
    virtual std::future<SuiteExecutionResult> runSuite(const TestSuite& suite) = 0;

    // Run a single test
    virtual std::future<TestExecutionResult> runTest(const TestCase& test, std::shared_ptr<BrowserContext> context) = 0;

    // Configuration
    virtual void setOutputDir(const std::string& dir) = 0;
    virtual void setBaseURL(const std::string& url) = 0;
    virtual void setRetries(int retries) = 0;
    virtual void setWorkers(int workers) = 0;
    virtual void setReporter(std::function<void(const TestExecutionResult&)> reporter) = 0;

    // Global setup/teardown
    virtual void setGlobalSetup(std::function<std::future<void>()> setup) = 0;
    virtual void setGlobalTeardown(std::function<std::future<void>()> teardown) = 0;
};

// ============================================================================
// Agent Integration — BrowserTestAgent for AI-driven testing
// ============================================================================

struct BrowserTestTask {
    std::string id;
    std::string description;  // Natural language: "Login to app and verify dashboard loads"
    std::string url;
    std::vector<std::string> assertions;  // "page contains 'Welcome'", "element '#submit' is visible"
    std::optional<std::string> testScript;  // Generated test code
    json context;  // Additional context for the agent
};

struct BrowserTestResult {
    bool success;
    std::string summary;
    std::vector<std::string> stepsExecuted;
    std::vector<std::string> screenshots;
    std::string videoPath;
    std::string tracePath;
    json findings;
    std::string error;
};

class BrowserTestAgent {
public:
    virtual ~BrowserTestAgent() = default;

    // Execute a natural language test task
    virtual std::future<BrowserTestResult> executeTask(const BrowserTestTask& task) = 0;

    // Generate test code from natural language
    virtual std::future<std::string> generateTestCode(const std::string& description, const std::string& url) = 0;

    // Run generated test code
    virtual std::future<BrowserTestResult> runTestCode(const std::string& testCode, const std::string& url) = 0;

    // Learn from test results
    virtual void learnFromResult(const BrowserTestTask& task, const BrowserTestResult& result) = 0;

    // Get learned patterns
    virtual json getLearnedPatterns() const = 0;
};

// ============================================================================
// Network Interception — For mocking API responses
// ============================================================================

struct RouteOptions {
    std::string urlPattern;
    std::string method = "";
    std::map<std::string, std::string> headers;
    json body;
    int statusCode = 200;
    int delayMs = 0;
};

class NetworkInterceptor {
public:
    virtual ~NetworkInterceptor() = default;

    // Intercept and mock
    virtual std::future<void> route(const std::string& urlPattern, const RouteOptions& options) = 0;
    virtual std::future<void> route(const std::string& urlPattern, std::function<void(const std::string&, const json&)> handler) = 0;
    virtual std::future<void> unroute(const std::string& urlPattern) = 0;
    virtual std::future<void> unrouteAll() = 0;

    // Wait for network events
    virtual std::future<json> waitForRequest(const std::string& urlPattern, int timeoutMs = 30000) = 0;
    virtual std::future<json> waitForResponse(const std::string& urlPattern, int timeoutMs = 30000) = 0;
    virtual std::future<std::vector<json>> waitForRequests(const std::string& urlPattern, int count, int timeoutMs = 30000) = 0;

    // Modify requests
    virtual std::future<void> modifyRequest(const std::string& urlPattern, std::function<void(json&)> modifier) = 0;
    virtual std::future<void> abortRequest(const std::string& urlPattern, const std::string& errorCode = "failed") = 0;

    // HAR export
    virtual std::future<std::string> exportHAR(const std::string& path = "") = 0;
};

// ============================================================================
// Visual Testing — Pixel-perfect comparison
// ============================================================================

struct VisualTestOptions {
    double threshold = 0.1;  // 0-1, pixel difference threshold
    bool ignoreColors = false;
    bool ignoreAntialiasing = true;
    std::string mask;  // CSS selector for regions to ignore
    std::string diffOutputPath;
};

struct VisualTestResult {
    bool match;
    double differencePercentage;
    std::string diffImagePath;
    std::string baselineImagePath;
    std::string actualImagePath;
};

class VisualTester {
public:
    virtual ~VisualTester() = default;

    // Compare current page with baseline
    virtual std::future<VisualTestResult> compare(const std::string& baselinePath, const VisualTestOptions& options = {}) = 0;

    // Update baseline
    virtual std::future<bool> updateBaseline(const std::string& baselinePath) = 0;

    // Compare element
    virtual std::future<VisualTestResult> compareElement(std::shared_ptr<ElementHandle> element, const std::string& baselinePath, const VisualTestOptions& options = {}) = 0;
};

// ============================================================================
// Factory Functions
// ============================================================================

std::shared_ptr<Playwright> createPlaywright();
std::shared_ptr<TestRunner> createTestRunner(std::shared_ptr<Playwright> playwright);
std::shared_ptr<BrowserTestAgent> createBrowserTestAgent(std::shared_ptr<Playwright> playwright);
std::shared_ptr<NetworkInterceptor> createNetworkInterceptor(std::shared_ptr<Page> page);
std::shared_ptr<VisualTester> createVisualTester(std::shared_ptr<Page> page);

} // namespace Browser
} // namespace RawrXD