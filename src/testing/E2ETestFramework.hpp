/**
 * E2ETestFramework.hpp
 *
 * Phase I Batch 3/5: E2E Testing Framework
 *
 * End-to-end testing with user journey simulation, visual regression,
 * cross-browser testing, and mobile testing support.
 */

#pragma once

#include "IntegrationTestFramework.hpp"

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>

namespace Testing {

// ============================================================================
// Forward Declarations
// ============================================================================

class E2ETest;
class UserJourney;
class PageObject;
class BrowserDriver;
class MobileDriver;

// ============================================================================
// Browser Types
// ============================================================================

enum class BrowserType {
    CHROME,
    FIREFOX,
    EDGE,
    SAFARI,
    HEADLESS_CHROME,
    HEADLESS_FIREFOX
};

enum class PlatformType {
    DESKTOP,
    MOBILE_IOS,
    MOBILE_ANDROID,
    TABLET_IOS,
    TABLET_ANDROID
};

// ============================================================================
// Element Locator
// ============================================================================

/**
 * Locator for UI elements.
 */
struct ElementLocator {
    enum class Strategy {
        ID,
        NAME,
        CLASS_NAME,
        TAG_NAME,
        CSS_SELECTOR,
        XPATH,
        LINK_TEXT,
        PARTIAL_LINK_TEXT,
        ACCESSIBILITY_ID
    };
    
    Strategy strategy;
    std::string value;
    
    ElementLocator() = default;
    ElementLocator(Strategy s, const std::string& v) : strategy(s), value(v) {}
    
    static ElementLocator ById(const std::string& id) {
        return ElementLocator(Strategy::ID, id);
    }
    
    static ElementLocator ByName(const std::string& name) {
        return ElementLocator(Strategy::NAME, name);
    }
    
    static ElementLocator ByCss(const std::string& selector) {
        return ElementLocator(Strategy::CSS_SELECTOR, selector);
    }
    
    static ElementLocator ByXPath(const std::string& xpath) {
        return ElementLocator(Strategy::XPATH, xpath);
    }
    
    static ElementLocator ByClass(const std::string& className) {
        return ElementLocator(Strategy::CLASS_NAME, className);
    }
    
    static ElementLocator ByAccessibilityId(const std::string& id) {
        return ElementLocator(Strategy::ACCESSIBILITY_ID, id);
    }
};

// ============================================================================
// UI Element
// ============================================================================

/**
 * Represents a UI element.
 */
class UIElement {
public:
    UIElement(BrowserDriver* driver, const ElementLocator& locator);
    
    // Actions
    void Click();
    void DoubleClick();
    void RightClick();
    void Hover();
    void Focus();
    void Blur();
    
    // Input
    void Type(const std::string& text);
    void Clear();
    void Submit();
    void SelectByText(const std::string& text);
    void SelectByValue(const std::string& value);
    void SelectByIndex(int index);
    void Check();
    void Uncheck();
    void Toggle();
    
    // Properties
    std::string GetText() const;
    std::string GetAttribute(const std::string& name) const;
    std::string GetProperty(const std::string& name) const;
    std::string GetCssValue(const std::string& property) const;
    std::string GetTagName() const;
    
    bool IsDisplayed() const;
    bool IsEnabled() const;
    bool IsSelected() const;
    bool IsChecked() const;
    
    // Location and size
    struct Rect {
        int x, y, width, height;
    };
    Rect GetRect() const;
    std::string GetScreenshot() const;  // Base64 encoded
    
    // Wait conditions
    bool WaitForVisible(uint64_t timeoutMs = 10000);
    bool WaitForHidden(uint64_t timeoutMs = 10000);
    bool WaitForEnabled(uint64_t timeoutMs = 10000);
    bool WaitForText(const std::string& text, uint64_t timeoutMs = 10000);
    
    // Children
    UIElement FindElement(const ElementLocator& locator);
    std::vector<UIElement> FindElements(const ElementLocator& locator);
    
private:
    BrowserDriver* driver_;
    ElementLocator locator_;
    void* elementHandle_ = nullptr;
};

// ============================================================================
// Browser Driver
// ============================================================================

/**
 * Browser automation driver.
 */
class BrowserDriver {
public:
    struct Config {
        BrowserType browser = BrowserType::CHROME;
        PlatformType platform = PlatformType::DESKTOP;
        std::string browserVersion;
        std::string platformVersion;
        std::string deviceName;
        
        // Window
        uint32_t windowWidth = 1920;
        uint32_t windowHeight = 1080;
        bool maximize = false;
        bool headless = false;
        
        // Timeouts
        uint64_t implicitWaitMs = 10000;
        uint64_t pageLoadTimeoutMs = 30000;
        uint64_t scriptTimeoutMs = 30000;
        
        // Options
        bool acceptInsecureCerts = false;
        bool privateMode = false;
        std::vector<std::string> extensions;
        std::map<std::string, std::string> preferences;
        std::vector<std::string> arguments;
    };
    
    explicit BrowserDriver(const Config& config);
    ~BrowserDriver();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // Navigation
    void Navigate(const std::string& url);
    void Refresh();
    void Back();
    void Forward();
    std::string GetCurrentUrl() const;
    std::string GetTitle() const;
    std::string GetPageSource() const;
    
    // Windows
    void MaximizeWindow();
    void MinimizeWindow();
    void SetWindowSize(uint32_t width, uint32_t height);
    void SetWindowPosition(int x, int y);
    void CloseWindow();
    void SwitchToWindow(const std::string& handle);
    void SwitchToFrame(const ElementLocator& locator);
    void SwitchToParentFrame();
    void SwitchToDefaultContent();
    std::vector<std::string> GetWindowHandles() const;
    std::string GetCurrentWindowHandle() const;
    
    // Alerts
    void AcceptAlert();
    void DismissAlert();
    std::string GetAlertText();
    void SetAlertText(const std::string& text);
    bool IsAlertPresent(uint64_t timeoutMs = 5000);
    
    // Cookies
    void AddCookie(const std::string& name, const std::string& value,
                   const std::string& domain = "", const std::string& path = "/",
                   uint64_t expiry = 0, bool secure = false, bool httpOnly = false);
    void DeleteCookie(const std::string& name);
    void DeleteAllCookies();
    std::map<std::string, std::string> GetCookies() const;
    std::string GetCookie(const std::string& name) const;
    
    // Local/Session Storage
    void SetLocalStorageItem(const std::string& key, const std::string& value);
    std::string GetLocalStorageItem(const std::string& key);
    void SetSessionStorageItem(const std::string& key, const std::string& value);
    std::string GetSessionStorageItem(const std::string& key);
    
    // JavaScript
    std::string ExecuteScript(const std::string& script);
    std::string ExecuteAsyncScript(const std::string& script, uint64_t timeoutMs = 30000);
    
    // Screenshots
    std::string TakeScreenshot();  // Base64 encoded PNG
    std::string TakeElementScreenshot(const ElementLocator& locator);
    bool CompareScreenshot(const std::string& baselinePath, double threshold = 0.1);
    
    // Elements
    UIElement FindElement(const ElementLocator& locator);
    std::vector<UIElement> FindElements(const ElementLocator& locator);
    bool IsElementPresent(const ElementLocator& locator);
    bool IsElementVisible(const ElementLocator& locator);
    
    // Waits
    bool WaitForElement(const ElementLocator& locator, uint64_t timeoutMs = 10000);
    bool WaitForElementVisible(const ElementLocator& locator, uint64_t timeoutMs = 10000);
    bool WaitForElementHidden(const ElementLocator& locator, uint64_t timeoutMs = 10000);
    bool WaitForPageLoad(uint64_t timeoutMs = 30000);
    bool WaitForTitle(const std::string& title, uint64_t timeoutMs = 10000);
    bool WaitForUrl(const std::string& url, uint64_t timeoutMs = 10000);
    
    // Mobile gestures
    void Tap(int x, int y);
    void Swipe(int startX, int startY, int endX, int endY, uint64_t durationMs = 500);
    void Pinch(double scale, int centerX, int centerY);
    void Rotate(double angle, int centerX, int centerY);
    void LongPress(int x, int y, uint64_t durationMs = 1000);
    
    // Performance
    struct PerformanceTiming {
        uint64_t navigationStart;
        uint64_t unloadEventStart;
        uint64_t unloadEventEnd;
        uint64_t redirectStart;
        uint64_t redirectEnd;
        uint64_t fetchStart;
        uint64_t domainLookupStart;
        uint64_t domainLookupEnd;
        uint64_t connectStart;
        uint64_t connectEnd;
        uint64_t secureConnectionStart;
        uint64_t requestStart;
        uint64_t responseStart;
        uint64_t responseEnd;
        uint64_t domLoading;
        uint64_t domInteractive;
        uint64_t domContentLoadedEventStart;
        uint64_t domContentLoadedEventEnd;
        uint64_t domComplete;
        uint64_t loadEventStart;
        uint64_t loadEventEnd;
    };
    PerformanceTiming GetPerformanceTiming() const;
    std::map<std::string, double> GetPerformanceMetrics() const;
    
    // Console logs
    std::vector<std::map<std::string, std::string>> GetBrowserLogs() const;
    void ClearBrowserLogs();
    
    // Network
    void EnableNetworkLogging();
    void DisableNetworkLogging();
    std::vector<std::map<std::string, std::string>> GetNetworkLogs() const;
    void SetNetworkConditions(int downloadKbps, int uploadKbps, int latencyMs);
    void ResetNetworkConditions();
    
private:
    Config config_;
    bool initialized_ = false;
    void* driverHandle_ = nullptr;
    void* sessionHandle_ = nullptr;
};

// ============================================================================
// Page Object
// ============================================================================

/**
 * Base class for page objects.
 */
class PageObject {
public:
    explicit PageObject(BrowserDriver* driver);
    virtual ~PageObject() = default;
    
    // Navigation
    virtual void Navigate() = 0;
    virtual bool IsAt() const = 0;
    
    // Wait
    bool WaitForPageLoad(uint64_t timeoutMs = 30000);
    
protected:
    BrowserDriver* driver_;
    
    // Element helpers
    UIElement Find(const ElementLocator& locator);
    UIElement FindById(const std::string& id);
    UIElement FindByName(const std::string& name);
    UIElement FindByCss(const std::string& selector);
    UIElement FindByXPath(const std::string& xpath);
    UIElement FindByText(const std::string& text);
    
    std::vector<UIElement> FindAll(const ElementLocator& locator);
    
    // Assertions
    void AssertTitle(const std::string& expected);
    void AssertUrl(const std::string& expected);
    void AssertElementPresent(const ElementLocator& locator);
    void AssertElementVisible(const ElementLocator& locator);
    void AssertElementText(const ElementLocator& locator, const std::string& expected);
    void AssertElementContainsText(const ElementLocator& locator, const std::string& expected);
};

// ============================================================================
// User Journey
// ============================================================================

/**
 * Represents a user journey/scenario.
 */
class UserJourney {
public:
    struct Step {
        std::string name;
        std::string description;
        std::function<void(BrowserDriver*)> action;
        std::function<bool(BrowserDriver*)> validation;
        uint64_t timeoutMs;
        bool optional;
        std::vector<std::string> tags;
    };
    
    struct Config {
        std::string name;
        std::string description;
        std::string startUrl;
        uint64_t timeoutMs = 300000;  // 5 minutes
        bool continueOnError = false;
        bool takeScreenshots = true;
        bool recordVideo = false;
    };
    
    explicit UserJourney(const Config& config);
    
    // Steps
    void AddStep(const Step& step);
    void AddStep(const std::string& name, std::function<void(BrowserDriver*)> action);
    void AddStep(const std::string& name, std::function<void(BrowserDriver*)> action,
                 std::function<bool(BrowserDriver*)> validation);
    
    // Data
    void SetTestData(const std::map<std::string, std::string>& data);
    std::string GetTestData(const std::string& key) const;
    
    // Execution
    struct Result {
        bool success;
        std::string failedStep;
        std::string errorMessage;
        uint64_t durationMs;
        std::vector<std::string> screenshots;
        std::string videoPath;
        std::map<std::string, std::string> outputData;
    };
    
    Result Execute(BrowserDriver* driver);
    
    // Accessors
    const Config& GetConfig() const { return config_; }
    
private:
    Config config_;
    std::vector<Step> steps_;
    std::map<std::string, std::string> testData_;
    mutable std::mutex dataMutex_;
};

// ============================================================================
// E2E Test
// ============================================================================

/**
 * End-to-end test case.
 */
class E2ETest {
public:
    struct Config {
        std::string name;
        std::string description;
        std::vector<BrowserType> browsers;
        std::vector<PlatformType> platforms;
        std::vector<std::string> tags;
        uint64_t timeoutMs = 300000;
        bool visualRegression = false;
        bool performanceMetrics = false;
        bool accessibilityCheck = false;
        std::string baselineScreenshotPath;
    };
    
    explicit E2ETest(const Config& config);
    
    // Journey
    void SetJourney(std::shared_ptr<UserJourney> journey);
    
    // Data providers
    using DataProvider = std::function<std::vector<std::map<std::string, std::string>>());
    void SetDataProvider(DataProvider provider);
    
    // Execution
    struct Result {
        std::string testName;
        BrowserType browser;
        PlatformType platform;
        bool success;
        std::string errorMessage;
        uint64_t durationMs;
        UserJourney::Result journeyResult;
        
        // Visual regression
        double visualDiff;
        bool visualRegressionFailed;
        
        // Performance
        std::map<std::string, double> performanceMetrics;
        
        // Accessibility
        std::vector<std::map<std::string, std::string>> accessibilityIssues;
    };
    
    std::vector<Result> Run(BrowserDriver* driver);
    
    // Accessors
    const Config& GetConfig() const { return config_; }
    
private:
    Config config_;
    std::shared_ptr<UserJourney> journey_;
    DataProvider dataProvider_;
    
    Result RunSingle(BrowserDriver* driver, const std::map<std::string, std::string>& data);
    bool CheckVisualRegression(BrowserDriver* driver);
    void CollectPerformanceMetrics(Result& result, BrowserDriver* driver);
    void CheckAccessibility(Result& result, BrowserDriver* driver);
};

// ============================================================================
// E2E Test Suite
// ============================================================================

/**
 * Suite of E2E tests.
 */
class E2ETestSuite {
public:
    struct Config {
        std::string name;
        std::string baseUrl;
        BrowserDriver::Config defaultBrowserConfig;
        bool parallel = false;
        uint32_t parallelTests = 2;
        bool retryFailed = false;
        uint32_t maxRetries = 2;
    };
    
    explicit E2ETestSuite(const Config& config);
    
    // Tests
    void AddTest(std::shared_ptr<E2ETest> test);
    void AddTests(const std::vector<std::shared_ptr<E2ETest>>& tests);
    
    // Page objects
    void RegisterPageObject(const std::string& name, std::function<std::shared_ptr<PageObject>(BrowserDriver*)> factory);
    std::shared_ptr<PageObject> CreatePageObject(const std::string& name, BrowserDriver* driver);
    
    // Execution
    struct Summary {
        uint32_t totalTests;
        uint32_t passed;
        uint32_t failed;
        uint32_t skipped;
        uint64_t durationMs;
        std::vector<E2ETest::Result> results;
    };
    
    Summary RunAll();
    E2ETest::Result Run(const std::string& testName);
    
    // Filtering
    void SetBrowserFilter(const std::vector<BrowserType>& browsers);
    void SetPlatformFilter(const std::vector<PlatformType>& platforms);
    void SetTagFilter(const std::vector<std::string>& include, const std::vector<std::string>& exclude);
    
private:
    Config config_;
    std::vector<std::shared_ptr<E2ETest>> tests_;
    std::map<std::string, std::function<std::shared_ptr<PageObject>(BrowserDriver*)>> pageObjects_;
    
    std::vector<BrowserType> browserFilter_;
    std::vector<PlatformType> platformFilter_;
    std::vector<std::string> includeTags_;
    std::vector<std::string> excludeTags_;
    
    std::vector<std::shared_ptr<E2ETest>> FilterTests() const;
};

// ============================================================================
// Visual Regression
// ============================================================================

/**
 * Visual regression testing.
 */
class VisualRegressionTester {
public:
    struct Config {
        double threshold = 0.1;  // 10% difference threshold
        bool ignoreAntialiasing = true;
        bool ignoreColors = false;
        std::vector<std::string> ignoreRegions;  // CSS selectors
        std::string baselineDirectory = "./baselines";
        std::string diffDirectory = "./diffs";
    };
    
    explicit VisualRegressionTester(const Config& config);
    
    // Baseline management
    void CaptureBaseline(const std::string& name, BrowserDriver* driver);
    void CaptureBaseline(const std::string& name, const std::string& screenshot);
    void UpdateBaseline(const std::string& name);
    void DeleteBaseline(const std::string& name);
    bool HasBaseline(const std::string& name) const;
    
    // Comparison
    struct ComparisonResult {
        bool match;
        double diffPercentage;
        uint64_t diffPixels;
        std::string diffImagePath;
        std::string baselinePath;
        std::string actualPath;
    };
    
    ComparisonResult Compare(const std::string& name, BrowserDriver* driver);
    ComparisonResult Compare(const std::string& name, const std::string& screenshot);
    
    // Batch comparison
    std::vector<ComparisonResult> CompareAll(BrowserDriver* driver);
    
    // Report
    std::string GenerateReport() const;
    
private:
    Config config_;
    
    double CalculateDiff(const std::string& baseline, const std::string& actual);
    std::string CreateDiffImage(const std::string& baseline, const std::string& actual, double diff);
};

// ============================================================================
// Accessibility Testing
// ============================================================================

/**
 * Accessibility testing.
 */
class AccessibilityTester {
public:
    struct Issue {
        std::string rule;
        std::string description;
        std::string impact;  // minor, moderate, serious, critical
        std::string target;
        std::string html;
        std::map<std::string, std::string> metadata;
    };
    
    struct Config {
        std::vector<std::string> rules;  // Empty = all rules
        std::vector<std::string> tags;   // wcag2a, wcag2aa, wcag2aaa, best-practice
        bool includePasses = false;
    };
    
    explicit AccessibilityTester(const Config& config = Config{});
    
    // Analysis
    std::vector<Issue> Analyze(BrowserDriver* driver);
    std::vector<Issue> Analyze(BrowserDriver* driver, const ElementLocator& context);
    
    // Specific checks
    bool CheckColorContrast(BrowserDriver* driver);
    bool CheckAltText(BrowserDriver* driver);
    bool CheckLabels(BrowserDriver* driver);
    bool CheckFocusOrder(BrowserDriver* driver);
    bool CheckAria(BrowserDriver* driver);
    
    // Report
    std::string GenerateReport(const std::vector<Issue>& issues) const;
    
    // Standards
    static Config Wcag2a();
    static Config Wcag2aa();
    static Config Wcag2aaa();
    static Config Section508();
};

// ============================================================================
// Mobile Testing
// ============================================================================

/**
 * Mobile-specific testing.
 */
class MobileTester {
public:
    struct DeviceConfig {
        std::string deviceName;
        std::string platformName;
        std::string platformVersion;
        std::string udid;
        std::string appPath;
        std::string bundleId;
        bool noReset = false;
        bool fullReset = false;
    };
    
    explicit MobileTester(const DeviceConfig& config);
    ~MobileTester();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // App lifecycle
    void LaunchApp();
    void CloseApp();
    void BackgroundApp(uint64_t seconds);
    void ResetApp();
    void InstallApp(const std::string& path);
    void RemoveApp();
    bool IsAppInstalled();
    
    // Context
    void SwitchToWebView();
    void SwitchToNative();
    std::vector<std::string> GetContexts() const;
    std::string GetCurrentContext() const;
    
    // Device
    void Shake();
    void Rotate(DeviceOrientation orientation);
    void SetLocation(double latitude, double longitude, double altitude = 0);
    void SimulateCall();
    void SimulateSms(const std::string& message);
    void SetBatteryLevel(int level);  // 0-100
    void SetBatteryState(const std::string& state);  // unknown, charging, discharging, notCharging, full
    void SimulateMemoryWarning();
    
    // Biometrics
    void EnrollBiometric();
    void SendBiometricMatch(bool match);
    
    // Performance
    struct PerformanceMetrics {
        double cpuUsage;
        double memoryUsage;
        double batteryLevel;
        uint64_t networkBytes;
        double fps;
    };
    PerformanceMetrics GetPerformanceMetrics() const;
    
    enum class DeviceOrientation {
        PORTRAIT,
        PORTRAIT_UPSIDE_DOWN,
        LANDSCAPE_LEFT,
        LANDSCAPE_RIGHT
    };
    
private:
    DeviceConfig config_;
    bool initialized_ = false;
    void* driverHandle_ = nullptr;
};

// ============================================================================
// Convenience Macros
// ============================================================================

#define E2E_TEST(name) \
    static void E2ETest_##name(Testing::BrowserDriver*); \
    static struct E2ETestReg_##name { \
        E2ETestReg_##name() { \
            Testing::E2ETest::Config config; \
            config.name = #name; \
            auto test = std::make_shared<Testing::E2ETest>(config); \
        } \
    } _e2e_test_reg_##name; \
    static void E2ETest_##name(Testing::BrowserDriver* driver)

#define PAGE_OBJECT(name) \
    class name##Page : public Testing::PageObject { \
    public: \
        explicit name##Page(Testing::BrowserDriver* driver) : Testing::PageObject(driver) {} \
        void Navigate() override; \
        bool IsAt() const override;

#define END_PAGE_OBJECT };

} // namespace Testing
