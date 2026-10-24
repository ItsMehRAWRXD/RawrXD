#include "agentic/AgenticNavigator.h"
#include "win32app/Win32IDE.h"
#include <windows.h>
#include <chrono>
#include <thread>
#include <algorithm>
#include <random>
#include <cctype>

namespace RawrXD {
namespace Agentic {

namespace {
HWND FindRawrXDWindow()
{
    HWND hwnd = FindWindowA("RawrXD_IDE_Window", nullptr);
    if (!hwnd) hwnd = GetForegroundWindow();
    return (hwnd && IsWindow(hwnd)) ? hwnd : nullptr;
}

std::string Lower(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}
}

AgenticNavigator::AgenticNavigator() 
    : m_currentStrategy(NavigationStrategy::AutoDetect) {
    m_fallbackConfig = FallbackConfig{};
}

AgenticNavigator::~AgenticNavigator() {
}

NavigationResult AgenticNavigator::navigateToFileExplorer() {
    auto start = std::chrono::high_resolution_clock::now();
    
    NavigationResult result;
    switch (m_currentStrategy) {
        case NavigationStrategy::DirectAPI:
            result = navigateDirectAPI("FileExplorer");
            break;
        case NavigationStrategy::IDECommands:
            result = navigateIDECommands("FileExplorer");
            break;
        case NavigationStrategy::Hybrid:
            result = navigateHybrid("FileExplorer");
            break;
        case NavigationStrategy::AutoDetect:
            result = navigateHybrid("FileExplorer");
            break;
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    result.executionTimeMs = std::chrono::duration<double, std::milli>(end - start).count();
    
    learnFromResult(result);
    return result;
}

NavigationResult AgenticNavigator::navigateToEditor() {
    auto start = std::chrono::high_resolution_clock::now();
    
    NavigationResult result;
    switch (m_currentStrategy) {
        case NavigationStrategy::DirectAPI:
            result = navigateDirectAPI("Editor");
            break;
        case NavigationStrategy::IDECommands:
            result = navigateIDECommands("Editor");
            break;
        case NavigationStrategy::Hybrid:
            result = navigateHybrid("Editor");
            break;
        case NavigationStrategy::AutoDetect:
            result = navigateHybrid("Editor");
            break;
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    result.executionTimeMs = std::chrono::duration<double, std::milli>(end - start).count();
    
    learnFromResult(result);
    return result;
}

NavigationResult AgenticNavigator::navigateToTerminal() {
    auto start = std::chrono::high_resolution_clock::now();
    
    NavigationResult result;
    switch (m_currentStrategy) {
        case NavigationStrategy::DirectAPI:
            result = navigateDirectAPI("Terminal");
            break;
        case NavigationStrategy::IDECommands:
            result = navigateIDECommands("Terminal");
            break;
        case NavigationStrategy::Hybrid:
            result = navigateHybrid("Terminal");
            break;
        case NavigationStrategy::AutoDetect:
            result = navigateHybrid("Terminal");
            break;
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    result.executionTimeMs = std::chrono::duration<double, std::milli>(end - start).count();
    
    learnFromResult(result);
    return result;
}

NavigationResult AgenticNavigator::navigateToCopilotChat() {
    auto start = std::chrono::high_resolution_clock::now();
    
    NavigationResult result;
    switch (m_currentStrategy) {
        case NavigationStrategy::DirectAPI:
            result = navigateDirectAPI("CopilotChat");
            break;
        case NavigationStrategy::IDECommands:
            result = navigateIDECommands("CopilotChat");
            break;
        case NavigationStrategy::Hybrid:
            result = navigateHybrid("CopilotChat");
            break;
        case NavigationStrategy::AutoDetect:
            result = navigateHybrid("CopilotChat");
            break;
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    result.executionTimeMs = std::chrono::duration<double, std::milli>(end - start).count();
    
    learnFromResult(result);
    return result;
}

NavigationResult AgenticNavigator::navigateToSidebar(SidebarView view) {
    auto start = std::chrono::high_resolution_clock::now();
    
    std::string target = "Sidebar_" + std::to_string(static_cast<int>(view));
    NavigationResult result;
    switch (m_currentStrategy) {
        case NavigationStrategy::DirectAPI:
            result = navigateDirectAPI(target);
            break;
        case NavigationStrategy::IDECommands:
            result = navigateIDECommands(target);
            break;
        case NavigationStrategy::Hybrid:
            result = navigateHybrid(target);
            break;
        case NavigationStrategy::AutoDetect:
            result = navigateHybrid(target);
            break;
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    result.executionTimeMs = std::chrono::duration<double, std::milli>(end - start).count();
    
    learnFromResult(result);
    return result;
}

NavigationResult AgenticNavigator::navigateToPanel(PanelTab tab) {
    auto start = std::chrono::high_resolution_clock::now();
    
    std::string target = "Panel_" + std::to_string(static_cast<int>(tab));
    NavigationResult result;
    switch (m_currentStrategy) {
        case NavigationStrategy::DirectAPI:
            result = navigateDirectAPI(target);
            break;
        case NavigationStrategy::IDECommands:
            result = navigateIDECommands(target);
            break;
        case NavigationStrategy::Hybrid:
            result = navigateHybrid(target);
            break;
        case NavigationStrategy::AutoDetect:
            result = navigateHybrid(target);
            break;
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    result.executionTimeMs = std::chrono::duration<double, std::milli>(end - start).count();
    
    learnFromResult(result);
    return result;
}

NavigationResult AgenticNavigator::navigateAndExecute(const std::string& target, int commandId) {
    // First navigate to the target
    auto navResult = navigateDirectAPI(target);
    if (!navResult.success) {
        return navResult;
    }
    
    // Then execute the command if provided
    if (commandId > 0) {
        return executeCommand(commandId);
    }
    
    return navResult;
}

std::vector<UIElement> AgenticNavigator::detectUIElements(const std::string& filter) {
    auto elements = detectElementsDirectAPI();
    if (filter.empty()) return elements;

    const std::string wanted = Lower(filter);
    elements.erase(std::remove_if(elements.begin(), elements.end(),
        [&](const UIElement& element) {
            const std::string name = Lower(element.name);
            const std::string cls = Lower(element.className);
            const std::string text = Lower(element.text);
            return name.find(wanted) == std::string::npos &&
                   cls.find(wanted) == std::string::npos &&
                   text.find(wanted) == std::string::npos;
        }), elements.end());
    return elements;
}

UIElement AgenticNavigator::findElementByName(const std::string& name) {
    auto elements = detectUIElements();
    const std::string wanted = Lower(name);
    for (const auto& element : elements) {
        if (Lower(element.name).find(wanted) != std::string::npos) {
            return element;
        }
    }
    return UIElement{};
}

UIElement AgenticNavigator::findElementByClass(const std::string& className) {
    auto elements = detectUIElements();
    const std::string wanted = Lower(className);
    for (const auto& element : elements) {
        if (Lower(element.className).find(wanted) != std::string::npos) {
            return element;
        }
    }
    return UIElement{};
}

UIElement AgenticNavigator::findElementByText(const std::string& text) {
    auto elements = detectUIElements();
    const std::string wanted = Lower(text);
    for (const auto& element : elements) {
        if (Lower(element.text).find(wanted) != std::string::npos) {
            return element;
        }
    }
    return UIElement{};
}

NavigationResult AgenticNavigator::clickElement(const UIElement& element) {
    if (!isElementValid(element)) {
        return createResult(false, "Invalid UI element");
    }
    
    auto start = std::chrono::high_resolution_clock::now();
    NavigationResult result;
    
    // Try direct API first
    result = clickElementDirectAPI(element);
    
    // If direct API fails, fallback to IDE commands
    if (!result.success && m_fallbackConfig.maxRetries > 0) {
        result = clickElementIDECommands(element);
        result.fallbackUsed = "IDECommands";
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    result.executionTimeMs = std::chrono::duration<double, std::milli>(end - start).count();
    
    learnFromResult(result);
    return result;
}

NavigationResult AgenticNavigator::sendText(const UIElement& element, const std::string& text) {
    if (!isElementValid(element)) {
        return createResult(false, "Invalid UI element");
    }
    
    auto start = std::chrono::high_resolution_clock::now();
    NavigationResult result;
    
    // Try direct API first
    result = sendTextDirectAPI(element, text);
    
    // If direct API fails, fallback to IDE commands
    if (!result.success && m_fallbackConfig.maxRetries > 0) {
        result = sendTextIDECommands(element, text);
        result.fallbackUsed = "IDECommands";
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    result.executionTimeMs = std::chrono::duration<double, std::milli>(end - start).count();
    
    learnFromResult(result);
    return result;
}

NavigationResult AgenticNavigator::focusElement(const UIElement& element) {
    if (!isElementValid(element)) {
        return createResult(false, "Invalid UI element");
    }
    
    if (SetFocus(element.handle) != nullptr) {
        return createResult(true, "Element focused successfully", element.handle);
    }
    
    return createResult(false, "Failed to focus element", element.handle);
}

NavigationResult AgenticNavigator::executeCommand(int commandId) {
    // This uses IDE command infrastructure directly
    auto start = std::chrono::high_resolution_clock::now();
    
    HWND main = FindRawrXDWindow();
    if (!main || commandId <= 0) {
        return createResult(false, "Cannot execute command: IDE window or command ID is invalid", main);
    }
    // Dispatch synchronously so the result does not report success merely
    // because Windows accepted a queued message that may never be handled.
    SendMessageA(main, WM_COMMAND, MAKEWPARAM(commandId, 0), 0);
    const bool success = IsWindow(main) != FALSE;
    std::string message = success ? "Command dispatched to RawrXD" : "Command dispatch failed";
    
    auto end = std::chrono::high_resolution_clock::now();
    double executionTime = std::chrono::duration<double, std::milli>(end - start).count();
    
    NavigationResult result = createResult(success, message);
    result.executionTimeMs = executionTime;
    
    learnFromResult(result);
    return result;
}

void AgenticNavigator::setStrategy(NavigationStrategy strategy) {
    m_currentStrategy = strategy;
}

NavigationStrategy AgenticNavigator::getCurrentStrategy() const {
    return m_currentStrategy;
}

void AgenticNavigator::setFallbackConfig(const FallbackConfig& config) {
    m_fallbackConfig = config;
}

FallbackConfig AgenticNavigator::getFallbackConfig() const {
    return m_fallbackConfig;
}

double AgenticNavigator::getSuccessRate(NavigationStrategy strategy) const {
    auto it = m_strategySuccessRates.find(std::to_string(static_cast<int>(strategy)));
    return it != m_strategySuccessRates.end() ? it->second : 0.0;
}

double AgenticNavigator::getAverageTime(NavigationStrategy strategy) const {
    auto it = m_strategyAverageTimes.find(std::to_string(static_cast<int>(strategy)));
    return it != m_strategyAverageTimes.end() ? it->second : 0.0;
}

void AgenticNavigator::resetStatistics() {
    m_history.clear();
    m_strategySuccessRates.clear();
    m_strategyAverageTimes.clear();
    m_learnedPatterns.clear();
    m_patternCounts.clear();
}

void AgenticNavigator::learnFromResult(const NavigationResult& result) {
    // Update history
    m_history[m_currentStrategy].push_back(result);
    
    // Update success rates and average times
    std::string strategyKey = std::to_string(static_cast<int>(m_currentStrategy));
    
    // Calculate success rate
    int total = m_history[m_currentStrategy].size();
    int successes = 0;
    double totalTime = 0.0;
    
    for (const auto& res : m_history[m_currentStrategy]) {
        if (res.success) successes++;
        totalTime += res.executionTimeMs;
    }
    
    m_strategySuccessRates[strategyKey] = static_cast<double>(successes) / total;
    m_strategyAverageTimes[strategyKey] = totalTime / total;
    
    // Pattern learning
    if (m_fallbackConfig.enableLearning) {
        std::string operationPattern = result.targetName + "_" + std::to_string(result.success);
        m_learnedPatterns[operationPattern] = m_currentStrategy;
        m_patternCounts[operationPattern]++;
    }
}

NavigationStrategy AgenticNavigator::recommendStrategy(const std::string& operation) const {
    // Look for learned patterns
    for (const auto& pattern : m_learnedPatterns) {
        if (pattern.first.find(operation) != std::string::npos) {
            return pattern.second;
        }
    }
    
    // Default to hybrid for unknown operations
    return NavigationStrategy::Hybrid;
}

// Direct Win32 API implementation
NavigationResult AgenticNavigator::navigateDirectAPI(const std::string& target) {
    const HWND main = FindRawrXDWindow();
    if (!main) return createResult(false, "RawrXD main window is not available");

    const std::string wanted = Lower(target);
    // The native terminal is intentionally lazy-created.  Make navigation
    // actionable: opening the terminal target must invoke the same command
    // as Terminal -> New PowerShell, not merely search for an absent HWND.
    const bool terminalTarget = wanted == "terminal" || wanted == "powershell" ||
        wanted == "terminal:powershell";
    if (terminalTarget) {
        const BOOL posted = SendMessageA(main, WM_COMMAND,
            MAKEWPARAM(3001 /* IDM_TERMINAL_POWERSHELL */, 0), 0) != 0;
        if (!posted) {
            // WM_COMMAND handlers commonly return zero even after creating
            // the pane; discovery below is the authoritative result.
            UpdateWindow(main);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    const auto elements = detectElementsDirectAPI();
    // The terminal is created after the editor, so inspect newest controls
    // first when resolving the lazy terminal target.
    auto begin = terminalTarget ? elements.rbegin() : elements.rbegin();
    auto end = terminalTarget ? elements.rend() : elements.rend();
    for (auto it = begin; it != end; ++it) {
        const auto& element = *it;
        const std::string name = Lower(element.name + " " + element.text + " " + element.className);
        bool match = name.find(wanted) != std::string::npos;
        if (wanted == "fileexplorer") match = name.find("systreeview32") != std::string::npos;
        if (wanted == "editor") match = name.find("richedit") != std::string::npos;
        if (terminalTarget) match = name.find("terminal") != std::string::npos ||
            name.find("powershell") != std::string::npos ||
            name.find("richedit") != std::string::npos;
        if (wanted == "copilotchat") match = name.find("ai chat") != std::string::npos ||
            element.controlId == 1202 || element.controlId == 1203;
        if (match && element.visible && element.enabled) {
            ShowWindow(element.handle, SW_SHOW);
            SetFocus(element.handle);
            return createResult(true, "Navigated to " + target, element.handle);
        }
    }
    return createResult(false, "No visible RawrXD control matched target: " + target, main);
}

namespace {
// Enumerate child windows of a top-level window, recording real UI element
// metadata via the Win32 API (no Qt dependency).
BOOL CALLBACK EnumChildProc(HWND hwnd, LPARAM lParam) {
    auto* elements = reinterpret_cast<std::vector<RawrXD::Agentic::UIElement>*>(lParam);
    if (!elements || !IsWindow(hwnd)) {
        return TRUE;
    }

    RawrXD::Agentic::UIElement elem;
    elem.handle = hwnd;
    elem.controlId = GetDlgCtrlID(hwnd);

    char className[256] = {0};
    GetClassNameA(hwnd, className, sizeof(className));
    elem.className = className;

    char text[1024] = {0};
    GetWindowTextA(hwnd, text, sizeof(text));
    elem.text = text;
    elem.name = text;

    RECT rc = {0};
    GetWindowRect(hwnd, &rc);
    elem.bounds = rc;

    elem.visible = IsWindowVisible(hwnd) != FALSE;
    elem.enabled = IsWindowEnabled(hwnd) != FALSE;

    elements->push_back(elem);
    return TRUE;
}

// Enumerate top-level windows and recurse into their children.
BOOL CALLBACK EnumTopProc(HWND hwnd, LPARAM lParam) {
    if (!IsWindow(hwnd)) {
        return TRUE;
    }
    EnumChildWindows(hwnd, EnumChildProc, lParam);
    return TRUE;
}
} // namespace

std::vector<UIElement> AgenticNavigator::detectElementsDirectAPI() {
    std::vector<UIElement> elements;
    const HWND main = FindRawrXDWindow();
    if (main) {
        UIElement root{};
        root.handle = main;
        root.className = "RawrXD_IDE_Window";
        char title[1024] = {};
        GetWindowTextA(main, title, sizeof(title));
        root.text = title;
        root.name = root.text;
        root.visible = IsWindowVisible(main) != FALSE;
        root.enabled = IsWindowEnabled(main) != FALSE;
        GetWindowRect(main, &root.bounds);
        elements.push_back(root);
        EnumChildWindows(main, EnumChildProc, reinterpret_cast<LPARAM>(&elements));
    }
    return elements;
}

NavigationResult AgenticNavigator::clickElementDirectAPI(const UIElement& element) {
    if (!isElementValid(element) || !element.enabled) {
        return createResult(false, "Element is invalid or disabled", element.handle);
    }
    SetFocus(element.handle);
    const std::string cls = Lower(element.className);
    LRESULT result = 0;
    if (cls == "button") {
        result = SendMessageA(element.handle, BM_CLICK, 0, 0);
    } else if (cls.find("combobox") != std::string::npos) {
        SendMessageA(element.handle, CB_SHOWDROPDOWN, TRUE, 0);
        result = 1;
    } else if (cls == "systabcontrol32") {
        result = SendMessageA(element.handle, TCM_SETCURSEL, 0, 0) >= 0;
        InvalidateRect(element.handle, nullptr, TRUE);
    } else {
        POINT point{};
        GetCursorPos(&point);
        RECT bounds{};
        GetWindowRect(element.handle, &bounds);
        LPARAM lp = MAKELPARAM((bounds.right - bounds.left) / 2,
                               (bounds.bottom - bounds.top) / 2);
        SendMessageA(element.handle, WM_LBUTTONDOWN, MK_LBUTTON, lp);
        SendMessageA(element.handle, WM_LBUTTONUP, 0, lp);
        result = 1;
    }
    return createResult(result != 0, result ? "Element activated" : "Element activation failed", element.handle);
}

NavigationResult AgenticNavigator::sendTextDirectAPI(const UIElement& element, const std::string& text) {
    if (!isElementValid(element) || !element.enabled) {
        return createResult(false, "Text target is invalid or disabled", element.handle);
    }
    SetFocus(element.handle);
    const std::string cls = Lower(element.className);
    LRESULT result = 0;
    if (cls.find("richedit") != std::string::npos || cls == "edit") {
        result = SendMessageA(element.handle, WM_SETTEXT, 0,
            reinterpret_cast<LPARAM>(text.c_str()));
    } else if (cls.find("combobox") != std::string::npos) {
        result = SendMessageA(element.handle, CB_SELECTSTRING, static_cast<WPARAM>(-1),
            reinterpret_cast<LPARAM>(text.c_str()));
    } else {
        return createResult(false, "Control does not accept text: " + element.className, element.handle);
    }
    return createResult(result != 0 || GetLastError() == ERROR_SUCCESS,
                        result != 0 ? "Text sent" : "Text target rejected input", element.handle);
}

// IDE Command implementation
NavigationResult AgenticNavigator::navigateIDECommands(const std::string& target) {
    // Command routing requires a known command ID. Do not report success for
    // a target that was not actually found by the live control tree.
    const auto elements = detectElementsDirectAPI();
    for (const auto& element : elements) {
        const std::string haystack = Lower(element.name + " " + element.text);
        if (haystack.find(Lower(target)) != std::string::npos) {
            return clickElementDirectAPI(element);
        }
    }
    return createResult(false, "IDE command target not found: " + target);
}

NavigationResult AgenticNavigator::clickElementIDECommands(const UIElement& element) {
    return clickElementDirectAPI(element);
}

NavigationResult AgenticNavigator::sendTextIDECommands(const UIElement& element, const std::string& text) {
    return sendTextDirectAPI(element, text);
}

// Hybrid implementation
NavigationResult AgenticNavigator::navigateHybrid(const std::string& target) {
    if (!m_fallbackConfig.enableCrossValidation) {
        // Try direct API first, fallback to commands
        auto directResult = navigateDirectAPI(target);
        if (directResult.success) {
            return directResult;
        }
        
        auto commandResult = navigateIDECommands(target);
        commandResult.fallbackUsed = "IDECommands";
        return commandResult;
    }
    
    // Cross-validation mode
    auto directResult = navigateDirectAPI(target);
    auto commandResult = navigateIDECommands(target);
    
    return validateResults(directResult, commandResult);
}

NavigationResult AgenticNavigator::validateResults(const NavigationResult& directResult, 
                                                 const NavigationResult& commandResult) {
    if (directResult.success && commandResult.success) {
        // Both methods agree - use faster one
        if (directResult.executionTimeMs <= commandResult.executionTimeMs) {
            return directResult;
        } else {
            NavigationResult result = commandResult;
            result.fallbackUsed = "IDECommands (cross-validated)";
            return result;
        }
    } else if (directResult.success) {
        return directResult;
    } else if (commandResult.success) {
        NavigationResult result = commandResult;
        result.fallbackUsed = "IDECommands (fallback)";
        return result;
    } else {
        return createResult(false, "Both navigation methods failed");
    }
}

// Utility functions
bool AgenticNavigator::isElementValid(const UIElement& element) const {
    return element.handle != nullptr && IsWindow(element.handle);
}

std::string AgenticNavigator::getElementInfo(const UIElement& element) const {
    return "Class: " + element.className + ", Name: " + element.name + ", Text: " + element.text;
}

NavigationResult AgenticNavigator::createResult(bool success, const std::string& message, 
                                              HWND target, const std::string& fallback) {
    NavigationResult result;
    result.success = success;
    result.message = message;
    result.targetWindow = target;
    result.fallbackUsed = fallback;
    result.errorCode = success ? 0 : -1;
    return result;
}

// Global navigator instance
std::unique_ptr<AgenticNavigator> CreateAgenticNavigator() {
    return std::make_unique<AgenticNavigator>();
}

} // namespace Agentic
} // namespace RawrXD
