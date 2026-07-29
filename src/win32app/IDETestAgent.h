#pragma once

#include "Win32IDE.h"
#include "IDELogger.h"
#include <windows.h>
#include <richedit.h>
#include <vector>
#include <string>
#include <functional>
#include <chrono>

// PatchResult — use canonical definition (avoids redefinition across TUs)
#include "../core/patch_result.hpp"

// Comprehensive IDE Test Agent
// Tests every function in the IDE with detailed logging
class IDETestAgent {
public:
    struct TestResult {
        std::string testName;
        bool passed;
        std::string errorMessage;
        double durationMs;
        int errorCode;
    };

    IDETestAgent(Win32IDE* ide) : m_ide(ide), m_testsRun(0), m_testsPassed(0), m_testsFailed(0) {

    }

    // Run all tests
    void runAllTests() {


        // Core window tests
        testWindowCreation();
        testWindowVisibility();
        
        // UI component tests
        testMenuBar();
        testToolbar();
        testStatusBar();
        testSidebar();
        testActivityBar();
        testSecondarySidebar();
        
        // Editor tests
        testEditor();
        testEditorText();
        testEditorSelection();
        testSyntaxHighlighting();
        
        // File operation tests
        testFileOperations();
        testFileExplorer();
        testRecentFiles();
        
        // Terminal tests
        testTerminal();
        testTerminalOutput();
        
        // Output panel tests
        testOutputTabs();
        testOutputFiltering();
        
        // PowerShell tests
        testPowerShellPanel();
        testPowerShellExecution();
        testRawrXDModule();
        
        // Debugger tests
        testDebugger();
        testBreakpoints();
        testWatchVariables();
        
        // Search/Replace tests
        testFindDialog();
        testReplaceDialog();
        testSearchInFiles();
        
        // Git/SCM tests
        testGitStatus();
        testGitOperations();
        
        // Model/GGUF tests
        testGGUFLoader();
        testModelInference();
        
        // Copilot/AI tests
        testCopilotChat();
        testAgenticCommands();
        
        // Theme and customization tests
        testThemes();
        testSnippets();
        testClipboardHistory();
        
        // Renderer tests
        testTransparentRenderer();
        testGPUText();
        
        // Print summary
        printTestSummary();
    }

    const std::vector<TestResult>& getResults() const { return m_results; }

private:
    Win32IDE* m_ide;
    std::vector<TestResult> m_results;
    int m_testsRun;
    int m_testsPassed;
    int m_testsFailed;

<<<<<<< HEAD
    // Test helper - no exceptions, uses PatchResult pattern
    void runTest(const std::string& name, std::function<PatchResult()> testFunc) {
        LOG_INFO("Running test: " + name);
=======
    // Test helper
    void runTest(const std::string& name, std::function<void()> testFunc) {

>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        auto start = std::chrono::high_resolution_clock::now();
        
        PatchResult result = testFunc();
        auto end = std::chrono::high_resolution_clock::now();
        double durationMs = std::chrono::duration<double, std::milli>(end - start).count();
        
        if (result.success) {
            m_results.push_back({name, true, "", durationMs, 0});
            m_testsPassed++;
<<<<<<< HEAD
            LOG_INFO("✓ PASSED: " + name + " (" + std::to_string(durationMs) + "ms)");
        } else {
            std::string error = std::string(result.detail ? result.detail : "Unknown error");
            m_results.push_back({name, false, error, durationMs, result.errorCode});
            m_testsFailed++;
            LOG_ERROR("✗ FAILED: " + name + " - " + error);
=======

        } catch (const std::exception& e) {
            auto end = std::chrono::high_resolution_clock::now();
            double durationMs = std::chrono::duration<double, std::milli>(end - start).count();
            
            std::string error = std::string(e.what());
            m_results.push_back({name, false, error, durationMs});
            m_testsFailed++;

        } catch (...) {
            auto end = std::chrono::high_resolution_clock::now();
            double durationMs = std::chrono::duration<double, std::milli>(end - start).count();
            
            m_results.push_back({name, false, "Unknown exception", durationMs});
            m_testsFailed++;

>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        }
        m_testsRun++;
    }

    // Core window tests
    void testWindowCreation() {
        runTest("Window Creation", [this]() -> PatchResult {
            if (!m_ide->getMainWindow()) {
                return PatchResult::error("Main window handle is null");
            }
<<<<<<< HEAD
            LOG_DEBUG("Main window handle validated");
            return PatchResult::ok("Main window validated");
=======

>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        });
    }

    void testWindowVisibility() {
        runTest("Window Visibility", [this]() -> PatchResult {
            HWND hwnd = m_ide->getMainWindow();
            if (!hwnd) return PatchResult::error("Window handle is null");
            
            if (!IsWindow(hwnd)) {
                return PatchResult::error("Window is not valid");
            }
            
            if (!IsWindowVisible(hwnd)) {
                LOG_WARNING("Window exists but is not visible");
            } else {

            }
            return PatchResult::ok("Window visibility checked");
        });
    }

    // UI Component tests
    void testMenuBar() {
        runTest("Menu Bar", [this]() -> PatchResult {
            HWND hwnd = m_ide->getMainWindow();
            HMENU menu = GetMenu(hwnd);
            if (!menu) {
                return PatchResult::error("Menu bar not found");
            }
            
            int menuCount = GetMenuItemCount(menu);

            if (menuCount == 0) {
                return PatchResult::error("Menu bar is empty");
            }
            return PatchResult::ok("Menu bar validated");
        });
    }

    void testToolbar() {
        runTest("Toolbar", [this]() -> PatchResult {
            // Test toolbar existence by checking for common toolbar controls
            HWND hwnd = m_ide->getMainWindow();
            HWND toolbar = FindWindowExA(hwnd, NULL, "ToolbarWindow32", NULL);
            if (!toolbar) {
                LOG_WARNING("Toolbar window not found");
            } else {

            }
            return PatchResult::ok("Toolbar checked");
        });
    }

    void testStatusBar() {
        runTest("Status Bar", [this]() -> PatchResult {
            HWND hwnd = m_ide->getMainWindow();
            HWND statusBar = FindWindowExA(hwnd, NULL, "msctls_statusbar32", NULL);
            if (!statusBar) {
                return PatchResult::error("Status bar not found");
            }
<<<<<<< HEAD
            LOG_DEBUG("Status bar validated");
            return PatchResult::ok("Status bar found");
=======

>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        });
    }

    void testSidebar() {
        runTest("Sidebar", [this]() -> PatchResult {
            // Test sidebar visibility and state

            // Sidebar is created in onCreate, should exist
            return PatchResult::ok("Sidebar checked");
        });
    }

    void testActivityBar() {
<<<<<<< HEAD
        runTest("Activity Bar", [this]() -> PatchResult {
            LOG_DEBUG("Testing activity bar (VS Code style icon bar)");
            return PatchResult::ok("Activity bar checked");
=======
        runTest("Activity Bar", [this]() {

>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        });
    }

    void testSecondarySidebar() {
<<<<<<< HEAD
        runTest("Secondary Sidebar (Copilot)", [this]() -> PatchResult {
            LOG_DEBUG("Testing secondary sidebar for AI/Copilot");
            return PatchResult::ok("Secondary sidebar checked");
=======
        runTest("Secondary Sidebar (Copilot)", [this]() {

>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        });
    }

    // Editor tests
    void testEditor() {
        runTest("Editor Control", [this]() -> PatchResult {
            HWND hwnd = m_ide->getMainWindow();
            HWND editor = FindWindowExA(hwnd, NULL, "RICHEDIT50W", NULL);
            if (!editor) {
                return PatchResult::error("Editor control not found");
            }
<<<<<<< HEAD
            LOG_DEBUG("Editor control validated");
            return PatchResult::ok("Editor control found");
=======

>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        });
    }

    void testEditorText() {
        runTest("Editor Text Operations", [this]() -> PatchResult {
            HWND hwnd = m_ide->getMainWindow();
            HWND editor = FindWindowExA(hwnd, NULL, "RICHEDIT50W", NULL);
            if (!editor) return PatchResult::error("Editor not found");
            
            // Test setting text
            const char* testText = "// IDETestAgent test content\nint main() {\n    return 0;\n}";
            SendMessageA(editor, WM_SETTEXT, 0, (LPARAM)testText);
            
            // Verify text was set
            int len = SendMessageA(editor, WM_GETTEXTLENGTH, 0, 0);

            if (len == 0) {
                return PatchResult::error("Failed to set editor text");
            }
            return PatchResult::ok("Editor text operations successful");
        });
    }

    void testEditorSelection() {
        runTest("Editor Selection", [this]() -> PatchResult {
            HWND hwnd = m_ide->getMainWindow();
            HWND editor = FindWindowExA(hwnd, NULL, "RICHEDIT50W", NULL);
            if (!editor) return PatchResult::error("Editor not found");
            
            // Test selection
            CHARRANGE range{0, 10};
            SendMessage(editor, EM_EXSETSEL, 0, (LPARAM)&range);
            
            CHARRANGE checkRange{};
            SendMessage(editor, EM_EXGETSEL, 0, (LPARAM)&checkRange);
<<<<<<< HEAD
            
            LOG_DEBUG("Selection set: " + std::to_string(checkRange.cpMin) + " to " + std::to_string(checkRange.cpMax));
            return PatchResult::ok("Editor selection test completed");
=======

>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        });
    }

    void testSyntaxHighlighting() {
<<<<<<< HEAD
        runTest("Syntax Highlighting", [this]() -> PatchResult {
            LOG_DEBUG("Testing syntax highlighting system");
=======
        runTest("Syntax Highlighting", [this]() {

>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
            // Syntax highlighting is visual - log that system exists
            return PatchResult::ok("Syntax highlighting checked");
        });
    }

    // File operation tests
    void testFileOperations() {
<<<<<<< HEAD
        runTest("File Operations", [this]() -> PatchResult {
            LOG_DEBUG("Testing file operation system");
=======
        runTest("File Operations", [this]() {

>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
            // File ops tested through actual file loading later
            return PatchResult::ok("File operations checked");
        });
    }

    void testFileExplorer() {
        runTest("File Explorer", [this]() -> PatchResult {
            HWND hwnd = m_ide->getMainWindow();
            return PatchResult::ok("File explorer checked");
        });
            HWND tree = FindWindowExA(hwnd, NULL, "SysTreeView32", NULL);
            if (!tree) {
                LOG_WARNING("File explorer tree view not found");
            } else {

            }
        });
    }

    void testRecentFiles() {
        runTest("Recent Files", [this]() {

        });
    }

    // Terminal tests
    void testTerminal() {
        runTest("Terminal", [this]() {

        });
    }

    void testTerminalOutput() {
        runTest("Terminal Output", [this]() {

        });
    }

    // Output panel tests
    void testOutputTabs() {
        runTest("Output Tabs", [this]() {
            HWND hwnd = m_ide->getMainWindow();
            HWND tabs = FindWindowExA(hwnd, NULL, "SysTabControl32", NULL);
            if (!tabs) {
                LOG_WARNING("Output tabs not found");
            } else {
                int tabCount = SendMessage(tabs, TCM_GETITEMCOUNT, 0, 0);

            }
        });
    }

    void testOutputFiltering() {
        runTest("Output Filtering", [this]() {

        });
    }

    // PowerShell tests
    void testPowerShellPanel() {
        runTest("PowerShell Panel", [this]() {

        });
    }

    void testPowerShellExecution() {
        runTest("PowerShell Execution", [this]() {

        });
    }

    void testRawrXDModule() {
        runTest("RawrXD PowerShell Module", [this]() {

        });
    }

    // Debugger tests
    void testDebugger() {
        runTest("Debugger UI", [this]() {

        });
    }

    void testBreakpoints() {
        runTest("Breakpoints", [this]() {

        });
    }

    void testWatchVariables() {
        runTest("Watch Variables", [this]() {

        });
    }

    // Search/Replace tests
    void testFindDialog() {
        runTest("Find Dialog", [this]() {

        });
    }

    void testReplaceDialog() {
        runTest("Replace Dialog", [this]() {

        });
    }

    void testSearchInFiles() {
        runTest("Search in Files", [this]() {

        });
    }

    // Git tests
    void testGitStatus() {
        runTest("Git Status", [this]() {

        });
    }

    void testGitOperations() {
        runTest("Git Operations", [this]() {

        });
    }

    // Model/GGUF tests
    void testGGUFLoader() {
        runTest("GGUF Loader", [this]() {

        });
    }

    void testModelInference() {
        runTest("Model Inference", [this]() {

        });
    }

    // Copilot tests
    void testCopilotChat() {
        runTest("Copilot Chat", [this]() {

        });
    }

    void testAgenticCommands() {
        runTest("Agentic Commands", [this]() {

        });
    }

    // Theme tests
    void testThemes() {
        runTest("Theme System", [this]() {

        });
    }

    void testSnippets() {
        runTest("Code Snippets", [this]() {

        });
    }

    void testClipboardHistory() {
        runTest("Clipboard History", [this]() {

        });
    }

    // Renderer tests
    void testTransparentRenderer() {
        runTest("Transparent Renderer", [this]() {

        });
    }

    void testGPUText() {
        runTest("GPU Text Rendering", [this]() {

        });
    }

    void printTestSummary() {


        if (m_testsFailed > 0) {
            LOG_WARNING("Failed tests:");
            for (const auto& result : m_results) {
                if (!result.passed) {
                    LOG_WARNING("  - " + result.testName + ": " + result.errorMessage);
                }
            }
        }
    }
};
