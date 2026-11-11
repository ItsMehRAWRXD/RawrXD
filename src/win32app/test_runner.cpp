// IDE Test Runner - Comprehensive function testing with logging
// Tests every aspect of the RawrXD IDE

#include "Win32IDE.h"
#include "IDETestAgent.h"
#include "IDELogger.h"
#include <windows.h>
#include <iostream>
#include <fstream>

int main(int argc, char* argv[]) {
    
    std::ofstream test("test_file_write.txt");
    test << "File write test successful" << std::endl;
    test.close();


    // Initialize logging to a specific test log file
    
    IDELogger::getInstance().initialize();


    try {
        // Create IDE instance
        HINSTANCE hInstance = GetModuleHandle(NULL);
        Win32IDE ide(hInstance);

        // Create main window (but don't show it if in automated mode)
        if (!ide.createWindow()) {


            return 1;
        }

        // Show window if not in headless mode
        bool headless = false;
        for (int i = 1; i < argc; i++) {
            if (std::string(argv[i]) == "--headless") {
                headless = true;
                break;
            }
        }

        if (!headless) {
            ide.showWindow();

        } else {

        }

        // Give the window time to fully initialize
        Sleep(500);
        
        // Create test agent
        IDETestAgent testAgent(&ide);

        // Run all tests
        
        testAgent.runAllTests();

        // Get results
        const auto& results = testAgent.getResults();
        
        // Print results to console


        int passed = 0, failed = 0;
        for (const auto& result : results) {
            if (result.passed) {
                passed++;
                
            } else {
                failed++;
                
            }
        }


        // Write detailed results to file (temp dir or cwd)
        char tempPath[MAX_PATH] = {};
        std::string resultPath = "RawrXD_IDE_TestResults.txt";
        if (GetTempPathA(MAX_PATH, tempPath))
            resultPath = std::string(tempPath) + "RawrXD_IDE_TestResults.txt";
        std::ofstream resultFile(resultPath);
        if (resultFile.is_open()) {
            resultFile << "RawrXD IDE Test Results\n";
            resultFile << "=======================\n\n";
            resultFile << "Test Run Date: " << __DATE__ << " " << __TIME__ << "\n\n";
            
            for (const auto& result : results) {
                resultFile << (result.passed ? "[PASS] " : "[FAIL] ");
                resultFile << result.testName;
                resultFile << " (" << result.durationMs << "ms)";
                if (!result.passed) {
                    resultFile << "\n  Error: " << result.errorMessage;
                }
                resultFile << "\n";
            }
            
            resultFile << "\nSummary:\n";
            resultFile << "Total: " << results.size() << "\n";
            resultFile << "Passed: " << passed << "\n";
            resultFile << "Failed: " << failed << "\n";
            resultFile.close();
            
            std::cout << "\nDetailed results written to: " << resultPath << "\n";
            LOG_INFO("Test results written to file");
        }

        std::cout << "Log file: see IDELogger output (e.g. %APPDATA%\\RawrXD\\ide.log or cwd)\n";
        
        LOG_INFO("Test runner completed");
        
        // If not headless, keep window open for manual inspection
        if (!headless) {
            
            std::cin.get();
        }

        return (failed == 0) ? 0 : 1;

    } catch (const std::exception& e) {
        LOG_CRITICAL("Test runner exception: " + std::string(e.what()));
        
        return 2;
    } catch (...) {
        LOG_CRITICAL("Unknown test runner exception");
        
        return 2;
    }
}
