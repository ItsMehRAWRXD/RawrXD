<<<<<<< HEAD
#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
using HWND = void*;
#endif
=======
/**
 * \file benchmark_menu_widget.hpp
 * \brief Benchmark menu and test selector widget for the IDE (Stubbed for Native Migration)
 * \author RawrXD Team
 * \date 2026-02-01
 */

#pragma once

#include <vector>
#include <string>
#include <memory>
#include <functional>
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

class BenchmarkRunner;

struct TestResult {
    std::string testName;
<<<<<<< HEAD
    bool passed = false;
    double avgLatencyMs = 0.0;
    double p95LatencyMs = 0.0;
    double successRate = 0.0;
};

class BenchmarkSelector {
public:
    void create(HWND parent, int x, int y, int w, int h);
=======
    bool passed;
    double avgLatencyMs;
    double p95LatencyMs;
    double successRate;
};

/**
 * @brief Widget for selecting which benchmarks to run
 * Stubbed out for non-Qt build
 */
class BenchmarkSelector {
public:
    explicit BenchmarkSelector(void* parent = nullptr);
    virtual ~BenchmarkSelector() = default;

    std::vector<std::string> getSelectedTests() const;
    std::string getSelectedModel() const;
    bool isGpuEnabled() const;
    bool isVerbose() const;

private:
    std::vector<void*> testCheckboxes_;
    void* modelCombo_;
    void* gpuCheckbox_;
    void* verboseCheckbox_;
};

/**
 * @brief Main benchmark control widget
 */
class BenchmarkMenuWidget {
public:
    explicit BenchmarkMenuWidget(void* parent = nullptr);
    ~BenchmarkMenuWidget();

    void show();
    void addTestResult(const std::string& name, bool passed, double latency);
    void updateProgress(int current, int total);
    void logMessage(const std::string& msg, int level);

private:
    void setupConnections();
    void startBenchmarks();
    void stopBenchmarks();

    std::unique_ptr<BenchmarkRunner> runner_;
    std::unique_ptr<BenchmarkSelector> selector_;
    
    // UI elements stubbed
    void* runButton_;
    void* stopButton_;
    void* progressBar_;
    void* logView_;
    void* resultsTable_;
    void* statusLabel_;
};

    // Get selected tests
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    std::vector<std::string> getSelectedTests() const;
    std::string getModelPath() const;
    void setModelPath(const std::string& path);
    bool isGPUEnabled() const;
    bool isVerbose() const;
    void selectAll();
    void deselectAll();

private:
    void setupUI();

    HWND parent_ = nullptr;
    HWND modelCombo_ = nullptr;
    HWND gpuCheckbox_ = nullptr;
    HWND verboseCheckbox_ = nullptr;
    std::vector<HWND> testCheckboxes_;
};

class BenchmarkLogOutput {
public:
    enum LogLevel {
        DEBUG = 0,
        INFO = 1,
        SUCCESS = 2,
        WARNING = 3,
        LOG_ERROR = 4
    };

    void attach(HWND hwnd);
    void logMessage(const std::string& message, LogLevel level = INFO);
    void logProgress(int current, int total);
    void logTestResult(const std::string& testName, bool passed, double latencyMs);
    void clear();

private:
    void formatLog(const std::string& message, LogLevel level);
    std::string levelToString(LogLevel level);
    uint32_t levelToColor(LogLevel level);

    HWND m_hwnd = nullptr;
};

class BenchmarkResultsDisplay {
public:
    void create(HWND parent, int x, int y, int w, int h);
    void setTotalTests(int count);
    void updateProgress(int current);
    void addResult(const std::string& testName, bool passed, double avgLatencyMs, double p95LatencyMs, double successRate);
    void showSummary(int passed, int total, double executionTimeSec);
    void reset();

private:
    void setupUI();

    HWND parent_ = nullptr;
    HWND progressBar_ = nullptr;
    HWND resultsDisplay_ = nullptr;
    int totalTests_ = 0;
    std::vector<TestResult> results_;
};

class BenchmarkMenu {
public:
    explicit BenchmarkMenu(HWND mainWindow = nullptr);
    ~BenchmarkMenu();

    void setMainWindow(HWND mainWindow) { mainWindow_ = mainWindow; }
    void initialize();
    void show();
    void openBenchmarkDialog();
    void runSelectedBenchmarks();
    void stopBenchmarks();
    void viewBenchmarkResults();

    BenchmarkSelector* ensureSelectorAttached(HWND parent);
    BenchmarkLogOutput* ensureLogAttached(HWND logEdit);
    BenchmarkResultsDisplay* ensureResultsAttached(HWND parent);
    void notifyFinished();

private:
    void createMenu();
    void createDialog();
    void connectHandlers();

    HWND mainWindow_ = nullptr;
    HWND dialogHwnd_ = nullptr;
    BenchmarkSelector* selector_ = nullptr;
    BenchmarkLogOutput* logOutput_ = nullptr;
    BenchmarkResultsDisplay* resultsDisplay_ = nullptr;
    std::unique_ptr<BenchmarkRunner> runner_;
    std::thread runnerThread_;
    std::atomic<bool> runnerActive_{false};
};
