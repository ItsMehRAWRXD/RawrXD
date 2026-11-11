#pragma once

#include <windows.h>
#include <string>
#include <functional>
#include <vector>

// Benchmark Menu for RawrXD IDE
class BenchmarkMenu {
public:
    BenchmarkMenu(HWND parentHwnd = nullptr);
    ~BenchmarkMenu();

    // Show the benchmark menu/dialog
    void show();

    // Set the main window handle
    void setMainWindow(HWND hwnd);

    // Initialize the benchmark menu
    void initialize();

    // Set callback for when menu is shown
    using ShowCallback = std::function<void(void*)>;
    void setShowCallback(ShowCallback callback, void* context);

    // Benchmark operations
    void runBenchmark(const std::string& benchmarkName);
    void stopBenchmark();
    bool isRunning() const;

    // Results
    struct BenchmarkResult {
        std::string name;
        double durationMs;
        double score;
        bool passed;
    };
    std::vector<BenchmarkResult> getResults() const;
    void clearResults();

    // Available benchmarks
    std::vector<std::string> getAvailableBenchmarks() const;

private:
    HWND m_parentHwnd;
    HWND m_hwnd;
    void* m_context;
    ShowCallback m_showCallback;
    bool m_isRunning;
    std::vector<BenchmarkResult> m_results;

    void createDialog();
    static INT_PTR CALLBACK dialogProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
};
