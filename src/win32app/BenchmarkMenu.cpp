#include "BenchmarkMenu.h"
#include <commctrl.h>

#pragma comment(lib, "comctl32.lib")

BenchmarkMenu::BenchmarkMenu(HWND parentHwnd)
    : m_parentHwnd(parentHwnd)
    , m_hwnd(nullptr)
    , m_context(nullptr)
    , m_showCallback(nullptr)
    , m_isRunning(false)
{
}

BenchmarkMenu::~BenchmarkMenu() {
    if (m_hwnd) {
        DestroyWindow(m_hwnd);
    }
}

void BenchmarkMenu::show() {
    if (m_showCallback) {
        m_showCallback(m_context);
    }
    createDialog();
}

void BenchmarkMenu::setMainWindow(HWND hwnd) {
    m_parentHwnd = hwnd;
}

void BenchmarkMenu::initialize() {
    // Initialize benchmark menu resources
    // Stub implementation - full initialization would set up UI components
}

void BenchmarkMenu::setShowCallback(ShowCallback callback, void* context) {
    m_showCallback = callback;
    m_context = context;
}

void BenchmarkMenu::runBenchmark(const std::string& benchmarkName) {
    m_isRunning = true;
    // Benchmark execution implementation
    // This is a stub - full implementation would run actual benchmarks
    m_isRunning = false;
}

void BenchmarkMenu::stopBenchmark() {
    m_isRunning = false;
}

bool BenchmarkMenu::isRunning() const {
    return m_isRunning;
}

std::vector<BenchmarkMenu::BenchmarkResult> BenchmarkMenu::getResults() const {
    return m_results;
}

void BenchmarkMenu::clearResults() {
    m_results.clear();
}

std::vector<std::string> BenchmarkMenu::getAvailableBenchmarks() const {
    return {
        "Inference Speed Test",
        "Memory Throughput",
        "Token Generation Rate",
        "Model Load Time",
        "UI Responsiveness"
    };
}

void BenchmarkMenu::createDialog() {
    // Dialog creation implementation
    // This is a stub - full implementation would create actual dialog
}

INT_PTR CALLBACK BenchmarkMenu::dialogProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_INITDIALOG:
        return TRUE;
    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL) {
            EndDialog(hwnd, LOWORD(wParam));
            return TRUE;
        }
        break;
    }
    return FALSE;
}
