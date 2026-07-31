#include "profiler.h"
#include <chrono>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

class Batch3SmokeTest {
public:
    Batch3SmokeTest() : profiler(std::make_unique<Profiler>()) {}
    bool runAllTests() {
        std::cout << "=== Batch 3 Profiler Smoke Test Suite ===\n\n";
        bool allPassed = true;
        allPassed &= testBasicProfiling();
        allPassed &= testPhaseMarking();
        allPassed &= testMemoryTracking();
        allPassed &= testSnapshot();
        allPassed &= testReportExport();
        std::cout << "\n=== Smoke Test Results ===\n";
        std::cout << "Overall: " << (allPassed ? "PASSED" : "FAILED") << "\n";
        return allPassed;
    }
private:
    std::unique_ptr<Profiler> profiler;
    bool testBasicProfiling() {
        std::cout << "Test 1: Basic Profiling... ";
        try {
            profiler->startProfiling();
            if (!profiler->isProfiling()) { std::cout << "FAILED\n"; return false; }
            profiler->recordMemoryAllocation(1024 * 1024);
            profiler->recordBatchCompleted(10, 100);
            auto snap = profiler->getCurrentSnapshot();
            if (snap.memoryUsageMB < 0) { std::cout << "FAILED\n"; return false; }
            profiler->stopProfiling();
            std::cout << "PASSED\n"; return true;
        } catch (const std::exception& e) { std::cout << "FAILED (" << e.what() << ")\n"; return false; }
    }
    bool testPhaseMarking() {
        std::cout << "Test 2: Phase Marking... ";
        try {
            profiler->startProfiling();
            profiler->markPhaseStart("forward");
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            profiler->markPhaseEnd("forward");
            profiler->stopProfiling();
            std::cout << "PASSED\n"; return true;
        } catch (const std::exception& e) { std::cout << "FAILED (" << e.what() << ")\n"; return false; }
    }
    bool testMemoryTracking() {
        std::cout << "Test 3: Memory Tracking... ";
        try {
            profiler->startProfiling();
            profiler->recordMemoryAllocation(2048 * 1024);
            profiler->recordMemoryAllocation(1024 * 1024);
            profiler->recordMemoryDeallocation(512 * 1024);
            auto snap = profiler->getCurrentSnapshot();
            if (snap.memoryUsageMB <= 0.0f) { std::cout << "FAILED\n"; return false; }
            profiler->stopProfiling();
            std::cout << "PASSED\n"; return true;
        } catch (const std::exception& e) { std::cout << "FAILED (" << e.what() << ")\n"; return false; }
    }
    bool testSnapshot() {
        std::cout << "Test 4: Snapshot... ";
        try {
            profiler->startProfiling();
            profiler->recordMemoryAllocation(64 * 1024 * 1024);
            auto snap = profiler->getCurrentSnapshot();
            if (snap.timestamp == 0) { std::cout << "FAILED\n"; return false; }
            profiler->stopProfiling();
            std::cout << "PASSED\n"; return true;
        } catch (const std::exception& e) { std::cout << "FAILED (" << e.what() << ")\n"; return false; }
    }
    bool testReportExport() {
        std::cout << "Test 5: Report Export... ";
        try {
            profiler->startProfiling();
            profiler->recordMemoryAllocation(1024 * 1024);
            profiler->stopProfiling();
            auto report = profiler->getProfilingReport();
            if (report.empty()) { std::cout << "FAILED\n"; return false; }
            if (profiler->exportReport("test_profiler_report.json")) { std::cout << "PASSED\n"; return true; }
            std::cout << "FAILED\n"; return false;
        } catch (const std::exception& e) { std::cout << "FAILED (" << e.what() << ")\n"; return false; }
    }
};
int main() {
    Batch3SmokeTest test;
    return test.runAllTests() ? 0 : 1;
}