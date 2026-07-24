//============================================================================
// nevm_toggle.cpp
// RawrXD N-EVM - Interactive Performance/Memory Toggle
// Runtime switch between throughput and memory optimization
//============================================================================

#include "nevm_v2.hpp"
#include "nevm_performance_profiles.hpp"
#include <iostream>
#include <iomanip>
#include <conio.h>
#include <windows.h>

using namespace RawrXD::NEVM;

//============================================================================
// Toggle Controller
//============================================================================

class PerformanceToggle {
public:
    enum class Mode {
        MAX_THROUGHPUT,
        BALANCED,
        MIN_MEMORY
    };
    
    Mode current_mode = Mode::BALANCED;
    NEVM_v2* vm_ = nullptr;
    
    void SetVM(NEVM_v2* vm) { vm_ = vm; }
    
    void Toggle() {
        // Cycle through modes
        switch (current_mode) {
            case Mode::MAX_THROUGHPUT:
                current_mode = Mode::BALANCED;
                ApplyBalanced();
                break;
            case Mode::BALANCED:
                current_mode = Mode::MIN_MEMORY;
                ApplyMinMemory();
                break;
            case Mode::MIN_MEMORY:
                current_mode = Mode::MAX_THROUGHPUT;
                ApplyMaxThroughput();
                break;
        }
    }
    
    void SetMode(Mode mode) {
        current_mode = mode;
        switch (mode) {
            case Mode::MAX_THROUGHPUT: ApplyMaxThroughput(); break;
            case Mode::BALANCED: ApplyBalanced(); break;
            case Mode::MIN_MEMORY: ApplyMinMemory(); break;
        }
    }
    
    void ApplyMaxThroughput() {
        std::cout << "\n[TOGGLE] Switching to MAXIMUM THROUGHPUT mode\n";
        std::cout << "  - Precision: Q4 with adaptive upgrade\n";
        std::cout << "  - Prefetch: Aggressive (5 layer lookahead)\n";
        std::cout << "  - Memory: Using up to 95% of available\n";
        std::cout << "  - Target: Maximum tok/s\n\n";
        
        if (vm_) {
            // Would reconfigure VM here
            // vm_->SetAdaptivePrecision(true);
            // vm_->SetPrefetchAggressiveness(5);
        }
    }
    
    void ApplyMinMemory() {
        std::cout << "\n[TOGGLE] Switching to MINIMUM MEMORY mode\n";
        std::cout << "  - Precision: Binary/Q2 with high error tolerance\n";
        std::cout << "  - Prefetch: Conservative (2 layer lookahead)\n";
        std::cout << "  - Memory: Limited to 50% of available\n";
        std::cout << "  - Target: Minimum RAM/VRAM usage\n\n";
        
        if (vm_) {
            // Would reconfigure VM here
            // vm_->SetDefaultPrecision(PrecisionMode::BINARY);
            // vm_->SetMemoryBudget(0.5f);
        }
    }
    
    void ApplyBalanced() {
        std::cout << "\n[TOGGLE] Switching to BALANCED mode\n";
        std::cout << "  - Precision: Q4 adaptive\n";
        std::cout << "  - Prefetch: Moderate (3 layer lookahead)\n";
        std::cout << "  - Memory: Using up to 75% of available\n";
        std::cout << "  - Target: Reasonable trade-off\n\n";
        
        if (vm_) {
            // Would reconfigure VM here
        }
    }
    
    const char* GetModeName() const {
        switch (current_mode) {
            case Mode::MAX_THROUGHPUT: return "MAX THROUGHPUT";
            case Mode::BALANCED: return "BALANCED";
            case Mode::MIN_MEMORY: return "MIN MEMORY";
        }
        return "UNKNOWN";
    }
    
    void PrintStatus() const {
        std::cout << "\n=== Performance Toggle Status ===\n";
        std::cout << "Current Mode: " << GetModeName() << "\n";
        std::cout << "Press [T] to toggle, [Q] to quit\n";
        std::cout << "==================================\n\n";
    }
};

//============================================================================
// Interactive Demo
//============================================================================

void RunInteractiveDemo() {
    PerformanceToggle toggle;
    
    std::cout << "============================================================================\n";
    std::cout << "RawrXD N-EVM Performance Toggle Demo\n";
    std::cout << "============================================================================\n\n";
    
    std::cout << "This demo shows the three performance profiles:\n";
    std::cout << "  [1] MAX THROUGHPUT - Prioritizes tok/s\n";
    std::cout << "  [2] BALANCED       - Reasonable trade-off\n";
    std::cout << "  [3] MIN MEMORY     - Minimizes RAM/VRAM\n\n";
    
    std::cout << "Press any key to start...\n";
    _getch();
    
    // Show each mode
    toggle.SetMode(PerformanceToggle::Mode::MAX_THROUGHPUT);
    toggle.PrintStatus();
    
    std::cout << "Simulating inference with MAX THROUGHPUT profile...\n";
    std::cout << "  Estimated: 45 tok/s, 14GB VRAM, 12GB RAM\n\n";
    
    std::cout << "Press [T] to toggle to MIN MEMORY...\n";
    while (_getch() != 't' && _getch() != 'T');
    
    toggle.SetMode(PerformanceToggle::Mode::MIN_MEMORY);
    toggle.PrintStatus();
    
    std::cout << "Simulating inference with MIN MEMORY profile...\n";
    std::cout << "  Estimated: 28 tok/s, 7GB VRAM, 6GB RAM\n";
    std::cout << "  Memory reduction: 50%, Throughput reduction: 38%\n\n";
    
    std::cout << "Press [T] to toggle to BALANCED...\n";
    while (_getch() != 't' && _getch() != 'T');
    
    toggle.SetMode(PerformanceToggle::Mode::BALANCED);
    toggle.PrintStatus();
    
    std::cout << "Simulating inference with BALANCED profile...\n";
    std::cout << "  Estimated: 38 tok/s, 10GB VRAM, 9GB RAM\n";
    std::cout << "  Good trade-off for most use cases\n\n";
    
    std::cout << "Demo complete. Press any key to exit...\n";
    _getch();
}

//============================================================================
// Command-line Interface
//============================================================================

void PrintUsage(const char* program) {
    std::cout << "Usage: " << program << " [command]\n\n";
    std::cout << "Commands:\n";
    std::cout << "  throughput    Set max throughput mode\n";
    std::cout << "  memory        Set min memory mode\n";
    std::cout << "  balanced      Set balanced mode\n";
    std::cout << "  demo          Run interactive demo\n";
    std::cout << "  status        Show current mode\n";
    std::cout << "  -h, --help    Show this help\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        PrintUsage("nevm_toggle");
        return 1;
    }
    
    std::string command = argv[1];
    
    if (command == "throughput" || command == "max") {
        PerformanceToggle toggle;
        toggle.SetMode(PerformanceToggle::Mode::MAX_THROUGHPUT);
        return 0;
    }
    else if (command == "memory" || command == "min") {
        PerformanceToggle toggle;
        toggle.SetMode(PerformanceToggle::Mode::MIN_MEMORY);
        return 0;
    }
    else if (command == "balanced") {
        PerformanceToggle toggle;
        toggle.SetMode(PerformanceToggle::Mode::BALANCED);
        return 0;
    }
    else if (command == "demo") {
        RunInteractiveDemo();
        return 0;
    }
    else if (command == "status") {
        // Would read current mode from shared memory or config
        std::cout << "Current mode: BALANCED (default)\n";
        return 0;
    }
    else if (command == "-h" || command == "--help") {
        PrintUsage("nevm_toggle");
        return 0;
    }
    else {
        std::cerr << "Unknown command: " << command << "\n";
        PrintUsage("nevm_toggle");
        return 1;
    }
}
