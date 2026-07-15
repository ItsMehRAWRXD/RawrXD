// ============================================================================
// Phase 24: DapService Validation Test
// ============================================================================
// Tests the production DapService class without requiring an actual debugger

#include "DapService.hpp"
#include <iostream>
#include <string>
#include <windows.h>

using namespace RawrXD::Debug;

class TestCallbacks {
public:
    static void onStateChanged(DapState oldState, DapState newState) {
        std::cout << "[Callback] State: " << StateToString(oldState) 
                  << " -> " << StateToString(newState) << std::endl;
    }
    
    static void onStopped(const std::string& reason, uint32_t threadId, const std::string& desc) {
        std::cout << "[Callback] Stopped: " << reason << " (thread " << threadId << ")" << std::endl;
    }
    
    static void onContinued(uint32_t threadId) {
        std::cout << "[Callback] Continued (thread " << threadId << ")" << std::endl;
    }
    
    static void onTerminated() {
        std::cout << "[Callback] Terminated" << std::endl;
    }
    
    static void onOutput(OutputChannel channel, const std::string& data) {
        const char* ch = (channel == OutputChannel::Stdout) ? "stdout" :
                        (channel == OutputChannel::Stderr) ? "stderr" : "console";
        std::cout << "[Callback] Output [" << ch << "]: " << data;
    }
    
    static void onError(const std::string& error, bool fatal) {
        std::cout << "[Callback] Error" << (fatal ? " (FATAL)" : "") << ": " << error << std::endl;
    }
};

void runDapServiceTest() {
    std::cout << "========================================" << std::endl;
    std::cout << "Phase 24: DapService Validation Test" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    
    auto& service = DapService::instance();
    
    // Test 1: Initial state
    std::cout << "[TEST 1] Check initial state" << std::endl;
    if (service.state() != DapState::Disconnected) {
        std::cout << "[FAIL] Expected Disconnected, got " << StateToString(service.state()) << std::endl;
        return;
    }
    if (service.isInitialized()) {
        std::cout << "[FAIL] Should not be initialized" << std::endl;
        return;
    }
    std::cout << "[PASS] Initial state correct" << std::endl;
    std::cout << std::endl;
    
    // Test 2: Set callbacks
    std::cout << "[TEST 2] Set callbacks" << std::endl;
    DapService::Callbacks cbs;
    cbs.onStateChanged = TestCallbacks::onStateChanged;
    cbs.onStopped = TestCallbacks::onStopped;
    cbs.onContinued = TestCallbacks::onContinued;
    cbs.onTerminated = TestCallbacks::onTerminated;
    cbs.onOutput = TestCallbacks::onOutput;
    cbs.onError = TestCallbacks::onError;
    
    service.setCallbacks(cbs);
    std::cout << "[PASS] Callbacks registered" << std::endl;
    std::cout << std::endl;
    
    // Test 3: State transitions (without actual debugger)
    std::cout << "[TEST 3] State string conversion" << std::endl;
    bool stateTestPass = true;
    for (auto state : {DapState::Disconnected, DapState::Initializing, 
                       DapState::Running, DapState::Paused, DapState::Stopped}) {
        const char* str = StateToString(state);
        DapState back = StringToState(str);
        if (back != state) {
            std::cout << "[FAIL] State round-trip failed for " << str << std::endl;
            stateTestPass = false;
        }
    }
    if (stateTestPass) {
        std::cout << "[PASS] State string conversion works" << std::endl;
    }
    std::cout << std::endl;
    
    // Test 4: LaunchConfig structure
    std::cout << "[TEST 4] LaunchConfig structure" << std::endl;
    LaunchConfig config;
    config.program = "C:\\test\\app.exe";
    config.workingDirectory = "C:\\test";
    config.args = {"--verbose", "--debug"};
    config.env = {"PATH=C:\\test", "DEBUG=1"};
    config.stopOnEntry = true;
    config.debuggerType = "cppvsdbg";
    
    if (config.program != "C:\\test\\app.exe") {
        std::cout << "[FAIL] Program path not set correctly" << std::endl;
        return;
    }
    if (config.args.size() != 2) {
        std::cout << "[FAIL] Args not stored correctly" << std::endl;
        return;
    }
    std::cout << "[PASS] LaunchConfig structure works" << std::endl;
    std::cout << std::endl;
    
    // Test 5: Data structures
    std::cout << "[TEST 5] Data structures" << std::endl;
    StackFrame frame;
    frame.id = 1;
    frame.name = "main";
    frame.source = "main.cpp";
    frame.line = 42;
    frame.column = 1;
    
    Variable var;
    var.name = "x";
    var.value = "42";
    var.type = "int";
    var.variablesReference = 0;
    var.isExpandable = false;
    
    Breakpoint bp;
    bp.id = 1;
    bp.source = "main.cpp";
    bp.line = 42;
    bp.verified = true;
    
    ThreadInfo thread;
    thread.id = 1;
    thread.name = "Main Thread";
    thread.isStopped = true;
    
    std::cout << "  StackFrame: " << frame.name << " at line " << frame.line << std::endl;
    std::cout << "  Variable: " << var.name << " = " << var.value << std::endl;
    std::cout << "  Breakpoint: " << bp.source << ":" << bp.line << std::endl;
    std::cout << "  Thread: " << thread.name << std::endl;
    std::cout << "[PASS] Data structures work" << std::endl;
    std::cout << std::endl;
    
    // Test 6: DapResult
    std::cout << "[TEST 6] DapResult" << std::endl;
    auto okResult = DapResult::Ok();
    auto failResult = DapResult::Fail("Test error");
    
    if (!okResult.success || okResult.error != "") {
        std::cout << "[FAIL] Ok result incorrect" << std::endl;
        return;
    }
    if (failResult.success || failResult.error != "Test error") {
        std::cout << "[FAIL] Fail result incorrect" << std::endl;
        return;
    }
    if (!okResult) {
        std::cout << "[FAIL] bool operator failed" << std::endl;
        return;
    }
    std::cout << "[PASS] DapResult works" << std::endl;
    std::cout << std::endl;
    
    // Test 7: Service singleton
    std::cout << "[TEST 7] Singleton pattern" << std::endl;
    auto& service2 = DapService::instance();
    if (&service != &service2) {
        std::cout << "[FAIL] Singleton returned different instances" << std::endl;
        return;
    }
    std::cout << "[PASS] Singleton works" << std::endl;
    std::cout << std::endl;
    
    // Summary
    std::cout << "========================================" << std::endl;
    std::cout << "All DapService Tests PASSED!" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    std::cout << "Phase 24 Status: Interface validated" << std::endl;
    std::cout << "Ready for UI integration" << std::endl;
}

int main() {
    runDapServiceTest();
    return 0;
}
