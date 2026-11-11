//============================================================================
// test_sovereign_task_instrumentation.cpp
// RawrXD N-EVM - Test for SOVEREIGN_TASK Macro with PageFaultMonitor
//============================================================================

#include "sovereign_task_instrumentation.hpp"
#include <iostream>
#include <string>
#include <vector>
#include <cmath>

using namespace RawrXD::NEVM::Sovereign;

//============================================================================
// Test Functions
//============================================================================

void SimulateModelLoading() {
    SOVEREIGN_TASK("ModelLoading");
    
    // Simulate memory allocation during model loading
    std::vector<float> model_weights(1024 * 1024);  // 4MB
    for (size_t i = 0; i < model_weights.size(); ++i) {
        model_weights[i] = static_cast<float>(i) * 0.001f;
    }
    
    // Simulate processing
    for (volatile int i = 0; i < 1000000; ++i) {}
}

void SimulateInference() {
    SOVEREIGN_TASK("Inference");
    
    // Simulate inference computation
    std::vector<float> activations(1024 * 1024);
    for (size_t i = 0; i < activations.size(); ++i) {
        activations[i] = std::sin(static_cast<float>(i) * 0.01f);
    }
    
    // Simulate processing
    for (volatile int i = 0; i < 500000; ++i) {}
}

void SimulateKVCacheAccess() {
    SOVEREIGN_TASK("KVCacheAccess");
    
    // Simulate KV cache operations
    std::vector<uint8_t> k_cache(1024 * 1024);
    std::vector<uint8_t> v_cache(1024 * 1024);
    
    // Write to cache
    for (size_t i = 0; i < k_cache.size(); ++i) {
        k_cache[i] = static_cast<uint8_t>(i % 256);
        v_cache[i] = static_cast<uint8_t>((i + 128) % 256);
    }
    
    // Simulate processing
    for (volatile int i = 0; i < 200000; ++i) {}
}

void SimulateCheckpointSave() {
    SOVEREIGN_TASK("CheckpointSave");
    
    // Simulate checkpoint serialization
    std::vector<uint8_t> checkpoint_data(10 * 1024 * 1024);  // 10MB
    for (size_t i = 0; i < checkpoint_data.size(); ++i) {
        checkpoint_data[i] = static_cast<uint8_t>(i % 256);
    }
    
    // Simulate processing
    for (volatile int i = 0; i < 300000; ++i) {}
}

void SimulateNestedTasks() {
    SOVEREIGN_TASK("OuterTask");
    
    std::cout << "  Starting nested task simulation...\n";
    
    // Inner task 1
    {
        SOVEREIGN_TASK("InnerTask1");
        std::vector<float> data(1024 * 512);
        for (size_t i = 0; i < data.size(); ++i) {
            data[i] = static_cast<float>(i);
        }
        for (volatile int i = 0; i < 100000; ++i) {}
    }
    
    // Inner task 2
    {
        SOVEREIGN_TASK("InnerTask2");
        std::vector<float> data(1024 * 512);
        for (size_t i = 0; i < data.size(); ++i) {
            data[i] = static_cast<float>(i) * 0.5f;
        }
        for (volatile int i = 0; i < 100000; ++i) {}
    }
    
    std::cout << "  Nested tasks complete.\n";
}

void SimulateConditionalTask(bool should_run) {
    SOVEREIGN_TASK_IF("ConditionalTask", should_run) {
        std::cout << "  Running conditional task...\n";
        std::vector<float> data(1024 * 256);
        for (size_t i = 0; i < data.size(); ++i) {
            data[i] = static_cast<float>(i);
        }
        for (volatile int i = 0; i < 50000; ++i) {}
    }
}

//============================================================================
// Test Suite
//============================================================================

int main(int argc, char* argv[]) {
    std::cout << "================================================================================\n";
    std::cout << "  SOVEREIGN_TASK Instrumentation Test\n";
    std::cout << "  PageFaultMonitor Integration Validation\n";
    std::cout << "================================================================================\n\n";
    
    // Set verbose mode
    SetVerbose(true);
    
    // Set custom log file
    SetSessionLogFile("test_sovereign_session.log");
    
    std::cout << "Running test scenarios...\n\n";
    
    // Test 1: Model Loading
    std::cout << "[TEST 1] Model Loading\n";
    SimulateModelLoading();
    std::cout << "\n";
    
    // Test 2: Inference
    std::cout << "[TEST 2] Inference\n";
    SimulateInference();
    std::cout << "\n";
    
    // Test 3: KV Cache Access
    std::cout << "[TEST 3] KV Cache Access\n";
    SimulateKVCacheAccess();
    std::cout << "\n";
    
    // Test 4: Checkpoint Save
    std::cout << "[TEST 4] Checkpoint Save\n";
    SimulateCheckpointSave();
    std::cout << "\n";
    
    // Test 5: Nested Tasks
    std::cout << "[TEST 5] Nested Tasks\n";
    SimulateNestedTasks();
    std::cout << "\n";
    
    // Test 6: Conditional Task (true)
    std::cout << "[TEST 6] Conditional Task (should run)\n";
    SimulateConditionalTask(true);
    std::cout << "\n";
    
    // Test 7: Conditional Task (false)
    std::cout << "[TEST 7] Conditional Task (should NOT run)\n";
    SimulateConditionalTask(false);
    std::cout << "  (Task skipped as expected)\n\n";
    
    // Test 8: Multiple sequential tasks
    std::cout << "[TEST 8] Sequential Tasks (Lifecycle Simulation)\n";
    {
        SOVEREIGN_TASK("LifecycleManager::OnTaskStart");
        std::cout << "  Task started...\n";
        for (volatile int i = 0; i < 100000; ++i) {}
    }
    
    SimulateModelLoading();
    SimulateInference();
    SimulateKVCacheAccess();
    
    {
        SOVEREIGN_TASK("LifecycleManager::OnTaskComplete");
        std::cout << "  Task completing...\n";
        for (volatile int i = 0; i < 100000; ++i) {}
    }
    
    std::cout << "\n";
    
    // Summary
    std::cout << "================================================================================\n";
    std::cout << "  Test Complete\n";
    std::cout << "================================================================================\n";
    std::cout << "\nSession log written to: test_sovereign_session.log\n";
    std::cout << "\nEach task automatically generated a memory performance report:\n";
    std::cout << "  - Duration (ms)\n";
    std::cout << "  - Page fault delta (Δ)\n";
    std::cout << "  - Working set changes\n";
    std::cout << "  - Delta Zero status (✓ = optimal)\n\n";
    
    return 0;
}
