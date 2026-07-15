// scheduler_test.cpp
// Unit tests for Layer 0: Credit-Based Scheduler

#include "../scheduler.h"
#include <cassert>
#include <chrono>
#include <iostream>
#include <thread>

using namespace rawrxd::scheduler;

// ═══════════════════════════════════════════════════════════════════════════════
// Test Helpers
// ═══════════════════════════════════════════════════════════════════════════════

void TestCreditAllocation() {
    std::cout << "Test: CreditAllocation..." << std::endl;
    
    CreditBasedScheduler scheduler;
    scheduler.SetCreditLimit(NodeType::Inference, 1000);
    
    // Allocate credits
    auto alloc = scheduler.AllocateCredits(NodeType::Inference, Priority::Normal, 100);
    assert(alloc.has_value());
    assert(alloc->granted == 100);
    assert(!alloc->throttled);
    
    // Try to allocate more than available
    auto alloc2 = scheduler.AllocateCredits(NodeType::Inference, Priority::Normal, 2000);
    assert(!alloc2.has_value()); // Should fail
    
    // Critical priority should succeed even with no credits
    auto alloc3 = scheduler.AllocateCredits(NodeType::Inference, Priority::Critical, 500);
    assert(alloc3.has_value());
    
    std::cout << "  PASSED" << std::endl;
}

void TestQueueManagement() {
    std::cout << "Test: QueueManagement..." << std::endl;
    
    CreditBasedScheduler scheduler;
    scheduler.SetMaxQueueDepth(NodeType::Inference, 10);
    
    // Enqueue items
    assert(scheduler.Enqueue(1, NodeType::Inference, Priority::Normal));
    assert(scheduler.Enqueue(2, NodeType::Inference, Priority::High));
    assert(scheduler.Enqueue(3, NodeType::Inference, Priority::Critical));
    
    // Peek should return highest priority (Critical = 0)
    auto peek = scheduler.Peek();
    assert(peek.has_value());
    assert(peek.value() == 3); // Critical priority
    
    // Dequeue should return in priority order
    auto item1 = scheduler.Dequeue();
    assert(item1.has_value());
    assert(item1.value() == 3); // Critical first
    
    auto item2 = scheduler.Dequeue();
    assert(item2.has_value());
    assert(item2.value() == 2); // High second
    
    std::cout << "  PASSED" << std::endl;
}

void TestBackpressure() {
    std::cout << "Test: Backpressure..." << std::endl;
    
    CreditBasedScheduler scheduler;
    
    // Initially no pressure
    assert(!scheduler.IsUnderPressure());
    assert(scheduler.GetRecommendedThrottle() == 0.0f);
    
    // Fill queue to create pressure
    for (int i = 0; i < 10000; ++i) {
        scheduler.Enqueue(i, NodeType::Inference, Priority::Normal);
    }
    
    // Should be under pressure now
    assert(scheduler.IsUnderPressure());
    assert(scheduler.GetRecommendedThrottle() > 0.0f);
    
    std::cout << "  PASSED" << std::endl;
}

void TestStatistics() {
    std::cout << "Test: Statistics..." << std::endl;
    
    CreditBasedScheduler scheduler;
    scheduler.SetCreditLimit(NodeType::Inference, 1000);
    
    // Reset stats
    scheduler.ResetStatistics();
    
    // Do some allocations
    scheduler.AllocateCredits(NodeType::Inference, Priority::Normal, 100);
    scheduler.AllocateCredits(NodeType::Inference, Priority::Normal, 200);
    
    auto stats = scheduler.GetStatistics();
    assert(stats.total_allocations == 2);
    
    std::cout << "  PASSED" << std::endl;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════════════════════

int main() {
    std::cout << "=== RawrXD Scheduler Tests ===" << std::endl;
    std::cout << std::endl;
    
    try {
        TestCreditAllocation();
        TestQueueManagement();
        TestBackpressure();
        TestStatistics();
        
        std::cout << std::endl;
        std::cout << "All tests PASSED!" << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Test FAILED: " << e.what() << std::endl;
        return 1;
    }
}
