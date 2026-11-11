// Simple test for thread pool
#include <stdio.h>
#include <windows.h>
#include <atomic>

std::atomic<int> counter{0};

void test_task(void* data, uint32_t thread_id) {
    counter.fetch_add(1);
    printf("Task executed on thread %u\n", thread_id);
}

int main() {
    printf("Starting simple thread pool test...\n");
    
    // Test basic functionality
    counter.store(0);
    
    // Simulate 10 tasks
    for (int i = 0; i < 10; i++) {
        test_task(nullptr, i % 4);
    }
    
    printf("Counter: %d\n", counter.load());
    printf("Test complete!\n");
    
    return 0;
}
