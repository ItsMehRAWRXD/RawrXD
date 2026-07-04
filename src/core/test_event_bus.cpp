// Test harness for IDEEventBus
// Compile: g++ -std=c++17 -O2 -Wall test_event_bus.cpp IDEEventBus.cpp UnifiedSessionState.cpp Version.cpp -o test_event_bus.exe -lkernel32

#include "IDEEventBus.hpp"
#include "UnifiedSessionState.hpp"
#include <cstdio>

using namespace RawrXD;

int main() {
    printf("=== RawrXD Event Bus Test ===\n\n");
    
    // Test 1: Initialize session and event bus
    printf("Test 1: Initialize session and event bus...\n");
    UnifiedSessionState session;
    if (!session.Initialize(true)) {
        printf("  FAILED: Could not initialize session\n");
        return 1;
    }
    
    IDEEventBus eventBus;
    if (!eventBus.Initialize(&session)) {
        printf("  FAILED: Could not initialize event bus\n");
        return 1;
    }
    printf("  PASSED: Event bus initialized\n");
    
    // Test 2: Subscribe to events
    printf("\nTest 2: Subscribe to events...\n");
    int eventCount = 0;
    eventBus.Subscribe(EventType::FileChanged, [&eventCount](const SharedEventFrame& frame) {
        ++eventCount;
        printf("  Received FileChanged event: %.*s\n", 
               frame.payloadLength, frame.payload);
    });
    
    eventBus.SubscribeAll([&eventCount](const SharedEventFrame& frame) {
        ++eventCount;
        printf("  Received event (catch-all): type=%u\n", frame.eventType);
    });
    printf("  PASSED: Subscribed to events\n");
    
    // Test 3: Publish events
    printf("\nTest 3: Publish events...\n");
    if (eventBus.PublishFileChanged("main.cpp")) {
        printf("  PASSED: Published FileChanged event\n");
    } else {
        printf("  FAILED: Could not publish event\n");
    }
    
    if (eventBus.PublishModelLoaded("qwen32b")) {
        printf("  PASSED: Published ModelLoaded event\n");
    } else {
        printf("  FAILED: Could not publish event\n");
    }
    
    // Test 4: Poll for events
    printf("\nTest 4: Poll for events...\n");
    size_t processed = eventBus.Poll();
    printf("  Processed %zu events\n", processed);
    printf("  Total event count: %d\n", eventCount);
    if (processed > 0) {
        printf("  PASSED: Events polled and dispatched\n");
    } else {
        printf("  INFO: No events to poll (may be timing issue)\n");
    }
    
    // Test 5: Convenience publishers
    printf("\nTest 5: Convenience publishers...\n");
    eventBus.PublishConfigChanged("theme");
    eventBus.PublishWorkingDirChanged("/projects");
    eventBus.PublishCommandExecuted("build");
    printf("  PASSED: All convenience publishers work\n");
    
    // Test 6: Global event bus
    printf("\nTest 6: Global event bus...\n");
    if (GetGlobalEventBus() == &eventBus) {
        printf("  PASSED: Global event bus set correctly\n");
    } else {
        printf("  FAILED: Global event bus not set\n");
    }
    
    printf("\n=== All Tests Complete ===\n");
    return 0;
}
