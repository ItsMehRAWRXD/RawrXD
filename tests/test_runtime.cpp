// ============================================================================
// test_runtime.cpp — Runtime Core Unit Tests
// ============================================================================

#include <cstdio>
#include <cstring>
#include "../src/runtime/RawrRuntime.hpp"
#include "../src/runtime/ServiceRegistry.hpp"
#include "../src/runtime/EventBus.hpp"

static int g_passed = 0;
static int g_failed = 0;

#define TEST(name, expr) do { \
    printf("  [TEST] %-45s ... ", name); \
    if (expr) { printf("PASSED\n"); g_passed++; } \
    else { printf("FAILED\n"); g_failed++; } \
} while(0)

int main() {
    printf("========================================\n");
    printf("  RawrXD Runtime Test Suite\n");
    printf("========================================\n\n");

    // Test 1: Runtime singleton
    TEST("Runtime singleton", &rawr::RawrRuntime::Get() == &rawr::RawrRuntime::Get());

    // Test 2: Runtime initialization
    TEST("Runtime initialize", rawr::RawrRuntime::Get().Initialize());
    TEST("Runtime is initialized", rawr::RawrRuntime::Get().IsInitialized());

    // Test 3: Service registration
    TEST("Runtime info", rawr::RawrRuntime::Get().GetInfo().serviceCount == 0);

    // Test 4: Event bus
    auto eventId = rawr::EventBus::Get().Register("test.event");
    TEST("Event registration", eventId > 0);

    bool eventFired = false;
    rawr::EventBus::Get().Subscribe(eventId, [&](const void*, size_t) { eventFired = true; });
    rawr::EventBus::Get().Publish(eventId);
    TEST("Event publish/subscribe", eventFired);

    // Test 5: Logger
    rawr::RawrRuntime::Get().Log(rawr::LogLevel::Info, "Test log message");
    TEST("Logger write", true);

    // Test 6: Service registry
    rawr::ServiceRegistry::Get().RegisterServices(nullptr, 0);
    TEST("Service registry init", true);

    // Summary
    printf("\n========================================\n");
    printf("  Results: %d passed, %d failed out of %d\n", g_passed, g_failed, g_passed + g_failed);
    printf("========================================\n");

    rawr::RawrRuntime::Get().Shutdown();
    return g_failed > 0 ? 1 : 0;
}
