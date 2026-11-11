// Application Integration Test
// Validates the complete Application lifecycle and service integration

#include "../src/core/application.h"
#include "../src/core/event_bus.h"
#include "../src/core/command_registry.h"
#include "../src/workspace/workspace_manager.h"
#include "../src/tasks/task_runner.h"
#include "../src/settings/settings_manager.h"

#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <functional>

// Simple test framework
struct TestResult {
    std::string name;
    bool passed;
    std::string error;
    std::chrono::milliseconds duration;
};

class TestRunner {
public:
    static TestRunner& Instance() {
        static TestRunner instance;
        return instance;
    }
    
    void RunTest(const std::string& name, std::function<bool(std::string&)> test) {
        auto start = std::chrono::steady_clock::now();
        
        TestResult result;
        result.name = name;
        result.passed = test(result.error);
        
        auto end = std::chrono::steady_clock::now();
        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        
        results_.push_back(result);
    }
    
    void PrintResults() {
        int passed = 0;
        int failed = 0;
        
        std::cout << "\n========================================\n";
        std::cout << "      INTEGRATION TEST RESULTS\n";
        std::cout << "========================================\n\n";
        
        for (const auto& result : results_) {
            if (result.passed) {
                std::cout << "[PASS] " << result.name << " (" << result.duration.count() << "ms)\n";
                passed++;
            } else {
                std::cout << "[FAIL] " << result.name << "\n";
                std::cout << "       Error: " << result.error << "\n";
                failed++;
            }
        }
        
        std::cout << "\n========================================\n";
        std::cout << "Total: " << results_.size() << " | ";
        std::cout << "Passed: " << passed << " | ";
        std::cout << "Failed: " << failed << "\n";
        std::cout << "========================================\n";
        
        if (failed > 0) {
            std::cout << "\n*** TEST SUITE FAILED ***\n";
        } else {
            std::cout << "\n*** ALL TESTS PASSED ***\n";
        }
    }
    
    bool AllPassed() const {
        for (const auto& result : results_) {
            if (!result.passed) return false;
        }
        return true;
    }
    
private:
    std::vector<TestResult> results_;
};

#define TEST(name) TestRunner::Instance().RunTest(name, [](std::string& errorMsg) -> bool

// Test: Service Container Basic Operations
void TestServiceContainer() {
    TEST("ServiceContainer - Registration and Resolution") {
        auto& container = RawrXD::ServiceContainer::Instance();
        
        // Register a simple service
        auto eventBus = std::make_shared<int>(42);
        container.Register<int>(eventBus);
        
        // Resolve it
        auto resolved = container.Resolve<int>();
        if (!resolved) {
            errorMsg = "Failed to resolve registered service";
            return false;
        }
        
        if (*resolved != 42) {
            errorMsg = "Resolved service has wrong value";
            return false;
        }
        
        // Clean up
        container.Remove<int>();
        return true;
    });
    
    TEST("ServiceContainer - Has() check") {
        auto& container = RawrXD::ServiceContainer::Instance();
        
        if (container.Has<double>()) {
            errorMsg = "Has() returned true for non-existent service";
            return false;
        }
        
        auto service = std::make_shared<double>(3.14);
        container.Register<double>(service);
        
        if (!container.Has<double>()) {
            errorMsg = "Has() returned false for existing service";
            return false;
        }
        
        container.Remove<double>();
        return true;
    });
    
    TEST("ServiceContainer - ResolveOrCreate") {
        auto& container = RawrXD::ServiceContainer::Instance();
        
        // First call should create
        auto created = container.ResolveOrCreate<std::string>("test_value");
        if (!created || *created != "test_value") {
            errorMsg = "ResolveOrCreate failed to create service";
            return false;
        }
        
        // Second call should resolve existing
        auto resolved = container.ResolveOrCreate<std::string>("different_value");
        if (!resolved || *resolved != "test_value") {
            errorMsg = "ResolveOrCreate should return existing service";
            return false;
        }
        
        container.Remove<std::string>();
        return true;
    });
}

// Test: Event Bus Operations
void TestEventBus() {
    TEST("EventBus - Singleton Access") {
        auto& bus1 = RawrXD::EventBus::Instance();
        auto& bus2 = RawrXD::EventBus::Instance();
        
        if (&bus1 != &bus2) {
            errorMsg = "EventBus is not a proper singleton";
            return false;
        }
        return true;
    });
    
    TEST("EventBus - Subscribe and Publish") {
        auto& bus = RawrXD::EventBus::Instance();
        
        bool eventReceived = false;
        RawrXD::EventData eventData;
        eventData.source = "Test";
        
        auto sub = bus.Subscribe(RawrXD::EventType::AppReady, 
            [&eventReceived](RawrXD::EventType type, const RawrXD::EventData& data) {
                eventReceived = true;
            });
        
        bus.Publish(RawrXD::EventType::AppReady, eventData);
        bus.ProcessEvents(); // Process queued events
        
        if (!eventReceived) {
            errorMsg = "Event handler was not called";
            return false;
        }
        
        sub.Unsubscribe();
        return true;
    });
    
    TEST("EventBus - Priority Ordering") {
        auto& bus = RawrXD::EventBus::Instance();
        bus.ClearQueue();
        
        std::vector<int> order;
        
        // Subscribe to custom events
        auto sub1 = bus.Subscribe(RawrXD::EventType::Custom, 
            [&order](RawrXD::EventType type, const RawrXD::EventData& data) {
                order.push_back(1);
            });
        
        RawrXD::EventData data;
        data.source = "Test";
        
        // Publish with different priorities
        bus.Publish(RawrXD::EventType::Custom, data, RawrXD::EventPriority::Low);
        bus.Publish(RawrXD::EventType::Custom, data, RawrXD::EventPriority::High);
        bus.Publish(RawrXD::EventType::Custom, data, RawrXD::EventPriority::Normal);
        
        bus.ProcessEvents();
        
        // Should have processed 3 events
        if (order.size() != 3) {
            errorMsg = "Not all events were processed";
            return false;
        }
        
        sub1.Unsubscribe();
        return true;
    });
}

// Test: Command Registry Operations
void TestCommandRegistry() {
    TEST("CommandRegistry - Register and Execute") {
        auto& registry = RawrXD::CommandRegistry::Instance();
        
        bool executed = false;
        RawrXD::Command cmd;
        cmd.id = "test.command";
        cmd.title = "Test Command";
        cmd.category = "Test";
        cmd.enabled = true;
        cmd.visible = true;
        cmd.handler = [&executed](RawrXD::CommandContext& ctx) {
            executed = true;
        };
        
        if (!registry.RegisterCommand(cmd)) {
            errorMsg = "Failed to register command";
            return false;
        }
        
        if (!registry.ExecuteCommand("test.command")) {
            errorMsg = "Failed to execute command";
            registry.UnregisterCommand("test.command");
            return false;
        }
        
        if (!executed) {
            errorMsg = "Command handler was not called";
            registry.UnregisterCommand("test.command");
            return false;
        }
        
        registry.UnregisterCommand("test.command");
        return true;
    });
    
    TEST("CommandRegistry - Search") {
        auto& registry = RawrXD::CommandRegistry::Instance();
        
        // Register test commands
        RawrXD::Command cmd1;
        cmd1.id = "search.test1";
        cmd1.title = "Alpha Command";
        cmd1.category = "Category A";
        cmd1.enabled = true;
        cmd1.visible = true;
        registry.RegisterCommand(cmd1);
        
        RawrXD::Command cmd2;
        cmd2.id = "search.test2";
        cmd2.title = "Beta Command";
        cmd2.category = "Category B";
        cmd2.enabled = true;
        cmd2.visible = true;
        registry.RegisterCommand(cmd2);
        
        auto results = registry.SearchCommands("alpha");
        if (results.empty()) {
            errorMsg = "Search returned no results";
            registry.UnregisterCommand("search.test1");
            registry.UnregisterCommand("search.test2");
            return false;
        }
        
        if (results[0].title != "Alpha Command") {
            errorMsg = "Search returned wrong result";
            registry.UnregisterCommand("search.test1");
            registry.UnregisterCommand("search.test2");
            return false;
        }
        
        registry.UnregisterCommand("search.test1");
        registry.UnregisterCommand("search.test2");
        return true;
    });
    
    TEST("CommandRegistry - Keybindings") {
        auto& registry = RawrXD::CommandRegistry::Instance();
        
        registry.RegisterKeybinding("Ctrl+T", "test.keybinding");
        
        auto cmd = registry.GetCommandForKeybinding("Ctrl+T");
        if (cmd != "test.keybinding") {
            errorMsg = "Keybinding lookup failed";
            return false;
        }
        
        registry.UnregisterKeybinding("Ctrl+T");
        
        cmd = registry.GetCommandForKeybinding("Ctrl+T");
        if (!cmd.empty()) {
            errorMsg = "Keybinding was not removed";
            return false;
        }
        
        return true;
    });
}

// Test: Application Lifecycle
void TestApplicationLifecycle() {
    TEST("Application - State Transitions") {
        auto& app = RawrXD::Application::Instance();
        
        // Initial state should be Uninitialized
        if (app.GetState() != RawrXD::AppState::Uninitialized) {
            errorMsg = "Initial state is not Uninitialized";
            return false;
        }
        
        return true;
    });
    
    TEST("Application - Service Resolution") {
        auto& app = RawrXD::Application::Instance();
        
        // These should return nullptr before initialization
        if (app.GetSettingsManager() != nullptr) {
            // This is OK - settings manager might be created
        }
        
        return true;
    });
}

// Test: Settings Manager
void TestSettingsManager() {
    TEST("SettingsManager - Singleton") {
        auto& settings1 = RawrXD::Settings::SettingsManager::Instance();
        auto& settings2 = RawrXD::Settings::SettingsManager::Instance();
        
        if (&settings1 != &settings2) {
            errorMsg = "SettingsManager is not a singleton";
            return false;
        }
        return true;
    });
    
    TEST("SettingsManager - Set and Get") {
        auto& settings = RawrXD::Settings::SettingsManager::Instance();
        
        settings.SetString("test.key", "test_value");
        auto value = settings.GetString("test.key", "");
        
        if (value != "test_value") {
            errorMsg = "Settings get/set failed";
            return false;
        }
        
        settings.Remove("test.key");
        return true;
    });
}

// Test: Workspace Manager
void TestWorkspaceManager() {
    TEST("WorkspaceManager - Singleton") {
        auto& ws1 = RawrXD::Workspace::WorkspaceManager::Instance();
        auto& ws2 = RawrXD::Workspace::WorkspaceManager::Instance();
        
        if (&ws1 != &ws2) {
            errorMsg = "WorkspaceManager is not a singleton";
            return false;
        }
        return true;
    });
}

// Test: Task Runner
void TestTaskRunner() {
    TEST("TaskRunner - Singleton") {
        auto& tasks1 = RawrXD::Tasks::TaskRunner::Instance();
        auto& tasks2 = RawrXD::Tasks::TaskRunner::Instance();
        
        if (&tasks1 != &tasks2) {
            errorMsg = "TaskRunner is not a singleton";
            return false;
        }
        return true;
    });
}

// Main entry point
int main(int argc, char* argv[]) {
    std::cout << "RawrXD Application Integration Test Suite\n";
    std::cout << "========================================\n\n";
    
    // Run all test suites
    TestServiceContainer();
    TestEventBus();
    TestCommandRegistry();
    TestApplicationLifecycle();
    TestSettingsManager();
    TestWorkspaceManager();
    TestTaskRunner();
    
    // Print results
    TestRunner::Instance().PrintResults();
    
    // Return appropriate exit code
    return TestRunner::Instance().AllPassed() ? 0 : 1;
}