/**
 * @file rc01_test.cpp
 * @brief RawrXD Production Certification Gate RC-01 Test Harness
 *
 * Tests NativeProcess, NativeTimer, NativeJson, NativeSettings, NativeWidget
 * with explicit PASS/FAIL results and reproducible logs.
 *
 * Build: cl /EHsc /O2 rc01_test.cpp /Fe:rc01_test.exe /link ...
 * Run:   rc01_test.exe
 */

#include <windows.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <chrono>
#include <thread>
#include <atomic>
#include <cassert>

// Include the native implementations
#include "core/qt_elimination.h"

using json = nlohmann::json;

// ============================================================================
// Test result tracking
// ============================================================================
struct TestResult {
    std::string name;
    bool passed;
    std::string detail;
    std::string sourceLocation;  // file:line
};

static std::vector<TestResult> g_results;
static int g_passCount = 0;
static int g_failCount = 0;

#define TEST(name, expr, detail, loc) \
    do { \
        bool result = (expr); \
        TestResult r; \
        r.name = (name); \
        r.passed = result; \
        r.detail = (detail); \
        r.sourceLocation = (loc); \
        g_results.push_back(r); \
        if (result) { ++g_passCount; std::cout << "  PASS: " << (name) << " - " << (detail) << std::endl; } \
        else { ++g_failCount; std::cout << "  FAIL: " << (name) << " - " << (detail) << " [" << (loc) << "]" << std::endl; } \
    } while(0)

// ============================================================================
// RC-01.1: NativeProcess tests
// ============================================================================
static void testNativeProcess() {
    std::cout << "\n=== RC-01.1: NativeProcess ===" << std::endl;

    // Test 1: Execute 'ver' command - should succeed with output
    {
        NativeProcessResult result = NativeProcess::execute("ver", {}, "", 10000);
        TEST("NativeProcess.ver_exit_code",
             result.success && result.exitCode == 0,
             "exitCode=" + std::to_string(result.exitCode) + " success=" + std::to_string(result.success),
             "rc01_test.cpp:54");
        TEST("NativeProcess.ver_has_output",
             !result.stdoutOutput.empty(),
             "stdout length=" + std::to_string(result.stdoutOutput.length()),
             "rc01_test.cpp:57");
        TEST("NativeProcess.ver_contains_windows",
             result.stdoutOutput.find("Windows") != std::string::npos ||
             result.stdoutOutput.find("windows") != std::string::npos,
             "stdout contains 'Windows': " + result.stdoutOutput.substr(0, 80),
             "rc01_test.cpp:60");
    }

    // Test 2: Execute 'echo' command with arguments
    {
        NativeProcessResult result = NativeProcess::execute("echo", {"hello_world_test"}, "", 10000);
        TEST("NativeProcess.echo_exit_code",
             result.success && result.exitCode == 0,
             "exitCode=" + std::to_string(result.exitCode),
             "rc01_test.cpp:67");
        TEST("NativeProcess.echo_output",
             result.stdoutOutput.find("hello_world_test") != std::string::npos,
             "stdout: " + result.stdoutOutput.substr(0, 80),
             "rc01_test.cpp:70");
    }

    // Test 3: Execute non-existent command - should fail gracefully
    {
        NativeProcessResult result = NativeProcess::execute("nonexistent_command_xyz123", {}, "", 5000);
        TEST("NativeProcess.nonexistent_fails",
             !result.success,
             "success=" + std::to_string(result.success) + " exitCode=" + std::to_string(result.exitCode),
             "rc01_test.cpp:77");
    }

    // Test 4: Process timeout - a command that runs too long
    {
        auto start = std::chrono::steady_clock::now();
        NativeProcessResult result = NativeProcess::execute("ping", {"-n", "30", "127.0.0.1"}, "", 3000);
        auto elapsed = std::chrono::steady_clock::now() - start;
        TEST("NativeProcess.timeout_respected",
             !result.success && elapsed < std::chrono::seconds(10),
             "success=" + std::to_string(result.success) + " elapsed_ms=" +
             std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count()),
             "rc01_test.cpp:88");
    }

    // Test 5: NativeProcess::exists
    {
        bool cmdExists = NativeProcess::exists("cmd");
        TEST("NativeProcess.exists_cmd",
             cmdExists,
             "exists=" + std::to_string(cmdExists),
             "rc01_test.cpp:96");
        bool fakeExists = NativeProcess::exists("nonexistent_xyz123.exe");
        TEST("NativeProcess.exists_fake",
             !fakeExists,
             "exists=" + std::to_string(fakeExists),
             "rc01_test.cpp:99");
    }
}

// ============================================================================
// RC-01.2: NativeTimer tests
// ============================================================================
static void testNativeTimer() {
    std::cout << "\n=== RC-01.2: NativeTimer ===" << std::endl;

    // Test 1: Single-shot timer fires callback
    {
        std::atomic<bool> fired{false};
        NativeTimer timer;
        timer.start(100, true, [&fired]() { fired.store(true); });

        // Wait up to 2 seconds for callback
        int waited = 0;
        while (!fired.load() && waited < 2000) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            waited += 50;
        }

        TEST("NativeTimer.single_shot_fires",
             fired.load(),
             "fired=" + std::to_string(fired.load()) + " waited_ms=" + std::to_string(waited),
             "rc01_test.cpp:115");
        TEST("NativeTimer.single_shot_timely",
             waited < 1500,
             "waited_ms=" + std::to_string(waited),
             "rc01_test.cpp:118");
    }

    // Test 2: Timer stop prevents further callbacks
    {
        std::atomic<int> count{0};
        NativeTimer timer;
        timer.start(50, false, [&count]() { count.fetch_add(1); });

        std::this_thread::sleep_for(std::chrono::milliseconds(150));
        int countBeforeStop = count.load();
        timer.stop();

        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        int countAfterStop = count.load();

        TEST("NativeTimer.stop_prevents_callbacks",
             countAfterStop == countBeforeStop,
             "count_before=" + std::to_string(countBeforeStop) + " count_after=" + std::to_string(countAfterStop),
             "rc01_test.cpp:135");
        TEST("NativeTimer.fired_at_least_once",
             countBeforeStop > 0,
             "count=" + std::to_string(countBeforeStop),
             "rc01_test.cpp:138");
    }

    // Test 3: Timer isRunning reflects state
    {
        NativeTimer timer;
        TEST("NativeTimer.not_running_initially",
             !timer.isRunning(),
             "isRunning=" + std::to_string(timer.isRunning()),
             "rc01_test.cpp:145");

        std::atomic<bool> fired{false};
        timer.start(5000, true, [&fired]() { fired.store(true); });
        TEST("NativeTimer.running_after_start",
             timer.isRunning(),
             "isRunning=" + std::to_string(timer.isRunning()),
             "rc01_test.cpp:149");
        timer.stop();
        TEST("NativeTimer.not_running_after_stop",
             !timer.isRunning(),
             "isRunning=" + std::to_string(timer.isRunning()),
             "rc01_test.cpp:152");
    }

    // Test 4: setInterval changes timing
    {
        std::atomic<int> count{0};
        NativeTimer timer;
        timer.start(100, false, [&count]() { count.fetch_add(1); });
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
        int count1 = count.load();
        timer.setInterval(300);
        std::this_thread::sleep_for(std::chrono::milliseconds(400));
        int count2 = count.load();
        timer.stop();

        TEST("NativeTimer.setinterval_affects_rate",
             count2 - count1 <= count1,  // rate should slow down
             "count_before_setInterval=" + std::to_string(count1) + " count_after=" + std::to_string(count2),
             "rc01_test.cpp:167");
    }
}

// ============================================================================
// RC-01.3: NativeJson tests
// ============================================================================
static void testNativeJson() {
    std::cout << "\n=== RC-01.3: NativeJson ===" << std::endl;

    // Test 1: Parse valid JSON object
    {
        json parsed = NativeJson::fromJson(R"({"name":"test","value":42,"active":true})");
        TEST("NativeJson.parse_valid_object",
             !parsed.is_null() && parsed.is_object(),
             "is_null=" + std::to_string(parsed.is_null()) + " is_object=" + std::to_string(parsed.is_object()),
             "rc01_test.cpp:180");
        TEST("NativeJson.get_string",
             parsed["name"] == "test",
             "name=" + parsed["name"].get<std::string>(),
             "rc01_test.cpp:183");
        TEST("NativeJson.get_int",
             parsed["value"] == 42,
             "value=" + std::to_string(parsed["value"].get<int>()),
             "rc01_test.cpp:186");
        TEST("NativeJson.get_bool",
             parsed["active"] == true,
             "active=" + std::to_string(parsed["active"].get<bool>()),
             "rc01_test.cpp:189");
    }

    // Test 2: Parse valid JSON array
    {
        json parsed = NativeJson::fromJson(R"([1,2,3,4,5])");
        TEST("NativeJson.parse_valid_array",
             !parsed.is_null() && parsed.is_array(),
             "is_null=" + std::to_string(parsed.is_null()) + " is_array=" + std::to_string(parsed.is_array()),
             "rc01_test.cpp:197");
        TEST("NativeJson.array_size",
             parsed.size() == 5,
             "size=" + std::to_string(parsed.size()),
             "rc01_test.cpp:200");
    }

    // Test 3: Parse invalid JSON - should return empty json (not crash)
    {
        json parsed = NativeJson::fromJson("not json at all");
        TEST("NativeJson.invalid_returns_empty",
             parsed.is_null() || parsed.is_discarded(),
             "type=" + parsed.type_name(),
             "rc01_test.cpp:206");
    }

    // Test 4: Parse empty string
    {
        json parsed = NativeJson::fromJson("");
        TEST("NativeJson.empty_returns_empty",
             parsed.is_null() || parsed.is_discarded(),
             "type=" + parsed.type_name(),
             "rc01_test.cpp:213");
    }

    // Test 5: Serialize to string
    {
        json obj = {{"key", "value"}, {"num", 100}};
        std::string serialized = NativeJson::toJson(obj);
        TEST("NativeJson.serialize",
             !serialized.empty(),
             "serialized=" + serialized.substr(0, 80),
             "rc01_test.cpp:220");
        TEST("NativeJson.serialize_roundtrip",
             NativeJson::fromJson(serialized)["key"] == "value",
             "roundtrip key=" + NativeJson::fromJson(serialized)["key"].get<std::string>(),
             "rc01_test.cpp:223");
    }

    // Test 6: NativeJson::get with default
    {
        json obj = {{"existing", "found"}};
        std::string val = NativeJson::get<std::string>(obj, "existing", "default");
        TEST("NativeJson.get_existing",
             val == "found",
             "val=" + val,
             "rc01_test.cpp:230");
        std::string missing = NativeJson::get<std::string>(obj, "missing", "default");
        TEST("NativeJson.get_missing_default",
             missing == "default",
             "val=" + missing,
             "rc01_test.cpp:233");
    }

    // Test 7: NativeJson::isObject / isArray
    {
        json obj = {{"a", 1}};
        json arr = {1, 2, 3};
        TEST("NativeJson.isObject",
             NativeJson::isObject(obj),
             "is_object=" + std::to_string(NativeJson::isObject(obj)),
             "rc01_test.cpp:240");
        TEST("NativeJson.isArray",
             NativeJson::isArray(arr),
             "is_array=" + std::to_string(NativeJson::isArray(arr)),
             "rc01_test.cpp:243");
        TEST("NativeJson.isObject_on_array_false",
             !NativeJson::isObject(arr),
             "is_object=" + std::to_string(NativeJson::isObject(arr)),
             "rc01_test.cpp:246");
    }
}

// ============================================================================
// RC-01.4: NativeSettings tests
// ============================================================================
static void testNativeSettings() {
    std::cout << "\n=== RC-01.4: NativeSettings ===" << std::endl;

    // Use a temp file for testing
    std::string tempPath = "F:\\rawrxd\\rc01_test_settings.json";

    // Test 1: Write and read back
    {
        NativeSettings settings(tempPath);
        settings.setValue("test_string", "hello_settings");
        settings.setInt("test_int", 12345);
        settings.setBool("test_bool", true);
        settings.sync();  // Force save to disk

        TEST("NativeSettings.write_and_read_string",
             settings.value("test_string") == "hello_settings",
             "value=" + settings.value("test_string"),
             "rc01_test.cpp:259");
        TEST("NativeSettings.write_and_read_int",
             settings.intValue("test_int") == 12345,
             "value=" + std::to_string(settings.intValue("test_int")),
             "rc01_test.cpp:262");
        TEST("NativeSettings.write_and_read_bool",
             settings.boolValue("test_bool") == true,
             "value=" + std::to_string(settings.boolValue("test_bool")),
             "rc01_test.cpp:265");
    }

    // Test 2: Persistence across instances
    {
        NativeSettings settings2(tempPath);
        TEST("NativeSettings.persistence_string",
             settings2.value("test_string") == "hello_settings",
             "value=" + settings2.value("test_string"),
             "rc01_test.cpp:272");
        TEST("NativeSettings.persistence_int",
             settings2.intValue("test_int") == 12345,
             "value=" + std::to_string(settings2.intValue("test_int")),
             "rc01_test.cpp:275");
        TEST("NativeSettings.persistence_bool",
             settings2.boolValue("test_bool") == true,
             "value=" + std::to_string(settings2.boolValue("test_bool")),
             "rc01_test.cpp:278");
    }

    // Test 3: Default values for missing keys
    {
        NativeSettings settings3(tempPath);
        std::string missing = settings3.value("nonexistent_key", "default_val");
        TEST("NativeSettings.missing_default_string",
             missing == "default_val",
             "value=" + missing,
             "rc01_test.cpp:285");
        int missingInt = settings3.intValue("nonexistent_int", 999);
        TEST("NativeSettings.missing_default_int",
             missingInt == 999,
             "value=" + std::to_string(missingInt),
             "rc01_test.cpp:288");
        bool missingBool = settings3.boolValue("nonexistent_bool", false);
        TEST("NativeSettings.missing_default_bool",
             missingBool == false,
             "value=" + std::to_string(missingBool),
             "rc01_test.cpp:291");
    }

    // Test 4: contains() method
    {
        NativeSettings settings4(tempPath);
        TEST("NativeSettings.contains_existing",
             settings4.contains("test_string"),
             "contains=" + std::to_string(settings4.contains("test_string")),
             "rc01_test.cpp:298");
        TEST("NativeSettings.contains_missing",
             !settings4.contains("nonexistent"),
             "contains=" + std::to_string(settings4.contains("nonexistent")),
             "rc01_test.cpp:301");
    }

    // Test 5: remove() method
    {
        NativeSettings settings5(tempPath);
        settings5.setValue("temp_key", "temp_value");
        TEST("NativeSettings.contains_before_remove",
             settings5.contains("temp_key"),
             "contains=" + std::to_string(settings5.contains("temp_key")),
             "rc01_test.cpp:308");
        settings5.remove("temp_key");
        TEST("NativeSettings.contains_after_remove",
             !settings5.contains("temp_key"),
             "contains=" + std::to_string(settings5.contains("temp_key")),
             "rc01_test.cpp:311");
    }

    // Cleanup temp file
    DeleteFileA(tempPath.c_str());
}

// ============================================================================
// RC-01.5: NativeWidget tests
// ============================================================================
static void testNativeWidget() {
    std::cout << "\n=== RC-01.5: NativeWidget ===" << std::endl;

    // Test 1: Create a real Win32 window
    {
        NativeWidget widget;
        bool created = widget.create(nullptr, 10, 10, 100, 50, "BUTTON", "Test Button",
                                     WS_CHILD | WS_VISIBLE);
        TEST("NativeWidget.create_window",
             created && widget.handle() != nullptr,
             "created=" + std::to_string(created) + " handle=" + std::to_string((uintptr_t)widget.handle()),
             "rc01_test.cpp:320");
    }

    // Test 2: Show/hide window
    {
        NativeWidget widget;
        widget.create(nullptr, 10, 10, 100, 50, "BUTTON", "ShowHide",
                      WS_CHILD | WS_VISIBLE);
        HWND hwnd = widget.handle();

        widget.hide();
        TEST("NativeWidget.hide",
             !IsWindowVisible(hwnd),
             "IsWindowVisible=" + std::to_string(IsWindowVisible(hwnd)),
             "rc01_test.cpp:328");

        widget.show();
        TEST("NativeWidget.show",
             IsWindowVisible(hwnd),
             "IsWindowVisible=" + std::to_string(IsWindowVisible(hwnd)),
             "rc01_test.cpp:331");
    }

    // Test 3: Enable/disable window
    {
        NativeWidget widget;
        widget.create(nullptr, 10, 10, 100, 50, "BUTTON", "EnableDisable",
                      WS_CHILD | WS_VISIBLE);
        HWND hwnd = widget.handle();

        widget.enable(false);
        TEST("NativeWidget.disable",
             !IsWindowEnabled(hwnd),
             "IsWindowEnabled=" + std::to_string(IsWindowEnabled(hwnd)),
             "rc01_test.cpp:338");

        widget.enable(true);
        TEST("NativeWidget.enable",
             IsWindowEnabled(hwnd),
             "IsWindowEnabled=" + std::to_string(IsWindowEnabled(hwnd)),
             "rc01_test.cpp:341");
    }

    // Test 4: Set/get window text
    {
        NativeWidget widget;
        widget.create(nullptr, 10, 10, 100, 50, "BUTTON", "Original Text",
                      WS_CHILD | WS_VISIBLE);

        widget.setText("New Button Text");
        TEST("NativeWidget.set_get_text",
             widget.getText() == "New Button Text",
             "text=" + widget.getText(),
             "rc01_test.cpp:348");
    }

    // Test 5: Widget handle is valid HWND
    {
        NativeWidget widget;
        widget.create(nullptr, 10, 10, 100, 50, "BUTTON", "HandleTest",
                      WS_CHILD | WS_VISIBLE);
        TEST("NativeWidget.handle_is_hwnd",
             IsWindow(widget.handle()),
             "IsWindow=" + std::to_string(IsWindow(widget.handle())),
             "rc01_test.cpp:355");
    }
}

// ============================================================================
// Main
// ============================================================================
int main() {
    std::cout << "============================================" << std::endl;
    std::cout << "RawrXD RC-01 Production Certification Test" << std::endl;
    std::cout << "============================================" << std::endl;
    std::cout << "Testing: NativeProcess, NativeTimer, NativeJson," << std::endl;
    std::cout << "         NativeSettings, NativeWidget" << std::endl;
    std::cout << "Build: " << __DATE__ << " " << __TIME__ << std::endl;
    std::cout << "============================================" << std::endl;

    testNativeProcess();
    testNativeTimer();
    testNativeJson();
    testNativeSettings();
    testNativeWidget();

    // Summary
    std::cout << "\n============================================" << std::endl;
    std::cout << "RC-01 SUMMARY" << std::endl;
    std::cout << "============================================" << std::endl;
    std::cout << "Total tests: " << (g_passCount + g_failCount) << std::endl;
    std::cout << "Passed:      " << g_passCount << std::endl;
    std::cout << "Failed:      " << g_failCount << std::endl;

    if (g_failCount > 0) {
        std::cout << "\nFAILURES:" << std::endl;
        for (const auto& r : g_results) {
            if (!r.passed) {
                std::cout << "  " << r.name << " - " << r.detail
                          << " [" << r.sourceLocation << "]" << std::endl;
            }
        }
    }

    std::cout << "\nRC-01 Result: " << (g_failCount == 0 ? "PASS" : "FAIL") << std::endl;
    std::cout << "============================================" << std::endl;

    return g_failCount == 0 ? 0 : 1;
}
