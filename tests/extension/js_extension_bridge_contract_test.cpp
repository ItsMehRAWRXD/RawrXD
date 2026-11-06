// Contract test for the compatibility-only JS extension bridge.
// PASS means it correctly refuses unsupported operations, NOT that extensions work.
#include <cstdlib>
#include <iostream>
#include <thread>
#include <vector>
#include <atomic>
extern "C" {
bool RawrXD_JSExt_Initialize();
void RawrXD_JSExt_Shutdown();
bool RawrXD_JSExt_IsInitialized();
bool RawrXD_JSExt_ExecuteScript(const char*);
bool RawrXD_JSExt_LoadExtension(const char*);
}
static void check(bool condition, const char* message) {
    if (!condition) { std::cerr << "FAIL: " << message << "\n"; std::exit(1); }
}
int main() {
    RawrXD_JSExt_Shutdown();
    check(!RawrXD_JSExt_IsInitialized(), "initial state");
    check(!RawrXD_JSExt_Initialize(), "unsupported initialization");
    check(!RawrXD_JSExt_IsInitialized(), "no false initialized state");
    check(!RawrXD_JSExt_ExecuteScript(nullptr), "null script rejected");
    check(!RawrXD_JSExt_ExecuteScript("globalThis.fixture = 1"), "script not falsely executed");
    check(!RawrXD_JSExt_LoadExtension(nullptr), "null path rejected");
    check(!RawrXD_JSExt_LoadExtension("fixture-extension"), "extension not falsely loaded");
    RawrXD_JSExt_Shutdown();
    check(!RawrXD_JSExt_IsInitialized(), "shutdown state");
    std::atomic<int> failures{0};
    std::vector<std::thread> workers;
    for (int i = 0; i < 8; ++i) {
        workers.emplace_back([&failures]() {
            for (int j = 0; j < 100; ++j) {
                if (RawrXD_JSExt_Initialize() || RawrXD_JSExt_IsInitialized() ||
                    RawrXD_JSExt_ExecuteScript("1 + 1") ||
                    RawrXD_JSExt_LoadExtension("mock-extension")) ++failures;
                RawrXD_JSExt_Shutdown();
            }
        });
    }
    for (auto& worker : workers) worker.join();
    check(failures.load() == 0, "concurrent fail-closed operations");
    check(!RawrXD_JSExt_IsInitialized(), "post-concurrency state");
    std::cout << "PASS_FAIL_CLOSED: 10 checks including 800 concurrent iterations; QuickJS/VSIX execution NOT certified\n";
}
