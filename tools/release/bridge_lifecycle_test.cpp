#include "Win32IDE_Deep2Bridge.h"
#include <chrono>
#include <condition_variable>
#include <iostream>
#include <string>

int main(int argc, char** argv) {
    if (argc < 2 || argc > 3) return 2;
    const bool sync = argc == 3 && std::string(argv[2]) == "--sync";
    std::cerr << "LIFECYCLE_PHASE=construct\n" << std::flush;
    Deep2Bridge bridge(nullptr);
    std::cerr << "LIFECYCLE_PHASE=initialize_begin\n" << std::flush;
    if (!bridge.Initialize(argv[1]) || !bridge.IsModelLoaded()) return 3;
    std::cerr << "LIFECYCLE_PHASE=initialize_complete\n" << std::flush;
    if (sync) {
        std::cerr << "LIFECYCLE_PHASE=sync_begin prompt=ping max_tokens=8\n" << std::flush;
        const std::string response = bridge.GenerateSync("ping", 8);
        std::cerr << "LIFECYCLE_PHASE=sync_complete chars=" << response.size() << "\n" << std::flush;
        if (response.empty()) return 6;
        std::cout << "BRIDGE_SYNC_TEST PASS chars=" << response.size() << "\n";
        bridge.Stop();
        return 0;
    }
    std::mutex mutex;
    std::condition_variable ready;
    for (int request = 0; request < 3; ++request) {
        std::cerr << "LIFECYCLE_PHASE=request_" << request << "_begin\n" << std::flush;
        bool completed = false;
        int tokens = 0;
        const bool started = bridge.GenerateStream("Hello", [&](const std::string& token, bool done) {
            std::lock_guard<std::mutex> lock(mutex);
            if (!token.empty()) ++tokens;
            if (done) { completed = true; ready.notify_one(); }
            return true;
        }, 1, 0.0f, 0.9f, 40);
        if (!started) return 4;
        std::unique_lock<std::mutex> lock(mutex);
        if (!ready.wait_for(lock, std::chrono::seconds(90), [&] { return completed; })) {
            lock.unlock(); bridge.Stop(); return 5;
        }
        if (!tokens) return 6;
        std::cerr << "LIFECYCLE_PHASE=request_" << request << "_complete tokens=" << tokens << "\n" << std::flush;
    }
    std::cerr << "LIFECYCLE_PHASE=stop_begin\n" << std::flush;
    bridge.Stop();
    std::cout << "BRIDGE_LIFECYCLE_TEST PASS requests=3\n";
    return 0;
}
