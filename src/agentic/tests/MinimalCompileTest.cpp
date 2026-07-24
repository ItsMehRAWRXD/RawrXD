// Minimal compile test for agentic headers
#include <iostream>
#include <mutex>
#include <shared_mutex>

// Test that basic C++17 features work
int main() {
    std::shared_mutex m;
    {
        std::unique_lock<std::shared_mutex> lock(m);
        std::cout << "Mutex test OK\n";
    }
    {
        std::shared_lock<std::shared_mutex> lock(m);
        std::cout << "Shared lock OK\n";
    }
    return 0;
}
