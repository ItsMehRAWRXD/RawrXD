// DEFECT 12: Race condition simulation - unsynchronized access
// Expected: Add proper synchronization
#include <iostream>
#include <thread>
#include <vector>
#include <mutex>

int counter = 0;
// BUG: No mutex protection
// std::mutex mtx;

void increment(int times) {
    for (int i = 0; i < times; ++i) {
        // std::lock_guard<std::mutex> lock(mtx);
        ++counter;
    }
}

int main() {
    std::vector<std::thread> threads;
    for (int i = 0; i < 10; ++i) {
        threads.emplace_back(increment, 1000);
    }
    for (auto& t : threads) {
        t.join();
    }
    
    // Expected: 10000, but race condition causes less
    if (counter == 10000) {
        std::cout << "PASS" << std::endl;
        return 0;
    } else {
        std::cout << "FAIL: Race condition, got " << counter << std::endl;
        return 1;
    }
}