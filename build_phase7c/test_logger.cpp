#include <iostream>
#include <chrono>
#include <thread>

int main() {
    std::cout << "Test starting..." << std::endl;
    
    auto now = std::chrono::steady_clock::now();
    auto us = std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count();
    
    std::cout << "Timestamp: " << us << std::endl;
    std::cout << "Test completed!" << std::endl;
    return 0;
}
