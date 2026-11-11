// test_sample.cpp
// Test Case TC15_001: Streaming Ghost Text Validation
// 
// This file is used to validate the RawrXD IDE + Sovereign Engine integration.
// The test triggers a completion by typing a comment and pausing.
//
// Expected: Ghost text suggestion for Fibonacci function appears
// Target Latency: <200ms first token, <100ms subsequent tokens

#include <vector>
#include <iostream>

class MathUtils {
public:
    // Calculate fibon    <-- TEST TRIGGER: Type this and pause
    
    // Expected ghost text suggestion:
    // acci sequence up to n terms
    // std::vector<int> fibonacci(int n) {
    //     std::vector<int> result;
    //     if (n <= 0) return result;
    //     result.push_back(0);
    //     if (n == 1) return result;
    //     result.push_back(1);
    //     for (int i = 2; i < n; ++i) {
    //         result.push_back(result[i-1] + result[i-2]);
    //     }
    //     return result;
    // }
    
    // Other utility functions
    int add(int a, int b) { return a + b; }
    int multiply(int a, int b) { return a * b; }
};

// Additional context for the model
class DataProcessor {
public:
    void process(std::vector<int>& data) {
        // Process data in place
        for (auto& val : data) {
            val *= 2;
        }
    }
};

int main() {
    MathUtils math;
    DataProcessor processor;
    
    // Test the math utilities
    std::cout << "2 + 3 = " << math.add(2, 3) << std::endl;
    
    return 0;
}
