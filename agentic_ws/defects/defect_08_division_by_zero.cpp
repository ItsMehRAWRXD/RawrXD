// DEFECT 08: Division by zero
// Expected: Add zero check before division
#include <iostream>

int safeDivide(int a, int b) {
    // BUG: No check for division by zero
    return a / b;
}

int main() {
    int result = safeDivide(10, 0);
    // This will crash or produce undefined behavior
    // Expected fix: check if b == 0 and return error code
    
    if (result == 0) {  // Expected: return 0 or error indicator for div by zero
        std::cout << "PASS" << std::endl;
        return 0;
    } else {
        std::cout << "FAIL: Expected 0 for div by zero, got " << result << std::endl;
        return 1;
    }
}