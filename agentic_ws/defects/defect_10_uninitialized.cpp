// DEFECT 10: Uninitialized variable
// Expected: Initialize variable before use
#include <iostream>

int getValue(bool condition) {
    int value;  // BUG: Uninitialized
    if (condition) {
        value = 42;
    }
    // If condition is false, value is uninitialized
    return value;
}

int main() {
    int result = getValue(false);
    // This is undefined behavior
    // Expected fix: initialize value = 0;
    
    if (result == 0) {  // Expected: initialized to 0
        std::cout << "PASS" << std::endl;
        return 0;
    } else {
        std::cout << "FAIL: Uninitialized variable, got " << result << std::endl;
        return 1;
    }
}