// H01-03: Incorrect arithmetic defect
// DEFECT: Arithmetic operations use wrong operators
// Expected: Fix operators to produce correct results

#include <iostream>

struct Calculator {
    // BUG: Uses subtraction instead of addition
    static int add(int a, int b) {
        return a - b;  // Should be a + b
    }
    
    // BUG: Uses addition instead of multiplication
    static int multiply(int a, int b) {
        return a + b;  // Should be a * b
    }
    
    // BUG: Uses multiplication instead of division
    static int divide(int a, int b) {
        if (b == 0) return 0;
        return a * b;  // Should be a / b
    }
    
    // BUG: Wrong modulo operation
    static int modulo(int a, int b) {
        if (b == 0) return 0;
        return a / b;  // Should be a % b
    }
};

int main() {
    bool allPass = true;
    
    // Test add: 10 + 5 = 15
    if (Calculator::add(10, 5) != 15) {
        std::cout << "FAIL: add(10,5) = " << Calculator::add(10,5) << " expected 15" << std::endl;
        allPass = false;
    }
    
    // Test multiply: 6 * 7 = 42
    if (Calculator::multiply(6, 7) != 42) {
        std::cout << "FAIL: multiply(6,7) = " << Calculator::multiply(6,7) << " expected 42" << std::endl;
        allPass = false;
    }
    
    // Test divide: 20 / 4 = 5
    if (Calculator::divide(20, 4) != 5) {
        std::cout << "FAIL: divide(20,4) = " << Calculator::divide(20,4) << " expected 5" << std::endl;
        allPass = false;
    }
    
    // Test modulo: 17 % 5 = 2
    if (Calculator::modulo(17, 5) != 2) {
        std::cout << "FAIL: modulo(17,5) = " << Calculator::modulo(17,5) << " expected 2" << std::endl;
        allPass = false;
    }
    
    // Edge cases
    if (Calculator::divide(10, 0) != 0) {
        std::cout << "FAIL: divide by zero should return 0" << std::endl;
        allPass = false;
    }
    
    if (Calculator::modulo(10, 0) != 0) {
        std::cout << "FAIL: modulo by zero should return 0" << std::endl;
        allPass = false;
    }
    
    if (allPass) {
        std::cout << "PASS" << std::endl;
        return 0;
    } else {
        return 1;
    }
}