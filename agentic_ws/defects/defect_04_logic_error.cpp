// DEFECT 04: Logic error - wrong operator
// Expected: Fix operator from - to +
#include <iostream>

int calculate(int a, int b, char op) {
    // BUG: Using subtraction instead of addition for '+'
    if (op == '+') return a - b;
    if (op == '-') return a - b;
    if (op == '*') return a * b;
    if (op == '/') return b != 0 ? a / b : 0;
    return 0;
}

int main() {
    int result = calculate(10, 5, '+');
    if (result == 15) {
        std::cout << "PASS" << std::endl;
        return 0;
    } else {
        std::cout << "FAIL: Expected 15, got " << result << std::endl;
        return 1;
    }
}