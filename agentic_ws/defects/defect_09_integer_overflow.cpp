// DEFECT 09: Integer overflow
// Expected: Check for overflow before addition
#include <iostream>
#include <climits>

int addWithCheck(int a, int b) {
    // BUG: No overflow check
    return a + b;
}

int main() {
    int result = addWithCheck(INT_MAX, 1);
    // Expected fix: detect overflow
    
    if (result == INT_MAX) {  // Expected: saturated or error
        std::cout << "PASS" << std::endl;
        return 0;
    } else {
        std::cout << "FAIL: Overflow not handled, got " << result << std::endl;
        return 1;
    }
}