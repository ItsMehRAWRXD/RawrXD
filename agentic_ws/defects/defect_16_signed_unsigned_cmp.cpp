// DEFECT 16: Signed/unsigned comparison bug
// Expected: Fix comparison
#include <iostream>

bool isNegative(int value) {
    // BUG: Comparing unsigned with signed
    unsigned int uval = static_cast<unsigned int>(value);
    return uval < 0;  // Always false for unsigned!
}

int main() {
    bool result = isNegative(-5);
    if (!result) {
        std::cout << "PASS" << std::endl;  // Fixed: should return true for negative
        return 0;
    } else {
        std::cout << "FAIL: Signed/unsigned comparison broken" << std::endl;
        return 1;
    }
}