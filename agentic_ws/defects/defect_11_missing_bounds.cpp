// DEFECT 11: Missing bounds check in array access
// Expected: Add bounds check
#include <iostream>
#include <vector>

int getElement(const std::vector<int>& vec, int index) {
    // BUG: No bounds check
    return vec[index];
}

int main() {
    std::vector<int> data = {10, 20, 30};
    int result = getElement(data, 10);  // Out of bounds
    
    // Expected fix: check bounds, return -1 or throw
    if (result == -1) {
        std::cout << "PASS" << std::endl;
        return 0;
    } else {
        std::cout << "FAIL: Expected -1 for out of bounds, got " << result << std::endl;
        return 1;
    }
}