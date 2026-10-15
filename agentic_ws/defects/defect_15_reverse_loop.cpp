// DEFECT 15: Off-by-one in reverse loop
// Expected: Fix reverse loop condition
#include <iostream>
#include <vector>

int reverseSum(const std::vector<int>& vec) {
    int sum = 0;
    // BUG: Starting at vec.size() instead of vec.size() - 1
    for (size_t i = vec.size(); i >= 0; --i) {
        sum += vec[i];
    }
    return sum;
}

int main() {
    std::vector<int> data = {10, 20, 30, 40, 50};
    int result = reverseSum(data);
    
    if (result == 150) {
        std::cout << "PASS" << std::endl;
        return 0;
    } else {
        std::cout << "FAIL: Expected 150, got " << result << std::endl;
        return 1;
    }
}