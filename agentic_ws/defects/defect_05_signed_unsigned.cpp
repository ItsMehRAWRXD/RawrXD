// DEFECT 05: Type mismatch - signed/unsigned comparison
// Expected: Fix comparison to handle signed/unsigned correctly
#include <iostream>
#include <vector>

int findIndex(const std::vector<int>& vec, int target) {
    // BUG: signed/unsigned mismatch - size_t is unsigned, -1 becomes large positive
    for (size_t i = 0; i < vec.size(); ++i) {
        if (vec[i] == target) return i;
    }
    return -1;  // BUG: -1 converted to size_t wraps to huge number
}

int main() {
    std::vector<int> data = {1, 2, 3, 4, 5};
    int idx = findIndex(data, 999);  // Not found
    
    if (idx == -1) {
        std::cout << "PASS" << std::endl;
        return 0;
    } else {
        std::cout << "FAIL: Expected -1, got " << idx << std::endl;
        return 1;
    }
}