// DEFECT 14: Wrong loop condition - infinite loop
// Expected: Fix loop condition
#include <iostream>
#include <vector>

int sumVector(const std::vector<int>& vec) {
    int sum = 0;
    // BUG: i < vec.size() should be i < vec.size(), but i is signed
    // and vec.size() is unsigned, so when vec is empty, it loops forever
    // Actually let's make a clearer bug
    for (size_t i = 0; i <= vec.size(); ++i) {  // Off-by-one again but different
        if (i < vec.size()) sum += vec[i];
    }
    return sum;
}

int main() {
    std::vector<int> data = {1, 2, 3, 4, 5};
    int result = sumVector(data);
    
    if (result == 15) {
        std::cout << "PASS" << std::endl;
        return 0;
    } else {
        std::cout << "FAIL: Expected 15, got " << result << std::endl;
        return 1;
    }
}