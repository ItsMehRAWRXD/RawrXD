// DEFECT 19: Move semantics bug - use after move
// Expected: Don't use moved-from object
#include <iostream>
#include <vector>
#include <utility>

std::vector<int> createVector() {
    return std::vector<int>{1, 2, 3, 4, 5};
}

int main() {
    std::vector<int> v1 = createVector();
    std::vector<int> v2 = std::move(v1);
    
    // BUG: Using v1 after move
    int size = v1.size();  // Unspecified but valid state
    
    // Expected: v2 has the data, v1 is in valid but unspecified state
    if (v2.size() == 5) {
        std::cout << "PASS" << std::endl;
        return 0;
    } else {
        std::cout << "FAIL: Move semantics broken" << std::endl;
        return 1;
    }
}