// DEFECT 06: Use-after-free
// Expected: Don't use pointer after delete
#include <iostream>

int main() {
    int* ptr = new int(42);
    delete ptr;
    
    // BUG: Use after free
    int value = *ptr;
    
    if (value == 42) {
        std::cout << "PASS" << std::endl;
        return 0;
    } else {
        std::cout << "FAIL: Expected 42, got " << value << std::endl;
        return 1;
    }
}