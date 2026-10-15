// DEFECT 18: Const correctness violation
// Expected: Fix const correctness
#include <iostream>

struct Container {
    std::vector<int> data;
    
    // BUG: Should be const method
    int getSize() {
        return data.size();
    }
    
    void add(int v) { data.push_back(v); }
};

int process(const Container& c) {
    // BUG: Can't call non-const method on const ref
    return c.getSize();
}

int main() {
    Container c;
    c.add(1);
    c.add(2);
    c.add(3);
    
    int size = process(c);
    if (size == 3) {
        std::cout << "PASS" << std::endl;
        return 0;
    } else {
        std::cout << "FAIL: Expected 3, got " << size << std::endl;
        return 1;
    }
}