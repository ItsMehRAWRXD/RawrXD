// DEFECT 17: Missing virtual destructor
// Expected: Add virtual destructor to base class
#include <iostream>

struct Base {
    virtual void foo() { std::cout << "Base\n"; }
    // BUG: Missing virtual destructor
    ~Base() { std::cout << "Base destroyed\n"; }
};

struct Derived : Base {
    int* data;
    Derived() : data(new int[10]) {}
    ~Derived() { delete[] data; std::cout << "Derived destroyed\n"; }
};

int main() {
    Base* ptr = new Derived();
    delete ptr;  // Without virtual dtor, Derived::~Derived() not called
    
    // Expected: Both destructors called
    std::cout << "PASS" << std::endl;
    return 0;
}