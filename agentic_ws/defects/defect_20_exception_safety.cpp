// DEFECT 20: Exception safety - resource leak on exception
// Expected: Use RAII for exception safety
#include <iostream>
#include <memory>

struct Resource {
    Resource() { std::cout << "Resource acquired\n"; }
    ~Resource() { std::cout << "Resource released\n"; }
    void use() { std::cout << "Resource used\n"; }
};

void riskyOperation(bool shouldThrow) {
    Resource* r = new Resource();
    r->use();
    if (shouldThrow) {
        throw std::runtime_error("Something failed");
    }
    delete r;  // BUG: Not reached if exception thrown
}

int main() {
    try {
        riskyOperation(true);
    } catch (...) {
        // Resource leaked!
    }
    
    // Expected: Use std::unique_ptr for RAII
    std::cout << "PASS" << std::endl;
    return 0;
}