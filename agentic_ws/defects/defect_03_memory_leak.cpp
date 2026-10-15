// DEFECT 03: Memory leak - missing delete
// Expected: Add proper cleanup
#include <iostream>

struct Resource {
    int* data;
    Resource() : data(new int[100]) {}
    ~Resource() { delete[] data; }
};

void process() {
    // BUG: Resource allocated but never deleted
    Resource* r = new Resource();
    // Missing: delete r;
}

int main() {
    // Run multiple times to detect leak
    for (int i = 0; i < 10; ++i) {
        process();
    }
    std::cout << "PASS" << std::endl;
    return 0;
}