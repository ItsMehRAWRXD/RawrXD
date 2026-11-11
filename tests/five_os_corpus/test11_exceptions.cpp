// Test 11: Exception handling (C++)
#include <iostream>
int main(void) {
    try {
        throw 42;
    } catch (int x) {
        std::cout << "caught=" << x << "\n";  // expect 42
    }
    return 0;
}
