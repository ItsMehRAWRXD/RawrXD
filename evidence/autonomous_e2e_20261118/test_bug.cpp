#include <iostream>
#include <string>

int compute(int x, int y) {
    return x * y;  // FIXED: was x + y
}

int main() {
    int result = compute(5, 3);
    std::cout << "Result: " << result << std::endl;
    return 0;
}