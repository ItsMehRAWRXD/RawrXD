#include <iostream>
#include <string>

int compute(int x, int y) {
    // BUG: should be x * y but uses x + y (logic error, not compile error)
        return x + y;
}

int main() {
    int result = compute(5, 3);
    std::cout << "Result: " << result << std::endl;
    return 0;
}
