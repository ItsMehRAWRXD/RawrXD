#include "calc.h"

int main() {
    // Expected: add(2,3) + mul(3,3) == 5 + 9 == 14
    const int value = add(2, 3) + mul(3, 3) + sub(0, 0);
    std::cout << "calc_ok " << value << std::endl;
    return (value == 14) ? 0 : 2;
}
