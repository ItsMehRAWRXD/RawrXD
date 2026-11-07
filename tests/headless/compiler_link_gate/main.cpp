#include <iostream>
int rawrxd_gate_add(int, int);
int main() {
    if (rawrxd_gate_add(2, 3) != 5) return 1;
    std::cout << "PASS compiler-link-run\n";
    return 0;
}
