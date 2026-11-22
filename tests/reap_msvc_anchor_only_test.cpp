// Deliberately never calls ConvertMsvcAvx2: only the production
// /include anchor may keep its external reference alive under /OPT:REF.
#include <cstdio>
int main() {
    std::puts("PASS production AVX2 linker anchor resolved");
    return 0;
}
