#include "../src/deep2/K2BoundedRuntimeGate.hpp"
#include <cstdio>
int main() {
    if (!Deep2::K2RuntimeWithinBound(1024, 4096)) {
        puts("VWA_BOUNDED_K2_001=FAIL");
        return 1;
    }
    puts("VWA_BOUNDED_K2_001=PASS");
    return 0;
}
