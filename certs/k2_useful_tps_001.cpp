#include "../src/deep2/K2UsefulTpsGate.hpp"
#include <cstdio>
int main() {
    if (!Deep2::K2UsefulTpsPass(2.0, 1.0)) {
        puts("K2_USEFUL_TPS_001=FAIL");
        return 1;
    }
    puts("K2_USEFUL_TPS_001=PASS");
    return 0;
}
