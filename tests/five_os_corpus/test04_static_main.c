// Test 04: Static library linking - main source
extern int lib_mul(int a, int b);
#include <stdio.h>
int main(void) {
    int r = lib_mul(6, 7);
    printf("mul=%d\n", r);  // expect 42
    return 0;
}
