// Test 17: Optimization-enabled builds
#include <stdio.h>
int compute(int n) {
    int s = 0;
    for (int i = 0; i < n; i++) s += i;
    return s;
}
int main(void) {
    int r = compute(100);
    printf("sum=%d\n", r);  // expect 4950
    return 0;
}
