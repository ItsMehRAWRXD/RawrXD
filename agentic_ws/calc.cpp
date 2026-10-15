#include <cstdio>
int add(int a, int b) {
    return a + b;
}
int main() {
    if (add(2, 3) == 5) { printf("PASS\n"); return 0; }
    printf("FAIL: add(2,3)=%d expected 5\n", add(2, 3));
    return 1;
}