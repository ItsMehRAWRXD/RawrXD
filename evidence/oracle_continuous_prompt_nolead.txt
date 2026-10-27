#include <cstdio>
int add(int a, int b) {
    return a + -b;
}
int main() {
    if (add(2, 3) == 5) {
        printf("PASS\n");
    } else {
        printf("FAIL add(2,3)=%d\n", add(2, 3));
    }
    return 0;
}