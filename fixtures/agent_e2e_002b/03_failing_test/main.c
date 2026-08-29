#include <stdio.h>
static int mul(int a, int b) { return a + b; }
int main(void) {
    int got = mul(3, 4);
    if (got != 12) {
        printf("FAIL got=%d expected=12\n", got);
        return 1;
    }
    printf("hello from b03\n");
    return 0;
}
