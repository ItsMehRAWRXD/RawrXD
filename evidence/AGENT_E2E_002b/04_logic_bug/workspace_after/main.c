#include <stdio.h>
static int add(int a, int b) { return a - b; }
int main(void) {
    int got = add(2, 3);
    if (got != 5) {
        printf("FAIL got=%d expected=5\n", got);
        return 1;
    }
    printf("hello from b04\n");
    return 0;
}
