// Test 09: Global initialization order
#include <stdio.h>

static int init_value = 0;

void init_global(void) {
    init_value = 42;
}

int main(void) {
    init_global();
    printf("init_value=%d\n", init_value);  // expect 42
    return 0;
}
