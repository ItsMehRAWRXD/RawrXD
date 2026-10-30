// Test 18: Incremental rebuilds - touches one file, rebuilds only that object
#include <stdio.h>
int helper(void);
int main(void) {
    int h = helper();
    printf("helper=%d\n", h);  // expect 7
    return 0;
}
