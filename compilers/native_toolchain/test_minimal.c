// Test calling convention
#include <stdio.h>
#include <windows.h>

// Assembly function - just returns 1
extern int test_minimal(void);

int main(void) {
    printf("Testing minimal function...\n");
    printf("Calling test_minimal()...\n");
    fflush(stdout);
    int result = test_minimal();
    printf("Result: %d\n", result);
    return 0;
}