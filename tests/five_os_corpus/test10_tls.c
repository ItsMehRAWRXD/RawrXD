// Test 10: Thread-local storage (MSVC-compatible)
#include <stdio.h>

__declspec(thread) int tls_value = 42;

int main(void) {
    printf("tls=%d\n", tls_value);  // expect 42
    return 0;
}
