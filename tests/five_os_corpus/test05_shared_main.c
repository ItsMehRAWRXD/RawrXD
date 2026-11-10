// Test 05: Shared library linking - main source
#ifdef _WIN32
#define SHARED_API __declspec(dllimport)
#else
#define SHARED_API
#endif

SHARED_API int shared_add(int a, int b);
#include <stdio.h>
int main(void) {
    int r = shared_add(10, 32);
    printf("shared=%d\n", r);  // expect 42
    return 0;
}
