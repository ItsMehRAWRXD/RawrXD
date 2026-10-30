// Test 16: Debug and release builds - same source, different configs
#include <stdio.h>
int main(void) {
#ifdef _DEBUG
    printf("debug\n");
#else
    printf("release\n");
#endif
    return 0;
}
