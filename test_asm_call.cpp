#include <cstdio>
#include <cstdint>

// External assembly function
extern "C" uint32_t TreeAttention_Test();

int main() {
    printf("Calling TreeAttention_Test...\n");
    uint32_t result = TreeAttention_Test();
    printf("Result: %u\n", result);
    return 0;
}
