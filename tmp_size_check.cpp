#include <cstdint>
#include <cstdio>

struct block_q2_K { uint8_t scales[16]; uint8_t qs[64]; uint16_t d; uint16_t dmin; };
struct block_q5_K { uint16_t d; uint8_t qh[32]; uint8_t qs[128]; };

int main() {
    printf("q2_K=%zu q5_K=%zu\n", sizeof(block_q2_K), sizeof(block_q5_K));
    return 0;
}
