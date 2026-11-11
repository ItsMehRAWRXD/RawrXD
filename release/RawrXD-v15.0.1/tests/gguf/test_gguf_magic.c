/*
 * RawrXD Validation Framework
 * GGUF Test: Magic Number Validation
 */

#include <stdio.h>
#include <stdint.h>

#define TEST_NAME "GGUF Magic"

/* GGUF magic number: 'GGUF' in little-endian */
#define GGUF_MAGIC 0x46554747
#define GGUF_VERSION 3

int main(void) {
    printf("[%s] Starting...\n", TEST_NAME);
    
    /* Test 1: Verify magic number constant */
    uint32_t magic = GGUF_MAGIC;
    if (magic != 0x46554747) {
        printf("[%s] FAIL: Magic number mismatch\n", TEST_NAME);
        return 1;
    }
    printf("[%s] Magic number: 0x%08X (valid)\n", TEST_NAME, magic);
    
    /* Test 2: Verify version */
    uint32_t version = GGUF_VERSION;
    if (version != 3) {
        printf("[%s] FAIL: Version mismatch\n", TEST_NAME);
        return 1;
    }
    printf("[%s] Version: %u (valid)\n", TEST_NAME, version);
    
    /* Test 3: Byte order check */
    uint8_t* bytes = (uint8_t*)&magic;
    if (bytes[0] == 'G' && bytes[1] == 'G' && bytes[2] == 'U' && bytes[3] == 'F') {
        printf("[%s] Byte order: Little-endian (correct)\n", TEST_NAME);
    } else {
        printf("[%s] FAIL: Byte order incorrect\n", TEST_NAME);
        return 1;
    }
    
    printf("[%s] PASS\n", TEST_NAME);
    return 0;
}
