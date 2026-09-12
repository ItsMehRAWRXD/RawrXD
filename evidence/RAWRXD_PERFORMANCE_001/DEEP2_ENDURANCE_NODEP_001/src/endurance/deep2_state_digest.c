/* deep2_state_digest.c — FNV-1a 64 */
#include "deep2_state_digest.h"
uint64_t d2_digest_u64(uint64_t h, uint64_t v)
{
    int i;
    if (!h) h = 14695981039346656037ull;
    for (i = 0; i < 8; ++i) {
        h ^= (v & 0xffull); h *= 1099511628211ull; v >>= 8;
    }
    return h;
}
uint64_t d2_digest_mem(uint64_t h, const void *p, uint64_t n)
{
    const unsigned char *b = (const unsigned char *)p; uint64_t i;
    if (!h) h = 14695981039346656037ull;
    for (i = 0; i < n; ++i) { h ^= b[i]; h *= 1099511628211ull; }
    return h;
}
