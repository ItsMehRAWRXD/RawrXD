/* ss_tensor_id.c — stable tensor identity hash (name+range+codec+dims) */
#include "ss_evidence.h"
#include <stdio.h>
#include <string.h>
static uint64_t fnv(uint64_t h, const void *p, size_t n)
{
    const unsigned char *b = (const unsigned char *)p; size_t i;
    for (i = 0; i < n; ++i) { h ^= b[i]; h *= 1099511628211ull; }
    return h;
}
uint64_t ss_tensor_id_hash(const SsTensorId *t)
{
    uint64_t h = 14695981039346656037ull;
    if (!t || !t->name) return 0;
    h = fnv(h, t->name, strlen(t->name));
    h = fnv(h, &t->abs_off, 8); h = fnv(h, &t->bytes, 8);
    h = fnv(h, &t->codec, 4); h = fnv(h, &t->dim0, 8); h = fnv(h, &t->dim1, 8);
    return h;
}
void ss_tensor_id_print(const SsTensorId *t, const char *when)
{
    if (!t) return;
    printf("TENSOR_ID_WHEN=%s NAME=%s ABS=%llu LEN=%llu CODEC=%u DIMS=%llu x %llu HASH=0x%llX\n",
           when ? when : "?", t->name ? t->name : "?",
           (unsigned long long)t->abs_off, (unsigned long long)t->bytes, t->codec,
           (unsigned long long)t->dim0, (unsigned long long)t->dim1,
           (unsigned long long)t->hash);
}
int ss_tensor_id_check(const SsTensorId *t, uint64_t expect)
{
    uint64_t h;
    if (!t) return 1;
    h = ss_tensor_id_hash(t);
    printf("TENSOR_ID_VERIFY expect=0x%llX got=0x%llX %s\n",
           (unsigned long long)expect, (unsigned long long)h,
           (h == expect && h != 0) ? "PASS" : "FAIL");
    return (h == expect && h != 0) ? 0 : 1;
}
