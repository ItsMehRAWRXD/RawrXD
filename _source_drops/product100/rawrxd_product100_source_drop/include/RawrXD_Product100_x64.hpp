#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint64_t P100_Fnv1a64(const void* data, uint64_t bytes);
uint32_t P100_CapAllows(uint64_t granted, uint64_t required);
int64_t  P100_FindByteSpan(const void* haystack, uint64_t haystack_bytes, const void* needle, uint64_t needle_bytes);
uint64_t P100_CountLf(const void* data, uint64_t bytes);
void     P100_SecureZero(void* data, uint64_t bytes);

#ifdef __cplusplus
}
#endif

