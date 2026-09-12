/* deep2_state_digest.h */
#ifndef DEEP2_STATE_DIGEST_H
#define DEEP2_STATE_DIGEST_H
#include <stdint.h>
uint64_t d2_digest_u64(uint64_t h, uint64_t v);
uint64_t d2_digest_mem(uint64_t h, const void *p, uint64_t n);
#endif
