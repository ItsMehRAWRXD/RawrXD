/* deep2_generation_epoch.h */
#ifndef DEEP2_GENERATION_EPOCH_H
#define DEEP2_GENERATION_EPOCH_H
#include <stdint.h>
typedef struct { uint64_t epoch; uint64_t rejects; } D2Epoch;
void d2_ep_init(D2Epoch *e, uint64_t start);
uint64_t d2_ep_bump(D2Epoch *e);
int d2_ep_accept(D2Epoch *e, uint64_t observed);
#endif
