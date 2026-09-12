#pragma once
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
void D2DbInit(void* state);
int  D2DbPlanToken(void* state, uint32_t totalRows, uint32_t rowAlignment, void* plan);
int  D2DbObserveToken(void* state, const void* sample);
#ifdef __cplusplus
}
#endif
