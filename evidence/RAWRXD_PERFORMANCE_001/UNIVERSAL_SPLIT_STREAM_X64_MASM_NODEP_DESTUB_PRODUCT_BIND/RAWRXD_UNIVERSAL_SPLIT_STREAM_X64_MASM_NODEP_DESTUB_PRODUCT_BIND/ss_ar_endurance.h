/* ss_ar_endurance.h — product-merged Top-15 ledger hooks on AR path */
#ifndef SS_AR_ENDURANCE_H
#define SS_AR_ENDURANCE_H
#include "ss_ar_user.h"
#include <stdint.h>
void ar_endurance_begin(ArUser *u);
int ar_endurance_end_fwd(ArUser *u, uint64_t pos);
int ar_endurance_finish(ArUser *u, uint64_t target);
void ar_endurance_print(const ArUser *u, uint64_t target);
#endif
