#include "deep2_endurance.h"
uint64_t d2_epoch_begin(D2Epoch *e){if(!e)return 0;if(++e->epoch==0)++e->epoch;return e->epoch;}
int d2_epoch_check(const D2Epoch *e,uint64_t o){return e&&e->epoch&&e->epoch==o?D2_OK:D2_ESTATE;}
