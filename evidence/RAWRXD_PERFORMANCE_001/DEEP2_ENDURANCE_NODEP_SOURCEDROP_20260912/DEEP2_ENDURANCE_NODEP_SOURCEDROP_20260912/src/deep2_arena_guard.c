#include "deep2_endurance.h"
#include <string.h>
static size_t up(size_t x,size_t a){return a?((x+(a-1))&~(a-1)):x;}
int d2_arena_init(D2Arena *a,void *m,size_t b){if(!a||!m||!b)return D2_EINVAL;memset(a,0,sizeof *a);a->base=(uint8_t*)m;a->capacity=b;a->canary_a=D2_CANARY_A;a->canary_b=D2_CANARY_B;return D2_OK;}
void *d2_arena_alloc(D2Arena *a,size_t b,size_t al){size_t p;if(!a||!b||a->frozen)return NULL;if(al==0)al=1;if(al&(al-1))return NULL;p=up(a->used,al);if(p>a->capacity||b>a->capacity-p)return NULL;a->used=p+b;if(a->used>a->high_water)a->high_water=a->used;return a->base+p;}
int d2_arena_freeze(D2Arena *a){if(!a)return D2_EINVAL;a->frozen=1;return D2_OK;}
int d2_arena_check(const D2Arena *a){if(!a||a->canary_a!=D2_CANARY_A||a->canary_b!=D2_CANARY_B||a->used>a->capacity||a->high_water>a->capacity)return D2_ECORRUPT;return D2_OK;}
void d2_arena_reset(D2Arena *a){if(a){a->used=0;a->high_water=0;a->frozen=0;a->canary_a=D2_CANARY_A;a->canary_b=D2_CANARY_B;}}
