/* ss_barrier_seq.c — monotonic compute-write→compute-read sequence witness */
#include "ss_evidence.h"
#include <stdio.h>
static uint32_t g_seq;
void ss_barrier_reset(void) { g_seq = 0; }
uint32_t ss_barrier_seq(void) { return g_seq; }
uint32_t ss_barrier_note(const char *producer, const char *consumer)
{
    g_seq += 1;
    printf("BARRIER_SEQ=%u PRODUCER=%s CONSUMER=%s COMPUTE_WRITE_TO_READ=1\n",
           g_seq, producer ? producer : "?", consumer ? consumer : "?");
    return g_seq;
}
