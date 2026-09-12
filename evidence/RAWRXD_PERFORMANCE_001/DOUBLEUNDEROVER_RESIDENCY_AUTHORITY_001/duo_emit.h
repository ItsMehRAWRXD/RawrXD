/* duo_emit.h */
#ifndef DUO_EMIT_H
#define DUO_EMIT_H
#include "duo_ticket.h"
int duo_ingest_split_stream(DuoTicket *t, uint64_t region, uint64_t ticket,
                            uint64_t off, uint64_t len, int identity,
                            uint64_t warm, uint64_t mg, uint64_t hot,
                            uint64_t gen, int parity, int gpu,
                            uint64_t owner, uint64_t codec);
void duo_print_disposition(const DuoTicket *t, const char *stop);
#endif
