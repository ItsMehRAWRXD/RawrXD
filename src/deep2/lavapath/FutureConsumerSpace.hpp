#pragma once
/* Future-consumer address space — grows with model; pages stay fixed. */
#include "FutureConsumerLaw.hpp"
#include "FreeTokenMicroZone.hpp"
#include <algorithm>
#include <cstdint>
#include <cstddef>
#include <cstdio>

#ifndef FUTURE_CONSUMER_CAP
#define FUTURE_CONSUMER_CAP 65536
#endif

namespace Deep2 {
namespace future {

using ConsumerId = uint64_t;
using TensorId = uint64_t;

struct FutureConsumer {
    ConsumerId consumerId = 0;
    uint64_t   logicalBegin = 0;
    uint64_t   logicalEnd = 0;
    uint32_t   firstUse = 0;
    uint32_t   lastUse = 0;
    uint32_t   nextUse = 0;
    uint16_t   layer = 0;
    uint8_t    op = 0;
    uint8_t    preferredDevice = 0;
    Tier       tier = Tier::Future5;
};

struct PhysicalPage {
    void*      base = nullptr;
    uint64_t   bytes = 0;
    ConsumerId current = 0;
    ConsumerId next = 0;
    uint32_t   generation = 0;
};

struct FutureAddress {
    ConsumerId consumer = 0;
    TensorId   tensor = 0;
    uint64_t   offset = 0;
    uint32_t   bytes = 0;
};

/* Hardened denom: never divide by zero time or bytes. */
inline uint64_t PriorityU64(uint64_t reuse, uint64_t stall, uint64_t probability,
                            uint64_t timeUntilUse, uint64_t bytes) {
    const uint64_t den = (std::max)(timeUntilUse, uint64_t{1}) *
                         (std::max)(bytes, uint64_t{1});
    return (reuse * stall * probability) / den;
}

inline double Priority(double reuse, double stall, double prob,
                       double timeUntil, double bytes) {
    return (double)PriorityU64(
        (uint64_t)(reuse > 0 ? reuse : 1),
        (uint64_t)(stall > 0 ? stall : 1),
        (uint64_t)(prob > 0 ? prob : 1),
        (uint64_t)(timeUntil > 0 ? timeUntil : 1),
        (uint64_t)(bytes > 0 ? bytes : 1));
}

bool InitFromPhysicalPool();
void Shutdown();
ConsumerId Register(uint16_t layer, uint8_t op, uint8_t device,
                    uint64_t logicalBytes, uint32_t nextUse);
bool AdvanceOwnership(uint32_t pageIdx, ConsumerId next);
int PageForConsumer(ConsumerId id);
uint64_t LogicalBytes();
uint64_t ConsumerCount();
uint64_t PhysicalPoolBytes();
int PhysicalPoolGrows();
void EmitLaw(FILE* f);

/* FUTURE_CONSUMER_EXEC_001 — survive real generation. */
void MarkGenerateBegin();
void NoteConsumerHit();
void NoteConsumerMiss();
void NotePrefetchHit();
void NotePrefetchLate();
void NoteStallNs(uint64_t ns);
void NotePhysicalOverwrite(uint32_t pageIdx);
void NoteStaleGenerationRead();
void EmitExec(FILE* f, uint32_t tokensCommitted, int rc);

} // namespace future
} // namespace Deep2
