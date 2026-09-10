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
#ifndef CHAIR_INVALID
#define CHAIR_INVALID 0xffffffffu
#endif

namespace Deep2 {
namespace future {

using ConsumerId = uint64_t;
using TensorId = uint64_t;
using ChairId = uint32_t;
using OwnerId = ConsumerId;
using ResourceId = uint32_t;
using ContinuationFn = void (*)(void*);

struct FutureConsumer {
    ConsumerId consumerId = 0;
    uint64_t   logicalBegin = 0;
    uint64_t   logicalEnd = 0;
    uint32_t   firstUse = 0;
    uint32_t   lastUse = 0;
    uint32_t   nextUse = 0; /* observational; not a wake key */
    uint16_t   layer = 0;   /* observational; not a wake key */
    uint8_t    op = 0;
    uint8_t    preferredDevice = 0;
    Tier       tier = Tier::Future5;
    ChairId    chairId = CHAIR_INVALID;
    uint32_t   expectedGeneration = 0;
};

/* Chair = physical residency slot. Index = ChairId. Generation tags reuse. */
struct PhysicalPage {
    void*      base = nullptr;
    uint64_t   bytes = 0;
    ConsumerId current = 0;
    ConsumerId next = 0;
    uint32_t   generation = 0;
    uint32_t   readyGeneration = 0;
    ResourceId resourceId = 0;
    OwnerId    waitOwner = 0;
    ContinuationFn continuation = nullptr;
    void*      continuationCtx = nullptr;
};
using Chair = PhysicalPage;

struct FutureAddress {
    ConsumerId consumer = 0;
    TensorId   tensor = 0;
    uint64_t   offset = 0;
    uint32_t   bytes = 0;
};

inline uint64_t PriorityU64(uint64_t reuse, uint64_t stall, uint64_t probability,
                            uint64_t timeUntilUse, uint64_t bytes) {
    const uint64_t den = (std::max)(timeUntilUse, uint64_t{1}) *
                         (std::max)(bytes, uint64_t{1});
    return (reuse * stall * probability) / den;
}

bool InitFromPhysicalPool();
void Shutdown();
ConsumerId Register(uint16_t layer, uint8_t op, uint8_t device,
                    uint64_t logicalBytes, uint32_t nextUse);
bool AdvanceOwnership(uint32_t pageIdx, ConsumerId next);
int PageForConsumer(ConsumerId id);
FutureConsumer* ConsumerAt(ConsumerId id);
Chair* ChairAt(ChairId id);
int BindContinuation(ChairId chair, uint32_t expectedGen, ContinuationFn fn,
                     void* ctx);
int SignalChairReady(ChairId chair, uint32_t readyGen);
int TryResumeChair(ChairId chair, uint32_t expectedGen);
uint64_t LogicalBytes();
uint64_t ConsumerCount();
uint64_t PhysicalPoolBytes();
int PhysicalPoolGrows();
void EmitLaw(FILE* f);
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
