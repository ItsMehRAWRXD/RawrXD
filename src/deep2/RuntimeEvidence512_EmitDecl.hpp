// RuntimeEvidence512_EmitDecl.hpp — extern "C" claim-isolated emitters.
#pragma once
#include "RuntimeEvidence512.hpp"

extern "C" {
int EvidenceInit512(Deep2::Ev512::EvidenceState* st,
                    Deep2::Ev512::EvidenceRecord* buf, uint64_t capacity,
                    uint64_t runId, uint32_t seqCap);
int EvidenceResetRun512(Deep2::Ev512::EvidenceState* st, uint64_t runId,
                        uint32_t seqCap);
uint64_t EvidenceGetCommittedCount(const Deep2::Ev512::EvidenceState* st);
uint64_t EvidenceGetDroppedCount(const Deep2::Ev512::EvidenceState* st);

int EvidenceEmitFirstTokenBoundary(Deep2::Ev512::EvidenceState* s, uint64_t a0,
                                   uint64_t a1);
int EvidenceEmitHiddenProbe(Deep2::Ev512::EvidenceState* s, uint64_t a0,
                            uint64_t a1);
int EvidenceEmitHiddenLast(Deep2::Ev512::EvidenceState* s, uint64_t a0,
                           uint64_t a1);
int EvidenceEmitBounds(Deep2::Ev512::EvidenceState* s, uint64_t a0, uint64_t a1,
                       uint32_t ok);
int EvidenceEmitValid(Deep2::Ev512::EvidenceState* s, uint64_t a0, uint64_t a1,
                      uint32_t ok);
int EvidenceEmitLogitsEntry(Deep2::Ev512::EvidenceState* s, uint64_t a0,
                            uint64_t a1);
int EvidenceEmitLogitsComplete(Deep2::Ev512::EvidenceState* s, uint64_t a0,
                               uint64_t a1);
int EvidenceEmitAttnComplete(Deep2::Ev512::EvidenceState* s, uint64_t a0,
                             uint64_t a1);
int EvidenceEmitPathBComplete(Deep2::Ev512::EvidenceState* s, uint64_t a0,
                              uint64_t a1);
int EvidenceEmitStreamComplete(Deep2::Ev512::EvidenceState* s, uint64_t a0,
                               uint64_t a1);
int EvidenceEmitStreamAbort(Deep2::Ev512::EvidenceState* s, uint64_t a0,
                            uint64_t a1);
int EvidenceEmitTeardownEntry(Deep2::Ev512::EvidenceState* s, uint64_t a0,
                              uint64_t a1);
int EvidenceEmitTeardownComplete(Deep2::Ev512::EvidenceState* s, uint64_t a0,
                                 uint64_t a1);
int EvidenceEmitTeardownFault(Deep2::Ev512::EvidenceState* s, uint64_t a0,
                              uint64_t a1);
int EvidenceEmitWallNs(Deep2::Ev512::EvidenceState* s, uint64_t a0,
                       uint64_t a1);
int EvidenceEmitDecodeTpsQ32_32(Deep2::Ev512::EvidenceState* s, uint64_t a0,
                                uint64_t a1);
int EvidenceEmitParity(Deep2::Ev512::EvidenceState* s, uint64_t a0, uint64_t a1,
                       uint32_t ok);
}
