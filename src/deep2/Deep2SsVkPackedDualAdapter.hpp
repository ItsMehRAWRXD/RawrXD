#pragma once
/* In-process adapter: SsVkProductBind → packed dual 84-byte Q2_K GEMV.
 * GATE=DEEP2_ENGINE_SSVK_DECODE_BIND_001 / BIND16  PROMOTE=0
 * FORBIDDEN: evidence.exe subprocess, receipt replay, 72-byte MASM. */
#include "Deep2SsVkProductBind.hpp"
#include "d2_engine_ssvk_bind16.h"

namespace Deep2 {

struct PackedDualAdapterCtx {
    void* opaque = nullptr; /* D2LiveCtx* when open */
    int ready = 0;
    /* Last overlap receipt (BIND16 export fills D2PackedProductProof). */
    uint64_t last_overlap_ns = 0;
    uint64_t last_critical_ns = 0;
    uint32_t last_shorter_pm = 0;
    uint32_t last_critical_pm = 0;
};

int PackedDualAdapterOpen(PackedDualAdapterCtx* ctx);
void PackedDualAdapterClose(PackedDualAdapterCtx* ctx);

int PackedDualAdapterGemv(
    void* user,
    const SsVkQ2KRequest* req,
    SsVkQ2KOpProof* proof);

/* Canonical BIND16 export body (same in-process dual path). */
int PackedDualAdapterProductRun(
    void* user,
    const D2PackedProductRequest* req,
    D2PackedProductProof* proof);

} // namespace Deep2
