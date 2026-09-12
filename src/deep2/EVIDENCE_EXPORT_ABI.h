/* EVIDENCE_EXPORT_ABI — canonical in-process packed Q2_K product run. */
#ifndef D2_EVIDENCE_EXPORT_ABI_H
#define D2_EVIDENCE_EXPORT_ABI_H
#include "d2_engine_ssvk_bind16.h"
#ifdef __cplusplus
extern "C" {
#endif

/* IN-PROCESS only. No CreateProcess. No receipt replay. 84-byte Q2_K. */
int d2_packed_q2k_product_run_v1(
    void* user,
    const D2PackedProductRequest* req,
    D2PackedProductProof* proof);

#ifdef __cplusplus
}
#endif
#endif
