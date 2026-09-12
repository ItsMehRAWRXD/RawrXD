#pragma once
#include "d2_engine_ssvk_bind16.h"
#ifdef __cplusplus
extern "C" {
#endif
int d2_packed_q2k_product_run_v1(
    void* user,
    const D2PackedProductRequest* req,
    D2PackedProductProof* proof);
#ifdef __cplusplus
}
#endif
