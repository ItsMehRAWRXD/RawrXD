/* d2_packed_q2k_product_run_v1 — canonical in-process BIND16 export.
 * FORBIDDEN: CreateProcess, receipt replay, 72-byte MASM. PROMOTE=0 */
#include "EVIDENCE_EXPORT_ABI.h"
#include "Deep2SsVkPackedDualAdapter.hpp"

extern "C" int d2_packed_q2k_product_run_v1(
    void* user,
    const D2PackedProductRequest* req,
    D2PackedProductProof* proof) {
    return Deep2::PackedDualAdapterProductRun(user, req, proof);
}
