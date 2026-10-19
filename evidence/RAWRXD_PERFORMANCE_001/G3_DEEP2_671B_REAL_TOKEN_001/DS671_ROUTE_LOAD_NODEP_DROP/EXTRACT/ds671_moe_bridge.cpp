/*
  Optional product bridge notes (not linked by default).
  Wire ds671 callbacks to Deep2::MoEWeightsLoader without sequential scan:

    measure: sum ExpertProjectionInfo.bytesPerExpert for blk layer
             (gate optional; up+down required; expertIdx==-1 stacked).
    load:    MoEWeightsLoader::LoadExpert(blk, expert) -> handle=(uint64_t)ptr
             actual_bytes = measured size.
    release: MoEWeightsLoader::Unpin(blk, expert)  [cache-owned; no free]
             OR keep adapter-owned packs and never call LoadExpert.

  blk = moe_layer + leading_dense_block_count  (R1 COMPLETE: 3)
  Names: blk.{L}.ffn_{gate,up,down}_exps.weight  (MoEWeightsLoader::ParseExpertName)

  Do NOT call from scheduler seal paths. PROMOTE=0. No TOKEN1_PASS invent.
*/
#include "ds671_tensor_adapter.h"

#if defined(DS671_LINK_MOE_WEIGHTS_LOADER) && DS671_LINK_MOE_WEIGHTS_LOADER
#include "../../../src/deep2/MoEWeightsLoader.hpp"
/* Product TU would implement C wrappers around MoEWeightsLoader here. */
#endif

/* Compile unit present so build can always link a bridge object. */
int ds671_moe_bridge_stub_present(void) { return 1; }
