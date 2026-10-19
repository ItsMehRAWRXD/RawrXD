#pragma once
#include "KimiCostAuthority.hpp"
namespace Deep2 { namespace kcost {
/* T may be MoEPlaceLiveCounters; template keeps standalone build no-dep. */
template<class T> inline void CaptureMoE(const T&c,Run&r){
 r.h2dBytes=c.h2d_bytes; r.d2hBytes=c.d2h_bytes; r.reloadBytes=c.reload_miss_bytes;
 r.joinWaitNs=c.gpu_join_wait_ns; r.gpu0WorkNs=c.gpu0_work_ns;
 r.gpu1WorkNs=c.gpu1_work_ns; r.selected=c.experts_selected;
 r.executed=c.experts_executed; r.submits=c.gpu_submits; r.waits=c.gpu_waits;
 r.moeLayers=c.moe_layers_gpu; r.d2hPartials=c.d2h_partial_vectors;
 r.workerFailures=c.worker_failures; r.backendAttested=c.product_backend_attested?1:0;
}
}} 
