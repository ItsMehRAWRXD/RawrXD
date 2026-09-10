#pragma once
/* HOST_DECODE FutureConsumer edge: Current(L) → Future1(L+1) → NVMe→RAM. */
#include "FutureConsumerSpace.hpp"
#include "KN_O3KKEN.h"
#include <cstdint>
#include <cstdio>

namespace Deep2 {
class NVMeStream;
namespace hostfc {

int Armed();
uint32_t LastEntered();
void MarkProductDecode();
void ArmFromProductRun(uint32_t layers);
void BindNvme(NVMeStream* s);
void BindMapPrefetch(void* (*fn)(uint64_t, size_t));
void BindHostWeight(void* ptr, uint64_t bytes, uint64_t fileOffset);
void HostPrefetch(uint32_t nextLayer); /* async NVMe→RAM; returns */
void EnterLayer(uint32_t L, uint32_t nLayers);
void ExitLayer(uint32_t L);
void SealDecode(int tokenSurvived, FILE* f);
void BindK3cConsumer(KN_ConsumerFn fn);
uint64_t LastKnO3Result();
uint64_t LastKnO3TokenWallNs();
int LastKnO3Status();
int KnO3Reached();

struct LayerEdge {
    uint32_t L = 0;
    int live = 0;
    LayerEdge(uint32_t layer, uint32_t nLayers);
    ~LayerEdge();
};

} /* namespace hostfc */
} /* namespace Deep2 */
