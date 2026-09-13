/* DualStickImbalance_Cost.cpp — adaptive EWMA cell update. ≤99. */
#include "DualStickImbalance_Cost.hpp"
#include "DualStickImbalance_State.hpp"
#include <cstdlib>

namespace Deep2 {
namespace ds_imb {

CostSlot g_cost[COST_CAP];
uint32_t g_costN = 0;
uint64_t g_layerPrior[2] = {16ull * 1000ull * 1000ull, 16ull * 1000ull * 1000ull};
uint32_t g_layerPriorN[2] = {0, 0};

int V7Mode() {
    const char* m = std::getenv("DEEP2_V7_MODE");
    if (!m || !*m || m[0] == 'o' || m[0] == 'O' || m[0] == '0') return 1;
    if (m[0] == 'b' || m[0] == 'B') return 2;
    return (m[0] == 'n' || m[0] == 'N') ? 0 : 1;
}

static CostSlot* Find(uint64_t key) {
    for (uint32_t i = 0; i < g_costN; ++i)
        if (g_cost[i].key == key) return &g_cost[i];
    return nullptr;
}

static void Ewma(uint64_t& slot, uint32_t n, uint64_t sample) {
    if (n < 4u) slot = (slot + sample) / 2ull;
    else slot = (slot * 7ull + sample) / 8ull;
}

void CostNoteSplit(int layer, int expert, unsigned gpu, int resident,
                   uint64_t kernNs, uint64_t h2dNs, uint64_t queueNs) {
    gpu &= 1u;
    if (!kernNs && !h2dNs && !resident) return;
    const uint64_t prior =
        g_layerPrior[gpu] ? g_layerPrior[gpu] : (kernNs ? kernNs : 1ull);
    if (kernNs) {
        if (kernNs > (prior << 3)) kernNs = prior << 3;
        if (kernNs < (prior >> 3)) kernNs = prior >> 3;
    }
    const uint64_t key =
        CellKey(layer, expert, gpu, resident, g_quant, g_inDim, g_outDim);
    CostSlot* s = Find(key);
    if (!s) {
        if (g_costN >= COST_CAP) return;
        s = &g_cost[g_costN++];
        s->key = key;
        s->ewma_kernel_ns = kernNs ? kernNs : prior;
        s->ewma_h2d_ns = h2dNs;
        s->queue_ns = queueNs;
        s->variance = 0;
        s->samples = 1;
    } else {
        const uint64_t old = s->ewma_kernel_ns;
        if (kernNs) {
            Ewma(s->ewma_kernel_ns, s->samples, kernNs);
            Ewma(s->variance, s->samples,
                 kernNs > old ? kernNs - old : old - kernNs);
        }
        if (h2dNs) Ewma(s->ewma_h2d_ns, s->samples, h2dNs);
        if (queueNs) Ewma(s->queue_ns, s->samples, queueNs);
        s->samples++;
    }
    if (kernNs) {
        Ewma(g_layerPrior[gpu], g_layerPriorN[gpu], kernNs);
        g_layerPriorN[gpu]++;
    }
}

uint64_t CostKernel(int layer, int expert, unsigned gpu, int resident) {
    CostSlot* s = Find(
        CellKey(layer, expert, gpu & 1u, resident, g_quant, g_inDim, g_outDim));
    if (s && s->samples >= 2u) return s->ewma_kernel_ns;
    if (s && s->samples == 1u)
        return (s->ewma_kernel_ns + g_layerPrior[gpu & 1u]) / 2ull;
    return g_layerPrior[gpu & 1u];
}

uint64_t CostH2d(int layer, int expert, unsigned gpu) {
    CostSlot* s =
        Find(CellKey(layer, expert, gpu & 1u, 0, g_quant, g_inDim, g_outDim));
    return (s && s->ewma_h2d_ns) ? s->ewma_h2d_ns : 0ull;
}

uint32_t CostSamples(int layer, int expert, unsigned gpu, int resident) {
    CostSlot* s = Find(
        CellKey(layer, expert, gpu & 1u, resident, g_quant, g_inDim, g_outDim));
    return s ? s->samples : 0u;
}

} // namespace ds_imb
} // namespace Deep2
