/* DualStickImbalance_Cost.cpp — attributable EWMA cell update. ≤99. */
#include "DualStickImbalance_Cost.hpp"
#include "DualStickImbalance_State.hpp"
#include "Deep2Missing15Observe.hpp"
#include <cstdlib>
namespace Deep2 {
namespace ds_imb {
CostSlot g_cost[COST_CAP];
uint32_t g_costN = 0;
uint64_t g_layerPrior[2] = {16ull * 1000ull * 1000ull, 16ull * 1000ull * 1000ull};
uint32_t g_layerPriorN[2] = {0, 0};
uint64_t g_sightSeq = 0;
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
                   uint64_t kernNs, uint64_t h2dNs, uint64_t /*queueNs*/) {
    gpu &= 1u;
    const uint32_t ak = d2m15_obs::sample_gate(1u, kernNs);
    const uint32_t ax = d2m15_obs::sample_gate(1u, h2dNs);
    const int x0 = (resident && !h2dNs && !kernNs) ? 1 : 0;
    if (!ak && !ax && !x0 && !resident) return;
    const uint64_t key =
        CellKey(layer, expert, gpu, resident, g_quant, g_inDim, g_outDim);
    CostSlot* s = Find(key);
    if (!s) {
        if (g_costN >= COST_CAP) return;
        s = &g_cost[g_costN++];
        *s = CostSlot{};
        s->key = key;
        s->resident = resident ? 1u : 0u;
        s->ewma_kernel_ns = g_layerPrior[gpu];
    }
    s->last_seen = ++g_sightSeq;
    s->samples++;
    if (ak) {
        const uint64_t old = s->ewma_kernel_ns;
        Ewma(s->ewma_kernel_ns, s->samp_kern, kernNs);
        Ewma(s->variance, s->samp_kern,
             kernNs > old ? kernNs - old : old - kernNs);
        s->last_kernel_ns = kernNs;
        s->samp_kern++;
        Ewma(g_layerPrior[gpu], g_layerPriorN[gpu], kernNs);
        g_layerPriorN[gpu]++;
    }
    if (ax) {
        Ewma(s->ewma_h2d_ns, s->samp_xfer, h2dNs);
        s->last_xfer_ns = h2dNs;
        s->samp_xfer++;
    } else if (x0) {
        s->last_xfer_ns = 0;
        s->ewma_h2d_ns = 0;
        s->samp_xfer++;
    }
}
static CostSlot* Slot(int layer, int expert, unsigned gpu, int resident) {
    return Find(
        CellKey(layer, expert, gpu & 1u, resident, g_quant, g_inDim, g_outDim));
}
uint64_t CostKernel(int layer, int expert, unsigned gpu, int resident) {
    CostSlot* s = Slot(layer, expert, gpu, resident);
    if (s && s->samp_kern >= 2u) return s->ewma_kernel_ns;
    if (s && s->samp_kern == 1u)
        return (s->ewma_kernel_ns + g_layerPrior[gpu & 1u]) / 2ull;
    return g_layerPrior[gpu & 1u];
}
uint64_t CostH2d(int layer, int expert, unsigned gpu) {
    CostSlot* s = Slot(layer, expert, gpu, 0);
    return (s && s->samp_xfer) ? s->ewma_h2d_ns : 0ull;
}
uint64_t CostVar(int layer, int expert, unsigned gpu, int resident) {
    CostSlot* s = Slot(layer, expert, gpu, resident);
    return s ? s->variance : 0ull;
}
uint32_t CostSamples(int layer, int expert, unsigned gpu, int resident) {
    CostSlot* s = Slot(layer, expert, gpu, resident);
    return s ? s->samples : 0u;
}
} // namespace ds_imb
} // namespace Deep2
