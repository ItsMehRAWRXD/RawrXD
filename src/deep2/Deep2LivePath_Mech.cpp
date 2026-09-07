// Live generate: StreamEngine + NVMe hop + elastic + plasma arm/layer/token
#include "Deep2LivePath.hpp"
#include "Deep2LivePath_Internal.hpp"
#include "StreamEngine.hpp"
#include "NVMeStream.h"
#include "PlasmaGovernor.hpp"

namespace Deep2 {
bool LivePath_SampleThermal(rawrxd::PlasmaGovernor* plasma);
void LivePath_MechEndImpl();

namespace {
StreamEngine g_stream;
NVMeStream* g_nvme = nullptr;
rawrxd::PlasmaGovernor* g_plasma = nullptr;
ElasticResidencyManager* g_elastic = nullptr;
uint32_t g_layers = 0;
uint32_t g_heads = 0;
bool g_streamReady = false;
bool g_nvmeEverActive = false;
}

StreamEngine& LivePath_MechStream() { return g_stream; }
bool& LivePath_MechStreamReady() { return g_streamReady; }
NVMeStream*& LivePath_MechNvme() { return g_nvme; }
rawrxd::PlasmaGovernor*& LivePath_MechPlasma() { return g_plasma; }
bool& LivePath_MechNvmeEver() { return g_nvmeEverActive; }
ElasticResidencyManager* LivePath_MechElastic() { return g_elastic; }

void LivePath_BindOwners(ElasticResidencyManager* elastic, NVMeStream* nvme,
                         rawrxd::PlasmaGovernor* plasma, uint32_t numLayers,
                         uint32_t numHeads) {
    g_elastic = elastic;
    g_nvme = nvme;
    g_plasma = plasma;
    g_layers = numLayers;
    g_heads = numHeads ? numHeads : 8;
    if (nvme && nvme->isReverseBunnyHop()) g_nvmeEverActive = true;
}

void LivePath_MechArm(ElasticResidencyManager* elastic) {
    if (!LivePath_MechOn(LP_MECH_ELASTIC) && !LivePath_MechOn(LP_MECH_STREAM) &&
        !LivePath_MechOn(LP_MECH_REVERSAL))
        return;
    auto& c = LivePath_Ctr();
    if (LivePath_MechOn(LP_MECH_ELASTIC) && elastic) c.elasticArmed = 1;
    if (!LivePath_MechOn(LP_MECH_STREAM)) return;
    if (!g_streamReady && g_layers > 0) {
        StreamConfig cfg;
        cfg.numLayers = g_layers;
        cfg.totalHeads = g_heads;
        cfg.activeHeads = g_heads > 4 ? 4 : g_heads;
        cfg.undeadHop = true;
        cfg.hotpatchRelive = true;
        if (g_stream.Initialize(cfg) && g_stream.unreverseHot()) {
            g_streamReady = true;
            c.streamArmed = 1;
        }
    } else if (g_streamReady) {
        (void)g_stream.unreverseHot();
        c.streamArmed = 1;
    }
    if (!g_nvme) c.nvmeAbsence = 1;
    else if (g_nvme->hopReverseChunk()) {
        c.nvmeHops++; g_nvmeEverActive = true; c.nvmeAbsence = 0;
    } else {
        c.nvmeAbsence = g_nvmeEverActive ? 2u : 1u;
    }
    if (LivePath_SampleThermal(g_plasma)) { c.plasmaSamples++; c.plasmaAbsence = 0; }
    else c.plasmaAbsence = 1;
}

void LivePath_MechLayer(uint32_t layer) {
    if (!LivePath_MechOn(LP_MECH_STREAM)) return;
    auto& c = LivePath_Ctr();
    if (g_streamReady && g_stream.ReviveLayer((int)layer)) {
        c.streamAlive++;
        if (g_stream.GetState() == StreamState::Alive) c.streamArmed = 1;
    }
}

void LivePath_MechToken() {
    if (!LivePath_MechOn(LP_MECH_STREAM)) return;
    auto& c = LivePath_Ctr();
    if (g_nvme && g_nvme->hopReverseChunk()) { c.nvmeHops++; c.nvmeAbsence = 0; }
    else if (g_nvme) c.nvmeAbsence = g_nvmeEverActive ? 2u : 1u;
    else c.nvmeAbsence = 1;
    if (LivePath_SampleThermal(g_plasma)) { c.plasmaSamples++; c.plasmaAbsence = 0; }
    else c.plasmaAbsence = 1;
}

void LivePath_MechEnd() { LivePath_MechEndImpl(); }

} // namespace Deep2
