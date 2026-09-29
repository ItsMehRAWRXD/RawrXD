// TpsClassAuthority.cpp — RAWRXD_TPS_CLASS_AUTHORITY_001
#include "TpsClassAuthority.h"
#include "ReceiptAuthority.h"
#include <atomic>
#include <string>
namespace rawrxd { namespace tps {
static std::atomic<int> g_physicalModel{0};
static std::atomic<int> g_effectiveAccepted{0};
static std::atomic<int> g_visibleStream{0};
static std::atomic<int> g_cacheReplay{0};
static std::atomic<int> g_speculativeAccepted{0};
static std::atomic<int> g_syntheticInvalid{0};
static std::atomic<int> g_debugContaminated{0};
static const char* className(Class c) {
    switch (c) {
        case Class::PhysicalModel:       return "PhysicalModel";
        case Class::EffectiveAccepted:   return "EffectiveAccepted";
        case Class::VisibleStream:       return "VisibleStream";
        case Class::CacheReplay:         return "CacheReplay";
        case Class::SpeculativeAccepted: return "SpeculativeAccepted";
        case Class::SyntheticInvalid:    return "SyntheticInvalid";
        case Class::DebugContaminated:   return "DebugContaminated";
    }
    return "Unknown";
}
void classify(Class cls) {
    switch (cls) {
        case Class::PhysicalModel:       g_physicalModel.fetch_add(1); break;
        case Class::EffectiveAccepted:   g_effectiveAccepted.fetch_add(1); break;
        case Class::VisibleStream:       g_visibleStream.fetch_add(1); break;
        case Class::CacheReplay:         g_cacheReplay.fetch_add(1); break;
        case Class::SpeculativeAccepted: g_speculativeAccepted.fetch_add(1); break;
        case Class::SyntheticInvalid:    g_syntheticInvalid.fetch_add(1); break;
        case Class::DebugContaminated:   g_debugContaminated.fetch_add(1); break;
    }
}
void writeTpsClassReceipt(const std::string& path) {
    rawrxd::receipt::beginGate(path, "RAWRXD_TPS_CLASS_AUTHORITY_001");
    rawrxd::receipt::writeKeyValueInt(path, "PHYSICAL_MODEL", g_physicalModel.load());
    rawrxd::receipt::writeKeyValueInt(path, "EFFECTIVE_ACCEPTED", g_effectiveAccepted.load());
    rawrxd::receipt::writeKeyValueInt(path, "VISIBLE_STREAM", g_visibleStream.load());
    rawrxd::receipt::writeKeyValueInt(path, "CACHE_REPLAY", g_cacheReplay.load());
    rawrxd::receipt::writeKeyValueInt(path, "SPECULATIVE_ACCEPTED", g_speculativeAccepted.load());
    rawrxd::receipt::writeKeyValueInt(path, "SYNTHETIC_INVALID", g_syntheticInvalid.load());
    rawrxd::receipt::writeKeyValueInt(path, "DEBUG_CONTAMINATED", g_debugContaminated.load());
    // Invalid classes must be zero for a clean verdict
    bool clean = (g_syntheticInvalid.load() == 0 && g_debugContaminated.load() == 0);
    rawrxd::receipt::endGate(path, clean ? "PASS" : "FAIL");
}
}} // namespace rawrxd::tps