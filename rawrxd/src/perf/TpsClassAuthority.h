// TpsClassAuthority.h — RAWRXD_TPS_CLASS_AUTHORITY_001
#pragma once
#include <string>
#include <cstdint>
namespace rawrxd { namespace tps {
enum class Class {
    PhysicalModel,
    EffectiveAccepted,
    VisibleStream,
    CacheReplay,
    SpeculativeAccepted,
    SyntheticInvalid,
    DebugContaminated
};
void classify(Class cls);
void writeTpsClassReceipt(const std::string& path);
}} // namespace rawrxd::tps