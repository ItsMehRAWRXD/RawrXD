#pragma once
#include <cstdint>
namespace rawr::product {

constexpr uint32_t kRuntimeAbiV1 = 1;

enum Cap : uint32_t {
    CapStream = 1u,
    CapTools = 2u,
    CapSession = 4u,
    CapRepo = 8u,
    CapComplete = 16u,
    CapAgent = 32u,
    CapAll = 63u
};

extern "C" uint32_t RawrProductAbiVer();
extern "C" uint32_t RawrProductCaps();
extern "C" uint32_t RawrTokenEst(uint32_t chars);
extern "C" uint32_t RawrFnv1a32(const void* buf, uint32_t len);

inline bool AbiOk() { return RawrProductAbiVer() == kRuntimeAbiV1; }
inline bool HasCap(uint32_t bit) { return (RawrProductCaps() & bit) != 0; }

} // namespace rawr::product
