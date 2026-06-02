#pragma once

#include <cstdint>

namespace RawrXD
{

enum class BackendLaneType : std::uint8_t
{
    Unknown = 0,
    TitanHost = 1,
    NativeDll = 2,
    StandaloneExe = 3,
};

inline const char* BackendLaneTypeName(BackendLaneType lane)
{
    switch (lane)
    {
        case BackendLaneType::TitanHost:
            return "titan_host";
        case BackendLaneType::NativeDll:
            return "native_dll";
        case BackendLaneType::StandaloneExe:
            return "standalone_exe";
        case BackendLaneType::Unknown:
        default:
            return "unknown";
    }
}

inline std::uint32_t BackendLaneTypeCode(BackendLaneType lane)
{
    return static_cast<std::uint32_t>(lane);
}

}  // namespace RawrXD
