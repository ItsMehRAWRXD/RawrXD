#pragma once
#include <windows.h>
namespace RawrXD::Win32Visibility {
    template <typename... Args> inline void LogPlacementSnapshot(Args&&...) {}
    template <typename... Args> inline bool NormalizePlacementForVisibility(Args&&...) { return false; }
}
