// hexmag_client.hpp — HexMag CLI + IDE API (routes to MASM control plane)
#pragma once

#include "core/hexmag_control_plane.hpp"

#include <string>
#include <functional>

#ifdef __cplusplus
extern "C" {
#endif

__declspec(dllexport) int HexMagJIT_Init(size_t capacity);
__declspec(dllexport) void HexMagJIT_Shutdown(void);
__declspec(dllexport) int HexMagJIT_EmitExit42(void);
__declspec(dllexport) int HexMagJIT_Execute(void);
__declspec(dllexport) int HexMagCLI_Run(int argc, const char** argv);
__declspec(dllexport) void hexmag_connect_stub(void);

#ifdef __cplusplus
}
#endif

// AskResult / StreamResult / tryLaunchService / healthCheck / resolveBaseUrl /
// askWithAutoStart / streamAgentWithAutoStart live in RawrXD::HexMag
// (hexmag_control_plane.hpp) — Win32IDE already calls those symbols.
