// rawrxd_win32_syntax_bridge.h - Win32-specific syntax bridge
// Stub header for build compatibility

#pragma once

#ifndef RAWRXD_WIN32_SYNTAX_BRIDGE_H
#define RAWRXD_WIN32_SYNTAX_BRIDGE_H

#include "rawrxd_syntax_bridge.h"
#include <windows.h>

namespace RawrXD {
namespace Win32SyntaxBridge {

// Win32-specific extensions
struct Win32SyntaxContext : SyntaxBridge::SyntaxBridgeContext {
    HWND hwnd_editor;
    HDC hdc_render;
};

inline void InitWin32SyntaxBridge(Win32SyntaxContext* ctx, HWND hwnd) {
    SyntaxBridge::InitSyntaxBridge(ctx);
    ctx->hwnd_editor = hwnd;
    ctx->hdc_render = nullptr;
}

} // namespace Win32SyntaxBridge
} // namespace RawrXD

#endif // RAWRXD_WIN32_SYNTAX_BRIDGE_H