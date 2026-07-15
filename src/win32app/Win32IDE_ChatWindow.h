// ============================================================================
// RawrXD Win32 Chat Window - Header
// ============================================================================

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque handle
typedef void* RawrXDChatWindowHandle;

// Callback types
typedef void (*RawrXDChatMessageCallback)(const char* role, const char* content);
typedef void (*RawrXDChatStatusCallback)(const char* status);

// C API for chat window
__declspec(dllexport) RawrXDChatWindowHandle RawrXDChatWindow_Create(HWND hParent, HINSTANCE hInstance);
__declspec(dllexport) void RawrXDChatWindow_Destroy(RawrXDChatWindowHandle handle);
__declspec(dllexport) void RawrXDChatWindow_Show(RawrXDChatWindowHandle handle);
__declspec(dllexport) void RawrXDChatWindow_Hide(RawrXDChatWindowHandle handle);
__declspec(dllexport) void RawrXDChatWindow_SendMessage(RawrXDChatWindowHandle handle, const char* message);
__declspec(dllexport) void RawrXDChatWindow_ClearHistory(RawrXDChatWindowHandle handle);
__declspec(dllexport) void RawrXDChatWindow_SetModel(RawrXDChatWindowHandle handle, const char* model);
__declspec(dllexport) const char* RawrXDChatWindow_GetModel(RawrXDChatWindowHandle handle);
__declspec(dllexport) HWND RawrXDChatWindow_GetHwnd(RawrXDChatWindowHandle handle);
__declspec(dllexport) BOOL RawrXDChatWindow_IsVisible(RawrXDChatWindowHandle handle);

#ifdef __cplusplus
}

namespace RawrXD {
namespace UI {

// C++ class forward declaration
class ChatWindow;

} // namespace UI
} // namespace RawrXD

#endif // __cplusplus