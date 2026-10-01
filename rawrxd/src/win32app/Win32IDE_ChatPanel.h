// Win32IDE_ChatPanel.h — ChatPanel API header
#pragma once
#include <string>
#include <functional>
#include <cstddef>

namespace RawrXD::IDE {

enum class MsgRole { User, Assistant, System, Tool };

void ChatPanel_AddMessage(MsgRole role, const std::string& text);
void ChatPanel_BeginStreaming();
void ChatPanel_AppendStreamToken(const std::string& token);
void ChatPanel_EndStreaming();
void ChatPanel_SetSendCallback(std::function<void(const std::string&)> cb);
// RAWRXD_IDE_STOP_001: wired to the Stop button's WM_COMMAND handler.
void ChatPanel_SetCancelCallback(std::function<void()> cb);
void ChatPanel_Clear();

// Gate-evidence accessors. Read the same message store that ChatPaint renders,
// so a certification run can assert on exactly what the user sees.
size_t ChatPanel_MessageCount();
std::string ChatPanel_GetMessage(size_t index);
bool ChatPanel_IsLastStreaming();
size_t ChatPanel_StreamingTokenCount();

} // namespace RawrXD::IDE
