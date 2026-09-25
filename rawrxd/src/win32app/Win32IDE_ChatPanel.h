// Win32IDE_ChatPanel.h — ChatPanel API header
#pragma once
#include <string>

namespace RawrXD::IDE {

enum class MsgRole { User, Assistant, System, Tool };

void ChatPanel_AddMessage(MsgRole role, const std::string& text);
void ChatPanel_BeginStreaming();
void ChatPanel_AppendStreamToken(const std::string& token);
void ChatPanel_EndStreaming();
void ChatPanel_SetSendCallback(std::function<void(const std::string&)> cb);
void ChatPanel_Clear();

} // namespace RawrXD::IDE
