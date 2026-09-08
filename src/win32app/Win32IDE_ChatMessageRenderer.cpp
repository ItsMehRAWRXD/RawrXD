#include "Win32IDE.h"
#include "../ui/chat_message_renderer.h"
#include <windows.h>
#include <string>

void HandleChatMessageRenderer(void* idePtr) {
    Win32IDE* ide = static_cast<Win32IDE*>(idePtr);
    if (!ide) return;
    RawrXD::UI::ChatMessage msg;
    msg.id = "ide-chat-render";
    msg.role = RawrXD::UI::MessageRole::ASSISTANT;
    msg.rawContent = "```cpp\nint main(){return 0;}\n```";
    const auto render = RawrXD::UI::ChatMessageRenderer::Global().renderMessage(msg);
    std::string line = render.success
        ? "[ChatMessageRenderer] HTML ok\n"
        : std::string("[ChatMessageRenderer] FAIL ") +
              (render.detail ? render.detail : "") + "\n";
    ide->appendToOutput(line, "Chat",
                        render.success ? Win32IDE::OutputSeverity::Info
                                       : Win32IDE::OutputSeverity::Error);
    if (!render.success) {
        MessageBoxA(ide->getMainWindow(), line.c_str(), "Chat Message Renderer",
                    MB_ICONERROR | MB_OK);
    }
}
