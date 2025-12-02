#pragma once
#include <windows.h>
#include <string>

namespace RawrXD {
namespace UI {

// ChatPanel: composite bottom view with transcript + input + send
class ChatPanel {
public:
    ChatPanel() = default;
    bool create(HWND parent, int idBase = 40000);
    void resize(int x, int y, int w, int h);
    void appendMessage(const std::string& who, const std::string& text);
    std::string getInput() const;
    void clearInput();
    HWND hwnd() const { return m_container; }
    HWND transcript() const { return m_transcript; }
    HWND input() const { return m_input; }
    HWND sendBtn() const { return m_send; }

private:
    HWND m_container = nullptr;
    HWND m_transcript = nullptr;
    HWND m_input = nullptr;
    HWND m_send = nullptr;
};

} // namespace UI
} // namespace RawrXD
