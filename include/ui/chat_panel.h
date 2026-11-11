
#pragma once

#include <string>
#include <vector>
#include <functional>

#ifdef _WIN32
#include <windows.h>
#endif

namespace RawrXD {
namespace UI {

struct ToolActionStatus;

enum class MdTokenKind { Text, Bold, Italic, Code, CodeBlock, Heading, BulletItem };

struct MdToken {
    MdTokenKind kind;
    std::string text;
    std::string meta;
};

class ChatPanel {
public:
    bool create(HWND parent, int idBase);
    void resize(int x, int y, int w, int h);
    void appendMessage(const std::string& who, const std::string& text);
    void appendToolAction(const ToolActionStatus& action);
    void appendWorkingBubble(const struct WorkingBubble& bubble);
    void setDarkMode(bool dark);
    void setFontSize(int size);
    std::string getInput() const;
    void clearInput();
    bool handleCommand(WPARAM wParam, LPARAM lParam);
    HWND hwnd() const { return m_container; }

    using SendCallback = std::function<void(const std::string&)>;
    void setSendCallback(SendCallback cb) { m_sendCallback = cb; }

private:
    HWND m_container{nullptr};
    HWND m_transcript{nullptr};
    HWND m_input{nullptr};
    HWND m_send{nullptr};
    int m_idBase = 0;
    SendCallback m_sendCallback;

    // Colors
    COLORREF m_bgColor = RGB(30, 30, 30);
    COLORREF m_fgColor = RGB(220, 220, 220);
    COLORREF m_codeColor = RGB(86, 156, 214);
    COLORREF m_headingColor = RGB(0, 188, 235);
    COLORREF m_bulletColor = RGB(180, 180, 180);
    COLORREF m_userColor = RGB(0, 188, 235);
    COLORREF m_assistantColor = RGB(200, 150, 255);
    COLORREF m_toolIconColor = RGB(150, 150, 150);
    int m_fontSize = 10;
    bool m_darkMode = true;

    // Markdown parsing
    std::vector<MdToken> parseMarkdown(const std::string& text) const;

    // RichEdit formatting helpers
    void setCharFormat(DWORD effects, COLORREF color, int heightTwips, const wchar_t* face);
    void appendPlainText(const std::wstring& text);
    void appendBoldText(const std::wstring& text);
    void appendItalicText(const std::wstring& text);
    void appendCodeSpan(const std::wstring& text);
    void appendCodeBlock(const std::string& lang, const std::wstring& code);
    void appendHeading(const std::wstring& text, int level);
    void appendBullet(const std::wstring& text);
    void appendSeparator();
    void appendRichTokens(const std::string& who, const std::vector<MdToken>& tokens);
};

} // namespace UI
} // namespace RawrXD

