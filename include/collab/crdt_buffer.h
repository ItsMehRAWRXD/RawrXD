
#ifndef CRDT_BUFFER_H
#define CRDT_BUFFER_H

#include <string>
#include <functional>

// CRDT text buffer → conflict-free multi-user edits (Win32 native, no Qt)
class CRDTBuffer
{
public:
    explicit CRDTBuffer();

    // Apply remote operation
    void applyRemoteOperation(const std::string &operationJson);

    // Get current text
    std::string getText() const { return m_text; }

    // Insert text at position
    void insertText(int position, const std::string &text);

    // Delete text from position
    void deleteText(int position, int length);

    // Callbacks (replacing Qt signals)
    std::function<void(const std::string&)> m_onTextChanged;
    std::function<void(const std::string&)> m_onOperationGenerated;

private:
    std::string m_text;
};

#endif // CRDT_BUFFER_H

