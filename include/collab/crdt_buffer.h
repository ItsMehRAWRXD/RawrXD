// crdt_buffer.h — product Collab string buffer (NEURAL_CRDT_GATE_001)
// SOURCE_WIRED via Win32IDE_Collab + src/collab/crdt_buffer.cpp.
// SYNTHETIC=partial: position insert/delete + naive JSON op apply.
// NOT conflict-free CRDT (no site/tombstone/merge). NOT CRDT_PASS.
// PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0. ABSORB=NOT_AUTHORIZED.

#ifndef CRDT_BUFFER_H
#define CRDT_BUFFER_H

#include <string>
#include <functional>

// OT-lite collaborative text buffer (Win32 native, no Qt). Not a real CRDT.
class CRDTBuffer
{
public:
    explicit CRDTBuffer();

    // Apply remote operation (JSON or legacy INSERT:/DELETE: forms)
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
