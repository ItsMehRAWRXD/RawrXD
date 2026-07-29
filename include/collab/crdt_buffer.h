<<<<<<< HEAD
#ifndef CRDT_BUFFER_H
#define CRDT_BUFFER_H

// C++20, no Qt. CRDT text buffer; callbacks replace signals.

#include <string>
#include <functional>

class CRDTBuffer
{
public:
    using TextChangedFn    = std::function<void(const std::string& newText)>;
    using OperationGeneratedFn = std::function<void(const std::string& operation)>;

    CRDTBuffer() = default;

    void setOnTextChanged(TextChangedFn f)         { m_onTextChanged = std::move(f); }
    void setOnOperationGenerated(OperationGeneratedFn f) { m_onOperationGenerated = std::move(f); }

    void applyRemoteOperation(const std::string& operation);
    std::string getText() const { return m_text; }
    void insertText(int position, const std::string& text);
    void deleteText(int position, int length);

private:
    std::string m_text;
    TextChangedFn    m_onTextChanged;
    OperationGeneratedFn m_onOperationGenerated;
};

#endif // CRDT_BUFFER_H
=======
#ifndef CRDT_BUFFER_H
#define CRDT_BUFFER_H

#include <QObject>
#include <QString>

// CRDT text buffer → conflict-free multi-user edits
class CRDTBuffer : public QObject
{
    Q_OBJECT

public:
    explicit CRDTBuffer(QObject *parent = nullptr);

    // Apply remote operation
    void applyRemoteOperation(const QString &operation);

    // Get current text
    QString getText() const;

    // Insert text at position
    void insertText(int position, const QString &text);

    // Delete text from position
    void deleteText(int position, int length);

signals:
    // Emitted when text changes
    void textChanged(const QString &newText);

    // Emitted when operation needs to be sent to other clients
    void operationGenerated(const QString &operation);

private:
    QString m_text;
};

#endif // CRDT_BUFFER_H
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
