#pragma once
#include <QObject>
#include <QString>

namespace SoloIDE {

class LSPClient : public QObject {
    Q_OBJECT
public:
    explicit LSPClient(QObject* parent = nullptr);
    ~LSPClient() override;

    void initialize(const QString& projectPath);
    void openFile(const QString& file);
    void closeFile(const QString& file);
    void textChanged(const QString& file, const QString& text, int version);
    void requestCompletion(const QString& file, int line, int character);

    bool isInitialized() const { return m_initialized; }

signals:
    void diagnosticsReady(const QString& file, const QVariantList& diagnostics);
    void completionReady(const QVariantList& completions);

private:
    bool m_initialized = false;
};

} // namespace SoloIDE
