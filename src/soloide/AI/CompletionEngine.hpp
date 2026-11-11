#pragma once
#include <QObject>
#include <QString>
#include <QPoint>
#include "MultiModalModelRouter.hpp"

namespace SoloIDE {

class CompletionEngine : public QObject {
    Q_OBJECT
public:
    explicit CompletionEngine(MultiModalModelRouter* router, QObject* parent = nullptr);
    ~CompletionEngine() override;

    void requestCompletion(const QString& text, const QPoint& cursorPos);
    void cancelCompletion();
    bool isComputing() const { return m_computing; }

signals:
    void completionReady(const QString& ghostText);
    void completionFailed(const QString& reason);

private:
    MultiModalModelRouter* m_router;
    bool m_computing = false;
};

} // namespace SoloIDE
