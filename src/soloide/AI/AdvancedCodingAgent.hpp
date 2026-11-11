#pragma once
#include <QObject>
#include <QString>
#include "MultiModalModelRouter.hpp"

namespace SoloIDE {

class AdvancedCodingAgent : public QObject {
    Q_OBJECT
public:
    explicit AdvancedCodingAgent(MultiModalModelRouter* router, QObject* parent = nullptr);
    ~AdvancedCodingAgent() override;

    void chat(const QString& message);
    void explain(const QString& code);
    void generateTests(const QString& code);
    void optimize(const QString& code);

signals:
    void responseReady(const QString& response);
    void actionCompleted(const QString& action, bool success);

private:
    MultiModalModelRouter* m_router;
};

} // namespace SoloIDE
