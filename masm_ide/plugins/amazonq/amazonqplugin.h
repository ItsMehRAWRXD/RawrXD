#pragma once

#include <extensionsystem/iplugin.h>
#include <QObject>
#include <QAction>
#include <QMenu>
#include <QNetworkAccessManager>
#include <QJsonObject>

class QTextEdit;
class QDockWidget;
class QWebEngineView;

namespace AmazonQ {

class BedrockClient;
class ChatWidget;
class CompletionProvider;

class AmazonQPlugin : public ExtensionSystem::IPlugin
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID "org.qt-project.Qt.QtCreatorPlugin" FILE "plugin.json")

public:
    AmazonQPlugin();
    ~AmazonQPlugin() override;

    bool initialize(const QStringList &arguments, QString *errorString) override;
    void extensionsInitialized() override;
    ShutdownFlag aboutToShutdown() override;

private slots:
    void openChatPanel();
    void requestCompletion();
    void explainCode();
    void reviewCode();
    void generateTests();
    void optimizeCode();

private:
    void setupMenus();
    void setupDockWidget();
    void setupCompletionProvider();
    void loadBedrockConfig();

    QAction *m_chatAction;
    QAction *m_completionAction;
    QAction *m_explainAction;
    QAction *m_reviewAction;
    QAction *m_testAction;
    QAction *m_optimizeAction;
    
    QMenu *m_amazonQMenu;
    QDockWidget *m_chatDock;
    ChatWidget *m_chatWidget;
    CompletionProvider *m_completionProvider;
    BedrockClient *m_bedrockClient;
    
    QString m_bedrockEndpoint;
    QString m_awsRegion;
    QString m_modelId;
    bool m_useExistingBedrock;
};

} // namespace AmazonQ