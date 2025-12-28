#include "amazonqplugin.h"
#include "bedrocklient.h"
#include "chatwidget.h"
#include "completionprovider.h"

#include <coreplugin/icore.h>
#include <coreplugin/actionmanager/actionmanager.h>
#include <coreplugin/actionmanager/command.h>
#include <coreplugin/actionmanager/actioncontainer.h>
#include <coreplugin/coreconstants.h>
#include <texteditor/texteditor.h>
#include <texteditor/textdocument.h>

#include <QAction>
#include <QMenu>
#include <QMenuBar>
#include <QDockWidget>
#include <QSettings>
#include <QMessageBox>
#include <QApplication>

using namespace Core;
using namespace TextEditor;

namespace AmazonQ {

AmazonQPlugin::AmazonQPlugin()
    : m_chatAction(nullptr)
    , m_completionAction(nullptr)
    , m_explainAction(nullptr)
    , m_reviewAction(nullptr)
    , m_testAction(nullptr)
    , m_optimizeAction(nullptr)
    , m_amazonQMenu(nullptr)
    , m_chatDock(nullptr)
    , m_chatWidget(nullptr)
    , m_completionProvider(nullptr)
    , m_bedrockClient(nullptr)
    , m_useExistingBedrock(true)
{
}

AmazonQPlugin::~AmazonQPlugin()
{
    delete m_bedrockClient;
    delete m_completionProvider;
}

bool AmazonQPlugin::initialize(const QStringList &arguments, QString *errorString)
{
    Q_UNUSED(arguments)
    Q_UNUSED(errorString)

    loadBedrockConfig();
    
    // Initialize Bedrock client with existing configuration
    m_bedrockClient = new BedrockClient(this);
    m_bedrockClient->setEndpoint(m_bedrockEndpoint);
    m_bedrockClient->setRegion(m_awsRegion);
    m_bedrockClient->setModelId(m_modelId);
    m_bedrockClient->setUseExistingConfig(m_useExistingBedrock);

    setupMenus();
    setupDockWidget();
    setupCompletionProvider();

    return true;
}

void AmazonQPlugin::extensionsInitialized()
{
    // Plugin is fully loaded
}

ExtensionSystem::IPlugin::ShutdownFlag AmazonQPlugin::aboutToShutdown()
{
    return SynchronousShutdown;
}

void AmazonQPlugin::setupMenus()
{
    ActionContainer *menu = ActionManager::createMenu("AmazonQ.Menu");
    menu->menu()->setTitle("Amazon Q");
    menu->setOnAllDisabledBehavior(ActionContainer::Show);

    // Chat action
    m_chatAction = new QAction("Open Chat Panel", this);
    Command *chatCmd = ActionManager::registerAction(m_chatAction, "AmazonQ.Chat");
    chatCmd->setDefaultKeySequence(QKeySequence("Ctrl+Shift+Q"));
    menu->addAction(chatCmd);
    connect(m_chatAction, &QAction::triggered, this, &AmazonQPlugin::openChatPanel);

    menu->addSeparator();

    // Code completion action
    m_completionAction = new QAction("Request Completion", this);
    Command *completionCmd = ActionManager::registerAction(m_completionAction, "AmazonQ.Completion");
    completionCmd->setDefaultKeySequence(QKeySequence("Ctrl+Space"));
    menu->addAction(completionCmd);
    connect(m_completionAction, &QAction::triggered, this, &AmazonQPlugin::requestCompletion);

    // Explain code action
    m_explainAction = new QAction("Explain Code", this);
    Command *explainCmd = ActionManager::registerAction(m_explainAction, "AmazonQ.Explain");
    explainCmd->setDefaultKeySequence(QKeySequence("Ctrl+Shift+E"));
    menu->addAction(explainCmd);
    connect(m_explainAction, &QAction::triggered, this, &AmazonQPlugin::explainCode);

    // Review code action
    m_reviewAction = new QAction("Review Code", this);
    Command *reviewCmd = ActionManager::registerAction(m_reviewAction, "AmazonQ.Review");
    reviewCmd->setDefaultKeySequence(QKeySequence("Ctrl+Shift+R"));
    menu->addAction(reviewCmd);
    connect(m_reviewAction, &QAction::triggered, this, &AmazonQPlugin::reviewCode);

    // Generate tests action
    m_testAction = new QAction("Generate Tests", this);
    Command *testCmd = ActionManager::registerAction(m_testAction, "AmazonQ.Tests");
    testCmd->setDefaultKeySequence(QKeySequence("Ctrl+Shift+T"));
    menu->addAction(testCmd);
    connect(m_testAction, &QAction::triggered, this, &AmazonQPlugin::generateTests);

    // Optimize code action
    m_optimizeAction = new QAction("Optimize Code", this);
    Command *optimizeCmd = ActionManager::registerAction(m_optimizeAction, "AmazonQ.Optimize");
    optimizeCmd->setDefaultKeySequence(QKeySequence("Ctrl+Shift+O"));
    menu->addAction(optimizeCmd);
    connect(m_optimizeAction, &QAction::triggered, this, &AmazonQPlugin::optimizeCode);

    // Add to main menu bar
    ActionContainer *menuBar = ActionManager::actionContainer(Core::Constants::MENU_BAR);
    menuBar->addMenu(menu);
}

void AmazonQPlugin::setupDockWidget()
{
    m_chatWidget = new ChatWidget(m_bedrockClient);
    
    m_chatDock = new QDockWidget("Amazon Q Chat", ICore::mainWindow());
    m_chatDock->setWidget(m_chatWidget);
    m_chatDock->setObjectName("AmazonQChatDock");
    
    ICore::mainWindow()->addDockWidget(Qt::RightDockWidgetArea, m_chatDock);
    m_chatDock->hide(); // Initially hidden
}

void AmazonQPlugin::setupCompletionProvider()
{
    m_completionProvider = new CompletionProvider(m_bedrockClient, this);
    // Register with text editor for auto-completion
}

void AmazonQPlugin::loadBedrockConfig()
{
    QSettings settings;
    settings.beginGroup("AmazonQ");
    
    // Use existing Bedrock configuration by default
    m_useExistingBedrock = settings.value("useExistingBedrock", true).toBool();
    m_bedrockEndpoint = settings.value("bedrockEndpoint", "https://bedrock-runtime.us-east-1.amazonaws.com").toString();
    m_awsRegion = settings.value("awsRegion", "us-east-1").toString();
    m_modelId = settings.value("modelId", "anthropic.claude-3-sonnet-20240229-v1:0").toString();
    
    settings.endGroup();
}

void AmazonQPlugin::openChatPanel()
{
    if (m_chatDock) {
        m_chatDock->show();
        m_chatDock->raise();
        m_chatWidget->focusInput();
    }
}

void AmazonQPlugin::requestCompletion()
{
    if (auto editor = TextEditor::TextEditorWidget::currentTextEditorWidget()) {
        QString code = editor->textDocument()->plainText();
        int cursorPos = editor->textCursor().position();
        
        if (m_completionProvider) {
            m_completionProvider->requestCompletion(code, cursorPos);
        }
    }
}

void AmazonQPlugin::explainCode()
{
    if (auto editor = TextEditor::TextEditorWidget::currentTextEditorWidget()) {
        QString selectedText = editor->textCursor().selectedText();
        if (selectedText.isEmpty()) {
            QMessageBox::information(ICore::mainWindow(), "Amazon Q", 
                "Please select some code to explain.");
            return;
        }
        
        openChatPanel();
        m_chatWidget->sendMessage("Explain this MASM assembly code:\n\n" + selectedText);
    }
}

void AmazonQPlugin::reviewCode()
{
    if (auto editor = TextEditor::TextEditorWidget::currentTextEditorWidget()) {
        QString selectedText = editor->textCursor().selectedText();
        if (selectedText.isEmpty()) {
            selectedText = editor->textDocument()->plainText();
        }
        
        openChatPanel();
        m_chatWidget->sendMessage("Review this MASM assembly code for potential issues and improvements:\n\n" + selectedText);
    }
}

void AmazonQPlugin::generateTests()
{
    if (auto editor = TextEditor::TextEditorWidget::currentTextEditorWidget()) {
        QString selectedText = editor->textCursor().selectedText();
        if (selectedText.isEmpty()) {
            selectedText = editor->textDocument()->plainText();
        }
        
        openChatPanel();
        m_chatWidget->sendMessage("Generate test cases for this MASM assembly code:\n\n" + selectedText);
    }
}

void AmazonQPlugin::optimizeCode()
{
    if (auto editor = TextEditor::TextEditorWidget::currentTextEditorWidget()) {
        QString selectedText = editor->textCursor().selectedText();
        if (selectedText.isEmpty()) {
            selectedText = editor->textDocument()->plainText();
        }
        
        openChatPanel();
        m_chatWidget->sendMessage("Optimize this MASM assembly code for performance:\n\n" + selectedText);
    }
}

} // namespace AmazonQ