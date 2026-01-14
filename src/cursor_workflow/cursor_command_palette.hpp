#pragma once
#include "../qtapp/command_palette.hpp"
#include "../agentic/agentic_engine.h"

class CursorCommandPalette : public CommandPalette {
    Q_OBJECT
public:
    CursorCommandPalette(AgenticEngine* engine, QWidget* parent = nullptr);
    
    void registerCursorCommands();
    
private slots:
    // Core Cursor commands
    void cmdK_explain();
    void cmdK_refactor();
    void cmdK_generateTests();
    void cmdK_fixBug();
    void cmdK_optimizeCode();
    void cmdK_addComments();
    void cmdK_generateFunction();
    void cmdK_extractVariable();
    void cmdK_inlineVariable();
    void cmdK_renameSymbol();
    
    // Multi-file operations
    void cmdK_findUsages();
    void cmdK_goToDefinition();
    void cmdK_implementInterface();
    void cmdK_generateClass();
    void cmdK_createModule();
    
    // AI-powered workflows
    void cmdK_explainError();
    void cmdK_suggestFix();
    void cmdK_generateDocumentation();
    void cmdK_reviewCode();
    void cmdK_securityScan();
    
    // GitHub Copilot style
    void cmdK_chatWithAI();
    void cmdK_generateCommitMessage();
    void cmdK_reviewPR();
    void cmdK_createIssue();
    
private:
    AgenticEngine* m_agenticEngine;
    QString getCurrentSelection();
    QString getCurrentFile();
    void executeAICommand(const QString& command, const QString& context);
};
