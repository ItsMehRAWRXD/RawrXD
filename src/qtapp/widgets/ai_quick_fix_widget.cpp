#include "ai_quick_fix_widget.h"
#include <QHBoxLayout>

AIQuickFixWidget::AIQuickFixWidget(QWidget* parent) : QWidget(parent)
{
    QVBoxLayout* layout = new QVBoxLayout(this);
    
    QLabel* title = new QLabel("AI Quick Fix", this);
    title->setStyleSheet("font-size: 16px; font-weight: bold; color: #ffffff;");
    layout->addWidget(title);
    
    // Issue description
    QLabel* issueLabel = new QLabel("Detected Issues", this);
    issueLabel->setStyleSheet("font-size: 14px; color: #cccccc;");
    layout->addWidget(issueLabel);
    
    m_issueList = new QListWidget(this);
    m_issueList->setStyleSheet("background-color: #2d2d2d; color: #e0e0e0; border: 1px solid #404040;");
    m_issueList->addItem("Unused variable 'temp'");
    m_issueList->addItem("Missing include directive");
    m_issueList->addItem("Potential memory leak");
    layout->addWidget(m_issueList);
    
    // Solution
    QLabel* solutionLabel = new QLabel("Suggested Fix", this);
    solutionLabel->setStyleSheet("font-size: 14px; color: #cccccc;");
    layout->addWidget(solutionLabel);
    
    m_solutionText = new QTextEdit(this);
    m_solutionText->setStyleSheet("background-color: #1e1e1e; color: #d4d4d4; border: 1px solid #404040;");
    m_solutionText->setPlainText("// AI-generated fix\n// Remove unused variable or use it properly");
    layout->addWidget(m_solutionText);
    
    // Buttons
    QHBoxLayout* buttonLayout = new QHBoxLayout();
    
    m_analyzeButton = new QPushButton("Analyze Code", this);
    connect(m_analyzeButton, &QPushButton::clicked, this, &AIQuickFixWidget::analyzeCode);
    buttonLayout->addWidget(m_analyzeButton);
    
    m_applyButton = new QPushButton("Apply Fix", this);
    connect(m_applyButton, &QPushButton::clicked, this, &AIQuickFixWidget::applyFix);
    buttonLayout->addWidget(m_applyButton);
    
    layout->addLayout(buttonLayout);
}

AIQuickFixWidget::~AIQuickFixWidget()
{
    // Cleanup if needed
}

void AIQuickFixWidget::applyFix()
{
    // Apply the suggested fix to the code
    // In real implementation, this would modify the source file
    m_solutionText->setPlainText("// Fix applied successfully!");
}

void AIQuickFixWidget::analyzeCode()
{
    // Analyze the current code for issues
    // In real implementation, this would use AI to analyze code
    m_issueList->clear();
    m_issueList->addItem("Analyzing code...");
}