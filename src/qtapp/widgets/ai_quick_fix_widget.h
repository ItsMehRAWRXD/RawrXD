#pragma once

#include <QWidget>
#include <QVBoxLayout>
#include <QLabel>
#include <QTextEdit>
#include <QPushButton>
#include <QListWidget>

class AIQuickFixWidget : public QWidget
{
    Q_OBJECT

public:
    explicit AIQuickFixWidget(QWidget* parent = nullptr);
    ~AIQuickFixWidget();

private slots:
    void applyFix();
    void analyzeCode();

private:
    QListWidget* m_issueList;
    QTextEdit* m_solutionText;
    QPushButton* m_applyButton;
    QPushButton* m_analyzeButton;
};
