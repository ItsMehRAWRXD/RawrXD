#pragma once

#include <QDialog>
#include <QTextEdit>
#include <QPushButton>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QLabel>

/**
 * @brief DiffViewer - Side-by-side diff viewer with accept/reject functionality
 * 
 * Ported from diff_engine.asm MASM implementation.
 * Provides a visual comparison between original and suggested code changes.
 */
class DiffViewer : public QDialog {
    Q_OBJECT

public:
    explicit DiffViewer(QWidget* parent = nullptr);
    ~DiffViewer();

    // Show diff (from MASM DiffEngine_Show)
    void showDiff(const QString& filePath, const QString& original, const QString& modified);

    // Highlight changes (from MASM DiffEngine_HighlightChanges)
    void highlightChanges();

signals:
    void accepted(const QString& filePath, const QString& newContent);
    void rejected(const QString& filePath);

private slots:
    // Button handlers (from MASM DiffEngine_OnAccept / DiffEngine_OnReject)
    void onAccept();
    void onReject();

private:
    QString m_filePath;
    QTextEdit* m_oldEdit{nullptr};
    QTextEdit* m_newEdit{nullptr};
    QPushButton* m_acceptBtn{nullptr};
    QPushButton* m_rejectBtn{nullptr};

    // Helper methods
    void setupUi();
    void applyDiffStyles();
};
