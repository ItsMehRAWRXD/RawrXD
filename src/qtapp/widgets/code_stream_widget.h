/**
 * @file code_stream_widget.h
 * @brief Header for CodeStreamWidget - Live code streaming and diff visualization
 */

#pragma once

#include <QWidget>
#include <QString>
#include <QList>

class QVBoxLayout;
class QHBoxLayout;
class QTextEdit;
class QPushButton;
class QLabel;
class QComboBox;
class QSplitter;
class QListWidget;

struct CodeDiff {
    QString operation; // "add", "remove", "modify"
    int lineNumber;
    QString oldCode;
    QString newCode;
    QString timestamp;
};

class CodeStreamWidget : public QWidget {
    Q_OBJECT
    
public:
    explicit CodeStreamWidget(QWidget* parent = nullptr);
    ~CodeStreamWidget();
    
public slots:
    void onStartStream();
    void onStopStream();
    void onClearHistory();
    void onApplyDiff(int index);
    void onRejectDiff(int index);
    void onViewDiff(int index);
    void onExportStream();
    void onCompareVersions();
    void updateStreamStatus(const QString& status);
    
signals:
    void streamStarted();
    void streamStopped();
    void diffApplied(const CodeDiff& diff);
    void streamExported(const QString& filename);
    
private:
    void setupUI();
    void createDiffPanel();
    void connectSignals();
    void populateDiffList();
    void restoreState();
    void saveState();
    
    // UI Components
    QVBoxLayout* mMainLayout;
    QHBoxLayout* mControlLayout;
    QHBoxLayout* mCompareLayout;
    
    // Stream control
    QPushButton* mStartButton;
    QPushButton* mStopButton;
    QPushButton* mClearButton;
    QLabel* mStatusLabel;
    QLabel* mStreamDurationLabel;
    
    // Diff display
    QSplitter* mSplitter;
    QListWidget* mDiffListWidget;
    
    // Code comparison
    QTextEdit* mOldCodeEditor;
    QTextEdit* mNewCodeEditor;
    
    // Diff actions
    QPushButton* mApplyButton;
    QPushButton* mRejectButton;
    QPushButton* mViewButton;
    
    // Additional controls
    QLabel* mVersionLabel;
    QComboBox* mVersionCombo;
    QPushButton* mCompareButton;
    QPushButton* mExportButton;
    
    // State tracking
    bool mStreamActive;
    QList<CodeDiff> mDiffHistory;
};


