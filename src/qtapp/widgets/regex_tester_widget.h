/**
 * @file regex_tester_widget.h
 * @brief Full Regex Tester Widget implementation for RawrXD IDE
 * @author RawrXD Team
 */

#pragma once

#include <QWidget>
#include <QTextEdit>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QComboBox>
#include <QCheckBox>
#include <QPushButton>
#include <QLabel>
#include <QSplitter>
#include <QTreeWidget>
#include <QTableWidget>
#include <QTabWidget>
#include <QToolBar>
#include <QListWidget>
#include <QSettings>
#include <QRegularExpression>
#include <QSyntaxHighlighter>
#include <QTimer>
#include <QUndoStack>

/**
 * @brief Structure representing a single regex match
 */
struct RegexMatch {
    int start;
    int end;
    QString text;
    QVector<QPair<QString, QString>> groups;  // name -> value
};

/**
 * @brief Structure for regex pattern info
 */
struct PatternInfo {
    QString pattern;
    QString description;
    QRegularExpression::PatternOptions options;
    QString category;
};

/**
 * @brief Highlighter for matched text in the test input
 */
class MatchHighlighter : public QSyntaxHighlighter {
    Q_OBJECT

public:
    explicit MatchHighlighter(QTextDocument* parent = nullptr);
    
    void setMatches(const QVector<RegexMatch>& matches);
    void setCurrentMatchIndex(int index);
    void setColors(const QVector<QColor>& colors);

protected:
    void highlightBlock(const QString& text) override;

private:
    QVector<RegexMatch> m_matches;
    int m_currentMatchIndex = -1;
    QVector<QColor> m_colors;
};

/**
 * @brief Highlighter for regex pattern syntax
 */
class RegexSyntaxHighlighter : public QSyntaxHighlighter {
    Q_OBJECT

public:
    explicit RegexSyntaxHighlighter(QTextDocument* parent = nullptr);

protected:
    void highlightBlock(const QString& text) override;

private:
    struct HighlightRule {
        QRegularExpression pattern;
        QTextCharFormat format;
    };
    QVector<HighlightRule> m_rules;
};

/**
 * @brief Full Regex Tester Widget
 * 
 * Features:
 * - Real-time regex matching with multiple modes
 * - Capture group extraction and naming
 * - Replacement preview with backreferences
 * - Match highlighting with navigation
 * - Pattern library with common patterns
 * - Regex explanation/breakdown
 * - Pattern history and favorites
 * - Export matches to various formats
 * - Multi-line and single-line modes
 * - Pattern validation and error highlighting
 */
class RegexTesterWidget : public QWidget {
    Q_OBJECT

public:
    enum MatchMode {
        MatchAll,      // Find all matches
        MatchFirst,    // Find first match only
        MatchFullText  // Pattern must match entire string
    };
    Q_ENUM(MatchMode)

    explicit RegexTesterWidget(QWidget* parent = nullptr);
    ~RegexTesterWidget();

    // Pattern management
    void setPattern(const QString& pattern);
    QString getPattern() const;
    
    void setTestText(const QString& text);
    QString getTestText() const;
    
    void setReplacement(const QString& replacement);
    QString getReplacement() const;
    
    // Options
    void setMatchMode(MatchMode mode);
    MatchMode getMatchMode() const { return m_matchMode; }
    
    void setCaseSensitive(bool sensitive);
    void setMultilineMode(bool enabled);
    void setDotMatchesAll(bool enabled);
    void setExtendedSyntax(bool enabled);
    void setUnicodeMode(bool enabled);
    
    // Results
    QVector<RegexMatch> getMatches() const { return m_matches; }
    int getMatchCount() const { return m_matches.size(); }
    QString getReplacementResult() const;
    
    // Pattern library
    void loadPatternLibrary();
    void addToFavorites(const QString& pattern, const QString& description);

signals:
    void patternChanged(const QString& pattern);
    void matchesUpdated(int count);
    void patternError(const QString& error);
    void replacementReady(const QString& result);

public slots:
    void runMatch();
    void runReplace();
    void clearResults();
    void copyMatches();
    void exportMatches();
    void navigateToMatch(int index);
    void navigateNext();
    void navigatePrevious();

private slots:
    void onPatternChanged();
    void onTestTextChanged();
    void onOptionsChanged();
    void onPatternLibraryItemSelected(QTreeWidgetItem* item);
    void onHistoryItemSelected(QListWidgetItem* item);

private:
    void setupUI();
    void setupToolbar();
    void setupPatternInput();
    void setupTestInput();
    void setupResultsView();
    void setupPatternLibrary();
    void setupReplacementPanel();
    void connectSignals();
    
    void updateMatches();
    void updateMatchDisplay();
    void updateReplacementPreview();
    void updateExplanation();
    void highlightMatches();
    
    QRegularExpression::PatternOptions getCurrentOptions() const;
    QString explainPattern(const QString& pattern);
    void addToHistory(const QString& pattern);
    void loadHistory();
    void saveHistory();
    
    QString formatMatchForExport(const RegexMatch& match, const QString& format);

private:
    // UI Components
    QToolBar* m_toolbar;
    QSplitter* m_mainSplitter;
    QSplitter* m_leftSplitter;
    QTabWidget* m_rightTabWidget;
    
    // Pattern input
    QTextEdit* m_patternEdit;
    RegexSyntaxHighlighter* m_patternHighlighter;
    QLabel* m_patternStatusLabel;
    QPushButton* m_matchBtn;
    QPushButton* m_replaceBtn;
    
    // Options
    QComboBox* m_modeCombo;
    QCheckBox* m_caseSensitiveCheck;
    QCheckBox* m_multilineCheck;
    QCheckBox* m_dotAllCheck;
    QCheckBox* m_extendedCheck;
    QCheckBox* m_unicodeCheck;
    
    // Test input
    QPlainTextEdit* m_testInput;
    MatchHighlighter* m_matchHighlighter;
    
    // Results
    QTableWidget* m_matchTable;
    QTreeWidget* m_groupTree;
    QLabel* m_matchCountLabel;
    QPushButton* m_prevMatchBtn;
    QPushButton* m_nextMatchBtn;
    
    // Replacement
    QLineEdit* m_replacementEdit;
    QTextEdit* m_replacementPreview;
    QPushButton* m_copyReplacementBtn;
    
    // Pattern library
    QTreeWidget* m_libraryTree;
    QListWidget* m_historyList;
    QListWidget* m_favoritesList;
    
    // Explanation
    QTextEdit* m_explanationView;
    
    // State
    QVector<RegexMatch> m_matches;
    int m_currentMatchIndex = 0;
    MatchMode m_matchMode = MatchAll;
    QStringList m_history;
    QVector<PatternInfo> m_favorites;
    QTimer* m_updateTimer;
    QSettings* m_settings;
    
    // Pattern library data
    QVector<PatternInfo> m_patternLibrary;
};
