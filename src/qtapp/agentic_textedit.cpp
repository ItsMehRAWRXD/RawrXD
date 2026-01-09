/**
 * @file agentic_textedit.cpp
 * @brief Implementation of RawrXD::AgenticTextEdit - AI-powered code editor widget
 */

#include "agentic_textedit.hpp"
#include <QTextEdit>
#include <QSyntaxHighlighter>
#include <QTextDocument>
#include <QTextBlock>
#include <QDebug>
#include <QRegularExpression>
#include <QFont>

namespace RawrXD {

class CodeSyntaxHighlighter : public QSyntaxHighlighter {
public:
    CodeSyntaxHighlighter(QTextDocument* parent = nullptr) : QSyntaxHighlighter(parent) {}
    
    void highlightBlock(const QString& text) override {
        // Simple keyword highlighting
        QTextCharFormat keywordFormat;
        keywordFormat.setForeground(Qt::darkBlue);
        keywordFormat.setFontWeight(QFont::Bold);
        
        QStringList keywords = {"class", "struct", "void", "int", "float", "double", 
                               "bool", "const", "static", "auto", "return", "if", "else",
                               "for", "while", "switch", "case", "break", "continue",
                               "public", "private", "protected", "namespace", "template"};
        
        for (const auto& keyword : keywords) {
            QRegularExpression pattern("\\b" + keyword + "\\b");
            auto matches = pattern.globalMatch(text);
            while (matches.hasNext()) {
                auto match = matches.next();
                setFormat(match.capturedStart(), match.capturedLength(), keywordFormat);
            }
        }
        
        // Comment highlighting
        QTextCharFormat commentFormat;
        commentFormat.setForeground(Qt::darkGreen);
        
        QRegularExpression commentPattern("//[^\n]*");
        auto commentMatches = commentPattern.globalMatch(text);
        while (commentMatches.hasNext()) {
            auto match = commentMatches.next();
            setFormat(match.capturedStart(), match.capturedLength(), commentFormat);
        }
        
        // String highlighting
        QTextCharFormat stringFormat;
        stringFormat.setForeground(Qt::darkRed);
        
        QRegularExpression stringPattern("\"[^\"]*\"");
        auto stringMatches = stringPattern.globalMatch(text);
        while (stringMatches.hasNext()) {
            auto match = stringMatches.next();
            setFormat(match.capturedStart(), match.capturedLength(), stringFormat);
        }
    }
};

AgenticTextEditLegacy::AgenticTextEditLegacy(QWidget* parent)
    : QTextEdit(parent)
    , m_lspClient(nullptr)
    , m_highlighter(nullptr)
{
    setFont(QFont("Courier New", 10));
    setTabStopDistance(40);  // 4 spaces
}

void AgenticTextEditLegacy::initialize()
{
    // Set up syntax highlighting
    if (!m_highlighter) {
        m_highlighter = new CodeSyntaxHighlighter(document());
    }
    
    // Connect document changes for auto-save
    connect(document(), &QTextDocument::contentsChanged, this, [this]() {
        emit contentChanged();
    });
}

void AgenticTextEditLegacy::setLSPClient(LSPClient* client)
{
    m_lspClient = client;
    if (m_lspClient) {
        // Connect LSP signals for completion, hover, etc.
        // This will be implemented when LSPClient is fully defined
    }
}

void AgenticTextEditLegacy::setDocumentUri(const QString& uri)
{
    m_documentUri = uri;
    if (m_lspClient) {
        // Notify LSP server of document open
        // m_lspClient->notifyDocumentOpen(uri, toPlainText());
    }
}

void AgenticTextEditLegacy::applyCompletion(const QString& completion)
{
    QTextCursor cursor = textCursor();
    
    // Find the word start
    cursor.movePosition(QTextCursor::StartOfWord, QTextCursor::KeepAnchor);
    
    // Insert completion
    cursor.insertText(completion);
    setTextCursor(cursor);
}

void AgenticTextEditLegacy::applySyntaxFix(const QString& fixedCode)
{
    setPlainText(fixedCode);
    emit syntaxFixed();
}

void AgenticTextEditLegacy::showCodeLens(const QString& hint)
{
    // Display code lens hint above current line
    emit codeLensUpdated(hint);
}

QString AgenticTextEditLegacy::getSelectedText() const
{
    return textCursor().selectedText();
}

int AgenticTextEditLegacy::getCurrentLineNumber() const
{
    return textCursor().blockNumber() + 1;
}

int AgenticTextEditLegacy::getCurrentColumnNumber() const
{
    return textCursor().positionInBlock() + 1;
}

QString AgenticTextEditLegacy::getLineText(int lineNumber) const
{
    if (lineNumber < 1) return "";
    
    QTextDocument* doc = document();
    QTextBlock block = doc->findBlockByLineNumber(lineNumber - 1);
    return block.text();
}

void AgenticTextEditLegacy::insertAtLine(int lineNumber, const QString& text)
{
    QTextDocument* doc = document();
    QTextBlock block = doc->findBlockByLineNumber(lineNumber - 1);
    
    if (block.isValid()) {
        QTextCursor cursor(block);
        cursor.movePosition(QTextCursor::EndOfBlock);
        cursor.insertText("\n" + text);
    }
}

void AgenticTextEditLegacy::replaceLine(int lineNumber, const QString& text)
{
    QTextDocument* doc = document();
    QTextBlock block = doc->findBlockByLineNumber(lineNumber - 1);
    
    if (block.isValid()) {
        QTextCursor cursor(block);
        cursor.select(QTextCursor::LineUnderCursor);
        cursor.insertText(text);
    }
}

void AgenticTextEditLegacy::deleteRange(int startLine, int startCol, int endLine, int endCol)
{
    QTextDocument* doc = document();
    
    QTextBlock startBlock = doc->findBlockByLineNumber(startLine - 1);
    QTextBlock endBlock = doc->findBlockByLineNumber(endLine - 1);
    
    if (startBlock.isValid() && endBlock.isValid()) {
        QTextCursor cursor(startBlock);
        cursor.setPosition(startBlock.position() + startCol);
        
        QTextCursor endCursor(endBlock);
        endCursor.setPosition(endBlock.position() + endCol);
        
        cursor.setPosition(endCursor.position(), QTextCursor::KeepAnchor);
        cursor.removeSelectedText();
    }
}

} // namespace RawrXD
