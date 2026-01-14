/**
 * @file notebook_widget.cpp
 * @brief Implementation of NotebookWidget - Interactive notebook interface
 */

#include "notebook_widget.h"
#include <QApplication>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QSplitter>
#include <QTabWidget>
#include <QTextEdit>
#include <QPushButton>
#include <QLabel>
#include <QComboBox>
#include <QListWidget>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QScrollArea>
#include <QGroupBox>
#include <QProgressBar>
#include <QTimer>
#include <QMenu>
#include <QAction>
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonDocument>
#include <QProcess>
#include <QSettings>
#include <QFileDialog>
#include <QMessageBox>
#include <QInputDialog>
#include <QStandardPaths>
#include <QDir>
#include <QFile>
#include <QTextStream>
#include <QSyntaxHighlighter>
#include <QRegularExpression>
#include <QRegularExpressionMatch>
#include <QRegularExpressionMatchIterator>
#include <QTextCharFormat>
#include <QFont>
#include <QColor>
#include <QBrush>
#include <QPainter>
#include <QPaintEvent>
#include <QResizeEvent>
#include <QMouseEvent>
#include <QKeyEvent>
#include <QFocusEvent>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QMimeData>
#include <QUrl>
#include <QApplication>
#include <QClipboard>
#include <QDesktopServices>
#include <QDateTime>
#include <QUuid>
#include <QThread>
#include <QMutex>
#include <QWaitCondition>
#include <QEventLoop>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QUrlQuery>
#include <QTemporaryFile>
#include <QDebug>

// ============================================================================
// NotebookCell Implementation
// ============================================================================

NotebookCell::NotebookCell(QWidget* parent)
    : QWidget(parent)
    , type_(Code)
    , executionCount_(0)
    , isRunning_(false)
    , mainLayout_(nullptr)
    , headerLayout_(nullptr)
    , typeIndicator_(nullptr)
    , typeCombo_(nullptr)
    , runBtn_(nullptr)
    , stopBtn_(nullptr)
    , executionLabel_(nullptr)
    , menuBtn_(nullptr)
    , editor_(nullptr)
    , highlighter_(nullptr)
    , outputWidget_(nullptr)
    , outputLayout_(nullptr)
    , outputLabel_(nullptr)
    , errorLabel_(nullptr)
    , contextMenu_(nullptr)
{
    setupUI();
    setupConnections();
    updateUI();
}

NotebookCell::~NotebookCell()
{
    // Cleanup handled by Qt parent-child system
}

void NotebookCell::setupUI()
{
    mainLayout_ = new QVBoxLayout(this);
    mainLayout_->setContentsMargins(5, 5, 5, 5);
    mainLayout_->setSpacing(2);

    // Header
    headerLayout_ = new QHBoxLayout();
    headerLayout_->setContentsMargins(0, 0, 0, 0);

    typeIndicator_ = new QLabel("●");
    typeIndicator_->setFixedWidth(20);
    typeIndicator_->setAlignment(Qt::AlignCenter);
    headerLayout_->addWidget(typeIndicator_);

    typeCombo_ = new QComboBox(this);
    typeCombo_->addItem("Code", Code);
    typeCombo_->addItem("Markdown", Markdown);
    typeCombo_->addItem("Raw", Raw);
    typeCombo_->setFixedWidth(80);
    headerLayout_->addWidget(typeCombo_);

    headerLayout_->addStretch();

    executionLabel_ = new QLabel("[-]");
    executionLabel_->setFixedWidth(40);
    executionLabel_->setAlignment(Qt::AlignCenter);
    headerLayout_->addWidget(executionLabel_);

    runBtn_ = new QPushButton("▶");
    runBtn_->setFixedSize(25, 25);
    runBtn_->setToolTip(tr("Execute cell"));
    headerLayout_->addWidget(runBtn_);

    stopBtn_ = new QPushButton("■");
    stopBtn_->setFixedSize(25, 25);
    stopBtn_->setToolTip(tr("Stop execution"));
    stopBtn_->setVisible(false);
    headerLayout_->addWidget(stopBtn_);

    menuBtn_ = new QPushButton("⋮");
    menuBtn_->setFixedSize(25, 25);
    menuBtn_->setToolTip(tr("Cell options"));
    headerLayout_->addWidget(menuBtn_);

    mainLayout_->addLayout(headerLayout_);

    // Editor
    editor_ = new QTextEdit(this);
    editor_->setMinimumHeight(30);
    editor_->setMaximumHeight(200);
    editor_->setLineWrapMode(QTextEdit::WidgetWidth);
    editor_->setAcceptRichText(false);
    mainLayout_->addWidget(editor_);

    highlighter_ = new CodeHighlighter(editor_->document());

    // Output area
    outputWidget_ = new QWidget(this);
    outputLayout_ = new QVBoxLayout(outputWidget_);
    outputLayout_->setContentsMargins(0, 0, 0, 0);

    outputLabel_ = new QLabel(this);
    outputLabel_->setWordWrap(true);
    outputLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    outputLabel_->setStyleSheet("background-color: rgba(0,0,0,0.05); padding: 5px; border-radius: 3px;");
    outputLayout_->addWidget(outputLabel_);

    errorLabel_ = new QLabel(this);
    errorLabel_->setWordWrap(true);
    errorLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    errorLabel_->setStyleSheet("background-color: rgba(255,200,200,0.3); padding: 5px; border-radius: 3px; color: red;");
    errorLabel_->setVisible(false);
    outputLayout_->addWidget(errorLabel_);

    mainLayout_->addWidget(outputWidget_);
    outputWidget_->setVisible(false);

    // Context menu
    contextMenu_ = new QMenu(this);
    contextMenu_->addAction(tr("Execute Cell"), this, &NotebookCell::onExecuteClicked);
    contextMenu_->addAction(tr("Clear Output"), this, [this]() { clearOutput(); });
    contextMenu_->addSeparator();
    contextMenu_->addAction(tr("Move Cell Up"), this, [this]() { emit moveUpRequested(); });
    contextMenu_->addAction(tr("Move Cell Down"), this, [this]() { emit moveDownRequested(); });
    contextMenu_->addSeparator();
    contextMenu_->addAction(tr("Delete Cell"), this, [this]() { emit deleteRequested(); });
}

void NotebookCell::setupConnections()
{
    connect(typeCombo_, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &NotebookCell::onTypeChanged);
    connect(runBtn_, &QPushButton::clicked, this, &NotebookCell::onExecuteClicked);
    connect(menuBtn_, &QPushButton::clicked, this, [this]() { showContextMenu(menuBtn_->mapToGlobal(QPoint(0, menuBtn_->height()))); });
    connect(editor_, &QTextEdit::textChanged, this, &NotebookCell::onContentChanged);
}

void NotebookCell::setType(CellType type)
{
    if (type_ != type) {
        type_ = type;
        typeCombo_->setCurrentIndex(static_cast<int>(type));
        updateUI();
        emit typeChanged(type);
    }
}

void NotebookCell::setContent(const QString& content)
{
    editor_->setPlainText(content);
}

QString NotebookCell::getContent() const
{
    return editor_->toPlainText();
}

void NotebookCell::setOutput(const QString& output)
{
    outputLabel_->setText(output);
    outputWidget_->setVisible(!output.isEmpty());
}

QString NotebookCell::getOutput() const
{
    return outputLabel_->text();
}

void NotebookCell::setExecutionCount(int count)
{
    executionCount_ = count;
    if (count > 0) {
        executionLabel_->setText(QString("[%1]").arg(count));
    } else {
        executionLabel_->setText("[-]");
    }
}

void NotebookCell::setRunning(bool running)
{
    isRunning_ = running;
    runBtn_->setVisible(!running);
    stopBtn_->setVisible(running);

    if (running) {
        executionLabel_->setText("[*]");
    }
}

void NotebookCell::setError(const QString& error)
{
    error_ = error;
    errorLabel_->setText(error);
    errorLabel_->setVisible(!error.isEmpty());
    outputWidget_->setVisible(!getOutput().isEmpty() || !error.isEmpty());
}

void NotebookCell::focusEditor()
{
    editor_->setFocus();
    editor_->moveCursor(QTextCursor::End);
}

void NotebookCell::clearOutput()
{
    setOutput("");
    setError("");
    outputWidget_->setVisible(false);
}

QJsonObject NotebookCell::toJson() const
{
    QJsonObject obj;
    obj["cell_type"] = typeCombo_->currentText().toLower();
    obj["source"] = getContent();

    if (!getOutput().isEmpty()) {
        QJsonObject outputs;
        outputs["output_type"] = "stream";
        outputs["text"] = getOutput();
        obj["outputs"] = QJsonArray({outputs});
    }

    if (executionCount_ > 0) {
        obj["execution_count"] = executionCount_;
    }

    return obj;
}

void NotebookCell::fromJson(const QJsonObject& obj)
{
    QString cellType = obj["cell_type"].toString();
    if (cellType == "code") {
        setType(Code);
    } else if (cellType == "markdown") {
        setType(Markdown);
    } else if (cellType == "raw") {
        setType(Raw);
    }

    setContent(obj["source"].toString());

    if (obj.contains("execution_count")) {
        setExecutionCount(obj["execution_count"].toInt());
    }

    if (obj.contains("outputs")) {
        QJsonArray outputs = obj["outputs"].toArray();
        if (!outputs.isEmpty()) {
            QJsonObject output = outputs[0].toObject();
            setOutput(output["text"].toString());
        }
    }
}

void NotebookCell::paintEvent(QPaintEvent* event)
{
    QWidget::paintEvent(event);

    // Draw border
    QPainter painter(this);
    painter.setPen(QPen(QColor(200, 200, 200), 1));
    painter.drawRect(rect().adjusted(0, 0, -1, -1));
}

void NotebookCell::mousePressEvent(QMouseEvent* event)
{
    if (event->button() == Qt::RightButton) {
        showContextMenu(event->pos());
    }
    QWidget::mousePressEvent(event);
}

void NotebookCell::contextMenuEvent(QContextMenuEvent* event)
{
    showContextMenu(event->pos());
}

void NotebookCell::onContentChanged()
{
    emit contentChanged();
}

void NotebookCell::onExecuteClicked()
{
    emit executeRequested();
}

void NotebookCell::onTypeChanged(int index)
{
    CellType newType = static_cast<CellType>(typeCombo_->itemData(index).toInt());
    setType(newType);
}

void NotebookCell::showContextMenu(const QPoint& pos)
{
    contextMenu_->exec(mapToGlobal(pos));
}

void NotebookCell::updateUI()
{
    updateTypeIndicator();

    // Update highlighter
    if (highlighter_) {
        switch (type_) {
            case Code:
                highlighter_->setLanguage("python"); // Default to Python
                break;
            case Markdown:
                highlighter_->setLanguage("markdown");
                break;
            case Raw:
                highlighter_->setLanguage("");
                break;
        }
    }
}

void NotebookCell::updateTypeIndicator()
{
    QColor color;
    QString text;

    switch (type_) {
        case Code:
            color = QColor(100, 150, 200);
            text = "●";
            break;
        case Markdown:
            color = QColor(150, 200, 100);
            text = "●";
            break;
        case Raw:
            color = QColor(200, 150, 100);
            text = "●";
            break;
    }

    typeIndicator_->setText(text);
    typeIndicator_->setStyleSheet(QString("color: %1; font-weight: bold;").arg(color.name()));
}

// ============================================================================
// CodeHighlighter Implementation
// ============================================================================

CodeHighlighter::CodeHighlighter(QTextDocument* parent)
    : QSyntaxHighlighter(parent)
    , language_("python")
{
    setupPythonRules();
}

void CodeHighlighter::setLanguage(const QString& language)
{
    if (language_ != language) {
        language_ = language;

        rules_.clear();
        formats_.clear();

        if (language == "python") {
            setupPythonRules();
        } else if (language == "javascript") {
            setupJavaScriptRules();
        } else if (language == "cpp" || language == "c++") {
            setupCppRules();
        } else if (language == "java") {
            setupJavaRules();
        } else if (language == "markdown") {
            setupMarkdownRules();
        }
    }
}

void CodeHighlighter::highlightBlock(const QString& text)
{
    for (int i = 0; i < rules_.size(); ++i) {
        QRegularExpressionMatchIterator matchIterator = rules_[i].globalMatch(text);
        while (matchIterator.hasNext()) {
            QRegularExpressionMatch match = matchIterator.next();
            setFormat(match.capturedStart(), match.capturedLength(), formats_[i]);
        }
    }
}

void CodeHighlighter::setupPythonRules()
{
    // Keywords
    QTextCharFormat keywordFormat;
    keywordFormat.setForeground(QColor(100, 100, 200));
    keywordFormat.setFontWeight(QFont::Bold);
    QStringList keywords = {"and", "as", "assert", "break", "class", "continue", "def", "del", "elif", "else", "except", "finally", "for", "from", "global", "if", "import", "in", "is", "lambda", "not", "or", "pass", "raise", "return", "try", "while", "with", "yield"};
    for (const QString& keyword : keywords) {
        rules_.append(QRegularExpression(QString("\\b%1\\b").arg(keyword)));
        formats_.append(keywordFormat);
    }

    // Strings
    QTextCharFormat stringFormat;
    stringFormat.setForeground(QColor(150, 100, 150));
    rules_.append(QRegularExpression("\".*\""));
    formats_.append(stringFormat);
    rules_.append(QRegularExpression("'.*'"));
    formats_.append(stringFormat);

    // Comments
    QTextCharFormat commentFormat;
    commentFormat.setForeground(QColor(100, 150, 100));
    rules_.append(QRegularExpression("#[^\n]*"));
    formats_.append(commentFormat);
}

void CodeHighlighter::setupJavaScriptRules()
{
    // Keywords
    QTextCharFormat keywordFormat;
    keywordFormat.setForeground(QColor(100, 100, 200));
    keywordFormat.setFontWeight(QFont::Bold);
    QStringList keywords = {"break", "case", "catch", "continue", "debugger", "default", "delete", "do", "else", "finally", "for", "function", "if", "in", "instanceof", "new", "return", "switch", "this", "throw", "try", "typeof", "var", "void", "while", "with"};
    for (const QString& keyword : keywords) {
        rules_.append(QRegularExpression(QString("\\b%1\\b").arg(keyword)));
        formats_.append(keywordFormat);
    }

    // Strings
    QTextCharFormat stringFormat;
    stringFormat.setForeground(QColor(150, 100, 150));
    rules_.append(QRegularExpression("\".*\""));
    formats_.append(stringFormat);
    rules_.append(QRegularExpression("'.*'"));
    formats_.append(stringFormat);

    // Comments
    QTextCharFormat commentFormat;
    commentFormat.setForeground(QColor(100, 150, 100));
    rules_.append(QRegularExpression("//[^\n]*"));
    formats_.append(commentFormat);
    rules_.append(QRegularExpression("/\\*.*\\*/"));
    formats_.append(commentFormat);
}

void CodeHighlighter::setupCppRules()
{
    // Keywords
    QTextCharFormat keywordFormat;
    keywordFormat.setForeground(QColor(100, 100, 200));
    keywordFormat.setFontWeight(QFont::Bold);
    QStringList keywords = {"alignas", "alignof", "and", "and_eq", "asm", "auto", "bitand", "bitor", "bool", "break", "case", "catch", "char", "char16_t", "char32_t", "class", "compl", "const", "constexpr", "const_cast", "continue", "decltype", "default", "delete", "do", "double", "dynamic_cast", "else", "enum", "explicit", "export", "extern", "false", "float", "for", "friend", "goto", "if", "inline", "int", "long", "mutable", "namespace", "new", "noexcept", "not", "not_eq", "nullptr", "operator", "or", "or_eq", "private", "protected", "public", "register", "reinterpret_cast", "return", "short", "signed", "sizeof", "static", "static_assert", "static_cast", "struct", "switch", "template", "this", "thread_local", "throw", "true", "try", "typedef", "typeid", "typename", "union", "unsigned", "using", "virtual", "void", "volatile", "wchar_t", "while", "xor", "xor_eq"};
    for (const QString& keyword : keywords) {
        rules_.append(QRegularExpression(QString("\\b%1\\b").arg(keyword)));
        formats_.append(keywordFormat);
    }

    // Strings
    QTextCharFormat stringFormat;
    stringFormat.setForeground(QColor(150, 100, 150));
    rules_.append(QRegularExpression("\".*\""));
    formats_.append(stringFormat);

    // Comments
    QTextCharFormat commentFormat;
    commentFormat.setForeground(QColor(100, 150, 100));
    rules_.append(QRegularExpression("//[^\n]*"));
    formats_.append(commentFormat);
    rules_.append(QRegularExpression("/\\*.*\\*/"));
    formats_.append(commentFormat);
}

void CodeHighlighter::setupJavaRules()
{
    // Keywords
    QTextCharFormat keywordFormat;
    keywordFormat.setForeground(QColor(100, 100, 200));
    keywordFormat.setFontWeight(QFont::Bold);
    QStringList keywords = {"abstract", "assert", "boolean", "break", "byte", "case", "catch", "char", "class", "const", "continue", "default", "do", "double", "else", "enum", "extends", "final", "finally", "float", "for", "goto", "if", "implements", "import", "instanceof", "int", "interface", "long", "native", "new", "package", "private", "protected", "public", "return", "short", "static", "strictfp", "super", "switch", "synchronized", "this", "throw", "throws", "transient", "try", "void", "volatile", "while"};
    for (const QString& keyword : keywords) {
        rules_.append(QRegularExpression(QString("\\b%1\\b").arg(keyword)));
        formats_.append(keywordFormat);
    }

    // Strings
    QTextCharFormat stringFormat;
    stringFormat.setForeground(QColor(150, 100, 150));
    rules_.append(QRegularExpression("\".*\""));
    formats_.append(stringFormat);

    // Comments
    QTextCharFormat commentFormat;
    commentFormat.setForeground(QColor(100, 150, 100));
    rules_.append(QRegularExpression("//[^\n]*"));
    formats_.append(commentFormat);
    rules_.append(QRegularExpression("/\\*.*\\*/"));
    formats_.append(commentFormat);
}

void CodeHighlighter::setupMarkdownRules()
{
    // Headers
    QTextCharFormat headerFormat;
    headerFormat.setForeground(QColor(100, 100, 200));
    headerFormat.setFontWeight(QFont::Bold);
    rules_.append(QRegularExpression("^#{1,6}.*$"));
    formats_.append(headerFormat);

    // Links
    QTextCharFormat linkFormat;
    linkFormat.setForeground(QColor(150, 100, 150));
    rules_.append(QRegularExpression("\\[.*\\]\\(.*\\)"));
    formats_.append(linkFormat);

    // Code blocks
    QTextCharFormat codeFormat;
    codeFormat.setForeground(QColor(100, 150, 100));
    rules_.append(QRegularExpression("`.*`"));
    formats_.append(codeFormat);
}

// ============================================================================
// NotebookOutput Implementation
// ============================================================================

NotebookOutput::NotebookOutput(QWidget* parent)
    : QWidget(parent)
    , mimeType_("text/plain")
    , layout_(nullptr)
    , outputLabel_(nullptr)
    , errorLabel_(nullptr)
    , scrollArea_(nullptr)
{
    setupUI();
}

void NotebookOutput::setupUI()
{
    layout_ = new QVBoxLayout(this);
    layout_->setContentsMargins(0, 0, 0, 0);

    scrollArea_ = new QScrollArea(this);
    scrollArea_->setWidgetResizable(true);
    scrollArea_->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    scrollArea_->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);

    QWidget* contentWidget = new QWidget();
    QVBoxLayout* contentLayout = new QVBoxLayout(contentWidget);

    outputLabel_ = new QLabel(contentWidget);
    outputLabel_->setWordWrap(true);
    outputLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    outputLabel_->setStyleSheet("background-color: rgba(0,0,0,0.05); padding: 5px; border-radius: 3px;");
    contentLayout->addWidget(outputLabel_);

    errorLabel_ = new QLabel(contentWidget);
    errorLabel_->setWordWrap(true);
    errorLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    errorLabel_->setStyleSheet("background-color: rgba(255,200,200,0.3); padding: 5px; border-radius: 3px; color: red;");
    errorLabel_->setVisible(false);
    contentLayout->addWidget(errorLabel_);

    scrollArea_->setWidget(contentWidget);
    layout_->addWidget(scrollArea_);
}

void NotebookOutput::setOutput(const QString& output, const QString& outputType)
{
    output_ = output;
    mimeType_ = outputType;
    updateDisplay();
    emit outputChanged();
}

void NotebookOutput::appendOutput(const QString& output)
{
    output_ += output;
    updateDisplay();
    emit outputChanged();
}

void NotebookOutput::setError(const QString& error)
{
    error_ = error;
    errorLabel_->setText(error);
    errorLabel_->setVisible(!error.isEmpty());
    emit outputChanged();
}

void NotebookOutput::clear()
{
    output_.clear();
    error_.clear();
    updateDisplay();
}

void NotebookOutput::setMimeType(const QString& mimeType)
{
    mimeType_ = mimeType;
    updateDisplay();
}

QJsonObject NotebookOutput::toJson() const
{
    QJsonObject obj;
    obj["output_type"] = "stream";
    obj["text"] = output_;
    if (!error_.isEmpty()) {
        obj["error"] = error_;
    }
    return obj;
}

void NotebookOutput::updateDisplay()
{
    outputLabel_->setText(output_);
    outputLabel_->setVisible(!output_.isEmpty());
}

// ============================================================================
// NotebookKernel Implementation
// ============================================================================

NotebookKernel::NotebookKernel(QObject* parent)
    : QObject(parent)
    , language_("python")
    , isRunning_(false)
    , process_(nullptr)
{
}

NotebookKernel::~NotebookKernel()
{
    stopKernel();
}

void NotebookKernel::setLanguage(const QString& language)
{
    if (language_ != language) {
        language_ = language;
        if (isRunning_) {
            stopKernel();
            startKernel();
        }
    }
}

void NotebookKernel::executeCode(const QString& code, const QString& cellId)
{
    if (!isRunning_) {
        startKernel();
    }

    if (isRunning_ && process_) {
        currentCellId_ = cellId;
        outputBuffer_.clear();
        errorBuffer_.clear();

        emit executionStarted(cellId);

        // Write code to process
        process_->write(code.toUtf8() + "\n");
        process_->write("print('---END---')\n");
    }
}

void NotebookKernel::interrupt()
{
    if (process_ && isRunning_) {
        process_->kill();
    }
}

void NotebookKernel::startKernel()
{
    if (isRunning_) return;

    process_ = new QProcess(this);

    connect(process_, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, &NotebookKernel::onProcessFinished);
    connect(process_, &QProcess::errorOccurred, this, &NotebookKernel::onProcessError);
    connect(process_, &QProcess::readyReadStandardOutput, this, &NotebookKernel::onReadyReadStandardOutput);
    connect(process_, &QProcess::readyReadStandardError, this, &NotebookKernel::onReadyReadStandardError);

    QString program;
    QStringList arguments;

    if (language_ == "python") {
        program = "python";
        arguments << "-i" << "-c" << "import sys; print('Python kernel started')";
    } else if (language_ == "javascript" || language_ == "node") {
        program = "node";
        arguments << "-i" << "-e" << "console.log('Node.js kernel started')";
    } else {
        // Fallback - just use a shell
        program = "cmd";
        arguments << "/c" << "echo Kernel started";
    }

    process_->start(program, arguments);

    if (process_->waitForStarted(3000)) {
        isRunning_ = true;
    } else {
        emit executionError("", "Failed to start kernel");
    }
}

void NotebookKernel::stopKernel()
{
    if (process_) {
        process_->kill();
        process_->waitForFinished(3000);
        process_->deleteLater();
        process_ = nullptr;
    }
    isRunning_ = false;
}

void NotebookKernel::onProcessFinished(int exitCode, QProcess::ExitStatus exitStatus)
{
    isRunning_ = false;

    if (!currentCellId_.isEmpty()) {
        if (exitStatus == QProcess::CrashExit) {
            emit executionError(currentCellId_, "Kernel crashed");
        } else {
            // Process any remaining output
            onReadyReadStandardOutput();
            onReadyReadStandardError();

            // Remove the END marker if present
            if (outputBuffer_.endsWith("---END---\n")) {
                outputBuffer_.chop(10);
            }

            emit executionFinished(currentCellId_, outputBuffer_, errorBuffer_);
        }
        currentCellId_.clear();
    }
}

void NotebookKernel::onProcessError(QProcess::ProcessError error)
{
    isRunning_ = false;
    QString errorMsg;

    switch (error) {
        case QProcess::FailedToStart:
            errorMsg = "Failed to start kernel process";
            break;
        case QProcess::Crashed:
            errorMsg = "Kernel process crashed";
            break;
        case QProcess::Timedout:
            errorMsg = "Kernel process timed out";
            break;
        case QProcess::WriteError:
            errorMsg = "Write error to kernel process";
            break;
        case QProcess::ReadError:
            errorMsg = "Read error from kernel process";
            break;
        default:
            errorMsg = "Unknown kernel error";
    }

    if (!currentCellId_.isEmpty()) {
        emit executionError(currentCellId_, errorMsg);
        currentCellId_.clear();
    }
}

void NotebookKernel::onReadyReadStandardOutput()
{
    if (process_) {
        outputBuffer_ += process_->readAllStandardOutput();
    }
}

void NotebookKernel::onReadyReadStandardError()
{
    if (process_) {
        errorBuffer_ += process_->readAllStandardError();
    }
}

// ============================================================================
// NotebookWidget Implementation
// ============================================================================

NotebookWidget::NotebookWidget(QWidget* parent)
    : QWidget(parent)
    , mainLayout_(nullptr)
    , toolbarWidget_(nullptr)
    , toolbarLayout_(nullptr)
    , newBtn_(nullptr)
    , openBtn_(nullptr)
    , saveBtn_(nullptr)
    , saveAsBtn_(nullptr)
    , exportBtn_(nullptr)
    , addCodeBtn_(nullptr)
    , addMarkdownBtn_(nullptr)
    , addRawBtn_(nullptr)
    , deleteCellBtn_(nullptr)
    , moveUpBtn_(nullptr)
    , moveDownBtn_(nullptr)
    , executeBtn_(nullptr)
    , executeAllBtn_(nullptr)
    , clearBtn_(nullptr)
    , kernelLabel_(nullptr)
    , kernelCombo_(nullptr)
    , restartKernelBtn_(nullptr)
    , interruptBtn_(nullptr)
    , statusLabel_(nullptr)
    , scrollArea_(nullptr)
    , cellsContainer_(nullptr)
    , cellsLayout_(nullptr)
    , kernel_(nullptr)
    , kernelThread_(nullptr)
    , readOnly_(false)
    , modified_(false)
    , settings_(nullptr)
{
    settings_ = new QSettings(this);
    setupUI();
    setupConnections();
    createNewNotebook();

    qDebug() << "NotebookWidget initialized";
}

NotebookWidget::~NotebookWidget()
{
    if (kernelThread_) {
        kernelThread_->quit();
        kernelThread_->wait();
    }
}

void NotebookWidget::setupUI()
{
    mainLayout_ = new QVBoxLayout(this);
    mainLayout_->setContentsMargins(0, 0, 0, 0);
    mainLayout_->setSpacing(0);

    setupToolbar();

    // Main content area
    scrollArea_ = new QScrollArea(this);
    scrollArea_->setWidgetResizable(true);
    scrollArea_->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    scrollArea_->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);

    cellsContainer_ = new QWidget();
    cellsLayout_ = new QVBoxLayout(cellsContainer_);
    cellsLayout_->setSpacing(10);
    cellsLayout_->addStretch();

    scrollArea_->setWidget(cellsContainer_);
    mainLayout_->addWidget(scrollArea_);

    // Status bar
    QWidget* statusWidget = new QWidget(this);
    QHBoxLayout* statusLayout = new QHBoxLayout(statusWidget);
    statusLayout->setContentsMargins(4, 2, 4, 2);

    statusLabel_ = new QLabel(tr("Ready"), statusWidget);
    statusLabel_->setStyleSheet("color: gray; font-size: 11px;");
    statusLayout->addWidget(statusLabel_);

    statusLayout->addStretch();

    kernelLabel_ = new QLabel(tr("Kernel:"), statusWidget);
    statusLayout->addWidget(kernelLabel_);

    kernelCombo_ = new QComboBox(statusWidget);
    kernelCombo_->addItems({"Python", "JavaScript", "C++", "Java", "Shell"});
    kernelCombo_->setCurrentText("Python");
    statusLayout->addWidget(kernelCombo_);

    restartKernelBtn_ = new QPushButton(tr("Restart"), statusWidget);
    statusLayout->addWidget(restartKernelBtn_);

    interruptBtn_ = new QPushButton(tr("Interrupt"), statusWidget);
    statusLayout->addWidget(interruptBtn_);

    mainLayout_->addWidget(statusWidget);
}

void NotebookWidget::setupToolbar()
{
    toolbarWidget_ = new QWidget(this);
    toolbarLayout_ = new QHBoxLayout(toolbarWidget_);
    toolbarLayout_->setContentsMargins(4, 2, 4, 2);

    // File operations
    newBtn_ = new QPushButton(tr("New"), toolbarWidget_);
    openBtn_ = new QPushButton(tr("Open"), toolbarWidget_);
    saveBtn_ = new QPushButton(tr("Save"), toolbarWidget_);
    saveAsBtn_ = new QPushButton(tr("Save As"), toolbarWidget_);
    exportBtn_ = new QPushButton(tr("Export"), toolbarWidget_);

    toolbarLayout_->addWidget(newBtn_);
    toolbarLayout_->addWidget(openBtn_);
    toolbarLayout_->addWidget(saveBtn_);
    toolbarLayout_->addWidget(saveAsBtn_);
    toolbarLayout_->addWidget(exportBtn_);

    // Add separator (use spacing instead of QToolBar::addSeparator)
    toolbarLayout_->addSpacing(10);

    // Cell operations
    addCodeBtn_ = new QPushButton(tr("Code"), toolbarWidget_);
    addMarkdownBtn_ = new QPushButton(tr("Markdown"), toolbarWidget_);
    addRawBtn_ = new QPushButton(tr("Raw"), toolbarWidget_);
    deleteCellBtn_ = new QPushButton(tr("Delete"), toolbarWidget_);
    moveUpBtn_ = new QPushButton(tr("↑"), toolbarWidget_);
    moveDownBtn_ = new QPushButton(tr("↓"), toolbarWidget_);

    toolbarLayout_->addWidget(addCodeBtn_);
    toolbarLayout_->addWidget(addMarkdownBtn_);
    toolbarLayout_->addWidget(addRawBtn_);
    toolbarLayout_->addWidget(deleteCellBtn_);
    toolbarLayout_->addWidget(moveUpBtn_);
    toolbarLayout_->addWidget(moveDownBtn_);

    // Add separator (use spacing)
    toolbarLayout_->addSpacing(10);

    // Execution operations
    executeBtn_ = new QPushButton(tr("Run"), toolbarWidget_);
    executeAllBtn_ = new QPushButton(tr("Run All"), toolbarWidget_);
    clearBtn_ = new QPushButton(tr("Clear"), toolbarWidget_);

    toolbarLayout_->addWidget(executeBtn_);
    toolbarLayout_->addWidget(executeAllBtn_);
    toolbarLayout_->addWidget(clearBtn_);

    toolbarLayout_->addStretch();
}

void NotebookWidget::setupConnections()
{
    // File operations
    connect(newBtn_, &QPushButton::clicked, this, &NotebookWidget::onNewNotebook);
    connect(openBtn_, &QPushButton::clicked, this, &NotebookWidget::onOpenNotebook);
    connect(saveBtn_, &QPushButton::clicked, this, &NotebookWidget::onSaveNotebook);
    connect(saveAsBtn_, &QPushButton::clicked, this, &NotebookWidget::onSaveAsNotebook);
    connect(exportBtn_, &QPushButton::clicked, this, &NotebookWidget::onExportNotebook);

    // Cell operations
    connect(addCodeBtn_, &QPushButton::clicked, this, &NotebookWidget::onAddCodeCell);
    connect(addMarkdownBtn_, &QPushButton::clicked, this, &NotebookWidget::onAddMarkdownCell);
    connect(addRawBtn_, &QPushButton::clicked, this, &NotebookWidget::onAddRawCell);
    connect(deleteCellBtn_, &QPushButton::clicked, this, &NotebookWidget::onDeleteCell);
    connect(moveUpBtn_, &QPushButton::clicked, this, &NotebookWidget::onMoveCellUp);
    connect(moveDownBtn_, &QPushButton::clicked, this, &NotebookWidget::onMoveCellDown);

    // Execution operations
    connect(executeBtn_, &QPushButton::clicked, this, &NotebookWidget::onExecuteCell);
    connect(executeAllBtn_, &QPushButton::clicked, this, &NotebookWidget::onExecuteAllCells);
    connect(clearBtn_, &QPushButton::clicked, this, &NotebookWidget::onClearOutputs);

    // Kernel operations
    connect(kernelCombo_, &QComboBox::currentTextChanged, this, &NotebookWidget::onKernelLanguageChanged);
    connect(restartKernelBtn_, &QPushButton::clicked, this, &NotebookWidget::onRestartKernel);
    connect(interruptBtn_, &QPushButton::clicked, this, &NotebookWidget::onInterruptKernel);

    // Initialize kernel
    kernel_ = new NotebookKernel(this);
    connect(kernel_, &NotebookKernel::executionStarted, this, [this](const QString& cellId) {
        NotebookCell* cell = getCellById(cellId);
        if (cell) {
            cell->setRunning(true);
            statusLabel_->setText(tr("Executing cell..."));
        }
    });

    connect(kernel_, &NotebookKernel::executionFinished, this, &NotebookWidget::onCellExecuted);
    connect(kernel_, &NotebookKernel::executionError, this, [this](const QString& cellId, const QString& error) {
        NotebookCell* cell = getCellById(cellId);
        if (cell) {
            cell->setRunning(false);
            cell->setError(error);
            statusLabel_->setText(tr("Execution error"));
        }
    });
}

bool NotebookWidget::createNewNotebook()
{
    // Clear existing cells
    for (NotebookCell* cell : cells_) {
        cellsLayout_->removeWidget(cell);
        delete cell;
    }
    cells_.clear();

    currentFilePath_.clear();
    notebookTitle_ = tr("Untitled Notebook");
    modified_ = false;

    // Add a default code cell
    addCell(NotebookCell::Code);

    updateWindowTitle();
    updateToolbar();

    emit titleChanged(notebookTitle_);
    return true;
}

bool NotebookWidget::loadNotebook(const QString& filePath)
{
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QMessageBox::warning(this, tr("Load Error"), tr("Could not open file for reading."));
        return false;
    }

    QTextStream in(&file);
    QString content = in.readAll();
    file.close();

    QJsonDocument doc = QJsonDocument::fromJson(content.toUtf8());
    if (!doc.isObject()) {
        QMessageBox::warning(this, tr("Load Error"), tr("Invalid notebook format."));
        return false;
    }

    loadNotebookFromJson(doc.object());

    currentFilePath_ = filePath;
    modified_ = false;
    updateWindowTitle();

    emit notebookLoaded(filePath);
    return true;
}

bool NotebookWidget::saveNotebook(const QString& filePath)
{
    QString savePath = filePath.isEmpty() ? currentFilePath_ : filePath;
    if (savePath.isEmpty()) {
        return saveNotebookAs();
    }

    QFile file(savePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::warning(this, tr("Save Error"), tr("Could not open file for writing."));
        return false;
    }

    QJsonDocument doc(saveNotebookToJson());
    QTextStream out(&file);
    out << doc.toJson(QJsonDocument::Indented);
    file.close();

    currentFilePath_ = savePath;
    modified_ = false;
    updateWindowTitle();

    emit notebookSaved(savePath);
    return true;
}

bool NotebookWidget::saveNotebookAs()
{
    QString fileName = QFileDialog::getSaveFileName(this, tr("Save Notebook"),
                                                  QString("%1.ipynb").arg(notebookTitle_),
                                                  tr("Jupyter Notebook (*.ipynb);;JSON files (*.json)"));

    if (fileName.isEmpty()) return false;

    return saveNotebook(fileName);
}

void NotebookWidget::addCell(NotebookCell::CellType type, int index)
{
    NotebookCell* cell = new NotebookCell(cellsContainer_);

    // Generate unique ID
    QString cellId = generateCellId();
    cell->setProperty("cellId", cellId);

    cell->setType(type);

    connect(cell, &NotebookCell::executeRequested, this, [this, cell]() {
        int idx = getCellIndex(cell);
        if (idx >= 0) {
            executeCell(idx);
        }
    });

    connect(cell, &NotebookCell::deleteRequested, this, [this, cell]() {
        int idx = getCellIndex(cell);
        if (idx >= 0) {
            deleteCell(idx);
        }
    });

    connect(cell, &NotebookCell::moveUpRequested, this, [this, cell]() {
        int idx = getCellIndex(cell);
        if (idx > 0) {
            moveCell(idx, idx - 1);
        }
    });

    connect(cell, &NotebookCell::moveDownRequested, this, [this, cell]() {
        int idx = getCellIndex(cell);
        if (idx >= 0 && idx < cells_.size() - 1) {
            moveCell(idx, idx + 1);
        }
    });

    connect(cell, &NotebookCell::contentChanged, this, [this]() {
        markAsModified();
    });

    // Insert at specified index or at end
    if (index < 0 || index >= cells_.size()) {
        cells_.append(cell);
        cellsLayout_->insertWidget(cellsLayout_->count() - 1, cell);
    } else {
        cells_.insert(index, cell);
        cellsLayout_->insertWidget(index, cell);
    }

    updateCellNumbers();
    markAsModified();

    // Focus the new cell
    QTimer::singleShot(100, [cell]() {
        cell->focusEditor();
    });

    emit cellAdded();
}

void NotebookWidget::deleteCell(int index)
{
    if (index < 0 || index >= cells_.size()) return;

    NotebookCell* cell = cells_[index];
    cellsLayout_->removeWidget(cell);
    cells_.removeAt(index);
    delete cell;

    updateCellNumbers();
    markAsModified();

    emit cellDeleted();
}

void NotebookWidget::moveCell(int fromIndex, int toIndex)
{
    if (fromIndex < 0 || fromIndex >= cells_.size() ||
        toIndex < 0 || toIndex >= cells_.size() ||
        fromIndex == toIndex) return;

    NotebookCell* cell = cells_[fromIndex];
    cells_.removeAt(fromIndex);
    cells_.insert(toIndex, cell);

    // Reorder in layout
    cellsLayout_->removeWidget(cell);
    cellsLayout_->insertWidget(toIndex, cell);

    updateCellNumbers();
    markAsModified();

    emit cellMoved();
}

void NotebookWidget::executeCell(int index)
{
    if (index < 0 || index >= cells_.size()) return;

    NotebookCell* cell = cells_[index];
    if (cell->getType() != NotebookCell::Code) return;

    QString code = cell->getContent();
    if (code.trimmed().isEmpty()) return;

    QString cellId = cell->property("cellId").toString();
    kernel_->executeCode(code, cellId);
}

void NotebookWidget::executeAllCells()
{
    for (int i = 0; i < cells_.size(); ++i) {
        if (cells_[i]->getType() == NotebookCell::Code) {
            executeCell(i);
            // Small delay between executions
            QThread::msleep(100);
        }
    }
}

void NotebookWidget::clearAllOutputs()
{
    for (NotebookCell* cell : cells_) {
        cell->clearOutput();
    }
    markAsModified();
}

void NotebookWidget::setKernelLanguage(const QString& language)
{
    currentKernelLanguage_ = language.toLower();
    kernel_->setLanguage(currentKernelLanguage_);
    kernelCombo_->setCurrentText(language);
}

void NotebookWidget::restartKernel()
{
    kernel_->interrupt();
    setKernelLanguage(currentKernelLanguage_);
    statusLabel_->setText(tr("Kernel restarted"));
}

void NotebookWidget::interruptKernel()
{
    kernel_->interrupt();
    statusLabel_->setText(tr("Kernel interrupted"));
}

void NotebookWidget::refresh()
{
    updateCellNumbers();
    updateToolbar();
    updateWindowTitle();
}

void NotebookWidget::setReadOnly(bool readOnly)
{
    readOnly_ = readOnly;
    // Update UI elements based on read-only state
    updateToolbar();
}

QString NotebookWidget::getTitle() const
{
    return notebookTitle_;
}

void NotebookWidget::closeEvent(QCloseEvent* event)
{
    if (checkUnsavedChanges()) {
        event->accept();
    } else {
        event->ignore();
    }
}

void NotebookWidget::dragEnterEvent(QDragEnterEvent* event)
{
    if (event->mimeData()->hasUrls()) {
        event->acceptProposedAction();
    }
}

void NotebookWidget::dropEvent(QDropEvent* event)
{
    const QMimeData* mimeData = event->mimeData();
    if (mimeData->hasUrls()) {
        QList<QUrl> urls = mimeData->urls();
        if (!urls.isEmpty()) {
            QString filePath = urls.first().toLocalFile();
            if (filePath.endsWith(".ipynb") || filePath.endsWith(".json")) {
                loadNotebook(filePath);
            }
        }
    }
}

void NotebookWidget::loadNotebookFromJson(const QJsonObject& notebook)
{
    // Clear existing cells
    for (NotebookCell* cell : cells_) {
        cellsLayout_->removeWidget(cell);
        delete cell;
    }
    cells_.clear();

    notebookTitle_ = notebook["metadata"].toObject()["name"].toString(tr("Untitled Notebook"));

    QJsonArray cells = notebook["cells"].toArray();
    for (const QJsonValue& cellVal : cells) {
        QJsonObject cellObj = cellVal.toObject();
        NotebookCell::CellType type = NotebookCell::Code;

        QString cellType = cellObj["cell_type"].toString();
        if (cellType == "markdown") {
            type = NotebookCell::Markdown;
        } else if (cellType == "raw") {
            type = NotebookCell::Raw;
        }

        addCell(type);
        NotebookCell* cell = cells_.last();
        cell->fromJson(cellObj);
    }

    updateCellNumbers();
}

QJsonObject NotebookWidget::saveNotebookToJson() const
{
    QJsonObject notebook;
    notebook["nbformat"] = 4;
    notebook["nbformat_minor"] = 2;

    QJsonObject metadata;
    metadata["name"] = notebookTitle_;
    metadata["kernel"] = currentKernelLanguage_;
    notebook["metadata"] = metadata;

    QJsonArray cellsArray;
    for (NotebookCell* cell : cells_) {
        cellsArray.append(cell->toJson());
    }
    notebook["cells"] = cellsArray;

    return notebook;
}

NotebookCell* NotebookWidget::getCellById(const QString& cellId) const
{
    for (NotebookCell* cell : cells_) {
        if (cell->property("cellId").toString() == cellId) {
            return cell;
        }
    }
    return nullptr;
}

int NotebookWidget::getCellIndex(NotebookCell* cell) const
{
    return cells_.indexOf(cell);
}

QString NotebookWidget::generateCellId() const
{
    return QUuid::createUuid().toString(QUuid::WithoutBraces);
}

void NotebookWidget::updateCellNumbers()
{
    int codeCellCount = 1;
    for (NotebookCell* cell : cells_) {
        if (cell->getType() == NotebookCell::Code) {
            cell->setExecutionCount(codeCellCount++);
        } else {
            cell->setExecutionCount(0);
        }
    }
}

void NotebookWidget::scrollToCell(int index)
{
    if (index < 0 || index >= cells_.size()) return;

    NotebookCell* cell = cells_[index];
    scrollArea_->ensureWidgetVisible(cell);
}

void NotebookWidget::markAsModified()
{
    if (!modified_) {
        modified_ = true;
        updateWindowTitle();
    }
}

bool NotebookWidget::checkUnsavedChanges()
{
    if (!modified_) return true;

    QMessageBox::StandardButton reply = QMessageBox::question(this, tr("Unsaved Changes"),
                                                            tr("The notebook has unsaved changes. Save before closing?"),
                                                            QMessageBox::Save | QMessageBox::Discard | QMessageBox::Cancel);

    if (reply == QMessageBox::Save) {
        return saveNotebook();
    } else if (reply == QMessageBox::Cancel) {
        return false;
    }

    return true;
}

// Removed duplicate updateCellNumbers() - the first definition is kept above

void NotebookWidget::updateToolbar()
{
    bool hasCells = !cells_.isEmpty();
    bool hasSelection = false; // TODO: Implement cell selection

    deleteCellBtn_->setEnabled(hasSelection);
    moveUpBtn_->setEnabled(hasSelection);
    moveDownBtn_->setEnabled(hasSelection);
    executeBtn_->setEnabled(hasSelection);
    clearBtn_->setEnabled(hasCells);

    // Update based on read-only state
    if (readOnly_) {
        addCodeBtn_->setEnabled(false);
        addMarkdownBtn_->setEnabled(false);
        addRawBtn_->setEnabled(false);
        executeBtn_->setEnabled(false);
        executeAllBtn_->setEnabled(false);
    }
}

void NotebookWidget::updateWindowTitle()
{
    QString title = notebookTitle_;
    if (modified_) {
        title += " *";
    }
    if (!currentFilePath_.isEmpty()) {
        title += QString(" (%1)").arg(QFileInfo(currentFilePath_).fileName());
    }

    emit titleChanged(title);
}

void NotebookWidget::onNewNotebook()
{
    if (checkUnsavedChanges()) {
        createNewNotebook();
    }
}

void NotebookWidget::onOpenNotebook()
{
    if (!checkUnsavedChanges()) return;

    QString fileName = QFileDialog::getOpenFileName(this, tr("Open Notebook"),
                                                  QString(),
                                                  tr("Jupyter Notebook (*.ipynb);;JSON files (*.json);;All files (*)"));

    if (!fileName.isEmpty()) {
        loadNotebook(fileName);
    }
}

void NotebookWidget::onSaveNotebook()
{
    saveNotebook();
}

void NotebookWidget::onSaveAsNotebook()
{
    saveNotebookAs();
}

void NotebookWidget::onExportNotebook()
{
    QString fileName = QFileDialog::getSaveFileName(this, tr("Export Notebook"),
                                                  QString(),
                                                  tr("HTML files (*.html);;Markdown files (*.md);;PDF files (*.pdf)"));

    if (!fileName.isEmpty()) {
        // TODO: Implement export functionality
        QMessageBox::information(this, tr("Export"), tr("Export functionality not implemented yet"));
    }
}

void NotebookWidget::onAddCodeCell()
{
    addCell(NotebookCell::Code);
}

void NotebookWidget::onAddMarkdownCell()
{
    addCell(NotebookCell::Markdown);
}

void NotebookWidget::onAddRawCell()
{
    addCell(NotebookCell::Raw);
}

void NotebookWidget::onDeleteCell()
{
    // Delete selected cell from the cells list
    if (cells_.isEmpty()) return;
    
    // Find currently focused cell or use last cell
    int currentIndex = cells_.size() - 1;
    for (int i = 0; i < cells_.size(); ++i) {
        if (cells_[i]->hasFocus()) {
            currentIndex = i;
            break;
        }
    }
    
    deleteCell(currentIndex);
}

void NotebookWidget::onMoveCellUp()
{
    // Move selected cell up in the list
    if (cells_.isEmpty()) return;
    
    // Find currently focused cell
    int currentIndex = -1;
    for (int i = 0; i < cells_.size(); ++i) {
        if (cells_[i]->hasFocus()) {
            currentIndex = i;
            break;
        }
    }
    
    if (currentIndex > 0) {
        moveCell(currentIndex, currentIndex - 1);
    }
}

void NotebookWidget::onMoveCellDown()
{
    // Move selected cell down in the list
    if (cells_.isEmpty()) return;
    
    // Find currently focused cell
    int currentIndex = -1;
    for (int i = 0; i < cells_.size(); ++i) {
        if (cells_[i]->hasFocus()) {
            currentIndex = i;
            break;
        }
    }
    
    if (currentIndex >= 0 && currentIndex < cells_.size() - 1) {
        moveCell(currentIndex, currentIndex + 1);
    }
}

void NotebookWidget::onExecuteCell()
{
    // Execute selected cell - find currently focused cell
    if (cells_.isEmpty()) return;
    
    int currentIndex = -1;
    for (int i = 0; i < cells_.size(); ++i) {
        if (cells_[i]->hasFocus()) {
            currentIndex = i;
            break;
        }
    }
    
    if (currentIndex < 0) {
        // No focused cell, execute the last one
        currentIndex = cells_.size() - 1;
    }
    
    executeCell(currentIndex);
}

void NotebookWidget::onExecuteAllCells()
{
    executeAllCells();
}

void NotebookWidget::onClearOutputs()
{
    clearAllOutputs();
}

void NotebookWidget::onKernelLanguageChanged(const QString& language)
{
    setKernelLanguage(language);
}

void NotebookWidget::onRestartKernel()
{
    restartKernel();
}

void NotebookWidget::onInterruptKernel()
{
    interruptKernel();
}

void NotebookWidget::onCellExecuted(const QString& cellId, const QString& output, const QString& error)
{
    NotebookCell* cell = getCellById(cellId);
    if (cell) {
        cell->setRunning(false);
        cell->setOutput(output);
        if (!error.isEmpty()) {
            cell->setError(error);
        }
        statusLabel_->setText(tr("Ready"));

        int index = getCellIndex(cell);
        emit cellExecuted(index, output);
    }
}

void NotebookWidget::onCellAdded()
{
    updateToolbar();
}

void NotebookWidget::onCellDeleted()
{
    updateToolbar();
}

void NotebookWidget::onCellMoved()
{
    updateToolbar();
}