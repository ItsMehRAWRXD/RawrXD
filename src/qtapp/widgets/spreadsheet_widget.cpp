/**
 * @file spreadsheet_widget.cpp
 * @brief Implementation of SpreadsheetWidget - Embedded spreadsheet functionality
 */

#include "spreadsheet_widget.h"
#include <QApplication>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QSplitter>
#include <QTabWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QHeaderView>
#include <QPushButton>
#include <QLabel>
#include <QComboBox>
#include <QLineEdit>
#include <QTextEdit>
#include <QSpinBox>
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
#include <QVariant>
#include <QVariantList>
#include <QVariantMap>
#include <QList>
#include <QVector>
#include <QPair>
#include <QMap>
#include <QSet>
#include <QStack>
#include <QQueue>
#include <cmath>
#include <algorithm>
#include <functional>

// ============================================================================
// SpreadsheetCell Implementation
// ============================================================================

SpreadsheetCell::SpreadsheetCell()
    : QTableWidgetItem()
    , type_(Text)
{
}

SpreadsheetCell::SpreadsheetCell(const QString& text)
    : QTableWidgetItem(text)
    , type_(Text)
{
    setValue(QVariant(text));
}

SpreadsheetCell::~SpreadsheetCell()
{
}

void SpreadsheetCell::setType(CellType type)
{
    type_ = type;
}

void SpreadsheetCell::setFormula(const QString& formula)
{
    formula_ = formula;
    if (!formula.isEmpty()) {
        type_ = Formula;
    }
}

void SpreadsheetCell::setValue(const QVariant& value)
{
    value_ = value;

    // Auto-detect type
    if (value.type() == QVariant::String) {
        QString str = value.toString();
        if (str.startsWith('=')) {
            type_ = Formula;
            formula_ = str.mid(1);
        } else if (str.contains(QRegularExpression("^\\d+\\.?\\d*$"))) {
            type_ = Number;
        } else if (str.toLower() == "true" || str.toLower() == "false") {
            type_ = Boolean;
        } else {
            type_ = Text;
        }
    } else if (value.type() == QVariant::Double || value.type() == QVariant::Int) {
        type_ = Number;
    } else if (value.type() == QVariant::Bool) {
        type_ = Boolean;
    } else if (value.type() == QVariant::Date || value.type() == QVariant::DateTime) {
        type_ = Date;
    }
}

void SpreadsheetCell::setDisplayText(const QString& text)
{
    QTableWidgetItem::setText(text);
}

QString SpreadsheetCell::getDisplayText() const
{
    return QTableWidgetItem::text();
}

bool SpreadsheetCell::isEmpty() const
{
    return value_.isNull() || value_.toString().isEmpty();
}

void SpreadsheetCell::clear()
{
    value_ = QVariant();
    formula_.clear();
    type_ = Text;
    QTableWidgetItem::setText("");
}

QJsonObject SpreadsheetCell::toJson() const
{
    QJsonObject obj;
    obj["type"] = type_;
    obj["value"] = QJsonValue::fromVariant(value_);
    if (!formula_.isEmpty()) {
        obj["formula"] = formula_;
    }
    obj["display"] = getDisplayText();
    return obj;
}

void SpreadsheetCell::fromJson(const QJsonObject& obj)
{
    type_ = static_cast<CellType>(obj["type"].toInt());
    value_ = obj["value"].toVariant();
    formula_ = obj["formula"].toString();
    setDisplayText(obj["display"].toString());
}

QVariant SpreadsheetCell::evaluateFormula(const QMap<QString, SpreadsheetCell*>& cells)
{
    if (formula_.isEmpty()) {
        return value_;
    }

    try {
        return SpreadsheetFormula::evaluate(formula_, cells);
    } catch (const std::exception& e) {
        return QVariant(QString("#ERROR: %1").arg(e.what()));
    }
}

QVariant SpreadsheetCell::evaluateExpression(const QString& expr, const QMap<QString, SpreadsheetCell*>& cells)
{
    // Simple expression parser - in production would use a proper parser
    QString expression = expr.trimmed();

    // Handle cell references
    QRegularExpression cellRefRegex("([A-Z]+\\d+)");
    QRegularExpressionMatchIterator it = cellRefRegex.globalMatch(expression);
    while (it.hasNext()) {
        QRegularExpressionMatch match = it.next();
        QString ref = match.captured(1);
        if (cells.contains(ref)) {
            SpreadsheetCell* cell = cells[ref];
            QVariant cellValue = cell->evaluateFormula(cells);
            expression.replace(match.capturedStart(), match.capturedLength(), cellValue.toString());
        }
    }

    // Simple evaluation for basic arithmetic
    // In production, would use a proper expression evaluator
    try {
        // Very basic evaluation - just handle numbers and simple operations
        if (expression.contains(QRegularExpression("^\\d+\\.?\\d*$"))) {
            return expression.toDouble();
        }

        // Handle basic operations
        if (expression.contains('+')) {
            QStringList parts = expression.split('+', Qt::SkipEmptyParts);
            if (parts.size() == 2) {
                return parts[0].toDouble() + parts[1].toDouble();
            }
        }

        if (expression.contains('-')) {
            QStringList parts = expression.split('-', Qt::SkipEmptyParts);
            if (parts.size() == 2) {
                return parts[0].toDouble() - parts[1].toDouble();
            }
        }

        if (expression.contains('*')) {
            QStringList parts = expression.split('*', Qt::SkipEmptyParts);
            if (parts.size() == 2) {
                return parts[0].toDouble() * parts[1].toDouble();
            }
        }

        if (expression.contains('/')) {
            QStringList parts = expression.split('/', Qt::SkipEmptyParts);
            if (parts.size() == 2) {
                double divisor = parts[1].toDouble();
                if (divisor != 0) {
                    return parts[0].toDouble() / divisor;
                } else {
                    return QVariant("#DIV/0!");
                }
            }
        }

    } catch (...) {
        return QVariant("#VALUE!");
    }

    return QVariant(expression); // Return as string if can't evaluate
}

QVariant SpreadsheetCell::evaluateFunction(const QString& func, const QList<QVariant>& args)
{
    QString function = func.toUpper();

    if (function == "SUM") {
        double sum = 0;
        for (const QVariant& arg : args) {
            sum += arg.toDouble();
        }
        return sum;
    }

    if (function == "AVERAGE" || function == "AVG") {
        if (args.isEmpty()) return 0;
        double sum = 0;
        for (const QVariant& arg : args) {
            sum += arg.toDouble();
        }
        return sum / args.size();
    }

    if (function == "MAX") {
        if (args.isEmpty()) return QVariant();
        double max = args[0].toDouble();
        for (int i = 1; i < args.size(); ++i) {
            max = qMax(max, args[i].toDouble());
        }
        return max;
    }

    if (function == "MIN") {
        if (args.isEmpty()) return QVariant();
        double min = args[0].toDouble();
        for (int i = 1; i < args.size(); ++i) {
            min = qMin(min, args[i].toDouble());
        }
        return min;
    }

    if (function == "COUNT") {
        return args.size();
    }

    if (function == "UPPER") {
        if (!args.isEmpty()) {
            return args[0].toString().toUpper();
        }
    }

    if (function == "LOWER") {
        if (!args.isEmpty()) {
            return args[0].toString().toLower();
        }
    }

    if (function == "LEN" || function == "LENGTH") {
        if (!args.isEmpty()) {
            return args[0].toString().length();
        }
    }

    return QVariant(QString("#NAME?"));
}

QList<QVariant> SpreadsheetCell::parseArguments(const QString& argsStr, const QMap<QString, SpreadsheetCell*>& cells)
{
    QList<QVariant> args;
    QStringList argStrings = argsStr.split(',', Qt::SkipEmptyParts);

    for (const QString& argStr : argStrings) {
        QString arg = argStr.trimmed();

        // Check if it's a cell reference
        if (arg.contains(QRegularExpression("^[A-Z]+\\d+$"))) {
            if (cells.contains(arg)) {
                args.append(cells[arg]->evaluateFormula(cells));
            } else {
                args.append(QVariant(0)); // Empty cell
            }
        } else if (arg.contains(QRegularExpression("^\\d+\\.?\\d*$"))) {
            args.append(arg.toDouble());
        } else {
            args.append(arg);
        }
    }

    return args;
}

SpreadsheetRange SpreadsheetCell::parseRange(const QString& rangeStr)
{
    return SpreadsheetRange(rangeStr);
}

// ============================================================================
// SpreadsheetRange Implementation
// ============================================================================

SpreadsheetRange::SpreadsheetRange()
    : startRow_(-1), startCol_(-1), endRow_(-1), endCol_(-1)
{
}

SpreadsheetRange::SpreadsheetRange(int startRow, int startCol, int endRow, int endCol)
    : startRow_(startRow), startCol_(startCol), endRow_(endRow), endCol_(endCol)
{
}

SpreadsheetRange::SpreadsheetRange(const QString& rangeStr)
    : startRow_(-1), startCol_(-1), endRow_(-1), endCol_(-1)
{
    // Parse range like "A1:B5" or "A1"
    QString range = rangeStr.trimmed().toUpper();

    if (range.contains(':')) {
        QStringList parts = range.split(':');
        if (parts.size() == 2) {
            // Parse start cell
            QRegularExpression cellRegex("^([A-Z]+)(\\d+)$");
            QRegularExpressionMatch startMatch = cellRegex.match(parts[0]);
            QRegularExpressionMatch endMatch = cellRegex.match(parts[1]);

            if (startMatch.hasMatch() && endMatch.hasMatch()) {
                // Convert column letters to numbers (A=0, B=1, etc.)
                auto colFromString = [](const QString& col) {
                    int result = 0;
                    for (QChar c : col) {
                        result = result * 26 + (c.toLatin1() - 'A');
                    }
                    return result;
                };

                startCol_ = colFromString(startMatch.captured(1));
                startRow_ = startMatch.captured(2).toInt() - 1; // 1-based to 0-based
                endCol_ = colFromString(endMatch.captured(1));
                endRow_ = endMatch.captured(2).toInt() - 1;
            }
        }
    } else {
        // Single cell
        QRegularExpression cellRegex("^([A-Z]+)(\\d+)$");
        QRegularExpressionMatch match = cellRegex.match(range);

        if (match.hasMatch()) {
            auto colFromString = [](const QString& col) {
                int result = 0;
                for (QChar c : col) {
                    result = result * 26 + (c.toLatin1() - 'A');
                }
                return result;
            };

            startCol_ = endCol_ = colFromString(match.captured(1));
            startRow_ = endRow_ = match.captured(2).toInt() - 1;
        }
    }
}

bool SpreadsheetRange::isValid() const
{
    return startRow_ >= 0 && startCol_ >= 0 && endRow_ >= 0 && endCol_ >= 0;
}

bool SpreadsheetRange::contains(int row, int col) const
{
    return row >= startRow_ && row <= endRow_ && col >= startCol_ && col <= endCol_;
}

QList<QPair<int, int>> SpreadsheetRange::getCells() const
{
    QList<QPair<int, int>> cells;
    for (int row = startRow_; row <= endRow_; ++row) {
        for (int col = startCol_; col <= endCol_; ++col) {
            cells.append(qMakePair(row, col));
        }
    }
    return cells;
}

QString SpreadsheetRange::toString() const
{
    if (!isValid()) return "";

    auto colToString = [](int col) {
        QString result;
        while (col >= 0) {
            result.prepend(QChar('A' + (col % 26)));
            col = col / 26 - 1;
        }
        return result;
    };

    QString start = colToString(startCol_) + QString::number(startRow_ + 1);
    QString end = colToString(endCol_) + QString::number(endRow_ + 1);

    if (start == end) {
        return start;
    } else {
        return start + ":" + end;
    }
}

// ============================================================================
// SpreadsheetFormula Implementation
// ============================================================================

QVariant SpreadsheetFormula::evaluate(const QString& formula, const QMap<QString, SpreadsheetCell*>& cells)
{
    if (formula.isEmpty()) {
        return QVariant();
    }

    QString expr = formula.trimmed();

    // Handle function calls
    QRegularExpression funcRegex("^([A-Z]+)\\((.*)\\)$");
    QRegularExpressionMatch funcMatch = funcRegex.match(expr);

    if (funcMatch.hasMatch()) {
        QString funcName = funcMatch.captured(1);
        QString argsStr = funcMatch.captured(2);

        // Parse arguments
        QList<QVariant> args;
        if (!argsStr.isEmpty()) {
            QStringList argStrings = argsStr.split(',', Qt::SkipEmptyParts);
            for (const QString& argStr : argStrings) {
                QString arg = argStr.trimmed();

                // Check if it's a range
                if (arg.contains(':')) {
                    SpreadsheetRange range(arg);
                    if (range.isValid()) {
                        QList<QPair<int, int>> rangeCells = range.getCells();
                        for (const auto& cellPos : rangeCells) {
                            QString cellRef = QString("%1%2").arg(QChar('A' + cellPos.second)).arg(cellPos.first + 1);
                            if (cells.contains(cellRef)) {
                                args.append(cells[cellRef]->evaluateFormula(cells));
                            }
                        }
                    }
                } else if (arg.contains(QRegularExpression("^[A-Z]+\\d+$"))) {
                    // Single cell reference
                    if (cells.contains(arg)) {
                        args.append(cells[arg]->evaluateFormula(cells));
                    }
                } else {
                    // Literal value
                    args.append(arg);
                }
            }
        }

        return SpreadsheetCell().evaluateFunction(funcName, args);
    }

    // Handle simple expressions
    return parseExpression(expr, cells);
}

bool SpreadsheetFormula::isValidFormula(const QString& formula)
{
    if (formula.isEmpty()) return false;

    QString expr = formula.trimmed();

    // Check for function calls
    QRegularExpression funcRegex("^[A-Z]+\\(.*\\)$");
    if (funcRegex.match(expr).hasMatch()) {
        return true;
    }

    // Check for cell references and basic arithmetic
    QRegularExpression validExpr("^[A-Z\\d\\s+\\-*/()]+$");
    return validExpr.match(expr).hasMatch();
}

QStringList SpreadsheetFormula::extractDependencies(const QString& formula)
{
    QStringList dependencies;

    QRegularExpression cellRefRegex("([A-Z]+\\d+)");
    QRegularExpressionMatchIterator it = cellRefRegex.globalMatch(formula);

    while (it.hasNext()) {
        QRegularExpressionMatch match = it.next();
        dependencies.append(match.captured(1));
    }

    return dependencies;
}

QVariant SpreadsheetFormula::parseExpression(const QString& expr, const QMap<QString, SpreadsheetCell*>& cells)
{
    // Very basic expression parser
    QString expression = expr;

    // Replace cell references with values
    QRegularExpression cellRefRegex("([A-Z]+\\d+)");
    QRegularExpressionMatchIterator it = cellRefRegex.globalMatch(expression);
    while (it.hasNext()) {
        QRegularExpressionMatch match = it.next();
        QString ref = match.captured(1);
        if (cells.contains(ref)) {
            SpreadsheetCell* cell = cells[ref];
            QVariant cellValue = cell->evaluateFormula(cells);
            expression.replace(match.capturedStart(), match.capturedLength(), cellValue.toString());
        } else {
            expression.replace(match.capturedStart(), match.capturedLength(), "0");
        }
    }

    // Simple evaluation using Qt's JavaScript engine (fallback)
    // In production, would implement a proper expression parser
    return QVariant(expression); // Return as string for now
}

// ============================================================================
// SpreadsheetWidget Implementation
// ============================================================================

SpreadsheetWidget::SpreadsheetWidget(QWidget* parent)
    : QWidget(parent)
    , mainLayout_(nullptr)
    , toolbarWidget_(nullptr)
    , toolbarLayout_(nullptr)
    , newBtn_(nullptr)
    , openBtn_(nullptr)
    , saveBtn_(nullptr)
    , saveAsBtn_(nullptr)
    , exportBtn_(nullptr)
    , copyBtn_(nullptr)
    , cutBtn_(nullptr)
    , pasteBtn_(nullptr)
    , clearBtn_(nullptr)
    , insertRowBtn_(nullptr)
    , deleteRowBtn_(nullptr)
    , insertColBtn_(nullptr)
    , deleteColBtn_(nullptr)
    , sortBtn_(nullptr)
    , filterBtn_(nullptr)
    , formatBtn_(nullptr)
    , formulaBarWidget_(nullptr)
    , cellRefLabel_(nullptr)
    , formulaEdit_(nullptr)
    , table_(nullptr)
    , statusWidget_(nullptr)
    , statusLabel_(nullptr)
    , selectionLabel_(nullptr)
    , zoomLabel_(nullptr)
    , readOnly_(false)
    , modified_(false)
    , settings_(nullptr)
{
    settings_ = new QSettings(this);
    setupUI();
    setupConnections();
    createNewSpreadsheet();

    qDebug() << "SpreadsheetWidget initialized";
}

SpreadsheetWidget::~SpreadsheetWidget()
{
    // Cleanup handled by Qt parent-child system
}

void SpreadsheetWidget::setupUI()
{
    mainLayout_ = new QVBoxLayout(this);
    mainLayout_->setContentsMargins(0, 0, 0, 0);
    mainLayout_->setSpacing(0);

    setupToolbar();
    setupFormulaBar();
    setupTable();
    setupStatusBar();
}

void SpreadsheetWidget::setupToolbar()
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

    // Create separator widget (addSeparator not available in QHBoxLayout)
    QFrame* separator1 = new QFrame(toolbarWidget_);
    separator1->setFrameShape(QFrame::VLine);
    separator1->setFrameShadow(QFrame::Sunken);
    toolbarLayout_->addWidget(separator1);

    // Edit operations
    copyBtn_ = new QPushButton(tr("Copy"), toolbarWidget_);
    cutBtn_ = new QPushButton(tr("Cut"), toolbarWidget_);
    pasteBtn_ = new QPushButton(tr("Paste"), toolbarWidget_);
    clearBtn_ = new QPushButton(tr("Clear"), toolbarWidget_);

    toolbarLayout_->addWidget(copyBtn_);
    toolbarLayout_->addWidget(cutBtn_);
    toolbarLayout_->addWidget(pasteBtn_);
    toolbarLayout_->addWidget(clearBtn_);

    // Create separator widget
    QFrame* separator2 = new QFrame(toolbarWidget_);
    separator2->setFrameShape(QFrame::VLine);
    separator2->setFrameShadow(QFrame::Sunken);
    toolbarLayout_->addWidget(separator2);

    // Structure operations
    insertRowBtn_ = new QPushButton(tr("Insert Row"), toolbarWidget_);
    deleteRowBtn_ = new QPushButton(tr("Delete Row"), toolbarWidget_);
    insertColBtn_ = new QPushButton(tr("Insert Col"), toolbarWidget_);
    deleteColBtn_ = new QPushButton(tr("Delete Col"), toolbarWidget_);

    toolbarLayout_->addWidget(insertRowBtn_);
    toolbarLayout_->addWidget(deleteRowBtn_);
    toolbarLayout_->addWidget(insertColBtn_);
    toolbarLayout_->addWidget(deleteColBtn_);

    // Create separator widget
    QFrame* separator3 = new QFrame(toolbarWidget_);
    separator3->setFrameShape(QFrame::VLine);
    separator3->setFrameShadow(QFrame::Sunken);
    toolbarLayout_->addWidget(separator3);

    // Data operations
    sortBtn_ = new QPushButton(tr("Sort"), toolbarWidget_);
    filterBtn_ = new QPushButton(tr("Filter"), toolbarWidget_);
    formatBtn_ = new QPushButton(tr("Format"), toolbarWidget_);

    toolbarLayout_->addWidget(sortBtn_);
    toolbarLayout_->addWidget(filterBtn_);
    toolbarLayout_->addWidget(formatBtn_);

    toolbarLayout_->addStretch();

    mainLayout_->addWidget(toolbarWidget_);
}

void SpreadsheetWidget::setupFormulaBar()
{
    formulaBarWidget_ = new QWidget(this);
    QHBoxLayout* formulaLayout = new QHBoxLayout(formulaBarWidget_);
    formulaLayout->setContentsMargins(4, 2, 4, 2);

    cellRefLabel_ = new QLabel("A1", formulaBarWidget_);
    cellRefLabel_->setFixedWidth(40);
    cellRefLabel_->setAlignment(Qt::AlignCenter);
    cellRefLabel_->setStyleSheet("background-color: #f0f0f0; border: 1px solid #ccc;");

    formulaEdit_ = new QLineEdit(formulaBarWidget_);
    formulaEdit_->setPlaceholderText(tr("Enter formula or value"));

    formulaLayout->addWidget(cellRefLabel_);
    formulaLayout->addWidget(formulaEdit_);

    mainLayout_->addWidget(formulaBarWidget_);
}

void SpreadsheetWidget::setupTable()
{
    table_ = new QTableWidget(this);
    table_->setAlternatingRowColors(true);
    table_->setSelectionMode(QAbstractItemView::ExtendedSelection);
    table_->setContextMenuPolicy(Qt::CustomContextMenu);

    // Set up headers
    table_->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    table_->verticalHeader()->setSectionResizeMode(QHeaderView::Interactive);

    mainLayout_->addWidget(table_);
}

void SpreadsheetWidget::setupStatusBar()
{
    statusWidget_ = new QWidget(this);
    QHBoxLayout* statusLayout = new QHBoxLayout(statusWidget_);
    statusLayout->setContentsMargins(4, 2, 4, 2);

    statusLabel_ = new QLabel(tr("Ready"), statusWidget_);
    statusLabel_->setStyleSheet("color: gray; font-size: 11px;");

    selectionLabel_ = new QLabel("", statusWidget_);
    selectionLabel_->setStyleSheet("color: gray; font-size: 11px;");

    zoomLabel_ = new QLabel("100%", statusWidget_);
    zoomLabel_->setStyleSheet("color: gray; font-size: 11px;");

    statusLayout->addWidget(statusLabel_);
    statusLayout->addStretch();
    statusLayout->addWidget(selectionLabel_);
    statusLayout->addWidget(zoomLabel_);

    mainLayout_->addWidget(statusWidget_);
}

void SpreadsheetWidget::setupConnections()
{
    // File operations
    connect(newBtn_, &QPushButton::clicked, this, &SpreadsheetWidget::onNewSpreadsheet);
    connect(openBtn_, &QPushButton::clicked, this, &SpreadsheetWidget::onOpenSpreadsheet);
    connect(saveBtn_, &QPushButton::clicked, this, &SpreadsheetWidget::onSaveSpreadsheet);
    connect(saveAsBtn_, &QPushButton::clicked, this, &SpreadsheetWidget::onSaveAsSpreadsheet);
    connect(exportBtn_, &QPushButton::clicked, this, &SpreadsheetWidget::onExportSpreadsheet);

    // Edit operations
    connect(copyBtn_, &QPushButton::clicked, this, &SpreadsheetWidget::onCopy);
    connect(cutBtn_, &QPushButton::clicked, this, &SpreadsheetWidget::onCut);
    connect(pasteBtn_, &QPushButton::clicked, this, &SpreadsheetWidget::onPaste);
    connect(clearBtn_, &QPushButton::clicked, this, &SpreadsheetWidget::onClear);

    // Structure operations
    connect(insertRowBtn_, &QPushButton::clicked, this, &SpreadsheetWidget::onInsertRow);
    connect(deleteRowBtn_, &QPushButton::clicked, this, &SpreadsheetWidget::onDeleteRow);
    connect(insertColBtn_, &QPushButton::clicked, this, &SpreadsheetWidget::onInsertColumn);
    connect(deleteColBtn_, &QPushButton::clicked, this, &SpreadsheetWidget::onDeleteColumn);

    // Data operations
    connect(sortBtn_, &QPushButton::clicked, this, &SpreadsheetWidget::onSortRange);
    connect(filterBtn_, &QPushButton::clicked, this, &SpreadsheetWidget::onFilterRange);
    connect(formatBtn_, &QPushButton::clicked, this, &SpreadsheetWidget::onFormatCell);

    // Table operations
    connect(table_, &QTableWidget::cellChanged, this, &SpreadsheetWidget::onCellChanged);
    connect(table_, &QTableWidget::cellDoubleClicked, this, &SpreadsheetWidget::onCellDoubleClicked);
    connect(table_, &QTableWidget::itemSelectionChanged, this, &SpreadsheetWidget::onSelectionChanged);
    connect(table_, &QWidget::customContextMenuRequested, this, &SpreadsheetWidget::onContextMenuRequested);

    // Formula bar
    connect(formulaEdit_, &QLineEdit::returnPressed, [this]() {
        if (!table_->currentItem()) return;

        int row = table_->currentRow();
        int col = table_->currentColumn();
        QString text = formulaEdit_->text();

        if (text.startsWith('=')) {
            setCellFormula(row, col, text.mid(1));
        } else {
            setCellValue(row, col, text);
        }

        updateCellDisplay(row, col);
        recalculateAll();
    });
}

bool SpreadsheetWidget::createNewSpreadsheet(int rows, int cols)
{
    // Clear existing data
    cells_.clear();
    currentFilePath_.clear();
    spreadsheetTitle_ = tr("Untitled Spreadsheet");
    modified_ = false;

    initializeTable(rows, cols);
    updateWindowTitle();

    emit titleChanged(spreadsheetTitle_);
    return true;
}

bool SpreadsheetWidget::loadSpreadsheet(const QString& filePath)
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
        QMessageBox::warning(this, tr("Load Error"), tr("Invalid spreadsheet format."));
        return false;
    }

    loadSpreadsheetFromJson(doc.object());

    currentFilePath_ = filePath;
    modified_ = false;
    updateWindowTitle();

    emit spreadsheetLoaded(filePath);
    return true;
}

bool SpreadsheetWidget::saveSpreadsheet(const QString& filePath)
{
    QString savePath = filePath.isEmpty() ? currentFilePath_ : filePath;
    if (savePath.isEmpty()) {
        return saveSpreadsheetAs();
    }

    QFile file(savePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::warning(this, tr("Save Error"), tr("Could not open file for writing."));
        return false;
    }

    QJsonDocument doc(saveSpreadsheetToJson());
    QTextStream out(&file);
    out << doc.toJson(QJsonDocument::Indented);
    file.close();

    currentFilePath_ = savePath;
    modified_ = false;
    updateWindowTitle();

    emit spreadsheetSaved(savePath);
    return true;
}

bool SpreadsheetWidget::saveSpreadsheetAs()
{
    QString fileName = QFileDialog::getSaveFileName(this, tr("Save Spreadsheet"),
                                                  QString("%1.json").arg(spreadsheetTitle_),
                                                  tr("JSON files (*.json);;CSV files (*.csv);;All files (*)"));

    if (fileName.isEmpty()) return false;

    return saveSpreadsheet(fileName);
}

void SpreadsheetWidget::setCellValue(int row, int col, const QVariant& value)
{
    QString key = cellReference(row, col);
    SpreadsheetCell* cell = getCell(row, col);

    if (!cell) {
        cell = new SpreadsheetCell();
        setCell(row, col, cell);
    }

    cell->setValue(value);
    updateCellDisplay(row, col);
    markAsModified();

    emit cellChanged(row, col, value);
}

QVariant SpreadsheetWidget::getCellValue(int row, int col) const
{
    SpreadsheetCell* cell = getCell(row, col);
    return cell ? cell->getValue() : QVariant();
}

void SpreadsheetWidget::setCellFormula(int row, int col, const QString& formula)
{
    QString key = cellReference(row, col);
    SpreadsheetCell* cell = getCell(row, col);

    if (!cell) {
        cell = new SpreadsheetCell();
        setCell(row, col, cell);
    }

    cell->setFormula(formula);
    updateCellDisplay(row, col);
    markAsModified();

    emit cellChanged(row, col, cell->evaluateFormula(cells_));
}

QString SpreadsheetWidget::getCellFormula(int row, int col) const
{
    SpreadsheetCell* cell = getCell(row, col);
    return cell ? cell->getFormula() : QString();
}

void SpreadsheetWidget::setRangeValues(const SpreadsheetRange& range, const QList<QVariant>& values)
{
    QList<QPair<int, int>> cells = range.getCells();
    int valueIndex = 0;

    for (const auto& cellPos : cells) {
        if (valueIndex < values.size()) {
            setCellValue(cellPos.first, cellPos.second, values[valueIndex++]);
        }
    }

    recalculateAll();
}

QList<QVariant> SpreadsheetWidget::getRangeValues(const SpreadsheetRange& range) const
{
    QList<QVariant> values;
    QList<QPair<int, int>> cells = range.getCells();

    for (const auto& cellPos : cells) {
        values.append(getCellValue(cellPos.first, cellPos.second));
    }

    return values;
}

void SpreadsheetWidget::clearRange(const SpreadsheetRange& range)
{
    QList<QPair<int, int>> cells = range.getCells();

    for (const auto& cellPos : cells) {
        QString key = cellReference(cellPos.first, cellPos.second);
        cells_.remove(key);

        QTableWidgetItem* item = table_->item(cellPos.first, cellPos.second);
        if (item) {
            item->setText("");
        }
    }

    markAsModified();
}

void SpreadsheetWidget::insertRow(int row)
{
    table_->insertRow(row);

    // Shift existing cells down
    QMap<QString, SpreadsheetCell*> newCells;
    for (auto it = cells_.begin(); it != cells_.end(); ++it) {
        QPair<int, int> pos = parseCellReference(it.key());
        if (pos.first >= row) {
            QString newKey = cellReference(pos.first + 1, pos.second);
            newCells[newKey] = it.value();
        } else {
            newCells[it.key()] = it.value();
        }
    }
    cells_ = newCells;

    updateTableHeaders();
    markAsModified();
}

void SpreadsheetWidget::deleteRow(int row)
{
    if (table_->rowCount() <= 1) return;

    table_->removeRow(row);

    // Shift existing cells up
    QMap<QString, SpreadsheetCell*> newCells;
    for (auto it = cells_.begin(); it != cells_.end(); ++it) {
        QPair<int, int> pos = parseCellReference(it.key());
        if (pos.first > row) {
            QString newKey = cellReference(pos.first - 1, pos.second);
            newCells[newKey] = it.value();
        } else if (pos.first < row) {
            newCells[it.key()] = it.value();
        }
        // Cells in deleted row are discarded
    }
    cells_ = newCells;

    updateTableHeaders();
    markAsModified();
}

void SpreadsheetWidget::insertColumn(int col)
{
    table_->insertColumn(col);

    // Shift existing cells right
    QMap<QString, SpreadsheetCell*> newCells;
    for (auto it = cells_.begin(); it != cells_.end(); ++it) {
        QPair<int, int> pos = parseCellReference(it.key());
        if (pos.second >= col) {
            QString newKey = cellReference(pos.first, pos.second + 1);
            newCells[newKey] = it.value();
        } else {
            newCells[it.key()] = it.value();
        }
    }
    cells_ = newCells;

    updateTableHeaders();
    markAsModified();
}

void SpreadsheetWidget::deleteColumn(int col)
{
    if (table_->columnCount() <= 1) return;

    table_->removeColumn(col);

    // Shift existing cells left
    QMap<QString, SpreadsheetCell*> newCells;
    for (auto it = cells_.begin(); it != cells_.end(); ++it) {
        QPair<int, int> pos = parseCellReference(it.key());
        if (pos.second > col) {
            QString newKey = cellReference(pos.first, pos.second - 1);
            newCells[newKey] = it.value();
        } else if (pos.second < col) {
            newCells[it.key()] = it.value();
        }
        // Cells in deleted column are discarded
    }
    cells_ = newCells;

    updateTableHeaders();
    markAsModified();
}

void SpreadsheetWidget::recalculateAll()
{
    // Simple recalculation - in production would handle dependencies properly
    for (auto it = cells_.begin(); it != cells_.end(); ++it) {
        SpreadsheetCell* cell = it.value();
        if (cell->getType() == SpreadsheetCell::Formula) {
            QPair<int, int> pos = parseCellReference(it.key());
            QVariant result = cell->evaluateFormula(cells_);
            cell->setDisplayText(result.toString());
            table_->item(pos.first, pos.second)->setText(result.toString());
        }
    }
}

void SpreadsheetWidget::recalculateRange(const SpreadsheetRange& range)
{
    QList<QPair<int, int>> cells = range.getCells();

    for (const auto& cellPos : cells) {
        QString key = cellReference(cellPos.first, cellPos.second);
        if (cells_.contains(key)) {
            SpreadsheetCell* cell = cells_[key];
            if (cell->getType() == SpreadsheetCell::Formula) {
                QVariant result = cell->evaluateFormula(cells_);
                cell->setDisplayText(result.toString());
                table_->item(cellPos.first, cellPos.second)->setText(result.toString());
            }
        }
    }
}

void SpreadsheetWidget::refresh()
{
    updateTableHeaders();
    updateToolbar();
    updateFormulaBar();
    updateStatusBar();
    updateWindowTitle();
}

void SpreadsheetWidget::setReadOnly(bool readOnly)
{
    readOnly_ = readOnly;
    table_->setEditTriggers(readOnly ? QAbstractItemView::NoEditTriggers : QAbstractItemView::DoubleClicked);
    formulaEdit_->setReadOnly(readOnly);
    updateToolbar();
}

QString SpreadsheetWidget::getTitle() const
{
    return spreadsheetTitle_;
}

void SpreadsheetWidget::closeEvent(QCloseEvent* event)
{
    if (checkUnsavedChanges()) {
        event->accept();
    } else {
        event->ignore();
    }
}

void SpreadsheetWidget::dragEnterEvent(QDragEnterEvent* event)
{
    if (event->mimeData()->hasUrls()) {
        event->acceptProposedAction();
    }
}

void SpreadsheetWidget::dropEvent(QDropEvent* event)
{
    const QMimeData* mimeData = event->mimeData();
    if (mimeData->hasUrls()) {
        QList<QUrl> urls = mimeData->urls();
        if (!urls.isEmpty()) {
            QString filePath = urls.first().toLocalFile();
            if (filePath.endsWith(".json") || filePath.endsWith(".csv")) {
                loadSpreadsheet(filePath);
            }
        }
    }
}

void SpreadsheetWidget::loadSpreadsheetFromJson(const QJsonObject& spreadsheet)
{
    // Clear existing data
    cells_.clear();

    spreadsheetTitle_ = spreadsheet["title"].toString(tr("Untitled Spreadsheet"));

    QJsonObject metadata = spreadsheet["metadata"].toObject();
    int rows = metadata["rows"].toInt(100);
    int cols = metadata["cols"].toInt(26);

    initializeTable(rows, cols);

    QJsonObject data = spreadsheet["data"].toObject();
    for (auto it = data.begin(); it != data.end(); ++it) {
        QString cellRef = it.key();
        QJsonObject cellData = it.value().toObject();

        QPair<int, int> pos = parseCellReference(cellRef);
        if (pos.first >= 0 && pos.second >= 0 && pos.first < rows && pos.second < cols) {
            SpreadsheetCell* cell = new SpreadsheetCell();
            cell->fromJson(cellData);
            setCell(pos.first, pos.second, cell);
            updateCellDisplay(pos.first, pos.second);
        }
    }

    recalculateAll();
}

QJsonObject SpreadsheetWidget::saveSpreadsheetToJson() const
{
    QJsonObject spreadsheet;
    spreadsheet["title"] = spreadsheetTitle_;

    QJsonObject metadata;
    metadata["rows"] = table_->rowCount();
    metadata["cols"] = table_->columnCount();
    spreadsheet["metadata"] = metadata;

    QJsonObject data;
    for (auto it = cells_.begin(); it != cells_.end(); ++it) {
        data[it.key()] = it.value()->toJson();
    }
    spreadsheet["data"] = data;

    return spreadsheet;
}

SpreadsheetCell* SpreadsheetWidget::getCell(int row, int col) const
{
    QString key = cellReference(row, col);
    return cells_.value(key, nullptr);
}

void SpreadsheetWidget::setCell(int row, int col, SpreadsheetCell* cell)
{
    QString key = cellReference(row, col);
    cells_[key] = cell;
}

void SpreadsheetWidget::initializeTable(int rows, int cols)
{
    table_->setRowCount(rows);
    table_->setColumnCount(cols);
    updateTableHeaders();

    // Initialize empty cells
    for (int row = 0; row < rows; ++row) {
        for (int col = 0; col < cols; ++col) {
            QTableWidgetItem* item = new QTableWidgetItem();
            table_->setItem(row, col, item);
        }
    }
}

void SpreadsheetWidget::updateTableHeaders()
{
    // Update column headers (A, B, C, ...)
    for (int col = 0; col < table_->columnCount(); ++col) {
        table_->setHorizontalHeaderItem(col, new QTableWidgetItem(columnToString(col)));
    }

    // Update row headers (1, 2, 3, ...)
    for (int row = 0; row < table_->rowCount(); ++row) {
        table_->setVerticalHeaderItem(row, new QTableWidgetItem(QString::number(row + 1)));
    }
}

void SpreadsheetWidget::updateCellDisplay(int row, int col)
{
    SpreadsheetCell* cell = getCell(row, col);
    if (cell) {
        QTableWidgetItem* item = table_->item(row, col);
        if (item) {
            item->setText(cell->getDisplayText());
        }
    }
}

QString SpreadsheetWidget::columnToString(int col) const
{
    QString result;
    while (col >= 0) {
        result.prepend(QChar('A' + (col % 26)));
        col = col / 26 - 1;
    }
    return result;
}

int SpreadsheetWidget::stringToColumn(const QString& str) const
{
    int result = 0;
    for (QChar c : str.toUpper()) {
        result = result * 26 + (c.toLatin1() - 'A');
    }
    return result;
}

QString SpreadsheetWidget::cellReference(int row, int col) const
{
    return columnToString(col) + QString::number(row + 1);
}

QPair<int, int> SpreadsheetWidget::parseCellReference(const QString& ref) const
{
    QRegularExpression regex("^([A-Z]+)(\\d+)$");
    QRegularExpressionMatch match = regex.match(ref.toUpper());

    if (match.hasMatch()) {
        int col = stringToColumn(match.captured(1));
        int row = match.captured(2).toInt() - 1; // Convert to 0-based
        return qMakePair(row, col);
    }

    return qMakePair(-1, -1);
}

void SpreadsheetWidget::copyToClipboard(const SpreadsheetRange& range)
{
    QList<QVariant> values = getRangeValues(range);
    QStringList textValues;

    for (const QVariant& value : values) {
        textValues.append(value.toString());
    }

    QString clipboardText = textValues.join("\t");
    QApplication::clipboard()->setText(clipboardText);
}

void SpreadsheetWidget::pasteFromClipboard(int startRow, int startCol)
{
    QString clipboardText = QApplication::clipboard()->text();
    QStringList values = clipboardText.split('\t');

    int currentCol = startCol;
    for (const QString& value : values) {
        if (currentCol < table_->columnCount()) {
            setCellValue(startRow, currentCol, value);
            currentCol++;
        }
    }

    recalculateAll();
}

bool SpreadsheetWidget::hasCircularReference(int row, int col, const QString& formula)
{
    // Basic circular reference detection
    QString cellRef = cellReference(row, col);
    QStringList dependencies = SpreadsheetFormula::extractDependencies(formula);

    return dependencies.contains(cellRef);
}

void SpreadsheetWidget::sortRange(const SpreadsheetRange& range, int column, bool ascending)
{
    // Simple sort implementation
    QList<QPair<int, int>> cells = range.getCells();

    if (cells.isEmpty()) return;

    // Get values for the sort column
    QList<QPair<QVariant, int>> sortData;
    for (int row = range.startRow(); row <= range.endRow(); ++row) {
        QVariant value = getCellValue(row, column);
        sortData.append(qMakePair(value, row));
    }

    // Sort
    std::sort(sortData.begin(), sortData.end(), [ascending](const QPair<QVariant, int>& a, const QPair<QVariant, int>& b) {
        if (ascending) {
            return a.first.toString() < b.first.toString();
        } else {
            return a.first.toString() > b.first.toString();
        }
    });

    // Reorder rows
    for (int i = 0; i < sortData.size(); ++i) {
        int sourceRow = sortData[i].second;
        int destRow = range.startRow() + i;

        if (sourceRow != destRow) {
            // Swap entire rows
            for (int col = range.startCol(); col <= range.endCol(); ++col) {
                QVariant temp = getCellValue(destRow, col);
                setCellValue(destRow, col, getCellValue(sourceRow, col));
                setCellValue(sourceRow, col, temp);
            }
        }
    }

    recalculateAll();
}

void SpreadsheetWidget::filterRange(const SpreadsheetRange& range, int column, const QString& criteria)
{
    // Simple filter implementation - hide rows that don't match
    for (int row = range.startRow(); row <= range.endRow(); ++row) {
        QVariant value = getCellValue(row, column);
        bool matches = value.toString().contains(criteria, Qt::CaseInsensitive);

        table_->setRowHidden(row, !matches);
    }
}

bool SpreadsheetWidget::checkUnsavedChanges()
{
    if (!modified_) return true;

    QMessageBox::StandardButton reply = QMessageBox::question(this, tr("Unsaved Changes"),
                                                            tr("The spreadsheet has unsaved changes. Save before closing?"),
                                                            QMessageBox::Save | QMessageBox::Discard | QMessageBox::Cancel);

    if (reply == QMessageBox::Save) {
        return saveSpreadsheet();
    } else if (reply == QMessageBox::Cancel) {
        return false;
    }

    return true;
}

void SpreadsheetWidget::markAsModified()
{
    if (!modified_) {
        modified_ = true;
        updateWindowTitle();
    }
}

void SpreadsheetWidget::updateToolbar()
{
    bool hasSelection = !table_->selectedItems().isEmpty();
    bool hasData = !cells_.isEmpty();

    copyBtn_->setEnabled(hasSelection);
    cutBtn_->setEnabled(hasSelection && !readOnly_);
    pasteBtn_->setEnabled(!readOnly_);
    clearBtn_->setEnabled(hasSelection && !readOnly_);

    insertRowBtn_->setEnabled(!readOnly_);
    deleteRowBtn_->setEnabled(table_->rowCount() > 1 && !readOnly_);
    insertColBtn_->setEnabled(!readOnly_);
    deleteColBtn_->setEnabled(table_->columnCount() > 1 && !readOnly_);

    sortBtn_->setEnabled(hasSelection);
    filterBtn_->setEnabled(hasSelection);
    formatBtn_->setEnabled(hasSelection && !readOnly_);
}

void SpreadsheetWidget::updateFormulaBar()
{
    if (table_->currentItem()) {
        int row = table_->currentRow();
        int col = table_->currentColumn();

        cellRefLabel_->setText(cellReference(row, col));

        SpreadsheetCell* cell = getCell(row, col);
        if (cell && cell->getType() == SpreadsheetCell::Formula) {
            formulaEdit_->setText("=" + cell->getFormula());
        } else {
            formulaEdit_->setText(table_->currentItem()->text());
        }
    } else {
        cellRefLabel_->setText("");
        formulaEdit_->setText("");
    }
}

void SpreadsheetWidget::updateStatusBar()
{
    if (currentSelection_.isValid()) {
        selectionLabel_->setText(currentSelection_.toString());
    } else {
        selectionLabel_->setText("");
    }
}

void SpreadsheetWidget::updateWindowTitle()
{
    QString title = spreadsheetTitle_;
    if (modified_) {
        title += " *";
    }
    if (!currentFilePath_.isEmpty()) {
        title += QString(" (%1)").arg(QFileInfo(currentFilePath_).fileName());
    }

    emit titleChanged(title);
}

void SpreadsheetWidget::onNewSpreadsheet()
{
    if (checkUnsavedChanges()) {
        createNewSpreadsheet();
    }
}

void SpreadsheetWidget::onOpenSpreadsheet()
{
    if (!checkUnsavedChanges()) return;

    QString fileName = QFileDialog::getOpenFileName(this, tr("Open Spreadsheet"),
                                                  QString(),
                                                  tr("JSON files (*.json);;CSV files (*.csv);;All files (*)"));

    if (!fileName.isEmpty()) {
        loadSpreadsheet(fileName);
    }
}

void SpreadsheetWidget::onSaveSpreadsheet()
{
    saveSpreadsheet();
}

void SpreadsheetWidget::onSaveAsSpreadsheet()
{
    saveSpreadsheetAs();
}

void SpreadsheetWidget::onExportSpreadsheet()
{
    QString fileName = QFileDialog::getSaveFileName(this, tr("Export Spreadsheet"),
                                                  QString(),
                                                  tr("CSV files (*.csv);;HTML files (*.html);;All files (*)"));

    if (!fileName.isEmpty()) {
        // TODO: Implement export functionality
        QMessageBox::information(this, tr("Export"), tr("Export functionality not implemented yet"));
    }
}

void SpreadsheetWidget::onCellChanged(int row, int col)
{
    QTableWidgetItem* item = table_->item(row, col);
    if (item) {
        QString text = item->text();
        if (text.startsWith('=')) {
            setCellFormula(row, col, text.mid(1));
        } else {
            setCellValue(row, col, text);
        }
    }

    recalculateAll();
    markAsModified();
}

void SpreadsheetWidget::onCellDoubleClicked(int row, int col)
{
    updateFormulaBar();
}

void SpreadsheetWidget::onSelectionChanged()
{
    QList<QTableWidgetItem*> selectedItems = table_->selectedItems();

    if (selectedItems.isEmpty()) {
        currentSelection_ = SpreadsheetRange();
    } else {
        int minRow = INT_MAX, minCol = INT_MAX;
        int maxRow = INT_MIN, maxCol = INT_MIN;

        for (QTableWidgetItem* item : selectedItems) {
            minRow = qMin(minRow, item->row());
            minCol = qMin(minCol, item->column());
            maxRow = qMax(maxRow, item->row());
            maxCol = qMax(maxCol, item->column());
        }

        currentSelection_ = SpreadsheetRange(minRow, minCol, maxRow, maxCol);
    }

    updateStatusBar();
    updateToolbar();
}

void SpreadsheetWidget::onContextMenuRequested(const QPoint& pos)
{
    QMenu menu(this);

    menu.addAction(tr("Copy"), this, &SpreadsheetWidget::onCopy);
    menu.addAction(tr("Cut"), this, &SpreadsheetWidget::onCut);
    menu.addAction(tr("Paste"), this, &SpreadsheetWidget::onPaste);
    menu.addSeparator();
    menu.addAction(tr("Clear"), this, &SpreadsheetWidget::onClear);
    menu.addSeparator();
    menu.addAction(tr("Insert Row"), this, &SpreadsheetWidget::onInsertRow);
    menu.addAction(tr("Delete Row"), this, &SpreadsheetWidget::onDeleteRow);
    menu.addAction(tr("Insert Column"), this, &SpreadsheetWidget::onInsertColumn);
    menu.addAction(tr("Delete Column"), this, &SpreadsheetWidget::onDeleteColumn);
    menu.addSeparator();
    menu.addAction(tr("Sort..."), this, &SpreadsheetWidget::onSortRange);
    menu.addAction(tr("Filter..."), this, &SpreadsheetWidget::onFilterRange);
    menu.addAction(tr("Format Cell..."), this, &SpreadsheetWidget::onFormatCell);

    menu.exec(table_->mapToGlobal(pos));
}

void SpreadsheetWidget::onCopy()
{
    if (currentSelection_.isValid()) {
        copyToClipboard(currentSelection_);
    }
}

void SpreadsheetWidget::onCut()
{
    if (currentSelection_.isValid()) {
        copyToClipboard(currentSelection_);
        clearRange(currentSelection_);
    }
}

void SpreadsheetWidget::onPaste()
{
    if (table_->currentItem()) {
        pasteFromClipboard(table_->currentRow(), table_->currentColumn());
    }
}

void SpreadsheetWidget::onClear()
{
    if (currentSelection_.isValid()) {
        clearRange(currentSelection_);
    }
}

void SpreadsheetWidget::onInsertRow()
{
    if (table_->currentItem()) {
        insertRow(table_->currentRow());
    }
}

void SpreadsheetWidget::onDeleteRow()
{
    if (table_->currentItem()) {
        deleteRow(table_->currentRow());
    }
}

void SpreadsheetWidget::onInsertColumn()
{
    if (table_->currentItem()) {
        insertColumn(table_->currentColumn());
    }
}

void SpreadsheetWidget::onDeleteColumn()
{
    if (table_->currentItem()) {
        deleteColumn(table_->currentColumn());
    }
}

void SpreadsheetWidget::onSortRange()
{
    if (!currentSelection_.isValid()) return;

    bool ok;
    QStringList options;
    for (int col = currentSelection_.startCol(); col <= currentSelection_.endCol(); ++col) {
        options.append(columnToString(col));
    }

    QString selectedCol = QInputDialog::getItem(this, tr("Sort Range"),
                                              tr("Sort by column:"), options, 0, false, &ok);

    if (!ok) return;

    int sortCol = stringToColumn(selectedCol);

    QMessageBox::StandardButton reply = QMessageBox::question(this, tr("Sort Direction"),
                                                            tr("Sort ascending?"),
                                                            QMessageBox::Yes | QMessageBox::No);

    bool ascending = (reply == QMessageBox::Yes);

    sortRange(currentSelection_, sortCol, ascending);
}

void SpreadsheetWidget::onFilterRange()
{
    if (!currentSelection_.isValid()) return;

    bool ok;
    QString criteria = QInputDialog::getText(this, tr("Filter Range"),
                                           tr("Filter criteria:"), QLineEdit::Normal, "", &ok);

    if (!ok || criteria.isEmpty()) return;

    // Use first column for filtering
    filterRange(currentSelection_, currentSelection_.startCol(), criteria);
}

void SpreadsheetWidget::onFormatCell()
{
    // TODO: Implement cell formatting dialog
    QMessageBox::information(this, tr("Format Cell"), tr("Cell formatting not implemented yet"));
}