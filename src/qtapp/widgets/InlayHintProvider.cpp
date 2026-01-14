/**
 * @file InlayHintProvider.cpp
 * @brief Complete LSP Inlay Hints Implementation for RawrXD Agentic IDE
 * 
 * Provides inline type annotations, parameter names, and other hints
 * displayed directly in the editor without modifying source code.
 * 
 * @author RawrXD Team
 * @copyright 2024 RawrXD
 */

#include "InlayHintProvider.h"
#include <QRegularExpression>
#include <QRegularExpressionMatchIterator>
#include <QFileInfo>
#include <QDir>
#include <QDateTime>
#include <QCryptographicHash>
#include <QMutexLocker>
#include <QThreadPool>
#include <QtConcurrent>
#include <QFuture>
#include <QFutureWatcher>
#include <QColor>
#include <algorithm>
#include <functional>

namespace RawrXD {

// ============================================================================
// InlayHintItem Implementation
// ============================================================================

InlayHintItem::InlayHintItem()
    : m_line(0)
    , m_column(0)
    , m_kind(InlayHintKind::Default)
    , m_position(InlayHintPosition::After)
    , m_paddingLeft(false)
    , m_paddingRight(true)
    , m_foregroundColor(QColor("#888888"))
    , m_backgroundColor(QColor("#f0f0f0"))
    , m_isClickable(false)
{
}

InlayHintItem::InlayHintItem(int line, int column, const QString& label, InlayHintKind kind)
    : m_line(line)
    , m_column(column)
    , m_label(label)
    , m_kind(kind)
    , m_position(InlayHintPosition::After)
    , m_paddingLeft(false)
    , m_paddingRight(true)
    , m_foregroundColor(QColor("#888888"))
    , m_backgroundColor(QColor("#f0f0f0"))
    , m_isClickable(false)
{
    // Set kind-specific defaults
    switch (kind) {
        case InlayHintKind::Type:
            m_foregroundColor = QColor("#007acc");
            m_paddingLeft = true;
            break;
        case InlayHintKind::Parameter:
            m_foregroundColor = QColor("#795e26");
            m_paddingRight = false;
            break;
        case InlayHintKind::ChainingHint:
            m_foregroundColor = QColor("#098658");
            break;
        case InlayHintKind::EnumMember:
            m_foregroundColor = QColor("#af00db");
            break;
        case InlayHintKind::ClosingLabel:
            m_foregroundColor = QColor("#6a9955");
            m_position = InlayHintPosition::Before;
            break;
        case InlayHintKind::ImplicitConversion:
            m_foregroundColor = QColor("#d73a49");
            m_backgroundColor = QColor("#ffd7d5");
            break;
        case InlayHintKind::LifetimeElision:
            m_foregroundColor = QColor("#953800");
            break;
        case InlayHintKind::BindingMode:
            m_foregroundColor = QColor("#953800");
            break;
        case InlayHintKind::GenericType:
            m_foregroundColor = QColor("#267f99");
            break;
        case InlayHintKind::Designator:
            m_foregroundColor = QColor("#795e26");
            break;
        default:
            break;
    }
}

bool InlayHintItem::operator<(const InlayHintItem& other) const
{
    if (m_line != other.m_line) {
        return m_line < other.m_line;
    }
    return m_column < other.m_column;
}

bool InlayHintItem::isValid() const
{
    return m_line >= 0 && m_column >= 0 && !m_label.isEmpty();
}

QString InlayHintItem::toDisplayString() const
{
    QString result = m_label;
    
    if (m_paddingLeft) {
        result.prepend(QLatin1Char(' '));
    }
    if (m_paddingRight) {
        result.append(QLatin1Char(' '));
    }
    
    return result;
}

// ============================================================================
// InlayHintCache Implementation
// ============================================================================

InlayHintCache::InlayHintCache(int maxSize)
    : m_maxSize(maxSize)
{
}

void InlayHintCache::insert(const QString& key, const QList<InlayHintItem>& items, const QString& contentHash)
{
    QMutexLocker locker(&m_mutex);
    
    CacheEntry entry;
    entry.items = items;
    entry.contentHash = contentHash;
    entry.timestamp = QDateTime::currentMSecsSinceEpoch();
    
    m_cache[key] = entry;
    
    // Evict old entries if cache is too large
    if (m_cache.size() > m_maxSize) {
        evictOldest();
    }
}

bool InlayHintCache::lookup(const QString& key, const QString& contentHash, QList<InlayHintItem>& outItems) const
{
    QMutexLocker locker(&m_mutex);
    
    auto it = m_cache.find(key);
    if (it == m_cache.end()) {
        return false;
    }
    
    // Check if content hash matches (invalidate if content changed)
    if (it->contentHash != contentHash) {
        return false;
    }
    
    outItems = it->items;
    return true;
}

void InlayHintCache::invalidate(const QString& key)
{
    QMutexLocker locker(&m_mutex);
    m_cache.remove(key);
}

void InlayHintCache::clear()
{
    QMutexLocker locker(&m_mutex);
    m_cache.clear();
}

int InlayHintCache::size() const
{
    QMutexLocker locker(&m_mutex);
    return m_cache.size();
}

void InlayHintCache::evictOldest()
{
    if (m_cache.isEmpty()) return;
    
    QString oldestKey;
    qint64 oldestTime = std::numeric_limits<qint64>::max();
    
    for (auto it = m_cache.begin(); it != m_cache.end(); ++it) {
        if (it->timestamp < oldestTime) {
            oldestTime = it->timestamp;
            oldestKey = it.key();
        }
    }
    
    if (!oldestKey.isEmpty()) {
        m_cache.remove(oldestKey);
    }
}

// ============================================================================
// InlayHintProvider Implementation
// ============================================================================

InlayHintProvider::InlayHintProvider(QObject* parent)
    : QObject(parent)
    , m_cache(std::make_unique<InlayHintCache>(100))
    , m_maxHintLength(50)
    , m_minParameterNameLength(3)
    , m_minLinesForClosingLabel(10)
    , m_asyncEnabled(true)
{
    // Initialize enabled kinds
    m_enabledKinds[InlayHintKind::Type] = true;
    m_enabledKinds[InlayHintKind::Parameter] = true;
    m_enabledKinds[InlayHintKind::ChainingHint] = true;
    m_enabledKinds[InlayHintKind::ClosingLabel] = true;
    m_enabledKinds[InlayHintKind::EnumMember] = true;
    m_enabledKinds[InlayHintKind::GenericType] = true;
    m_enabledKinds[InlayHintKind::Default] = true;
    
    initializeLanguagePatterns();
    initializeBuiltinSignatures();
    
    qDebug() << "[InlayHintProvider] Initialized with" << m_enabledKinds.size() << "enabled hint kinds";
}

InlayHintProvider::~InlayHintProvider()
{
    qDebug() << "[InlayHintProvider] Destroyed, cache size:" << m_cache->size();
}

void InlayHintProvider::initializeLanguagePatterns()
{
    // C++ patterns
    InlayHintLanguagePatterns cpp;
    cpp.functionCallPattern = QRegularExpression(
        R"((\w+)\s*\(([^)]*)\))",
        QRegularExpression::MultilineOption
    );
    cpp.functionDefPattern = QRegularExpression(
        R"(^\s*(?:[\w<>]+\s+)*(\w+)\s*\(([^)]*)\)\s*(?:const\s*)?(?:\{|;))",
        QRegularExpression::MultilineOption
    );
    cpp.variablePattern = QRegularExpression(
        R"((?:auto|const\s+auto|volatile\s+auto)\s+(\w+)\s*=\s*([^;]+);)",
        QRegularExpression::MultilineOption
    );
    cpp.methodChainPattern = QRegularExpression(
        R"((\w+(?:\.|->)\w+)(?:\.|->)\w+)",
        QRegularExpression::MultilineOption
    );
    cpp.closingBracePattern = QRegularExpression(
        R"(^\s*\})",
        QRegularExpression::MultilineOption
    );
    cpp.genericPattern = QRegularExpression(
        R"(template\s*<[^>]+>)",
        QRegularExpression::MultilineOption
    );
    cpp.lambdaPattern = QRegularExpression(
        R"(\[([^]]*)\]\s*\(([^)]*)\)\s*(?:->\s*([^{]+))?\s*\{)",
        QRegularExpression::MultilineOption
    );
    m_languagePatterns[QStringLiteral("cpp")] = cpp;
    m_languagePatterns[QStringLiteral("c")] = cpp;
    m_languagePatterns[QStringLiteral("h")] = cpp;
    m_languagePatterns[QStringLiteral("hpp")] = cpp;
    
    // Python patterns
    InlayHintLanguagePatterns python;
    python.functionCallPattern = QRegularExpression(
        R"((\w+)\s*\(([^)]*)\))",
        QRegularExpression::MultilineOption
    );
    python.functionDefPattern = QRegularExpression(
        R"(^\s*(?:async\s+)?def\s+(\w+)\s*\(([^)]*)\)\s*(?:->\s*(\w+))?\s*:)",
        QRegularExpression::MultilineOption
    );
    python.variablePattern = QRegularExpression(
        R"((\w+)\s*=\s*([^\n]+))",
        QRegularExpression::MultilineOption
    );
    python.methodChainPattern = QRegularExpression(
        R"((\w+\.\w+)(?:\.\w+)+)",
        QRegularExpression::MultilineOption
    );
    python.closingBracePattern = QRegularExpression(
        R"(^\s*(?:return|pass|break|continue|raise)\s*$)",
        QRegularExpression::MultilineOption
    );
    python.genericPattern = QRegularExpression(
        R"(from\s+typing\s+import|List\[|Dict\[|Tuple\[)",
        QRegularExpression::MultilineOption
    );
    python.lambdaPattern = QRegularExpression(
        R"(lambda\s+([^:]+):)",
        QRegularExpression::MultilineOption
    );
    m_languagePatterns[QStringLiteral("py")] = python;
    m_languagePatterns[QStringLiteral("pyw")] = python;
    
    // JavaScript/TypeScript patterns
    InlayHintLanguagePatterns javascript;
    javascript.functionCallPattern = QRegularExpression(
        R"((\w+)\s*\(([^)]*)\))",
        QRegularExpression::MultilineOption
    );
    javascript.functionDefPattern = QRegularExpression(
        R"(^\s*(?:export\s+)?(?:async\s+)?(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:\([^)]*\)|[^=]+)\s*=>))",
        QRegularExpression::MultilineOption
    );
    javascript.variablePattern = QRegularExpression(
        R"((?:const|let|var)\s+(\w+)\s*(?::\s*[^=]+)?\s*=\s*([^;]+);)",
        QRegularExpression::MultilineOption
    );
    javascript.methodChainPattern = QRegularExpression(
        R"((\w+\.\w+)(?:\.\w+)+)",
        QRegularExpression::MultilineOption
    );
    javascript.closingBracePattern = QRegularExpression(
        R"(^\s*\})",
        QRegularExpression::MultilineOption
    );
    javascript.genericPattern = QRegularExpression(
        R"(<[^>]+>)",
        QRegularExpression::MultilineOption
    );
    javascript.lambdaPattern = QRegularExpression(
        R"((?:\([^)]*\)|[^=]+)\s*=>\s*\{)",
        QRegularExpression::MultilineOption
    );
    m_languagePatterns[QStringLiteral("js")] = javascript;
    m_languagePatterns[QStringLiteral("jsx")] = javascript;
    m_languagePatterns[QStringLiteral("ts")] = javascript;
    m_languagePatterns[QStringLiteral("tsx")] = javascript;
    
    // Rust patterns
    InlayHintLanguagePatterns rust;
    rust.functionCallPattern = QRegularExpression(
        R"((\w+)\s*\(([^)]*)\))",
        QRegularExpression::MultilineOption
    );
    rust.functionDefPattern = QRegularExpression(
        R"(^\s*(?:pub(?:\([^)]+\))?\s+)?(?:async\s+)?fn\s+(\w+)(?:<[^>]+>)?\s*\(([^)]*)\))",
        QRegularExpression::MultilineOption
    );
    rust.variablePattern = QRegularExpression(
        R"((?:let\s+(?:mut\s+)?(\w+)(?::\s*[^=]+)?\s*=\s*([^;]+);))",
        QRegularExpression::MultilineOption
    );
    rust.methodChainPattern = QRegularExpression(
        R"((\w+\.\w+)(?:\.\w+)+)",
        QRegularExpression::MultilineOption
    );
    rust.closingBracePattern = QRegularExpression(
        R"(^\s*\})",
        QRegularExpression::MultilineOption
    );
    rust.genericPattern = QRegularExpression(
        R"(<[^>]+>)",
        QRegularExpression::MultilineOption
    );
    rust.lambdaPattern = QRegularExpression(
        R"(\|([^|]*)\|\s*(?:->\s*([^{]+))?\s*\{)",
        QRegularExpression::MultilineOption
    );
    m_languagePatterns[QStringLiteral("rs")] = rust;
    
    // Go patterns
    InlayHintLanguagePatterns golang;
    golang.functionCallPattern = QRegularExpression(
        R"((\w+)\s*\(([^)]*)\))",
        QRegularExpression::MultilineOption
    );
    golang.functionDefPattern = QRegularExpression(
        R"(^\s*func\s+(\w+)\s*\(([^)]*)\))",
        QRegularExpression::MultilineOption
    );
    golang.variablePattern = QRegularExpression(
        R"((?:var\s+)?(\w+)\s*(?::=\s*|\s+[^=]+\s*=\s*)([^;]+))",
        QRegularExpression::MultilineOption
    );
    golang.methodChainPattern = QRegularExpression(
        R"((\w+\.\w+)(?:\.\w+)+)",
        QRegularExpression::MultilineOption
    );
    golang.closingBracePattern = QRegularExpression(
        R"(^\s*\})",
        QRegularExpression::MultilineOption
    );
    golang.genericPattern = QRegularExpression(
        R"(\[[^\]]+\])",
        QRegularExpression::MultilineOption
    );
    golang.lambdaPattern = QRegularExpression(
        R"(func\s*\([^)]*\)\s*\{)",
        QRegularExpression::MultilineOption
    );
    m_languagePatterns[QStringLiteral("go")] = golang;
}

void InlayHintProvider::initializeBuiltinSignatures()
{
    // C++ standard library functions
    FunctionSignature printfSig;
    printfSig.name = QStringLiteral("printf");
    printfSig.returnType = QStringLiteral("int");
    printfSig.parameters.append({"format", "const char*", "", false, false, 0});
    printfSig.parameters.append({"...", "", "", false, true, 1});
    m_functionSignatures[printfSig.name] = printfSig;
    
    FunctionSignature mallocSig;
    mallocSig.name = QStringLiteral("malloc");
    mallocSig.returnType = QStringLiteral("void*");
    mallocSig.parameters.append({"size", "size_t", "", false, false, 0});
    m_functionSignatures[mallocSig.name] = mallocSig;
    
    FunctionSignature strlenSig;
    strlenSig.name = QStringLiteral("strlen");
    strlenSig.returnType = QStringLiteral("size_t");
    strlenSig.parameters.append({"str", "const char*", "", false, false, 0});
    m_functionSignatures[strlenSig.name] = strlenSig;
    
    // Python builtins
    FunctionSignature printSig;
    printSig.name = QStringLiteral("print");
    printSig.returnType = QStringLiteral("None");
    printSig.parameters.append({"value", "Any", "", false, false, 0});
    printSig.parameters.append({"...", "", "", false, true, 1});
    m_functionSignatures[printSig.name] = printSig;
    
    FunctionSignature lenSig;
    lenSig.name = QStringLiteral("len");
    lenSig.returnType = QStringLiteral("int");
    lenSig.parameters.append({"obj", "object", "", false, false, 0});
    m_functionSignatures[lenSig.name] = lenSig;
    
    // JavaScript builtins
    FunctionSignature consoleLogSig;
    consoleLogSig.name = QStringLiteral("console.log");
    consoleLogSig.returnType = QStringLiteral("void");
    consoleLogSig.parameters.append({"...", "", "", false, true, 0});
    m_functionSignatures[consoleLogSig.name] = consoleLogSig;
    
    // Rust stdlib
    FunctionSignature printlnSig;
    printlnSig.name = QStringLiteral("println!");
    printlnSig.returnType = QStringLiteral("()");
    printlnSig.parameters.append({"format", "&str", "", false, false, 0});
    printlnSig.parameters.append({"...", "", "", false, true, 1});
    m_functionSignatures[printlnSig.name] = printlnSig;
    
    // Go builtins
    FunctionSignature fmtPrintlnSig;
    fmtPrintlnSig.name = QStringLiteral("fmt.Println");
    fmtPrintlnSig.returnType = QStringLiteral("int, error");
    fmtPrintlnSig.parameters.append({"...", "", "", false, true, 0});
    m_functionSignatures[fmtPrintlnSig.name] = fmtPrintlnSig;
}

QString InlayHintProvider::detectLanguage(const QString& filePath) const
{
    QFileInfo fileInfo(filePath);
    QString extension = fileInfo.suffix().toLower();
    
    static const QHash<QString, QString> extensionMap = {
        {QStringLiteral("cpp"), QStringLiteral("cpp")},
        {QStringLiteral("cxx"), QStringLiteral("cpp")},
        {QStringLiteral("cc"), QStringLiteral("cpp")},
        {QStringLiteral("c"), QStringLiteral("c")},
        {QStringLiteral("h"), QStringLiteral("h")},
        {QStringLiteral("hpp"), QStringLiteral("hpp")},
        {QStringLiteral("hxx"), QStringLiteral("hpp")},
        {QStringLiteral("py"), QStringLiteral("py")},
        {QStringLiteral("pyw"), QStringLiteral("pyw")},
        {QStringLiteral("js"), QStringLiteral("js")},
        {QStringLiteral("jsx"), QStringLiteral("jsx")},
        {QStringLiteral("ts"), QStringLiteral("ts")},
        {QStringLiteral("tsx"), QStringLiteral("tsx")},
        {QStringLiteral("rs"), QStringLiteral("rs")},
        {QStringLiteral("go"), QStringLiteral("go")}
    };
    
    return extensionMap.value(extension, QString());
}

QString InlayHintProvider::computeContentHash(const QString& content) const
{
    return QString::fromLatin1(
        QCryptographicHash::hash(content.toUtf8(), QCryptographicHash::Md5).toHex()
    );
}

QList<InlayHintItem> InlayHintProvider::getInlayHints(const QString& filePath, const QString& content)
{
    const QString language = detectLanguage(filePath);
    const QString contentHash = computeContentHash(content);
    
    // Check cache first
    QList<InlayHintItem> cachedHints;
    if (m_cache->lookup(filePath, contentHash, cachedHints)) {
        qDebug() << "[InlayHintProvider] Cache hit for" << filePath;
        return cachedHints;
    }
    
    qDebug() << "[InlayHintProvider] Computing inlay hints for" << filePath << "language:" << language;
    
    QList<InlayHintItem> hints;
    
    // Generate various types of hints
    if (m_enabledKinds.value(InlayHintKind::Type, false)) {
        auto variables = extractVariableDeclarations(content, language);
        hints.append(generateTypeHints(variables, content, language));
    }
    
    if (m_enabledKinds.value(InlayHintKind::Parameter, false)) {
        hints.append(generateParameterHints(content, language));
    }
    
    if (m_enabledKinds.value(InlayHintKind::ChainingHint, false)) {
        hints.append(generateChainingHints(content, language));
    }
    
    if (m_enabledKinds.value(InlayHintKind::ClosingLabel, false)) {
        hints.append(generateClosingLabelHints(content, language));
    }
    
    if (m_enabledKinds.value(InlayHintKind::EnumMember, false)) {
        hints.append(generateEnumHints(content, language));
    }
    
    if (m_enabledKinds.value(InlayHintKind::GenericType, false)) {
        hints.append(generateGenericHints(content, language));
    }
    
    // Sort hints by line and column
    std::sort(hints.begin(), hints.end());
    
    // Merge overlapping hints
    hints = mergeHints(hints);
    
    // Cache the results
    m_cache->insert(filePath, hints, contentHash);
    
    qDebug() << "[InlayHintProvider] Generated" << hints.size() << "inlay hints for" << filePath;
    
    return hints;
}

QList<InlayHintItem> InlayHintProvider::getInlayHintsForRange(
    const QString& filePath,
    const QString& content,
    int startLine,
    int endLine)
{
    QList<InlayHintItem> allHints = getInlayHints(filePath, content);
    QList<InlayHintItem> rangeHints;
    
    for (const InlayHintItem& hint : allHints) {
        if (hint.line() >= startLine && hint.line() <= endLine) {
            rangeHints.append(hint);
        }
    }
    
    return rangeHints;
}

QList<VariableDeclaration> InlayHintProvider::extractVariableDeclarations(
    const QString& content,
    const QString& language) const
{
    QList<VariableDeclaration> variables;
    
    auto it = m_languagePatterns.find(language);
    if (it == m_languagePatterns.end() || !it->variablePattern.isValid()) {
        return variables;
    }
    
    const InlayHintLanguagePatterns& patterns = *it;
    const QStringList lines = content.split(QLatin1Char('\n'));
    
    QRegularExpressionMatchIterator iter = patterns.variablePattern.globalMatch(content);
    while (iter.hasNext()) {
        QRegularExpressionMatch match = iter.next();
        
        VariableDeclaration var;
        var.name = match.captured(1);
        var.line = content.left(match.capturedStart()).count(QLatin1Char('\n'));
        var.column = match.capturedStart() - content.lastIndexOf(QLatin1Char('\n'), match.capturedStart()) - 1;
        
        // Infer type from the expression
        QString expression = match.captured(2).trimmed();
        var.inferredType = inferTypeFromExpression(expression, language, content);
        
        // Check if there's an explicit type annotation
        if (language == QStringLiteral("cpp") || language == QStringLiteral("c")) {
            // Look for type before the variable name
            QString beforeVar = content.mid(0, match.capturedStart()).trimmed();
            QRegularExpression typePattern(QStringLiteral("([\w<>]+)\s+" + QRegularExpression::escape(var.name)));
            QRegularExpressionMatch typeMatch = typePattern.match(beforeVar);
            if (typeMatch.hasMatch()) {
                var.explicitType = typeMatch.captured(1);
                var.hasExplicitType = true;
            }
        }
        
        variables.append(var);
    }
    
    return variables;
}

QList<InlayHintItem> InlayHintProvider::generateTypeHints(
    const QList<VariableDeclaration>& variables,
    const QString& content,
    const QString& language) const
{
    QList<InlayHintItem> hints;
    
    for (const VariableDeclaration& var : variables) {
        // Only show type hint if there's no explicit type and we inferred something useful
        if (!var.hasExplicitType && !var.inferredType.isEmpty() && var.inferredType != QStringLiteral("auto")) {
            InlayHintItem hint(var.line, var.column + var.name.length(), 
                              QStringLiteral(": %1").arg(var.inferredType), 
                              InlayHintKind::Type);
            hint.setTooltip(QStringLiteral("Inferred type: %1").arg(var.inferredType));
            hints.append(hint);
        }
    }
    
    return hints;
}

QList<InlayHintItem> InlayHintProvider::generateParameterHints(
    const QString& content,
    const QString& language) const
{
    QList<InlayHintItem> hints;
    
    auto it = m_languagePatterns.find(language);
    if (it == m_languagePatterns.end() || !it->functionCallPattern.isValid()) {
        return hints;
    }
    
    const InlayHintLanguagePatterns& patterns = *it;
    const QStringList lines = content.split(QLatin1Char('\n'));
    
    QRegularExpressionMatchIterator iter = patterns.functionCallPattern.globalMatch(content);
    while (iter.hasNext()) {
        QRegularExpressionMatch match = iter.next();
        
        QString functionName = match.captured(1);
        QString argString = match.captured(2);
        
        // Find function signature
        FunctionSignature signature = findFunctionSignature(functionName);
        if (signature.name.isEmpty()) {
            continue;
        }
        
        // Parse arguments
        QStringList arguments = parseCallArguments(argString);
        
        // Generate parameter hints
        for (int i = 0; i < qMin(arguments.size(), signature.parameters.size()); ++i) {
            const ParameterInfo& param = signature.parameters[i];
            
            // Skip short parameter names
            if (param.name.length() < m_minParameterNameLength) {
                continue;
            }
            
            // Find the argument position
            QString argument = arguments[i].trimmed();
            if (argument.isEmpty()) continue;
            
            // Calculate column position
            int argStart = match.capturedStart(2) + argString.indexOf(argument);
            int line = content.left(argStart).count(QLatin1Char('\n'));
            int column = argStart - content.lastIndexOf(QLatin1Char('\n'), argStart) - 1;
            
            InlayHintItem hint(line, column, QStringLiteral("%1:").arg(param.name), 
                              InlayHintKind::Parameter);
            hint.setPosition(InlayHintPosition::Before);
            hint.setTooltip(QStringLiteral("Parameter: %1").arg(param.name));
            hints.append(hint);
        }
    }
    
    return hints;
}

QList<InlayHintItem> InlayHintProvider::generateChainingHints(
    const QString& content,
    const QString& language) const
{
    QList<InlayHintItem> hints;
    
    auto it = m_languagePatterns.find(language);
    if (it == m_languagePatterns.end() || !it->methodChainPattern.isValid()) {
        return hints;
    }
    
    const InlayHintLanguagePatterns& patterns = *it;
    
    QRegularExpressionMatchIterator iter = patterns.methodChainPattern.globalMatch(content);
    while (iter.hasNext()) {
        QRegularExpressionMatch match = iter.next();
        
        QString chainStart = match.captured(1);
        QString inferredType = inferTypeFromExpression(chainStart, language, content);
        
        if (!inferredType.isEmpty()) {
            int line = content.left(match.capturedStart()).count(QLatin1Char('\n'));
            int column = match.capturedStart() - content.lastIndexOf(QLatin1Char('\n'), match.capturedStart()) - 1;
            
            InlayHintItem hint(line, column + chainStart.length(), 
                              QStringLiteral(" // <%1>").arg(inferredType), 
                              InlayHintKind::ChainingHint);
            hint.setTooltip(QStringLiteral("Chain returns: %1").arg(inferredType));
            hints.append(hint);
        }
    }
    
    return hints;
}

QList<InlayHintItem> InlayHintProvider::generateClosingLabelHints(
    const QString& content,
    const QString& language) const
{
    QList<InlayHintItem> hints;
    
    auto it = m_languagePatterns.find(language);
    if (it == m_languagePatterns.end() || !it->closingBracePattern.isValid()) {
        return hints;
    }
    
    const InlayHintLanguagePatterns& patterns = *it;
    const QStringList lines = content.split(QLatin1Char('\n'));
    
    // Track opening braces and their labels
    struct BlockInfo {
        QString label;
        int startLine;
        int indentLevel;
    };
    
    QVector<BlockInfo> blockStack;
    
    for (int lineNum = 0; lineNum < lines.size(); ++lineNum) {
        const QString& line = lines[lineNum];
        
        // Check for opening braces
        if (line.contains(QStringLiteral("{")) || 
            line.contains(QStringLiteral(":")) || 
            line.contains(QStringLiteral("do"))) {
            
            // Extract label from previous lines
            QString label;
            for (int i = lineNum - 1; i >= 0 && i >= lineNum - 3; --i) {
                QString prevLine = lines[i].trimmed();
                if (prevLine.startsWith(QStringLiteral("//")) || 
                    prevLine.startsWith(QStringLiteral("/*")) || 
                    prevLine.startsWith(QStringLiteral("#"))) {
                    continue;
                }
                
                // Extract function/class name
                QRegularExpression labelPattern;
                if (language == QStringLiteral("cpp") || language == QStringLiteral("c")) {
                    labelPattern = QRegularExpression(
                        R"((?:class|struct|namespace|enum|void|int|bool|float|double)\s+(\w+))"
                    );
                } else if (language == QStringLiteral("py")) {
                    labelPattern = QRegularExpression(
                        R"((?:def|class)\s+(\w+))"
                    );
                } else if (language == QStringLiteral("js") || language == QStringLiteral("ts")) {
                    labelPattern = QRegularExpression(
                        R"((?:function|class|const|let|var)\s+(\w+))"
                    );
                }
                
                QRegularExpressionMatch labelMatch = labelPattern.match(prevLine);
                if (labelMatch.hasMatch()) {
                    label = labelMatch.captured(1);
                    break;
                }
            }
            
            if (label.isEmpty()) {
                label = QStringLiteral("block");
            }
            
            BlockInfo block;
            block.label = label;
            block.startLine = lineNum;
            block.indentLevel = line.indexOf(QRegularExpression(QStringLiteral("[^\\s]")));
            blockStack.append(block);
        }
        
        // Check for closing braces
        QRegularExpressionMatch closeMatch = patterns.closingBracePattern.match(line);
        if (closeMatch.hasMatch() && !blockStack.isEmpty()) {
            BlockInfo block = blockStack.takeLast();
            
            // Only show label if block is large enough
            if (lineNum - block.startLine >= m_minLinesForClosingLabel) {
                int column = line.indexOf(QRegularExpression(QStringLiteral("[^\\s]")));
                if (column == -1) column = 0;
                
                InlayHintItem hint(lineNum, column, 
                                  QStringLiteral("// end %1").arg(block.label), 
                                  InlayHintKind::ClosingLabel);
                hint.setTooltip(QStringLiteral("End of %1").arg(block.label));
                hints.append(hint);
            }
        }
    }
    
    return hints;
}

QList<InlayHintItem> InlayHintProvider::generateEnumHints(
    const QString& content,
    const QString& language) const
{
    QList<InlayHintItem> hints;
    
    // Look for enum usage patterns
    QRegularExpression enumPattern;
    if (language == QStringLiteral("cpp") || language == QStringLiteral("c")) {
        enumPattern = QRegularExpression(
            R"((\w+)::(\w+))",
            QRegularExpression::MultilineOption
        );
    } else if (language == QStringLiteral("py")) {
        enumPattern = QRegularExpression(
            R"((\w+)\.(\w+))",
            QRegularExpression::MultilineOption
        );
    } else {
        return hints;
    }
    
    QRegularExpressionMatchIterator iter = enumPattern.globalMatch(content);
    while (iter.hasNext()) {
        QRegularExpressionMatch match = iter.next();
        
        QString enumName = match.captured(1);
        QString memberName = match.captured(2);
        
        int line = content.left(match.capturedStart()).count(QLatin1Char('\n'));
        int column = match.capturedStart() - content.lastIndexOf(QLatin1Char('\n'), match.capturedStart()) - 1;
        
        InlayHintItem hint(line, column + match.captured(0).length(), 
                          QStringLiteral(" // %1").arg(memberName), 
                          InlayHintKind::EnumMember);
        hint.setTooltip(QStringLiteral("Enum member: %1").arg(memberName));
        hints.append(hint);
    }
    
    return hints;
}

QList<InlayHintItem> InlayHintProvider::generateGenericHints(
    const QString& content,
    const QString& language) const
{
    QList<InlayHintItem> hints;
    
    auto it = m_languagePatterns.find(language);
    if (it == m_languagePatterns.end() || !it->genericPattern.isValid()) {
        return hints;
    }
    
    const InlayHintLanguagePatterns& patterns = *it;
    
    QRegularExpressionMatchIterator iter = patterns.genericPattern.globalMatch(content);
    while (iter.hasNext()) {
        QRegularExpressionMatch match = iter.next();
        
        QString genericText = match.captured(0);
        int line = content.left(match.capturedStart()).count(QLatin1Char('\n'));
        int column = match.capturedStart() - content.lastIndexOf(QLatin1Char('\n'), match.capturedStart()) - 1;
        
        InlayHintItem hint(line, column + genericText.length(), 
                          QStringLiteral(" // generic"), 
                          InlayHintKind::GenericType);
        hint.setTooltip(QStringLiteral("Generic type usage"));
        hints.append(hint);
    }
    
    return hints;
}

QString InlayHintProvider::inferTypeFromExpression(
    const QString& expression,
    const QString& language,
    const QString& context) const
{
    QString expr = expression.trimmed();
    
    // Simple type inference based on expression patterns
    if (expr.startsWith(QStringLiteral("\"")) || expr.startsWith(QStringLiteral("'"))) {
        return QStringLiteral("string");
    }
    
    if (expr == QStringLiteral("true") || expr == QStringLiteral("false")) {
        return QStringLiteral("bool");
    }
    
    if (QRegularExpression(QStringLiteral("^-?\\d+$")).match(expr).hasMatch()) {
        return QStringLiteral("int");
    }
    
    if (QRegularExpression(QStringLiteral("^-?\\d+\\.\\d+$")).match(expr).hasMatch()) {
        return QStringLiteral("float");
    }
    
    if (expr.startsWith(QStringLiteral("[")) || expr.startsWith(QStringLiteral("{"))) {
        return QStringLiteral("array");
    }
    
    if (expr.contains(QStringLiteral(".")) && !expr.contains(QStringLiteral(".."))) {
        return QStringLiteral("float");
    }
    
    // Language-specific inference
    if (language == QStringLiteral("cpp") || language == QStringLiteral("c")) {
        if (expr.startsWith(QStringLiteral("new "))) {
            return QStringLiteral("pointer");
        }
        if (expr.contains(QStringLiteral("->"))) {
            return QStringLiteral("pointer");
        }
    }
    
    if (language == QStringLiteral("py")) {
        if (expr.startsWith(QStringLiteral("["))) {
            return QStringLiteral("list");
        }
        if (expr.startsWith(QStringLiteral("{"))) {
            return QStringLiteral("dict");
        }
    }
    
    return QStringLiteral("auto");
}

FunctionSignature InlayHintProvider::findFunctionSignature(const QString& name) const
{
    return m_functionSignatures.value(name, FunctionSignature());
}

QStringList InlayHintProvider::parseCallArguments(const QString& argString) const
{
    QStringList arguments;
    QString currentArg;
    int parenDepth = 0;
    int bracketDepth = 0;
    int braceDepth = 0;
    
    for (QChar c : argString) {
        if (c == QLatin1Char('(')) parenDepth++;
        else if (c == QLatin1Char(')')) parenDepth--;
        else if (c == QLatin1Char('[')) bracketDepth++;
        else if (c == QLatin1Char(']')) bracketDepth--;
        else if (c == QLatin1Char('{')) braceDepth++;
        else if (c == QLatin1Char('}')) braceDepth--;
        
        if (c == QLatin1Char(',') && parenDepth == 0 && bracketDepth == 0 && braceDepth == 0) {
            arguments.append(currentArg.trimmed());
            currentArg.clear();
        } else {
            currentArg.append(c);
        }
    }
    
    if (!currentArg.isEmpty()) {
        arguments.append(currentArg.trimmed());
    }
    
    return arguments;
}

QString InlayHintProvider::truncateLabel(const QString& label) const
{
    if (m_maxHintLength > 0 && label.length() > m_maxHintLength) {
        return label.left(m_maxHintLength - 3) + QStringLiteral("...");
    }
    return label;
}

QList<InlayHintItem> InlayHintProvider::mergeHints(const QList<InlayHintItem>& hints) const
{
    if (hints.isEmpty()) {
        return hints;
    }
    
    QList<InlayHintItem> merged;
    int currentLine = -1;
    QList<InlayHintItem> lineHints;
    
    for (const InlayHintItem& hint : hints) {
        if (hint.line() != currentLine) {
            if (!lineHints.isEmpty()) {
                merged.append(lineHints);
            }
            lineHints.clear();
            currentLine = hint.line();
        }
        lineHints.append(hint);
    }
    
    if (!lineHints.isEmpty()) {
        merged.append(lineHints);
    }
    
    return merged;
}

void InlayHintProvider::getInlayHintsAsync(
    const QString& filePath,
    const QString& content,
    std::function<void(const QList<InlayHintItem>&)> callback)
{
    if (!m_asyncEnabled) {
        callback(getInlayHints(filePath, content));
        return;
    }
    
    QFuture<QList<InlayHintItem>> future = QtConcurrent::run([this, filePath, content]() {
        return getInlayHints(filePath, content);
    });
    
    QFutureWatcher<QList<InlayHintItem>>* watcher = new QFutureWatcher<QList<InlayHintItem>>(this);
    connect(watcher, &QFutureWatcher<QList<InlayHintItem>>::finished, this, [watcher, callback]() {
        callback(watcher->result());
        watcher->deleteLater();
    });
    
    watcher->setFuture(future);
}

void InlayHintProvider::invalidateFile(const QString& filePath)
{
    m_cache->invalidate(filePath);
    qDebug() << "[InlayHintProvider] Invalidated cache for" << filePath;
}

void InlayHintProvider::clearCache()
{
    m_cache->clear();
    qDebug() << "[InlayHintProvider] Cache cleared";
}

void InlayHintProvider::setEnabled(InlayHintKind kind, bool enabled)
{
    m_enabledKinds[kind] = enabled;
    
    // Clear cache when settings change
    m_cache->clear();
}

bool InlayHintProvider::isEnabled(InlayHintKind kind) const
{
    return m_enabledKinds.value(kind, false);
}

void InlayHintProvider::setMaxHintLength(int length)
{
    m_maxHintLength = qMax(0, length);
}

int InlayHintProvider::maxHintLength() const
{
    return m_maxHintLength;
}

void InlayHintProvider::setMinParameterNameLength(int chars)
{
    m_minParameterNameLength = qMax(1, chars);
}

int InlayHintProvider::minParameterNameLength() const
{
    return m_minParameterNameLength;
}

void InlayHintProvider::setMinLinesForClosingLabel(int lines)
{
    m_minLinesForClosingLabel = qMax(1, lines);
}

int InlayHintProvider::minLinesForClosingLabel() const
{
    return m_minLinesForClosingLabel;
}

void InlayHintProvider::registerFunctionSignatures(const QHash<QString, FunctionSignature>& signatures)
{
    m_functionSignatures.insert(signatures);
    qDebug() << "[InlayHintProvider] Registered" << signatures.size() << "function signatures";
}

void InlayHintProvider::addFunctionSignature(const QString& name, const FunctionSignature& signature)
{
    m_functionSignatures[name] = signature;
    qDebug() << "[InlayHintProvider] Added signature for" << name;
}

} // namespace RawrXD