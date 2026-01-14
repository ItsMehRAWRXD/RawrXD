// Stub implementations for missing linker symbols
#include <QString>
#include <QList>
#include <QJsonObject>
#include <QWidget>
#include <unordered_map>
#include <string>
#include <cstring>
#include <cstdlib>

namespace RawrXD {

// Forward declare enums/structs needed
enum Encoding { UTF8 = 0 };

struct MultiFileSearchResult {
    QString file;
    int lineNumber = 0;
};

class FileManager {
public:
    FileManager();
    ~FileManager();
    
    bool readFile(const QString& path, QString& content, Encoding* enc = nullptr);
    static QString toRelativePath(const QString& absPath, const QString& basePath);

private:
    // placeholder member
    int m_dummy = 0;
};

} // namespace RawrXD

// **EXPLICIT OUT-OF-LINE IMPLEMENTATIONS** (non-inline to force symbol generation)

RawrXD::FileManager::FileManager()
    : m_dummy(0) {}

RawrXD::FileManager::~FileManager() {}

bool RawrXD::FileManager::readFile(const QString& path, QString& content, Encoding* enc) {
    Q_UNUSED(path);
    Q_UNUSED(enc);
    content = "";
    return false;
}

QString RawrXD::FileManager::toRelativePath(const QString& absPath, const QString& basePath) {
    Q_UNUSED(basePath);
    return absPath;
}

// ============================================================================
// Backend namespace
// ============================================================================

namespace RawrXD { namespace Backend {

struct ToolResult {
    bool success = false;
    std::string tool_name;
    std::string result_data;
    std::string error_message;
    int exit_code = 0;
};

class AgenticToolExecutor {
public:
    explicit AgenticToolExecutor(const std::string& workspace_root = ".");
    ~AgenticToolExecutor();
    
    void setWorkspaceRoot(const std::string& root);
    ToolResult executeTool(const std::string& tool_name, 
                          const std::unordered_map<std::string, std::string>& params);
    
private:
    std::string m_workspace_root;
};

} } // namespace RawrXD::Backend

// **EXPLICIT OUT-OF-LINE IMPLEMENTATIONS** for AgenticToolExecutor

RawrXD::Backend::AgenticToolExecutor::AgenticToolExecutor(const std::string& workspace_root)
    : m_workspace_root(workspace_root) {}

RawrXD::Backend::AgenticToolExecutor::~AgenticToolExecutor() {}

void RawrXD::Backend::AgenticToolExecutor::setWorkspaceRoot(const std::string& root) {
    m_workspace_root = root;
}

RawrXD::Backend::ToolResult RawrXD::Backend::AgenticToolExecutor::executeTool(
    const std::string& tool_name, 
    const std::unordered_map<std::string, std::string>& params) {
    Q_UNUSED(tool_name);
    Q_UNUSED(params);
    return RawrXD::Backend::ToolResult{false, tool_name, "", "Not implemented", 1};
}

// ============================================================================
// Global stubs for missing classes
// ============================================================================

class ModelLoaderWidget : public QWidget {
public:
    explicit ModelLoaderWidget(QWidget* parent = nullptr);
    virtual ~ModelLoaderWidget();
};

// **EXPLICIT OUT-OF-LINE IMPLEMENTATIONS** for ModelLoaderWidget

ModelLoaderWidget::ModelLoaderWidget(QWidget* parent)
    : QWidget(parent) {}

ModelLoaderWidget::~ModelLoaderWidget() {}

// ============================================================================
// AgenticExecutor stub REMOVED - real implementation in src/agentic_executor.cpp
// ============================================================================

// ============================================================================
// Extern "C" brutal_gzip function stub
// ============================================================================
// These are the C functions declared in include/brutal_gzip.h
// that are referenced by inflate_deflate_cpp.cpp but not provided by the library

#ifdef __cplusplus
extern "C" {
#endif

// Brutal deflate (stored blocks only) - x64 MASM stub
// Since the real MASM function is not available, return a passthrough stub
void* deflate_brutal_masm(const void* src, size_t len, size_t* out_len) {
    if (!src || len == 0) {
        if (out_len) *out_len = 0;
        return nullptr;
    }
    
    // Allocate buffer for data (no actual compression, just passthrough)
    void* dest = malloc(len);
    if (!dest) {
        if (out_len) *out_len = 0;
        return nullptr;
    }
    
    // Copy data as-is (no compression)
    std::memcpy(dest, src, len);
    if (out_len) *out_len = len;
    return dest;
}

// Brutal deflate (stored blocks only) - ARM64 NEON stub
void* deflate_brutal_neon(const void* src, size_t len, size_t* out_len) {
    if (!src || len == 0) {
        if (out_len) *out_len = 0;
        return nullptr;
    }
    
    // Allocate buffer for data (no actual compression, just passthrough)
    void* dest = malloc(len);
    if (!dest) {
        if (out_len) *out_len = 0;
        return nullptr;
    }
    
    // Copy data as-is (no compression)
    std::memcpy(dest, src, len);
    if (out_len) *out_len = len;
    return dest;
}

#ifdef __cplusplus
}
#endif

// ============================================================
// Telemetry Stub - Required by compression_interface.cpp
// ============================================================
// Use the stub only when the real telemetry singleton is not linked.
#if !defined(RAWRXD_USE_REAL_TELEMETRY)
#include "qtapp/telemetry.h"

// Global telemetry singleton instance
static Telemetry* g_telemetry = nullptr;

Telemetry& GetTelemetry() {
    if (!g_telemetry) {
        g_telemetry = new Telemetry();
    }
    return *g_telemetry;
}
#endif // RAWRXD_USE_REAL_TELEMETRY

