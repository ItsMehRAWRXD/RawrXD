#include "LSPClient.hpp"
#include <QDebug>

namespace SoloIDE {

LSPClient::LSPClient(QObject* parent) : QObject(parent) {}
LSPClient::~LSPClient() = default;

void LSPClient::initialize(const QString& projectPath) {
    qDebug() << "[LSP] Initializing for:" << projectPath;
    m_initialized = true;
}

void LSPClient::openFile(const QString& file) {
    qDebug() << "[LSP] Open:" << file;
}

void LSPClient::closeFile(const QString& file) {
    qDebug() << "[LSP] Close:" << file;
}

void LSPClient::textChanged(const QString& file, const QString& text, int version) {
    Q_UNUSED(file); Q_UNUSED(text); Q_UNUSED(version);
}

void LSPClient::requestCompletion(const QString& file, int line, int character) {
    Q_UNUSED(file); Q_UNUSED(line); Q_UNUSED(character);
}

} // namespace SoloIDE
