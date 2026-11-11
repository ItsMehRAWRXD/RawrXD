#include "DAPClient.hpp"
#include "../Core/Bus.hpp"
#include <QDebug>
#include <QTimer>

namespace SoloIDE {

DAPClient::DAPClient(QObject* parent) : QObject(parent) {}
DAPClient::~DAPClient() = default;

void DAPClient::startDebugging(const QString& file) {
    qDebug() << "[DAP] Starting debug:" << file;
    m_running = true;
    emit debugStarted(file);
}

void DAPClient::stop() {
    qDebug() << "[DAP] Stopping debug";
    m_running = false;
    emit debugStopped();
}

void DAPClient::stepOver() { qDebug() << "[DAP] Step over"; }
void DAPClient::stepInto() { qDebug() << "[DAP] Step into"; }
void DAPClient::stepOut()  { qDebug() << "[DAP] Step out"; }

void DAPClient::toggleBreakpoint(const QString& file, int line) {
    qDebug() << "[DAP] Toggle breakpoint:" << file << ":" << line;
}

void DAPClient::continueExecution() {
    qDebug() << "[DAP] Continue";
}

} // namespace SoloIDE
