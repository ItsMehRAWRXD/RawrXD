// Win32IDE_LSPServer_stubs.cpp — G1 link stubs (AGENT_RUNTIME_VALIDATION_001)
// Real Win32IDE_LSPServer.cpp excluded due to winsock1/2 include-order conflicts.
// These keep declared LSP-server entry points resolved without inventing runtime PASS.
#include "Win32IDE.h"

void Win32IDE::initLSPServer() {}
void Win32IDE::shutdownLSPServer() {
    delete m_lspServer;
    m_lspServer = nullptr;
    m_lspServerInitialized = false;
}
void Win32IDE::cmdLSPServerStart() {}
void Win32IDE::cmdLSPServerStop() {}
void Win32IDE::cmdLSPServerReindex() {}
void Win32IDE::cmdLSPServerStatus() {}
void Win32IDE::cmdLSPServerStats() {}
void Win32IDE::cmdLSPServerPublishDiagnostics() {}
void Win32IDE::cmdLSPServerConfig() {}
void Win32IDE::cmdLSPServerExportSymbols() {}
void Win32IDE::cmdLSPServerLaunchStdio() {}
void Win32IDE::handleLSPServerStatusEndpoint(UINT_PTR) {}
bool Win32IDE::handleLSPServerCommand(int) { return false; }
void Win32IDE::forwardToLSPServer(const std::string&, const nlohmann::json&) {}
void Win32IDE::notifyLSPServerDidOpen(const std::string&, const std::string&, const std::string&) {}
void Win32IDE::notifyLSPServerDidChange(const std::string&, const std::string&) {}
void Win32IDE::notifyLSPServerDidClose(const std::string&) {}
