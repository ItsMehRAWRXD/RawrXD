// ============================================================================
// Win32IDE_AgentOllamaClient.cpp — LOCAL_ONLY_001 fail-closed stubs
// ============================================================================
// Ollama/HTTP client construction and :11434 probes are forbidden.
// Deep2/GGUF is the only production inference backend for this gate.
// ============================================================================

#include "Win32IDE.h"
#include "../agentic/LocalOnlyPolicy.h"
#include <string>

void Win32IDE::initAgentOllamaClient() {
    m_ollamaClientInitialized = false;
    m_ollamaConnected = false;
    m_ollamaEndpoint.clear();
    m_ollamaStatus = RawrXD::LocalOnly::kHardDiagnostic;
    LOG_INFO("LOCAL_ONLY_001: Agent Ollama HTTP client disabled (fail-closed)");
}

void Win32IDE::shutdownAgentOllamaClient() {
    m_ollamaClientInitialized = false;
    m_ollamaConnected = false;
    m_ollamaStatus = "Shutdown";
}

bool Win32IDE::testOllamaConnection() {
    m_ollamaConnected = false;
    m_ollamaStatus = RawrXD::LocalOnly::kHardDiagnostic;
    return false;
}

bool Win32IDE::isOllamaConnected() const {
    return false;
}

std::string Win32IDE::getOllamaStatus() const {
    return m_ollamaStatus.empty() ? std::string(RawrXD::LocalOnly::kHardDiagnostic) : m_ollamaStatus;
}

void Win32IDE::setOllamaEndpoint(const std::string& endpoint) {
    (void)endpoint;
    m_ollamaEndpoint.clear();
    m_ollamaConnected = false;
    m_ollamaStatus = RawrXD::LocalOnly::kNetworkForbidden;
}

std::string Win32IDE::getOllamaEndpoint() const {
    return std::string();
}
