// lsp_client_default.cpp - Default LSPClient implementations when lsp_client_incremental is not linked

#include "lsp_client.h"
#include <nlohmann/json.hpp>

namespace RawrXD {

void LSPClient::sendIncrementalUpdate(const std::string& uri, int64_t version,
                                      const std::string& oldContent,
                                      const std::string& newContent) {
    // Default implementation: send full document content as single change
    // This is less efficient than incremental but works without the full diff algorithm
    if (!m_transport || !m_transport->isConnected()) return;
    
    nlohmann::json params;
    params["textDocument"] = {{"uri", uri}, {"version", version}};
    
    // Send entire new content as a single change (no range = full document)
    nlohmann::json change;
    change["text"] = newContent;
    params["contentChanges"] = nlohmann::json::array({change});
    
    sendNotification("textDocument/didChange", params.dump());
}

void LSPClient::cancelRequest(const std::string& id) {
    // Mark request as cancelled locally
    m_pendingCancellations[id] = true;
    
    // Send cancellation notification to server if connected
    if (!m_transport || !m_transport->isConnected()) return;
    
    nlohmann::json params;
    params["id"] = id;
    sendNotification("$/cancelRequest", params.dump());
}

// Helper method implementations for default version
void LSPClient::sendNotification(const std::string& method, const std::string& params) {
    // Default: no-op (would be implemented by transport in full version)
    (void)method;
    (void)params;
}

LSPClient::Position LSPClient::offsetToPosition(const std::string& text, int offset) {
    Position pos{0, 0};
    int currentOffset = 0;
    
    for (char c : text) {
        if (currentOffset >= offset) break;
        if (c == '\n') {
            pos.line++;
            pos.character = 0;
        } else {
            pos.character++;
        }
        currentOffset++;
    }
    
    return pos;
}

} // namespace RawrXD
