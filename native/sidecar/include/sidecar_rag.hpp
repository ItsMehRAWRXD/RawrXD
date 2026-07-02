/**
 * RawrXD Sidecar RAG Integration
 * Wire Sovereign Context Engine into native sidecar
 */

#pragma once

#include "sidecar_protocol.hpp"
#include "sovereign_context.hpp"
#include <memory>

namespace rawrxd::sidecar {

/**
 * SidecarRAG - Integrates Sovereign Context Engine into sidecar
 * Provides semantic search for agent context
 */
class SidecarRAG {
public:
    SidecarRAG();
    ~SidecarRAG();
    
    bool initialize(const std::filesystem::path& dataDir);
    
    // Index workspace
    void indexWorkspace(const std::filesystem::path& workspacePath);
    
    // Search for context
    std::vector<rag::SearchResult> search(
        std::string_view query,
        size_t k = 10
    );
    
    // Get context for agent
    std::string getAgentContext(
        std::string_view query,
        std::string_view currentFile,
        size_t maxTokens = 2048
    );
    
    // Save index
    void saveIndex();
    
    // Get stats
    rag::SovereignContextEngine::Stats getStats() const;
    
private:
    std::unique_ptr<rag::SovereignContextEngine> m_engine;
    std::filesystem::path m_workspacePath;
};

} // namespace rawrxd::sidecar
