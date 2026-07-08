#include "inference_enforcement.h"
#include <chrono>
#include <iomanip>
#include <sstream>
#include <fstream>

namespace RawrXD {
namespace Enforcement {

// ============================================================================
// Audit Log Implementation
// ============================================================================
InferenceAuditLog& InferenceAuditLog::instance() {
    static InferenceAuditLog instance;
    return instance;
}

void InferenceAuditLog::record(const InferenceAuditEntry& entry) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_entries.push_back(entry);
    if (m_entries.size() > MAX_ENTRIES) {
        m_entries.erase(m_entries.begin());
    }
}

std::vector<InferenceAuditEntry> InferenceAuditLog::getRecent(int count) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<InferenceAuditEntry> result;
    int start = std::max(0, (int)m_entries.size() - count);
    for (int i = start; i < (int)m_entries.size(); ++i) {
        result.push_back(m_entries[i]);
    }
    return result;
}

void InferenceAuditLog::dumpToFile(const std::string& path) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::ofstream file(path, std::ios::app);
    if (!file.is_open()) return;
    
    for (const auto& e : m_entries) {
        file << e.timestamp << " | "
             << e.sourceFile << ":" << e.sourceLine << " | "
             << e.sourceFunc << " | "
             << e.model << " | "
             << (int)e.chosenPath << " | "
             << (e.success ? "OK" : "FAIL") << " | "
             << e.latencyMs << "ms\n";
    }
}

bool InferenceAuditLog::detectBypassPatterns(std::vector<std::string>& violations) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    bool found = false;
    
    // Look for suspicious patterns
    for (const auto& e : m_entries) {
        // If model was used but no gateway entry recorded
        if (e.chosenPath == ExecutionPath::LOCAL_GGUF && 
            e.sourceFunc.find("Gateway") == std::string::npos) {
            violations.push_back("Potential bypass: " + e.sourceFile + ":" + 
                               std::to_string(e.sourceLine));
            found = true;
        }
    }
    
    return found;
}

} // namespace Enforcement
} // namespace RawrXD
