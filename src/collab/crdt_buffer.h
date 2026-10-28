// ============================================================================
// crdt_buffer.h — RawrXD:: namespaced CRDT sketch (NEURAL_CRDT_GATE_001)
// ============================================================================
// ORPHAN vs product path: Win32IDE uses include/collab/crdt_buffer.h (global).
// This header is NOT the product owner. SYNTHETIC=partial site/clock sketch.
// NOT conflict-free CRDT_PASS. Do not invent PASS from source presence.
// PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0.
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <functional>
#include <cstdint>
#include <mutex>

namespace RawrXD {

enum class OperationType { INSERT, DELETE };

struct CRDTOperation {
    OperationType type = OperationType::INSERT;
    int position       = 0;
    std::string text;              // INSERT payload
    int length         = 0;        // DELETE length
    std::string siteId;
    int64_t logicalTimestamp = 0;
    std::string operationId;
};

class CRDTBuffer {
public:
    CRDTBuffer();

    void insertText(int position, const std::string& text);
    void deleteText(int position, int length);
    void applyRemoteOperation(const std::string& operationJson);
    std::string getText() const;

    const std::string& getSiteId() const { return m_siteId; }
    int64_t getLogicalClock() const { return m_logicalClock; }

    // Callbacks (no Qt signals)
    std::function<void(const std::string&)> textChanged;
    std::function<void(const std::string&)> operationGenerated;

    // Setter aliases for backward compat
    void setOnTextChanged(std::function<void(const std::string&)> fn) { textChanged = std::move(fn); }
    void setOnOperationGenerated(std::function<void(const std::string&)> fn) { operationGenerated = std::move(fn); }

private:
    std::string generateSiteId();
    CRDTOperation createInsertOperation(int position, const std::string& text);
    CRDTOperation createDeleteOperation(int position, int length);
    void applyOperation(const CRDTOperation& op);

    std::string m_siteId;
    int64_t     m_logicalClock = 0;
    std::string m_text;
};

} // namespace RawrXD
