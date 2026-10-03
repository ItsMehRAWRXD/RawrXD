// ============================================================================
// license_helper_utilities.cpp — License System Helper Utilities
// ============================================================================

#include "../include/enterprise_license.h"
#include "../include/license_audit_trail.h"
#include <cstring>
#include <ctime>

using namespace RawrXD::License;

// ============================================================================
// Tier Name Helpers
// ============================================================================

namespace RawrXD::License {

const char* tierName(LicenseTierV2 tier) {
    switch (tier) {
        case LicenseTierV2::Community:    return "Community";
        case LicenseTierV2::Professional: return "Professional";
        case LicenseTierV2::Enterprise:   return "Enterprise";
        case LicenseTierV2::Sovereign:    return "Sovereign";
        default:                          return "Unknown";
    }
}

} // namespace RawrXD::License

const char* getTierNameForDisplay(uint32_t tier) {
    return RawrXD::License::tierName(static_cast<LicenseTierV2>(tier));
}

// ============================================================================
// Timestamp Formatting Helpers
// ============================================================================

const char* formatTimestampForDisplay(uint32_t timestamp) {
    static char buf[64];
    time_t t = timestamp;
    struct tm* tm_info = localtime(&t);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm_info);
    return buf;
}

// ============================================================================
// Feature Name Helpers
// ============================================================================

const char* getFeatureNameForID(uint32_t featureID) {
    static const char* featureNames[] = {
        "Core Engine",                          // 0
        "GPU Acceleration",                     // 1
        "Multi-GPU Support",                    // 2
        "Vision Processing",                    // 3
        "Audio Processing",                     // 4
        "Agent Framework",                      // 5
        "Swarm Intelligence",                   // 6
        "Hotpatching System",                   // 7
        "Code Analysis",                        // 8
        "Auto-Refactoring",                     // 9
        "Chain of Thought Reasoning",           // 10
        // Add more as needed
    };

    if (featureID < sizeof(featureNames) / sizeof(featureNames[0])) {
        return featureNames[featureID];
    }
    return "Unknown Feature";
}

// ============================================================================
// Statistics Helpers
// ============================================================================

extern "C" {

float getFeatureDenialRate() {
    return g_auditTrailManager.getDenialRate();
}

uint32_t getAuditEventCount() {
    return g_auditTrailManager.getTotalEvents();
}

uint32_t getAuditDenialCount() {
    return g_auditTrailManager.getTotalDenials();
}

bool isSystemAnomalous() {
    return g_auditTrailManager.isInAnomalousState();
}

}  // extern "C"

// ============================================================================
// AuditTrailManager minimal definitions (stub implementations)
// ============================================================================
// These satisfy the link requirements for license_manager_panel.cpp and
// license_helper_utilities.cpp. Full implementation lives in
// license_audit_trail.cpp, which is not yet buildable due to Unicode/MBCS
// mismatches in its Windows API calls. When that file is fixed, these stubs
// should be removed so the real definitions take over.
// ============================================================================

namespace RawrXD::License {

AuditTrailManager::AuditTrailManager() = default;
AuditTrailManager::~AuditTrailManager() = default;

uint32_t AuditTrailManager::getTotalEvents() const { return m_totalEvents; }
uint32_t AuditTrailManager::getTotalDenials() const { return m_totalDenials; }
float    AuditTrailManager::getDenialRate(uint32_t) const {
    uint32_t total = m_totalEvents;
    return total > 0 ? static_cast<float>(m_totalDenials) / static_cast<float>(total) : 0.0f;
}
bool AuditTrailManager::isInAnomalousState() const { return m_isAnomalous; }

// Global instance
AuditTrailManager g_auditTrailManager;

} // namespace RawrXD::License
