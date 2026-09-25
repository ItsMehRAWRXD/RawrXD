#pragma once
#include <string>
#include <vector>
#include <optional>
#include <memory>
#include <mutex>
#include <functional>

namespace rawrxd::deep2 {

// ───────────────────────────────────────────────────────────────
// Patch detection descriptor
// ───────────────────────────────────────────────────────────────
struct PatchRecord {
    std::string patch_type;
    std::string source_location;
    std::string description;
    bool benign = false;
};

// ───────────────────────────────────────────────────────────────
// Anti-patcher — detects and prevents unauthorized binary patches
// ───────────────────────────────────────────────────────────────
class AntiPatcher {
public:
    AntiPatcher();
    ~AntiPatcher();

    // Register known-good signatures
    bool RegisterWhitelist(const std::string& module_name, const std::vector<uint8_t>& sha256);
    bool UnregisterWhitelist(const std::string& module_name);

    // Scan for unauthorized patches
    std::vector<PatchRecord> ScanMemoryRegion(const void* addr, size_t size);
    std::vector<PatchRecord> ScanModule(const std::string& module_name);

    // Apply protection
    bool WriteProtectRegion(void* addr, size_t size);
    bool RemoveProtection(void* addr, size_t size);

    // Audit
    std::vector<PatchRecord> GetDetectedPatches() const;
    void ClearDetections();

    // Callback on detection
    using DetectionCallback = std::function<void(const PatchRecord&)>;
    void SetDetectionCallback(DetectionCallback cb);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace rawrxd::deep2
