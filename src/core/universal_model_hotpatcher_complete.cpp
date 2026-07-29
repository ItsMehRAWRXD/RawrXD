// COMPLETE IMPLEMENTATION: Universal Model Hotpatcher
// Full model hotpatching with validation and rollback

#include "universal_model_hotpatcher.hpp"
#include <fstream>
#include <filesystem>
#include <vector>
#include <string>
#include <chrono>
#include <sha256.h>

namespace RawrXD {
namespace Hotpatch {

// Complete hotpatch record
struct HotpatchRecord {
    std::string patch_id;
    std::string model_path;
    std::string original_hash;
    std::string patched_hash;
    std::string backup_path;
    std::chrono::system_clock::time_point timestamp;
    bool active;
    std::vector<std::string> changes;
};

// Model hotpatcher implementation
class ModelHotpatcherImpl {
public:
    struct PatchValidationResult {
        bool valid;
        std::string error_message;
        std::vector<std::string> warnings;
    };
    
    PatchValidationResult ValidatePatch(const std::string& model_path,
                                        const std::vector<uint8_t>& patch_data) {
        PatchValidationResult result;
        
        // Check model exists
        if (!std::filesystem::exists(model_path)) {
            result.valid = false;
            result.error_message = "Model file not found: " + model_path;
            return result;
        }
        
        // Check model is valid GGUF
        std::ifstream model_file(model_path, std::ios::binary);
        if (!model_file) {
            result.valid = false;
            result.error_message = "Cannot read model file";
            return result;
        }
        
        // Check GGUF magic
        uint32_t magic;
        model_file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
        if (magic != 0x46554747) {  // "GGUF" in little-endian
            result.valid = false;
            result.error_message = "Invalid GGUF format";
            return result;
        }
        
        // Validate patch data
        if (patch_data.size() < 16) {
            result.valid = false;
            result.error_message = "Patch data too small";
            return result;
        }
        
        // Check patch header
        if (patch_data[0] != 'R' || patch_data[1] != 'P' || 
            patch_data[2] != 'T' || patch_data[3] != 'C') {
            result.valid = false;
            result.error_message = "Invalid patch header";
            return result;
        }
        
        result.valid = true;
        return result;
    }
    
    bool ApplyPatch(const std::string& model_path,
                    const std::vector<uint8_t>& patch_data,
                    const std::string& patch_id) {
        // Validate first
        auto validation = ValidatePatch(model_path, patch_data);
        if (!validation.valid) {
            return false;
        }
        
        // Create backup
        std::string backup_path = CreateBackup(model_path, patch_id);
        if (backup_path.empty()) {
            return false;
        }
        
        // Compute original hash
        std::string original_hash = ComputeFileHash(model_path);
        
        // Apply patch
        if (!ApplyPatchData(model_path, patch_data)) {
            // Restore from backup on failure
            RestoreFromBackup(backup_path, model_path);
            return false;
        }
        
        // Compute new hash
        std::string patched_hash = ComputeFileHash(model_path);
        
        // Record the patch
        HotpatchRecord record;
        record.patch_id = patch_id;
        record.model_path = model_path;
        record.original_hash = original_hash;
        record.patched_hash = patched_hash;
        record.backup_path = backup_path;
        record.timestamp = std::chrono::system_clock::now();
        record.active = true;
        
        // Extract changes from patch
        record.changes = ExtractChanges(patch_data);
        
        {
            std::lock_guard<std::mutex> lock(records_mutex_);
            patch_records_[patch_id] = record;
        }
        
        return true;
    }
    
    bool RollbackPatch(const std::string& patch_id) {
        std::lock_guard<std::mutex> lock(records_mutex_);
        
        auto it = patch_records_.find(patch_id);
        if (it == patch_records_.end()) {
            return false;
        }
        
        auto& record = it->second;
        
        if (!record.active) {
            return false;  // Already rolled back
        }
        
        // Restore from backup
        if (!RestoreFromBackup(record.backup_path, record.model_path)) {
            return false;
        }
        
        // Verify hash matches original
        std::string current_hash = ComputeFileHash(record.model_path);
        if (current_hash != record.original_hash) {
            // Hash mismatch - something went wrong
            return false;
        }
        
        record.active = false;
        return true;
    }
    
    std::vector<HotpatchRecord> GetActivePatches() {
        std::lock_guard<std::mutex> lock(records_mutex_);
        
        std::vector<HotpatchRecord> active;
        for (auto& [id, record] : patch_records_) {
            if (record.active) {
                active.push_back(record);
            }
        }
        
        return active;
    }
    
    std::string GeneratePatchReport() {
        std::lock_guard<std::mutex> lock(records_mutex_);
        
        std::stringstream report;
        report << "=== Model Hotpatch Report ===\n\n";
        report << "Total patches: " << patch_records_.size() << "\n";
        
        size_t active_count = 0;
        for (auto& [id, record] : patch_records_) {
            if (record.active) active_count++;
        }
        report << "Active patches: " << active_count << "\n";
        report << "Rolled back patches: " << (patch_records_.size() - active_count) << "\n\n";
        
        report << "--- Active Patches ---\n";
        for (auto& [id, record] : patch_records_) {
            if (record.active) {
                report << "Patch ID: " << id << "\n";
                report << "  Model: " << record.model_path << "\n";
                report << "  Original hash: " << record.original_hash << "\n";
                report << "  Patched hash: " << record.patched_hash << "\n";
                report << "  Changes:\n";
                for (auto& change : record.changes) {
                    report << "    - " << change << "\n";
                }
                report << "\n";
            }
        }
        
        return report.str();
    }
    
private:
    std::string CreateBackup(const std::string& model_path, 
                             const std::string& patch_id) {
        std::filesystem::path backup_dir = std::filesystem::temp_directory_path() / "rawrxd_backups";
        std::filesystem::create_directories(backup_dir);
        
        std::string backup_path = (backup_dir / (patch_id + ".gguf.backup")).string();
        
        try {
            std::filesystem::copy_file(model_path, backup_path, 
                                       std::filesystem::copy_options::overwrite_existing);
            return backup_path;
        } catch (...) {
            return "";
        }
    }
    
    bool RestoreFromBackup(const std::string& backup_path,
                           const std::string& model_path) {
        try {
            std::filesystem::copy_file(backup_path, model_path,
                                       std::filesystem::copy_options::overwrite_existing);
            return true;
        } catch (...) {
            return false;
        }
    }
    
    bool ApplyPatchData(const std::string& model_path,
                        const std::vector<uint8_t>& patch_data) {
        // Parse patch format
        // Format: RPTC (4 bytes) + version (4 bytes) + num_changes (4 bytes) + changes...
        
        if (patch_data.size() < 12) return false;
        
        uint32_t version = *reinterpret_cast<const uint32_t*>(&patch_data[4]);
        uint32_t num_changes = *reinterpret_cast<const uint32_t*>(&patch_data[8]);
        
        // Open model for modification
        std::fstream model_file(model_path, std::ios::in | std::ios::out | std::ios::binary);
        if (!model_file) return false;
        
        size_t offset = 12;
        for (uint32_t i = 0; i < num_changes; ++i) {
            if (offset + 12 > patch_data.size()) break;
            
            uint64_t change_offset = *reinterpret_cast<const uint64_t*>(&patch_data[offset]);
            uint32_t change_size = *reinterpret_cast<const uint32_t*>(&patch_data[offset + 8]);
            
            offset += 12;
            
            if (offset + change_size > patch_data.size()) break;
            
            // Apply change
            model_file.seekp(change_offset);
            model_file.write(reinterpret_cast<const char*>(&patch_data[offset]), change_size);
            
            offset += change_size;
        }
        
        return true;
    }
    
    std::string ComputeFileHash(const std::string& path) {
        std::ifstream file(path, std::ios::binary);
        if (!file) return "";
        
        SHA256_CTX ctx;
        SHA256_Init(&ctx);
        
        char buffer[8192];
        while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
            SHA256_Update(&ctx, buffer, file.gcount());
        }
        
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_Final(hash, &ctx);
        
        std::stringstream ss;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        }
        
        return ss.str();
    }
    
    std::vector<std::string> ExtractChanges(const std::vector<uint8_t>& patch_data) {
        std::vector<std::string> changes;
        
        if (patch_data.size() < 12) return changes;
        
        uint32_t num_changes = *reinterpret_cast<const uint32_t*>(&patch_data[8]);
        
        for (uint32_t i = 0; i < num_changes; ++i) {
            changes.push_back("Change " + std::to_string(i + 1));
        }
        
        return changes;
    }
    
    std::mutex records_mutex_;
    std::map<std::string, HotpatchRecord> patch_records_;
};

// Global instance
ModelHotpatcherImpl* g_hotpatcher = nullptr;

// Public API
bool InitializeHotpatcher() {
    if (g_hotpatcher) return true;
    g_hotpatcher = new ModelHotpatcherImpl();
    return true;
}

void ShutdownHotpatcher() {
    if (g_hotpatcher) {
        delete g_hotpatcher;
        g_hotpatcher = nullptr;
    }
}

bool ApplyModelPatch(const std::string& model_path,
                     const std::vector<uint8_t>& patch_data,
                     const std::string& patch_id) {
    if (!g_hotpatcher) InitializeHotpatcher();
    return g_hotpatcher->ApplyPatch(model_path, patch_data, patch_id);
}

bool RollbackModelPatch(const std::string& patch_id) {
    if (!g_hotpatcher) return false;
    return g_hotpatcher->RollbackPatch(patch_id);
}

std::string GetHotpatchReport() {
    if (!g_hotpatcher) return "Hotpatcher not initialized";
    return g_hotpatcher->GeneratePatchReport();
}

} // namespace Hotpatch
} // namespace RawrXD
