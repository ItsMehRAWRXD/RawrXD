// RawrXD-Script Golden Master Database Implementation
// Regression detection through execution fingerprint comparison

#include "golden_master.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <algorithm>
#include <cstring>

namespace RawrXD {
namespace Script {

// Static member definitions
std::unordered_map<std::string, GoldenMasterEntry> GoldenMasterDB::s_masters;
bool GoldenMasterDB::s_initialized = false;
std::string GoldenMasterDB::s_dbPath = "golden_masters.db";

// Initialize the database
bool GoldenMasterDB::Initialize(const std::string& dbPath) {
    s_dbPath = dbPath;
    s_initialized = true;
    return LoadFromDisk(dbPath);
}

// Seal a new golden master
bool GoldenMasterDB::SealMaster(
    const std::string& testName,
    const std::string& category,
    const ExecutionFingerprint& fingerprint,
    uint32_t eventCount,
    const std::string& description,
    uint32_t tolerancePercent) {
    
    if (!s_initialized) {
        Initialize();
    }
    
    GoldenMasterEntry entry;
    entry.testName = testName;
    entry.testCategory = category;
    entry.fingerprint = fingerprint;
    entry.expectedEventCount = eventCount;
    entry.tolerancePercent = tolerancePercent;
    entry.timestamp = GoldenMasterUtils::GetCurrentTimestamp();
    entry.description = description.empty() ? 
        "Sealed on " + std::to_string(entry.timestamp) : description;
    
    s_masters[testName] = entry;
    
    // Auto-save after each seal
    return SaveToDisk();
}

// Compare current execution against stored master
FingerprintComparison GoldenMasterDB::CompareAgainstMaster(
    const std::string& testName,
    const ExecutionFingerprint& currentFingerprint,
    uint32_t currentEventCount) {
    
    FingerprintComparison result;
    result.currentFingerprint = currentFingerprint;
    result.currentEventCount = currentEventCount;
    
    auto it = s_masters.find(testName);
    if (it == s_masters.end()) {
        result.status = FingerprintComparison::Status::MissingMaster;
        result.diagnosticMessage = "No golden master exists for test: " + testName;
        return result;
    }
    
    const GoldenMasterEntry& master = it->second;
    result.expectedFingerprint = master.fingerprint;
    result.expectedEventCount = master.expectedEventCount;
    
    // Calculate Hamming distance
    result.hammingDistance = GoldenMasterUtils::CalculateHammingDistance(
        currentFingerprint, master.fingerprint);
    
    // Calculate similarity score
    result.similarityScore = GoldenMasterUtils::CalculateSimilarity(
        currentFingerprint, master.fingerprint);
    
    // Check for exact match
    if (currentFingerprint == master.fingerprint) {
        if (currentEventCount == master.expectedEventCount) {
            result.status = FingerprintComparison::Status::Match;
            result.diagnosticMessage = "Exact match with golden master";
        } else {
            result.status = FingerprintComparison::Status::EventCountMismatch;
            result.diagnosticMessage = "Fingerprint matches but event count differs: " +
                std::to_string(currentEventCount) + " vs " + 
                std::to_string(master.expectedEventCount);
        }
        return result;
    }
    
    // Check if within tolerance
    if (GoldenMasterUtils::IsWithinTolerance(
            currentFingerprint, master.fingerprint, master.tolerancePercent)) {
        result.status = FingerprintComparison::Status::WithinTolerance;
        result.diagnosticMessage = "Within tolerance (" + 
            std::to_string(master.tolerancePercent) + "%)";
        return result;
    }
    
    // Mismatch
    result.status = FingerprintComparison::Status::Mismatch;
    result.diagnosticMessage = "Execution path deviation detected. " +
        std::string("Hamming distance: ") + std::to_string(result.hammingDistance) +
        ", Similarity: " + std::to_string(static_cast<int>(result.similarityScore * 100)) + "%";
    
    return result;
}

// Get master entry
bool GoldenMasterDB::GetMaster(const std::string& testName, GoldenMasterEntry& outEntry) {
    auto it = s_masters.find(testName);
    if (it != s_masters.end()) {
        outEntry = it->second;
        return true;
    }
    return false;
}

// Check if master exists
bool GoldenMasterDB::HasMaster(const std::string& testName) {
    return s_masters.find(testName) != s_masters.end();
}

// Delete master
bool GoldenMasterDB::DeleteMaster(const std::string& testName) {
    auto it = s_masters.find(testName);
    if (it != s_masters.end()) {
        s_masters.erase(it);
        return SaveToDisk();
    }
    return false;
}

// List all masters
std::vector<GoldenMasterEntry> GoldenMasterDB::ListMasters() {
    std::vector<GoldenMasterEntry> result;
    for (const auto& pair : s_masters) {
        result.push_back(pair.second);
    }
    return result;
}

// List by category
std::vector<GoldenMasterEntry> GoldenMasterDB::ListMastersByCategory(
    const std::string& category) {
    std::vector<GoldenMasterEntry> result;
    for (const auto& pair : s_masters) {
        if (pair.second.testCategory == category) {
            result.push_back(pair.second);
        }
    }
    return result;
}

// Save to disk (binary format)
bool GoldenMasterDB::SaveToDisk(const std::string& dbPath) {
    std::string path = dbPath.empty() ? s_dbPath : dbPath;
    std::ofstream file(path, std::ios::binary);
    if (!file) return false;
    
    // Write header
    uint32_t magic = 0x524D4744; // "RMGD" (RawrXD Master Golden Database)
    uint32_t version = 1;
    uint32_t count = static_cast<uint32_t>(s_masters.size());
    
    file.write(reinterpret_cast<const char*>(&magic), sizeof(magic));
    file.write(reinterpret_cast<const char*>(&version), sizeof(version));
    file.write(reinterpret_cast<const char*>(&count), sizeof(count));
    
    // Write entries
    for (const auto& pair : s_masters) {
        const GoldenMasterEntry& entry = pair.second;
        
        // Write test name length and name
        uint32_t nameLen = static_cast<uint32_t>(entry.testName.length());
        file.write(reinterpret_cast<const char*>(&nameLen), sizeof(nameLen));
        file.write(entry.testName.data(), nameLen);
        
        // Write category length and category
        uint32_t catLen = static_cast<uint32_t>(entry.testCategory.length());
        file.write(reinterpret_cast<const char*>(&catLen), sizeof(catLen));
        file.write(entry.testCategory.data(), catLen);
        
        // Write fingerprint
        file.write(reinterpret_cast<const char*>(&entry.fingerprint.low), sizeof(entry.fingerprint.low));
        file.write(reinterpret_cast<const char*>(&entry.fingerprint.high), sizeof(entry.fingerprint.high));
        
        // Write metadata
        file.write(reinterpret_cast<const char*>(&entry.expectedEventCount), sizeof(entry.expectedEventCount));
        file.write(reinterpret_cast<const char*>(&entry.tolerancePercent), sizeof(entry.tolerancePercent));
        file.write(reinterpret_cast<const char*>(&entry.timestamp), sizeof(entry.timestamp));
        
        // Write description
        uint32_t descLen = static_cast<uint32_t>(entry.description.length());
        file.write(reinterpret_cast<const char*>(&descLen), sizeof(descLen));
        file.write(entry.description.data(), descLen);
    }
    
    return file.good();
}

// Load from disk
bool GoldenMasterDB::LoadFromDisk(const std::string& dbPath) {
    std::string path = dbPath.empty() ? s_dbPath : dbPath;
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        // File doesn't exist - not an error, just empty database
        return true;
    }
    
    // Read header
    uint32_t magic, version, count;
    file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
    file.read(reinterpret_cast<char*>(&version), sizeof(version));
    file.read(reinterpret_cast<char*>(&count), sizeof(count));
    
    if (magic != 0x524D4744 || version != 1) {
        return false; // Invalid format
    }
    
    s_masters.clear();
    
    // Read entries
    for (uint32_t i = 0; i < count; i++) {
        GoldenMasterEntry entry;
        
        // Read test name
        uint32_t nameLen;
        file.read(reinterpret_cast<char*>(&nameLen), sizeof(nameLen));
        entry.testName.resize(nameLen);
        file.read(&entry.testName[0], nameLen);
        
        // Read category
        uint32_t catLen;
        file.read(reinterpret_cast<char*>(&catLen), sizeof(catLen));
        entry.testCategory.resize(catLen);
        file.read(&entry.testCategory[0], catLen);
        
        // Read fingerprint
        file.read(reinterpret_cast<char*>(&entry.fingerprint.low), sizeof(entry.fingerprint.low));
        file.read(reinterpret_cast<char*>(&entry.fingerprint.high), sizeof(entry.fingerprint.high));
        
        // Read metadata
        file.read(reinterpret_cast<char*>(&entry.expectedEventCount), sizeof(entry.expectedEventCount));
        file.read(reinterpret_cast<char*>(&entry.tolerancePercent), sizeof(entry.tolerancePercent));
        file.read(reinterpret_cast<char*>(&entry.timestamp), sizeof(entry.timestamp));
        
        // Read description
        uint32_t descLen;
        file.read(reinterpret_cast<char*>(&descLen), sizeof(descLen));
        entry.description.resize(descLen);
        file.read(&entry.description[0], descLen);
        
        s_masters[entry.testName] = entry;
    }
    
    return file.good();
}

// Clear all masters
void GoldenMasterDB::Clear() {
    s_masters.clear();
}

// Get statistics
size_t GoldenMasterDB::GetMasterCount() {
    return s_masters.size();
}

size_t GoldenMasterDB::GetCategoryCount() {
    std::unordered_set<std::string> categories;
    for (const auto& pair : s_masters) {
        categories.insert(pair.second.testCategory);
    }
    return categories.size();
}

// Export to JSON
bool GoldenMasterDB::ExportToJSON(const std::string& jsonPath) {
    std::ofstream file(jsonPath);
    if (!file) return false;
    
    file << "{\n";
    file << "  \"version\": 1,\n";
    file << "  \"timestamp\": " << GoldenMasterUtils::GetCurrentTimestamp() << ",\n";
    file << "  \"masterCount\": " << s_masters.size() << ",\n";
    file << "  \"masters\": [\n";
    
    bool first = true;
    for (const auto& pair : s_masters) {
        const GoldenMasterEntry& entry = pair.second;
        
        if (!first) file << ",\n";
        first = false;
        
        file << "    {\n";
        file << "      \"testName\": \"" << entry.testName << "\",\n";
        file << "      \"category\": \"" << entry.testCategory << "\",\n";
        file << "      \"fingerprint\": \"" << GoldenMasterUtils::FormatFingerprint(entry.fingerprint) << "\",\n";
        file << "      \"expectedEventCount\": " << entry.expectedEventCount << ",\n";
        file << "      \"tolerancePercent\": " << entry.tolerancePercent << ",\n";
        file << "      \"timestamp\": " << entry.timestamp << ",\n";
        file << "      \"description\": \"" << entry.description << "\"\n";
        file << "    }";
    }
    
    file << "\n  ]\n";
    file << "}\n";
    
    return file.good();
}

// Import from JSON (simplified - would use proper JSON parser in production)
bool GoldenMasterDB::ImportFromJSON(const std::string& jsonPath) {
    // Placeholder - would implement JSON parsing
    return false;
}

// ============================================================================
// Utility Functions
// ============================================================================

uint32_t GoldenMasterUtils::CalculateHammingDistance(
    const ExecutionFingerprint& a,
    const ExecutionFingerprint& b) {
    
    uint64_t diffLow = a.low ^ b.low;
    uint64_t diffHigh = a.high ^ b.high;
    
    // Count bits set in diffLow
    uint32_t count = 0;
    while (diffLow) {
        count += diffLow & 1;
        diffLow >>= 1;
    }
    
    // Count bits set in diffHigh
    while (diffHigh) {
        count += diffHigh & 1;
        diffHigh >>= 1;
    }
    
    return count;
}

double GoldenMasterUtils::CalculateSimilarity(
    const ExecutionFingerprint& a,
    const ExecutionFingerprint& b) {
    
    uint32_t distance = CalculateHammingDistance(a, b);
    uint32_t totalBits = 128; // 128-bit fingerprint
    
    return 1.0 - (static_cast<double>(distance) / totalBits);
}

bool GoldenMasterUtils::IsWithinTolerance(
    const ExecutionFingerprint& current,
    const ExecutionFingerprint& expected,
    uint32_t tolerancePercent) {
    
    if (tolerancePercent == 0) {
        return current == expected;
    }
    
    double similarity = CalculateSimilarity(current, expected);
    double tolerance = tolerancePercent / 100.0;
    
    return similarity >= (1.0 - tolerance);
}

uint64_t GoldenMasterUtils::GetCurrentTimestamp() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string GoldenMasterUtils::FormatFingerprint(const ExecutionFingerprint& fp) {
    char buffer[33];
    snprintf(buffer, sizeof(buffer), "%016llX%016llX", fp.high, fp.low);
    return std::string(buffer);
}

bool GoldenMasterUtils::ParseFingerprint(const std::string& str, ExecutionFingerprint& fp) {
    if (str.length() != 32) return false;
    
    try {
        fp.high = std::stoull(str.substr(0, 16), nullptr, 16);
        fp.low = std::stoull(str.substr(16, 16), nullptr, 16);
        return true;
    } catch (...) {
        return false;
    }
}

} // namespace Script
} // namespace RawrXD
