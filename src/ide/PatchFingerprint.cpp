/*===========================================================================
 * PatchFingerprint.cpp
 * RawrXD IDE - Patch Identity and Deduplication Implementation
 *===========================================================================*/

#include "PatchFingerprint.h"
#include <blake3.h>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <unordered_map>
#include <unordered_set>

namespace RawrXD {

/*===========================================================================
 * PATCH FINGERPRINT IMPLEMENTATION
 *===========================================================================*/

bool PatchFingerprint::operator==(const PatchFingerprint& other) const {
    return diffHash == other.diffHash &&
           filePath == other.filePath &&
           lineNumber == other.lineNumber;
}

bool PatchFingerprint::operator!=(const PatchFingerprint& other) const {
    return !(*this == other);
}

float PatchFingerprint::CalculateSimilarity(const PatchFingerprint& other) const {
    float score = 0.0f;
    float weight = 0.0f;
    
    // Diff hash similarity (highest weight)
    if (diffHash == other.diffHash) {
        score += 0.4f;
    }
    weight += 0.4f;
    
    // Context hash similarity
    if (contextHash == other.contextHash) {
        score += 0.2f;
    }
    weight += 0.2f;
    
    // File path
    if (filePath == other.filePath) {
        score += 0.15f;
    }
    weight += 0.15f;
    
    // Line number proximity
    if (filePath == other.filePath) {
        uint32_t lineDiff = (lineNumber > other.lineNumber) ? 
            (lineNumber - other.lineNumber) : (other.lineNumber - lineNumber);
        if (lineDiff < 5) {
            score += 0.15f * (1.0f - (lineDiff / 5.0f));
        }
    }
    weight += 0.15f;
    
    // Affected symbols
    if (affectedSymbols == other.affectedSymbols) {
        score += 0.1f;
    }
    weight += 0.1f;
    
    return weight > 0 ? (score / weight) : 0.0f;
}

bool PatchFingerprint::IsDuplicate(const PatchFingerprint& other, float threshold) const {
    return CalculateSimilarity(other) >= threshold;
}

bool PatchFingerprint::IsSemanticDuplicate(const PatchFingerprint& other) const {
    // Semantic duplicate = same fix pattern, possibly different location
    return patchType == other.patchType &&
           affectedSymbols == other.affectedSymbols &&
           diffHash == other.diffHash;
}

std::string PatchFingerprint::ToJson() const {
    std::stringstream json;
    json << "{\n";
    json << "  \"fingerprintId\": " << fingerprintId << ",\n";
    json << "  \"patchUuid\": \"" << patchUuid << "\",\n";
    json << "  \"sourceBeforeHash\": \"" << std::hex << sourceBeforeHash << std::dec << "\",\n";
    json << "  \"sourceAfterHash\": \"" << std::hex << sourceAfterHash << std::dec << "\",\n";
    json << "  \"diffHash\": \"" << std::hex << diffHash << std::dec << "\",\n";
    json << "  \"filePath\": \"" << filePath << "\",\n";
    json << "  \"lineNumber\": " << lineNumber << ",\n";
    json << "  \"patchType\": \"" << patchType << "\",\n";
    json << "  \"affectedSymbols\": \"" << affectedSymbols << "\",\n";
    json << "  \"timestamp\": " << timestamp << "\n";
    json << "}";
    return json.str();
}

PatchFingerprint PatchFingerprint::FromJson(const std::string& json) {
    PatchFingerprint fp;
    // TODO: Implement JSON parsing
    (void)json;
    return fp;
}

std::string PatchFingerprint::ToCompactString() const {
    std::stringstream ss;
    ss << patchType << "@" << filePath << ":" << lineNumber;
    ss << " [" << std::hex << (diffHash & 0xFFFF) << std::dec << "]";
    return ss.str();
}

uint64_t PatchFingerprint::ComputeDiffHash(const std::string& original, const std::string& replacement) {
    std::string combined = original + "\x00" + replacement;
    return PatchFingerprintUtils::ComputeBlake3Hash64(combined);
}

uint64_t PatchFingerprint::ComputeContextHash(const std::string& filePath, uint32_t line, uint32_t contextLines) {
    // TODO: Read actual file content and hash surrounding lines
    std::string context = filePath + ":" + std::to_string(line) + ":" + std::to_string(contextLines);
    return PatchFingerprintUtils::ComputeBlake3Hash64(context);
}

std::string PatchFingerprint::ExtractAffectedSymbols(const std::string& code) {
    auto functions = PatchFingerprintUtils::ExtractFunctionNames(code);
    auto classes = PatchFingerprintUtils::ExtractClassNames(code);
    
    std::stringstream result;
    for (const auto& f : functions) {
        if (!result.str().empty()) result << ",";
        result << f;
    }
    for (const auto& c : classes) {
        if (!result.str().empty()) result << ",";
        result << c;
    }
    return result.str();
}

/*===========================================================================
 * PATCH DEDUPLICATION ENGINE
 *===========================================================================*/

class PatchDeduplicationEngine::Impl {
public:
    std::unordered_map<uint64_t, PatchFingerprint> patchDatabase;
    std::unordered_map<uint64_t, bool> patchSuccess;  // fingerprintId -> success
    std::unordered_map<std::string, std::vector<uint64_t>> crashToPatches;
    
    Stats stats = {};
    std::string dbPath;
    bool initialized = false;
};

PatchDeduplicationEngine::PatchDeduplicationEngine() 
    : m_impl(std::make_unique<Impl>()) {
}

PatchDeduplicationEngine::~PatchDeduplicationEngine() {
    Shutdown();
}

bool PatchDeduplicationEngine::Initialize(const std::string& databasePath) {
    m_impl->dbPath = databasePath;
    m_impl->initialized = true;
    
    // TODO: Load existing database from disk
    return true;
}

void PatchDeduplicationEngine::Shutdown() {
    // TODO: Save database to disk
    m_impl->initialized = false;
}

DeduplicationInfo PatchDeduplicationEngine::CheckPatch(const PatchFingerprint& fingerprint) {
    DeduplicationInfo info;
    info.similarityScore = 0.0f;
    
    // Check for exact duplicate
    auto it = m_impl->patchDatabase.find(fingerprint.fingerprintId);
    if (it != m_impl->patchDatabase.end()) {
        info.result = DeduplicationResult::ExactDuplicate;
        info.matchedPatchId = std::to_string(it->second.patchUuid);
        info.similarityScore = 1.0f;
        info.recommendation = "Exact duplicate detected - skip this patch";
        m_impl->stats.exactDuplicatesDetected++;
        return info;
    }
    
    // Check for similar patches
    auto similar = FindSimilarPatches(fingerprint, 0.90f);
    if (!similar.empty()) {
        // Check if similar patch was a known failure
        for (const auto& similarPatch : similar) {
            auto successIt = m_impl->patchSuccess.find(similarPatch.fingerprintId);
            if (successIt != m_impl->patchSuccess.end() && !successIt->second) {
                info.result = DeduplicationResult::KnownFailure;
                info.matchedPatchId = std::to_string(similarPatch.patchUuid);
                info.similarityScore = fingerprint.CalculateSimilarity(similarPatch);
                info.recommendation = "Similar patch failed before - consider alternative approach";
                m_impl->stats.knownFailuresAvoided++;
                return info;
            }
        }
        
        // Check if similar patch was a known success
        for (const auto& similarPatch : similar) {
            auto successIt = m_impl->patchSuccess.find(similarPatch.fingerprintId);
            if (successIt != m_impl->patchSuccess.end() && successIt->second) {
                info.result = DeduplicationResult::KnownSuccess;
                info.matchedPatchId = std::to_string(similarPatch.patchUuid);
                info.similarityScore = fingerprint.CalculateSimilarity(similarPatch);
                info.recommendation = "Similar patch succeeded - high confidence";
                m_impl->stats.knownSuccessesReused++;
                return info;
            }
        }
        
        // Near duplicate but no known outcome
        info.result = DeduplicationResult::NearDuplicate;
        info.matchedPatchId = std::to_string(similar[0].patchUuid);
        info.similarityScore = fingerprint.CalculateSimilarity(similar[0]);
        info.recommendation = "Similar patch exists - review before applying";
        m_impl->stats.nearDuplicatesDetected++;
        return info;
    }
    
    // New patch
    info.result = DeduplicationResult::NewPatch;
    info.recommendation = "New patch - proceed with validation";
    return info;
}

void PatchDeduplicationEngine::RecordPatch(const PatchFingerprint& fingerprint, bool success) {
    m_impl->patchDatabase[fingerprint.fingerprintId] = fingerprint;
    m_impl->patchSuccess[fingerprint.fingerprintId] = success;
    m_impl->stats.totalPatches++;
}

std::vector<PatchFingerprint> PatchDeduplicationEngine::FindSimilarPatches(
    const PatchFingerprint& fingerprint, float threshold) {
    
    std::vector<PatchFingerprint> similar;
    
    for (const auto& pair : m_impl->patchDatabase) {
        float similarity = fingerprint.CalculateSimilarity(pair.second);
        if (similarity >= threshold) {
            similar.push_back(pair.second);
        }
    }
    
    // Sort by similarity
    std::sort(similar.begin(), similar.end(), [&fingerprint](const PatchFingerprint& a, const PatchFingerprint& b) {
        return fingerprint.CalculateSimilarity(a) > fingerprint.CalculateSimilarity(b);
    });
    
    return similar;
}

std::vector<PatchFingerprint> PatchDeduplicationEngine::GetPatchesForCrash(const std::string& crashSignature) {
    std::vector<PatchFingerprint> patches;
    auto it = m_impl->crashToPatches.find(crashSignature);
    if (it != m_impl->crashToPatches.end()) {
        for (uint64_t patchId : it->second) {
            auto patchIt = m_impl->patchDatabase.find(patchId);
            if (patchIt != m_impl->patchDatabase.end()) {
                patches.push_back(patchIt->second);
            }
        }
    }
    return patches;
}

std::vector<PatchFingerprint> PatchDeduplicationEngine::GetSuccessfulPatches() {
    std::vector<PatchFingerprint> patches;
    for (const auto& pair : m_impl->patchSuccess) {
        if (pair.second) {
            auto it = m_impl->patchDatabase.find(pair.first);
            if (it != m_impl->patchDatabase.end()) {
                patches.push_back(it->second);
            }
        }
    }
    return patches;
}

std::vector<PatchFingerprint> PatchDeduplicationEngine::GetFailedPatches() {
    std::vector<PatchFingerprint> patches;
    for (const auto& pair : m_impl->patchSuccess) {
        if (!pair.second) {
            auto it = m_impl->patchDatabase.find(pair.first);
            if (it != m_impl->patchDatabase.end()) {
                patches.push_back(it->second);
            }
        }
    }
    return patches;
}

PatchDeduplicationEngine::Stats PatchDeduplicationEngine::GetStats() const {
    return m_impl->stats;
}

void PatchDeduplicationEngine::CompactDatabase() {
    // Remove old/obsolete entries
    // TODO: Implement compaction logic
}

void PatchDeduplicationEngine::ExportToJson(const std::string& path) {
    // TODO: Export database to JSON
    (void)path;
}

void PatchDeduplicationEngine::ImportFromJson(const std::string& path) {
    // TODO: Import database from JSON
    (void)path;
}

/*===========================================================================
 * PATCH FINGERPRINT UTILITIES
 *===========================================================================*/

namespace PatchFingerprintUtils {

uint64_t ComputeBlake3Hash64(const std::string& data) {
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, data.data(), data.size());
    
    uint8_t hash[BLAKE3_OUT_LEN];
    blake3_hasher_finalize(&hasher, hash, BLAKE3_OUT_LEN);
    
    // Return first 8 bytes as uint64_t
    uint64_t result = 0;
    for (int i = 0; i < 8 && i < BLAKE3_OUT_LEN; i++) {
        result = (result << 8) | hash[i];
    }
    return result;
}

std::string ComputeBlake3HashHex(const std::string& data) {
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, data.data(), data.size());
    
    uint8_t hash[BLAKE3_OUT_LEN];
    blake3_hasher_finalize(&hasher, hash, BLAKE3_OUT_LEN);
    
    std::stringstream ss;
    for (int i = 0; i < BLAKE3_OUT_LEN; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

std::string ComputeUnifiedDiff(const std::string& original, const std::string& modified,
                              const std::string& filePath, uint32_t lineNumber) {
    std::stringstream diff;
    diff << "--- " << filePath << "\n";
    diff << "+++ " << filePath << "\n";
    diff << "@@ -" << lineNumber << " +" << lineNumber << " @@\n";
    diff << "-" << original << "\n";
    diff << "+" << modified << "\n";
    return diff.str();
}

std::vector<std::string> ExtractFunctionNames(const std::string& code) {
    std::vector<std::string> functions;
    // Simple regex-like extraction
    // TODO: Implement proper parsing
    (void)code;
    return functions;
}

std::vector<std::string> ExtractClassNames(const std::string& code) {
    std::vector<std::string> classes;
    // TODO: Implement proper parsing
    (void)code;
    return classes;
}

std::vector<std::string> ExtractVariableNames(const std::string& code) {
    std::vector<std::string> variables;
    // TODO: Implement proper parsing
    (void)code;
    return variables;
}

float JaccardSimilarity(const std::vector<std::string>& set1, const std::vector<std::string>& set2) {
    if (set1.empty() && set2.empty()) return 1.0f;
    
    std::unordered_set<std::string> s1(set1.begin(), set1.end());
    std::unordered_set<std::string> s2(set2.begin(), set2.end());
    
    std::vector<std::string> intersection;
    std::set_intersection(set1.begin(), set1.end(), set2.begin(), set2.end(),
                          std::back_inserter(intersection));
    
    std::vector<std::string> uni;
    std::set_union(set1.begin(), set1.end(), set2.begin(), set2.end(),
                   std::back_inserter(uni));
    
    return (float)intersection.size() / (float)uni.size();
}

float LevenshteinSimilarity(const std::string& s1, const std::string& s2) {
    // TODO: Implement Levenshtein distance
    (void)s1;
    (void)s2;
    return 0.0f;
}

float CodeSimilarity(const std::string& code1, const std::string& code2) {
    // Normalize code (remove whitespace, comments) then compare
    // TODO: Implement proper code similarity
    (void)code1;
    (void)code2;
    return 0.0f;
}

} // namespace PatchFingerprintUtils

} // namespace RawrXD
