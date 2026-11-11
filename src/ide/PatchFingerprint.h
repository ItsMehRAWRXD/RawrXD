/*===========================================================================
 * PatchFingerprint.h
 * RawrXD IDE - Patch Identity and Deduplication System
 * 
 * Prevents duplicate patches and enables repair history analysis
 *===========================================================================*/

#ifndef PATCH_FINGERPRINT_H
#define PATCH_FINGERPRINT_H

#include <windows.h>
#include <string>
#include <vector>
#include <stdint.h>
#include <functional>

namespace RawrXD {

/*===========================================================================
 * PATCH FINGERPRINT
 *===========================================================================*/

struct PatchFingerprint {
    // Identity
    uint64_t fingerprintId;           // Unique ID for this patch
    std::string patchUuid;              // UUID v4 for global uniqueness
    
    // Source state
    uint64_t sourceBeforeHash;        // BLAKE3 hash of file before
    uint64_t sourceAfterHash;         // BLAKE3 hash of file after
    uint64_t diffHash;                  // Hash of the diff itself
    
    // Content
    std::string filePath;               // File being modified
    uint32_t lineNumber;              // Line where patch applies
    std::string originalText;           // Text being replaced
    std::string replacementText;        // New text
    std::string contextHash;            // Hash of surrounding context (±3 lines)
    
    // Semantic info
    std::string affectedSymbols;        // Functions/classes modified
    std::string patchType;              // "null_check", "bounds_check", "type_fix", etc.
    std::vector<std::string> dependencies; // Other symbols this depends on
    
    // Metadata
    uint64_t timestamp;                 // When patch was created
    std::string agentVersion;           // Version of agent that generated it
    std::string modelHash;              // Hash of model used
    
    PatchFingerprint()
        : fingerprintId(0)
        , sourceBeforeHash(0)
        , sourceAfterHash(0)
        , diffHash(0)
        , lineNumber(0)
        , timestamp(0) {}
    
    // Comparison
    bool operator==(const PatchFingerprint& other) const;
    bool operator!=(const PatchFingerprint& other) const;
    
    // Similarity check (for near-duplicates)
    float CalculateSimilarity(const PatchFingerprint& other) const;
    bool IsDuplicate(const PatchFingerprint& other, float threshold = 0.95f) const;
    bool IsSemanticDuplicate(const PatchFingerprint& other) const;
    
    // Serialization
    std::string ToJson() const;
    static PatchFingerprint FromJson(const std::string& json);
    std::string ToCompactString() const;  // For display/logging
    
    // Hash computation
    static uint64_t ComputeDiffHash(const std::string& original, const std::string& replacement);
    static uint64_t ComputeContextHash(const std::string& filePath, uint32_t line, uint32_t contextLines = 3);
    static std::string ExtractAffectedSymbols(const std::string& code);
};

/*===========================================================================
 * PATCH DEDUPLICATION ENGINE
 *===========================================================================*/

enum class DeduplicationResult {
    NewPatch,           // Never seen before
    ExactDuplicate,     // Already proposed/applied
    NearDuplicate,      // Similar to existing (warn)
    KnownFailure,       // Similar patch failed before
    KnownSuccess        // Similar patch succeeded before
};

struct DeduplicationInfo {
    DeduplicationResult result;
    std::string matchedPatchId;         // If duplicate/failure/success
    float similarityScore;
    std::string recommendation;         // "Avoid - failed 3 times", etc.
    std::vector<std::string> relatedPatches;
};

class PatchDeduplicationEngine {
public:
    PatchDeduplicationEngine();
    ~PatchDeduplicationEngine();
    
    // Lifecycle
    bool Initialize(const std::string& databasePath);
    void Shutdown();
    
    // Core deduplication
    DeduplicationInfo CheckPatch(const PatchFingerprint& fingerprint);
    void RecordPatch(const PatchFingerprint& fingerprint, bool success);
    
    // Querying
    std::vector<PatchFingerprint> FindSimilarPatches(const PatchFingerprint& fingerprint, float threshold = 0.80f);
    std::vector<PatchFingerprint> GetPatchesForCrash(const std::string& crashSignature);
    std::vector<PatchFingerprint> GetSuccessfulPatches();
    std::vector<PatchFingerprint> GetFailedPatches();
    
    // Statistics
    struct Stats {
        uint32_t totalPatches;
        uint32_t exactDuplicatesDetected;
        uint32_t nearDuplicatesDetected;
        uint32_t knownFailuresAvoided;
        uint32_t knownSuccessesReused;
        float averageSimilarityThreshold;
    };
    Stats GetStats() const;
    
    // Maintenance
    void CompactDatabase();
    void ExportToJson(const std::string& path);
    void ImportFromJson(const std::string& path);

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
    
    // Indexing
    void UpdateIndexes(const PatchFingerprint& fingerprint);
    std::vector<PatchFingerprint> SearchByDiffHash(uint64_t diffHash);
    std::vector<PatchFingerprint> SearchByContextHash(uint64_t contextHash);
};

/*===========================================================================
 * PATCH FINGERPRINT UTILITIES
 *===========================================================================*/

namespace PatchFingerprintUtils {
    // Hash functions
    uint64_t ComputeBlake3Hash64(const std::string& data);
    std::string ComputeBlake3HashHex(const std::string& data);
    
    // Diff utilities
    std::string ComputeUnifiedDiff(const std::string& original, const std::string& modified,
                                   const std::string& filePath = "", uint32_t lineNumber = 0);
    
    // Symbol extraction
    std::vector<std::string> ExtractFunctionNames(const std::string& code);
    std::vector<std::string> ExtractClassNames(const std::string& code);
    std::vector<std::string> ExtractVariableNames(const std::string& code);
    
    // Similarity metrics
    float JaccardSimilarity(const std::vector<std::string>& set1, const std::vector<std::string>& set2);
    float LevenshteinSimilarity(const std::string& s1, const std::string& s2);
    float CodeSimilarity(const std::string& code1, const std::string& code2);
}

} // namespace RawrXD

#endif // PATCH_FINGERPRINT_H
