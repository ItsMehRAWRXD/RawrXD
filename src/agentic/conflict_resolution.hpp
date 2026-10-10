// ============================================================================
// File: src/agentic/conflict_resolution.hpp
//
// Purpose: Advanced Conflict Resolution Engine
// 3-way merge, semantic conflict detection, auto-resolution policies
//
// Production-ready implementation for multi-agent concurrent editing.
// Namespaces away from RawrXD::HexMag types (which have their own
// ConflictResolver/Edit/Conflict) so both coexist safely.
//
// Design principles:
//   - Structured results, no exceptions crossing the API boundary
//   - Thread-safe
//   - Deterministic: same inputs -> same resolution
//   - Observable: every decision is explainable in plain text
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <functional>
#include <mutex>
#include <atomic>
#include <thread>
#include <unordered_map>
#include <memory>
#include <optional>
#include <chrono>

namespace RawrXD {
namespace ConflictEngine {

// ============================================================================
// Core Types
// ============================================================================

struct TextRange {
    int startLine = 0;
    int startColumn = 0;
    int endLine = 0;
    int endColumn = 0;

    bool operator==(const TextRange& other) const {
        return startLine == other.startLine && startColumn == other.startColumn &&
               endLine == other.endLine && endColumn == other.endColumn;
    }

    bool overlaps(const TextRange& other) const {
        if (endLine < other.startLine || startLine > other.endLine) return false;
        if (endLine == other.startLine && endColumn < other.startColumn) return false;
        if (startLine == other.endLine && startColumn > other.endColumn) return false;
        return true;
    }

    bool contains(const TextRange& other) const {
        if (startLine > other.startLine) return false;
        if (startLine == other.startLine && startColumn > other.startColumn) return false;
        if (endLine < other.endLine) return false;
        if (endLine == other.endLine && endColumn < other.endColumn) return false;
        return true;
    }
};

struct DocumentPosition {
    int line = 0;
    int column = 0;
};

struct Edit {
    std::string id;
    std::string agentId;
    std::string filePath;
    TextRange range;
    std::string oldText;                 // original text (3-way merge "base")
    std::string newText;                 // replacement text
    int64_t timestamp = 0;
    int version = 0;                     // document version the edit is based on
    std::string description;
    std::unordered_map<std::string, std::string> metadata;

    enum class SemanticType {
        Unknown,
        FunctionSignature,
        FunctionBody,
        ClassDefinition,
        VariableDeclaration,
        ImportStatement,
        Comment,
        Configuration,
        TestCode,
        Documentation
    } semanticType = SemanticType::Unknown;

    int priority = 50;                   // 0-100, higher wins

    Edit() = default;
    explicit Edit(std::string a, std::string f) : agentId(std::move(a)), filePath(std::move(f)) {}
};

struct Conflict {
    std::string id;
    std::string filePath;
    std::vector<Edit> conflictingEdits;
    TextRange affectedRange;
    int64_t detectedAt = 0;
    std::string detectionReason;

    enum class ConflictType {
        TextOverlap,
        SemanticOverlap,
        DependencyConflict,
        StyleConflict,
        LogicConflict
    } type = ConflictType::TextOverlap;

    enum class ResolutionStrategy {
        None,
        AutoMerge,
        FirstWins,
        LastWins,
        PriorityWins,
        ManualRequired,
        SemanticMerge,
        Custom
    } resolutionStrategy = ResolutionStrategy::None;

    std::string resolvedText;
    std::string resolutionDetails;
    bool isResolved = false;
    int64_t resolvedAt = 0;

    Conflict() = default;
};

struct MergeResult {
    bool success = false;
    std::string mergedText;
    int conflictCount = 0;
    std::vector<std::string> warnings;
    std::string details;

    MergeResult() = default;
};

// ============================================================================
// Conflict Detection
// ============================================================================

class ConflictDetector {
public:
    struct DetectionConfig {
        bool enableSemanticDetection = true;
        bool enableDependencyDetection = true;
        bool enableStyleDetection = false;
        int maxOverlapThreshold = 0;
        std::vector<std::string> ignorePatterns;
    };

    ConflictDetector() = default;
    explicit ConflictDetector(const DetectionConfig& config);

    std::vector<Conflict> detectConflicts(const std::vector<Edit>& edits) const;
    std::vector<Conflict> detectConflictsForEdit(const Edit& newEdit,
                                                  const std::vector<Edit>& existingEdits) const;

    Edit::SemanticType classifyEditSemantics(const Edit& edit) const;
    bool hasSemanticDependency(const Edit& edit1, const Edit& edit2) const;

    void setConfig(const DetectionConfig& config);
    DetectionConfig getConfig() const;

private:
    DetectionConfig m_config;
    mutable std::mutex m_mutex;

    std::vector<std::pair<Edit, Edit>> findOverlappingEdits(const std::vector<Edit>& edits) const;
    Edit::SemanticType classifyByPattern(const std::string& text, const std::string& filePath) const;
    std::vector<std::string> extractSemanticTokens(const std::string& text) const;
    bool shouldIgnoreFile(const std::string& filePath) const;
};

// ============================================================================
// 3-Way Merge Engine
// ============================================================================

class ThreeWayMerge {
public:
    struct MergeOptions {
        bool preferLocal = false;
        bool preferRemote = false;
        bool markConflicts = true;
        std::string conflictMarkerStart = "<<<<<<< ours";
        std::string conflictMarkerMiddle = "=======";
        std::string conflictMarkerEnd = ">>>>>>> theirs";
        bool semanticAware = true;
    };

    ThreeWayMerge() = default;
    explicit ThreeWayMerge(const MergeOptions& options);

    // base = common ancestor, local = ours, remote = theirs
    MergeResult merge(const std::string& base,
                      const std::string& local,
                      const std::string& remote,
                      const std::string& filePath = "");

    MergeResult mergeEdits(const std::string& baseDocument,
                           const std::vector<Edit>& edits,
                           const std::string& filePath = "");

    struct DiffHunk {
        int baseStart = 0, baseLines = 0;
        int localStart = 0, localLines = 0;
        int remoteStart = 0, remoteLines = 0;
        std::vector<std::string> baseVector;
        std::vector<std::string> localVector;
        std::vector<std::string> remoteVector;
    };

    std::vector<DiffHunk> computeDiff3(const std::string& base,
                                        const std::string& local,
                                        const std::string& remote) const;

    // Format a conflicting region with the configured markers. Exposed so
    // callers (e.g. the swarm merger) can emit visible collisions instead of
    // silently dropping one side.
    std::string formatConflict(const std::vector<std::string>& local,
                               const std::vector<std::string>& remote,
                               const std::string& base = std::string()) const {
        return applyConflictMarkers(base, local, remote);
    }

    void setOptions(const MergeOptions& options);
    MergeOptions getOptions() const;

private:
    MergeOptions m_options;
    mutable std::mutex m_mutex;

    std::string mergeHunk(const DiffHunk& hunk) const;
    bool linesEquivalent(const std::string& a, const std::string& b,
                         const std::string& filePath) const;
    std::string applyConflictMarkers(const std::string& base,
                                     const std::vector<std::string>& local,
                                     const std::vector<std::string>& remote) const;
};

// ============================================================================
// Conflict Resolution Strategies
// ============================================================================

class ConflictResolver {
public:
    struct ResolutionPolicy {
        std::string name;
        std::string description;

        std::vector<Conflict::ConflictType> applicableTypes;
        std::vector<std::string> filePatterns;   // glob

        enum class Method {
            AutoMerge,      // try 3-way merge, fall back on failure
            FirstWins,      // earliest timestamp
            LastWins,       // latest timestamp
            PriorityWins,   // highest edit priority
            AgentWins,      // specific agent wins
            ManualRequired, // escalate
            Custom          // custom resolver fn
        } method = Method::AutoMerge;

        std::string preferredAgentId;            // for AgentWins
        std::function<Conflict::ResolutionStrategy(const Conflict&)> customResolver;
        Method fallbackMethod = Method::ManualRequired;

        int priority = 50;                       // higher = applied first

        // Ctor
        ResolutionPolicy() = default;
        ResolutionPolicy(std::string n) : name(std::move(n)) {}
    };

    ConflictResolver();

    Conflict resolve(const Conflict& conflict, const std::string& baseDocument = "");
    std::vector<Conflict> resolveAll(std::vector<Conflict> conflicts,
                                     const std::string& baseDocument = "");

    void registerPolicy(const ResolutionPolicy& policy);
    bool removePolicy(const std::string& name);
    std::vector<ResolutionPolicy> getPolicies() const;

    void setDefaultPolicy(const ResolutionPolicy& policy);

    Conflict autoResolve(const Conflict& conflict,
                         Conflict::ResolutionStrategy strategy,
                         const std::string& baseDocument = "");

private:
    mutable std::mutex m_mutex;
    std::vector<ResolutionPolicy> m_policies;
    ResolutionPolicy m_defaultPolicy;
    std::unique_ptr<ThreeWayMerge> m_threeWayMerge;

    const ResolutionPolicy* findMatchingPolicy(const Conflict& conflict) const;
    Conflict applyResolution(const Conflict& conflict,
                             ResolutionPolicy::Method method,
                             const std::string& baseDocument) const;
    Conflict semanticMerge(const Conflict& conflict,
                           const std::string& baseDocument) const;
};

// ============================================================================
// Conflict Manager - High-level orchestration
// ============================================================================

class ConflictManager {
public:
    struct Config {
        bool autoResolveEnabled = true;
        bool semanticDetectionEnabled = true;
        int maxConcurrentResolutions = 4;
        std::string conflictLogPath;
    };

    explicit ConflictManager(const Config& config = Config{});
    ~ConflictManager();

    // ---- Resolution policy ----
    // Replace the resolver's policy set. Policies are matched per conflict and
    // the highest-priority matching one wins.
    void setResolutionPolicy(const ConflictResolver::ResolutionPolicy& policy);
    void clearResolutionPolicies();
    ConflictResolver* resolver() { return m_resolver.get(); }

    std::vector<Edit> processEdits(const std::vector<Edit>& edits,
                                   const std::string& baseDocument = "");

    using ProcessCallback = std::function<void(const std::vector<Edit>& resolvedEdits,
                                               const std::vector<Conflict>& conflicts)>;
    void processEditsAsync(const std::vector<Edit>& edits,
                           const std::string& baseDocument,
                           ProcessCallback callback);

    std::vector<Conflict> getUnresolvedConflicts() const;
    std::vector<Conflict> getConflictHistory(int limit = 100) const;

    bool resolveManually(const std::string& conflictId,
                         const std::string& resolvedText,
                         const std::string& resolutionDetails);

    using ConflictCallback = std::function<void(const Conflict&)>;
    void onConflictDetected(ConflictCallback cb);
    void onConflictResolved(ConflictCallback cb);

    struct Stats {
        int64_t totalConflictsDetected = 0;
        int64_t totalAutoResolved = 0;
        int64_t totalManualRequired = 0;
        int64_t totalFailed = 0;
        double avgResolutionTimeMs = 0.0;
    };
    Stats getStats() const;
    bool exportConflictLog(const std::string& filePath) const;

private:
    Config m_config;
    std::unique_ptr<ConflictDetector> m_detector;
    std::unique_ptr<ConflictResolver> m_resolver;
    std::unique_ptr<ThreeWayMerge> m_merge;

    mutable std::mutex m_mutex;
    std::vector<Conflict> m_conflictHistory;
    std::vector<Conflict> m_unresolvedConflicts;

    ConflictCallback m_onDetected;
    ConflictCallback m_onResolved;

    std::atomic<int64_t> m_totalDetected{0};
    std::atomic<int64_t> m_totalAutoResolved{0};
    std::atomic<int64_t> m_totalManualRequired{0};
    std::atomic<int64_t> m_totalFailed{0};
    std::atomic<int64_t> m_totalResolutionTimeMs{0};
    std::atomic<int64_t> m_resolutionCount{0};

    struct AsyncJob {
        std::vector<Edit> edits;
        std::string baseDocument;
        ProcessCallback callback;
    };
    std::vector<AsyncJob> m_queue;
    std::thread m_workerThread;
    std::atomic<bool> m_running{false};
    std::atomic<bool> m_shutdown{false};
    std::mutex m_queueMutex;
    std::condition_variable m_queueCv;

    void workerLoop();
    void logConflict(const Conflict& conflict) const;
    static std::string escapeJsonField(const std::string& s);
};

// ============================================================================
// Swarm integration helpers (compatible with RawrXD::HexMar SwarmEdit shapes)
// ============================================================================

struct SwarmEdit {
    std::string taskId;
    std::string agentId;
    std::string filePath;
    std::string content;                    // full content after edit
    std::string diff;                       // unified diff
    int64_t timestamp = 0;
    std::vector<std::string> dependencies;  // task ids this edit depends on
};

struct SwarmConflict {
    std::string conflictId;
    std::vector<SwarmEdit> involvedEdits;
    std::string filePath;
    Conflict::ConflictType type = Conflict::ConflictType::TextOverlap;
    std::string reason;
    bool autoResolvable = false;
    std::string suggestedResolution;
};

class SwarmConflictResolver {
public:
    static std::vector<SwarmConflict> detectSwarmConflicts(const std::vector<SwarmEdit>& edits);
    static std::vector<SwarmEdit> resolveSwarmConflicts(
        const std::vector<SwarmEdit>& edits,
        const std::vector<SwarmConflict>& conflicts,
        ConflictResolver::ResolutionPolicy::Method strategy =
            ConflictResolver::ResolutionPolicy::Method::AutoMerge);
    static std::string mergeSwarmResults(const std::string& baseContent,
                                         const std::vector<SwarmEdit>& edits);
};

// ============================================================================
// Global accessor
// ============================================================================

ConflictManager& getGlobalConflictManager();

} // namespace ConflictEngine
} // namespace RawrXD
