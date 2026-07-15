/**
 * OscillationDampener.hpp
 *
 * Phase C.4 Batch 2/5: Oscillation Detection & Dampening
 *
 * Detects and dampens harmful oscillations in:
 * - Decision patterns (flip-flopping between choices)
 * - Mutation patterns (rapid graph changes)
 * - State oscillations (unstable runtime states)
 * - Resource oscillations (memory/CPU thrashing)
 *
 * Dampening Strategies:
 * - Hysteresis: Require sustained deviation before action
 * - Rate Limiting: Limit mutation/decision frequency
 * - Smoothing: Exponential moving average for noisy signals
 * - Deadband: Ignore small fluctuations
 */

#pragma once

#include "StabilityEnvelope.hpp"
#include "../core/SovereignState.hpp"
#include "DecisionTypes.hpp"

#include <cstring>
#include <vector>
#include <map>
#include <deque>
#include <memory>
#include <functional>

namespace Autonomy {

/**
 * Oscillation types
 */
enum class OscillationType {
    UNKNOWN,
    DECISION_FLIP_FLOP,      // Rapidly changing decisions
    MUTATION_BURST,          // Sudden spike in mutations
    STATE_UNSTABLE,          // State oscillating between values
    RESOURCE_THRASHING,      // Resource usage oscillating
    ROLE_CHURN,              // Frequent role reassignments
    PATTERN_CYCLIC           // Repeating pattern cycles
};

std::string OscillationTypeToString(OscillationType type);

/**
 * Oscillation severity
 */
enum class OscillationSeverity {
    NONE,
    MILD,        // Detected but within tolerance
    MODERATE,    // Requires monitoring
    SEVERE,      // Requires dampening action
    CRITICAL     // Emergency intervention required
};

std::string OscillationSeverityToString(OscillationSeverity severity);

/**
 * Oscillation detection result
 */
struct OscillationDetection {
    std::string detectionId;
    OscillationType type{OscillationType::UNKNOWN};
    OscillationSeverity severity{OscillationSeverity::NONE};
    std::string source;              // What is oscillating
    double frequencyHz{0.0};           // Oscillation frequency
    double amplitude{0.0};           // Oscillation amplitude
    double dampingRatio{0.0};        // Current damping effectiveness
    int64_t detectedAtMs{0};
    int durationMs{0};               // Duration of oscillation
    std::map<std::string, double> metrics;
    
    std::string ToJson() const;
    void Print() const;
};

/**
 * Dampening action
 */
struct DampeningAction {
    std::string actionId;
    std::string detectionId;       // Associated detection
    std::string type;                // Action type
    std::string description;
    double intensity{0.0};         // 0.0-1.0 action intensity
    int64_t appliedAtMs{0};
    int durationMs{0};               // How long to apply
    bool reversible{true};
    std::map<std::string, std::string> parameters;
    
    std::string ToJson() const;
};

/**
 * Historical sample for trend analysis
 */
struct StateSample {
    int64_t timestampMs{0};
    double value{0.0};
    std::string state;
    std::map<std::string, double> metrics;
};

/**
 * Oscillation detector configuration
 */
struct OscillationDetectorConfig {
    // Decision oscillation
    int decisionHistorySize{20};           // Samples to keep
    int decisionFlipThreshold{3};          // Flips to trigger detection
    int decisionTimeWindowMs{5000};        // Time window for flip detection
    
    // Mutation oscillation
    int mutationBurstThreshold{10};        // Mutations per window
    int mutationWindowMs{1000};            // Mutation window size
    
    // State oscillation
    int stateHistorySize{50};              // State samples to keep
    double stateVarianceThreshold{0.1};    // Variance threshold
    int stateWindowMs{10000};              // State analysis window
    
    // Resource oscillation
    int resourceHistorySize{30};           // Resource samples
    double resourceVarianceThreshold{0.2}; // Resource variance threshold
    
    // Role churn
    int roleChangeThreshold{5};            // Role changes per window
    int roleWindowMs{30000};               // Role analysis window
    
    // Pattern cyclic
    int patternHistorySize{100};           // Pattern samples
    double patternCorrelationThreshold{0.8}; // Cyclic pattern threshold
    
    std::string ToJson() const;
};

/**
 * Dampener configuration
 */
struct DampenerConfig {
    // Hysteresis
    int hysteresisSamples{3};              // Samples before action
    double hysteresisThreshold{0.05};      // Hysteresis band
    
    // Rate limiting
    int maxDecisionsPerSecond{10};
    int maxMutationsPerSecond{5};
    int maxStateChangesPerSecond{20};
    
    // Smoothing
    double smoothingAlpha{0.3};            // EMA alpha (0-1)
    int smoothingWindow{5};                // Smoothing window size
    
    // Deadband
    double deadbandThreshold{0.02};        // Ignore changes below this
    
    // Dampening intensity
    double mildDampening{0.25};
    double moderateDampening{0.5};
    double severeDampening{0.75};
    double criticalDampening{1.0};
    
    std::string ToJson() const;
};

/**
 * Oscillation Detector
 *
 * Detects various types of oscillations in the system.
 */
class OscillationDetector {
public:
    OscillationDetector();
    ~OscillationDetector();

    // Disable copy
    OscillationDetector(const OscillationDetector&) = delete;
    OscillationDetector& operator=(const OscillationDetector&) = delete;

    /**
     * Initialize detector
     */
    bool Initialize(const OscillationDetectorConfig& config);

    /**
     * Sample decision for oscillation detection
     */
    void SampleDecision(const Decision& decision);

    /**
     * Sample mutation for oscillation detection
     */
    void SampleMutation(const std::string& mutationType, 
                       const std::map<std::string, std::string>& details);

    /**
     * Sample state value for oscillation detection
     */
    void SampleState(const std::string& stateName, double value);

    /**
     * Sample resource usage
     */
    void SampleResource(const std::string& resourceName, double usage);

    /**
     * Sample role assignment
     */
    void SampleRoleChange(const std::string& workerId, 
                         const std::string& oldRole,
                         const std::string& newRole);

    /**
     * Sample pattern detection
     */
    void SamplePattern(const std::string& patternId, double strength);

    /**
     * Check for oscillations
     */
    std::vector<OscillationDetection> DetectOscillations();

    /**
     * Get recent detections
     */
    std::vector<OscillationDetection> GetRecentDetections(int limit = 10) const;

    /**
     * Clear history
     */
    void ClearHistory();

    /**
     * Print status
     */
    void PrintStatus() const;

private:
    OscillationDetectorConfig config_;
    bool initialized_{false};
    
    // History buffers
    std::deque<Decision> decisionHistory_;
    std::deque<std::pair<int64_t, std::string>> mutationHistory_;
    std::map<std::string, std::deque<StateSample>> stateHistories_;
    std::map<std::string, std::deque<StateSample>> resourceHistories_;
    std::deque<std::pair<int64_t, std::string>> roleChangeHistory_;
    std::deque<std::pair<int64_t, std::string>> patternHistory_;
    
    // Detections
    std::vector<OscillationDetection> detections_;
    mutable std::mutex detectionsMutex_;
    
    // Detection counter
    int detectionCounter_{0};
    
    // Detection methods
    OscillationDetection DetectDecisionFlipFlop();
    OscillationDetection DetectMutationBurst();
    OscillationDetection DetectStateOscillation();
    OscillationDetection DetectResourceThrashing();
    OscillationDetection DetectRoleChurn();
    OscillationDetection DetectPatternCyclic();
    
    // Helpers
    double CalculateVariance(const std::deque<StateSample>& samples) const;
    double CalculateFrequency(const std::deque<StateSample>& samples) const;
    bool DetectCycle(const std::deque<std::pair<int64_t, std::string>>& samples,
                     int minCycleLength, int maxCycleLength) const;
    int64_t GetCurrentTimeMs() const;
    std::string GenerateDetectionId();
};

/**
 * Oscillation Dampener
 *
 * Applies dampening actions to reduce oscillations.
 */
class OscillationDampener {
public:
    OscillationDampener();
    ~OscillationDampener();

    // Disable copy
    OscillationDampener(const OscillationDampener&) = delete;
    OscillationDampener& operator=(const OscillationDampener&) = delete;

    /**
     * Initialize dampener
     */
    bool Initialize(const DampenerConfig& config);

    /**
     * Apply dampening to detected oscillation
     */
    DampeningAction Dampen(const OscillationDetection& detection);

    /**
     * Apply hysteresis to value
     */
    double ApplyHysteresis(const std::string& signalName, 
                          double newValue,
                          double previousValue);

    /**
     * Apply rate limiting
     */
    bool ApplyRateLimit(const std::string& actionType);

    /**
     * Apply smoothing (EMA)
     */
    double ApplySmoothing(const std::string& signalName, double newValue);

    /**
     * Apply deadband filtering
     */
    double ApplyDeadband(double value, double center);

    /**
     * Get active dampening actions
     */
    std::vector<DampeningAction> GetActiveActions() const;

    /**
     * Cancel dampening action
     */
    bool CancelAction(const std::string& actionId);

    /**
     * Print status
     */
    void PrintStatus() const;

private:
    DampenerConfig config_;
    bool initialized_{false};
    
    // Rate limiting state
    std::map<std::string, std::deque<int64_t>> rateLimitWindows_;
    mutable std::mutex rateLimitMutex_;
    
    // Smoothing state (EMA)
    std::map<std::string, double> smoothedValues_;
    mutable std::mutex smoothingMutex_;
    
    // Hysteresis state
    std::map<std::string, double> hysteresisLastValues_;
    std::map<std::string, int> hysteresisCounters_;
    mutable std::mutex hysteresisMutex_;
    
    // Active actions
    std::vector<DampeningAction> activeActions_;
    mutable std::mutex actionsMutex_;
    
    // Action counter
    int actionCounter_{0};
    
    // Action generators
    DampeningAction GenerateDecisionDampening(const OscillationDetection& detection);
    DampeningAction GenerateMutationDampening(const OscillationDetection& detection);
    DampeningAction GenerateStateDampening(const OscillationDetection& detection);
    DampeningAction GenerateResourceDampening(const OscillationDetection& detection);
    DampeningAction GenerateRoleDampening(const OscillationDetection& detection);
    DampeningAction GeneratePatternDampening(const OscillationDetection& detection);
    
    // Helpers
    double GetDampeningIntensity(OscillationSeverity severity) const;
    int64_t GetCurrentTimeMs() const;
    std::string GenerateActionId();
};

/**
 * Integrated Oscillation Manager
 *
 * Combines detection and dampening for complete oscillation management.
 */
class OscillationManager {
public:
    OscillationManager();
    ~OscillationManager();

    // Disable copy
    OscillationManager(const OscillationManager&) = delete;
    OscillationManager& operator=(const OscillationManager&) = delete;

    /**
     * Initialize manager
     */
    bool Initialize(const OscillationDetectorConfig& detectorConfig,
                   const DampenerConfig& dampenerConfig);

    /**
     * Process system sample (decision, mutation, state, etc.)
     */
    void ProcessSample(const std::string& sampleType,
                      const std::map<std::string, std::string>& data);

    /**
     * Update and apply dampening
     */
    void Update();

    /**
     * Get current oscillations
     */
    std::vector<OscillationDetection> GetCurrentOscillations() const;

    /**
     * Get active dampening actions
     */
    std::vector<DampeningAction> GetActiveDampening() const;

    /**
     * Check if system is oscillating
     */
    bool IsOscillating() const;

    /**
     * Get overall stability score (0-1)
     */
    double GetStabilityScore() const;

    /**
     * Print status
     */
    void PrintStatus() const;

    // Component access
    OscillationDetector& GetDetector() { return detector_; }
    OscillationDampener& GetDampener() { return dampener_; }

private:
    OscillationDetector detector_;
    OscillationDampener dampener_;
    bool initialized_{false};
    
    int64_t lastUpdateMs_{0};
    int updateIntervalMs_{100};
};

/**
 * CLI for testing oscillation detection and dampening
 */
class OscillationManagerCLI {
public:
    static void PrintBanner();
    static void PrintUsage();
    static int Run(int argc, char* argv[]);
    
private:
    static void InteractiveMode(OscillationManager& manager);
    static void SimulateOscillation(OscillationManager& manager, 
                                     OscillationType type,
                                     int durationMs);
};

} // namespace Autonomy
