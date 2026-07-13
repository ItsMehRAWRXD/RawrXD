# Phase C.4 Batch 2/5: Oscillation Detection & Dampening

## Overview

The Oscillation Detection & Dampening system is a critical component of the Stability Envelope that detects and mitigates harmful oscillations in the sovereign runtime. Oscillations can occur in decisions, mutations, state values, resources, roles, and patterns - leading to instability and degraded performance.

## Architecture

### Components

1. **OscillationDetector**: Detects oscillations across 6 dimensions
2. **OscillationDampener**: Applies dampening strategies
3. **OscillationManager**: Integrates detection and dampening

### Oscillation Types

| Type | Description | Detection Method |
|------|-------------|------------------|
| DECISION_FLIP_FLOP | Rapidly changing decisions | Count decision type changes |
| MUTATION_BURST | Sudden spike in mutations | Rate threshold |
| STATE_UNSTABLE | State values oscillating | Variance analysis |
| RESOURCE_THRASHING | Resource usage oscillating | Variance + frequency |
| ROLE_CHURN | Frequent role reassignments | Change rate |
| PATTERN_CYCLIC | Repeating pattern cycles | Cycle detection |

## Dampening Strategies

### 1. Hysteresis
- Requires sustained deviation before action
- Prevents reaction to noise
- Configurable samples and threshold

### 2. Rate Limiting
- Limits action frequency
- Prevents overwhelming the system
- Per-action-type limits

### 3. Smoothing (EMA)
- Exponential moving average
- Reduces noise in signals
- Configurable alpha parameter

### 4. Deadband
- Ignores small fluctuations
- Reduces unnecessary adjustments
- Configurable threshold

## Configuration

### OscillationDetectorConfig
```cpp
struct OscillationDetectorConfig {
    // Decision oscillation
    int decisionHistorySize = 20;
    int decisionFlipThreshold = 3;
    int decisionTimeWindowMs = 5000;
    
    // Mutation oscillation
    int mutationBurstThreshold = 10;
    int mutationWindowMs = 1000;
    
    // State oscillation
    int stateHistorySize = 50;
    double stateVarianceThreshold = 0.1;
    int stateWindowMs = 10000;
    
    // Resource oscillation
    int resourceHistorySize = 30;
    double resourceVarianceThreshold = 0.2;
    
    // Role churn
    int roleChangeThreshold = 5;
    int roleWindowMs = 30000;
    
    // Pattern cyclic
    int patternHistorySize = 100;
    double patternCorrelationThreshold = 0.8;
};
```

### DampenerConfig
```cpp
struct DampenerConfig {
    // Hysteresis
    int hysteresisSamples = 3;
    double hysteresisThreshold = 0.05;
    
    // Rate limiting
    int maxDecisionsPerSecond = 10;
    int maxMutationsPerSecond = 5;
    int maxStateChangesPerSecond = 20;
    
    // Smoothing
    double smoothingAlpha = 0.3;
    int smoothingWindow = 5;
    
    // Deadband
    double deadbandThreshold = 0.02;
    
    // Dampening intensity by severity
    double mildDampening = 0.25;
    double moderateDampening = 0.5;
    double severeDampening = 0.75;
    double criticalDampening = 1.0;
};
```

## Usage

### Basic Usage
```cpp
#include "autonomy/OscillationDampener.hpp"

using namespace Autonomy;

// Initialize
OscillationManager manager;
OscillationDetectorConfig detectorConfig;
DampenerConfig dampenerConfig;
manager.Initialize(detectorConfig, dampenerConfig);

// Sample data
manager.ProcessSample("decision", {{"type", "optimize"}});
manager.ProcessSample("state", {{"name", "convergence"}, {"value", "0.85"}});
manager.ProcessSample("resource", {{"name", "cpu"}, {"usage", "0.75"}});

// Update (detects and dampens)
manager.Update();

// Check status
if (manager.IsOscillating()) {
    double stability = manager.GetStabilityScore();
    std::cout << "Stability: " << stability << "\n";
}
```

### Direct Detector Usage
```cpp
OscillationDetector detector;
detector.Initialize(detectorConfig);

// Sample decisions
detector.SampleDecision(decision);

// Sample state
detector.SampleState("convergence", 0.85);

// Detect
auto oscillations = detector.DetectOscillations();
for (const auto& osc : oscillations) {
    std::cout << "Detected: " << OscillationTypeToString(osc.type) 
              << " with severity " << OscillationSeverityToString(osc.severity) << "\n";
}
```

### Direct Dampener Usage
```cpp
OscillationDampener dampener;
dampener.Initialize(dampenerConfig);

// Apply dampening
DampeningAction action = dampener.Dampen(detection);

// Apply signal processing
double smoothed = dampener.ApplySmoothing("signal_name", newValue);
double hysteresis = dampener.ApplyHysteresis("signal_name", newValue, previousValue);
bool allowed = dampener.ApplyRateLimit("decision");
```

## Detection Algorithms

### Decision Flip-Flop Detection
1. Track decision history
2. Count type changes
3. Trigger if changes exceed threshold in time window
4. Severity based on flip frequency

### State Oscillation Detection
1. Collect state samples
2. Calculate variance
3. Calculate frequency (zero crossings)
4. Trigger if variance exceeds threshold

### Mutation Burst Detection
1. Track mutation timestamps
2. Count mutations in sliding window
3. Trigger if count exceeds threshold
4. Severity based on burst intensity

### Cycle Detection
1. Store pattern sequence
2. Look for repeating subsequences
3. Use correlation analysis
4. Trigger if correlation exceeds threshold

## Dampening Actions

| Oscillation Type | Dampening Action | Duration |
|------------------|------------------|----------|
| DECISION_FLIP_FLOP | Rate limit decisions | 5s |
| MUTATION_BURST | Cooldown between mutations | 10s |
| STATE_UNSTABLE | Increase smoothing | 15s |
| RESOURCE_THRASHING | Throttle operations | 20s |
| ROLE_CHURN | Stabilize assignments | 30s |
| PATTERN_CYCLIC | Dampen pattern detection | 10s |

## Integration with Stability Envelope

The Oscillation Manager integrates with the Stability Envelope:

```cpp
StabilityEnvelope envelope;
envelope.Initialize(config);

// Oscillation manager is part of envelope
auto& oscManager = envelope.GetOscillationManager();

// Samples flow through envelope
envelope.SampleDecision(decision);
envelope.SampleState("metric", value);

// Envelope update includes oscillation detection
envelope.Update();
```

## Performance Considerations

- History buffers are bounded (configurable size)
- Detection runs at configurable intervals
- Dampening actions are reversible
- Minimal overhead when no oscillations detected

## Testing

Run the CLI for interactive testing:
```bash
./oscillation-manager --interactive
```

Commands:
- `status` - Show current status
- `detect` - Show recent detections
- `dampen` - Show active dampening
- `simulate <type>` - Simulate oscillation
- `clear` - Clear history
- `quit` - Exit

## Future Enhancements

1. Machine learning for pattern prediction
2. Adaptive thresholds based on history
3. Cross-correlation between oscillation types
4. Predictive dampening before oscillation occurs
5. Integration with autonomous rollback

## References

- Phase C.4 Batch 1/5: Stability Envelope Specification
- Phase C.4 Batch 3/5: Autonomous Rollback Engine (upcoming)
- Phase C.4 Batch 4/5: Safety-Gated Decision Engine (upcoming)
- Phase C.4 Batch 5/5: Autonomous Stability Validator (upcoming)
