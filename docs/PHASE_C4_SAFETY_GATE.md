# Phase C.4 Batch 4/5: Safety-Gated Decision Engine

## Overview

The Safety-Gated Decision Engine is the preventative governance layer of the sovereign runtime. It validates all decisions, intents, and mutations before execution, preventing unsafe actions rather than recovering from them.

## Architecture

### Core Components

```
┌─────────────────────────────────────────────────────────────┐
│                      SafetyGate                            │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────┐  │
│  │   Profile   │  │     Risk     │  │   Constraint    │  │
│  │   Registry  │  │    Scorer    │  │    Checker      │  │
│  └─────────────┘  └──────────────┘  └─────────────────┘  │
└─────────────────────────────────────────────────────────────┘
         │                    │                    │
         ▼                    ▼                    ▼
┌─────────────┐      ┌──────────────┐      ┌─────────────────┐
│   Safety    │      │   Decision   │      │   Historical    │
│   Profiles  │      │    History   │      │    Violations   │
└─────────────┘      └──────────────┘      └─────────────────┘
```

### Component Responsibilities

1. **SafetyProfileRegistry**: Manages safety profiles for subsystems
2. **DecisionRiskScorer**: Calculates risk scores using weighted factors
3. **SafetyConstraintChecker**: Validates constraints and cooldowns
4. **SafetyGate**: Main entry point for safety validation

## Risk Scoring Formula

```
risk = w_state * instabilityScore +
       w_resource * resourcePressure +
       w_history * failureHistory +
       w_mutation * mutationRisk +
       w_intent * intentRisk +
       w_oscillation * oscillationSeverity
```

### Default Weights

| Factor | Weight | Description |
|--------|--------|-------------|
| State Instability | 0.25 | System stability score |
| Resource Pressure | 0.20 | Resource utilization |
| Failure History | 0.15 | Historical success rate |
| Mutation Risk | 0.15 | Mutation type risk |
| Intent Risk | 0.15 | Intent type risk |
| Oscillation Severity | 0.10 | Current oscillation level |

## Risk Classification

| Level | Score Range | Action |
|-------|-------------|--------|
| SAFE | 0.0 - 0.2 | Proceed with confidence |
| CAUTION | 0.2 - 0.5 | Proceed with monitoring |
| UNSAFE | 0.5 - 0.8 | Requires additional validation |
| CRITICAL | 0.8 - 1.0 | Blocked |

## Safety Profiles

Each subsystem has a safety profile defining:

### Resource Budget
- Max CPU percent
- Max memory percent
- Max GPU percent
- Max concurrent tasks
- Max queue depth

### Cooldowns
- Min decision interval
- Min mutation interval
- Min role change interval
- Min intent update interval

### Risk Thresholds
- Safe threshold (0.2)
- Caution threshold (0.5)
- Unsafe threshold (0.8)

### Action Classifications
- **ALLOWED**: Action permitted
- **RESTRICTED**: Requires additional validation
- **FORBIDDEN**: Action prohibited
- **CONDITIONAL**: Allowed under specific conditions

## Usage

### Basic Safety Check
```cpp
#include "autonomy/DecisionRiskScorer.hpp"

using namespace Autonomy;

// Initialize components
SafetyProfileRegistry profiles;
profiles.Initialize();

RiskWeights weights;
DecisionRiskScorer scorer;
scorer.Initialize(weights, &envelope, &oscillationManager, &history);

SafetyConstraintChecker checker;
checker.Initialize(&profiles);

SafetyGate gate;
gate.Initialize(&profiles, &scorer, &checker);

// Evaluate decision
Decision decision;
decision.decisionId = "dec_001";
decision.type = DecisionType::OPTIMIZE;
decision.confidence = 0.85;

auto assessment = gate.Evaluate(decision);
if (assessment.CanProceed()) {
    std::cout << "Decision approved\n";
    std::cout << "Risk level: " << RiskLevelToString(assessment.riskLevel) << "\n";
} else {
    std::cout << "Decision rejected: " << assessment.reason << "\n";
}
```

### Intent Validation
```cpp
Intent intent;
intent.intentId = "intent_001";
intent.type = IntentType::MODIFY;
intent.confidence = 0.75;

auto assessment = gate.Evaluate(intent);
if (assessment.approved) {
    // Convert intent to decision
}
```

### Mutation Gating
```cpp
std::map<std::string, std::string> params;
params["target"] = "graph_node_42";

auto assessment = gate.EvaluateMutation("MERGE_NODES", params);
if (assessment.approved) {
    // Execute mutation
}
```

### Custom Risk Weights
```cpp
RiskWeights customWeights;
customWeights.stateInstability = 0.3;    // Higher weight on stability
customWeights.resourcePressure = 0.25;   // Higher weight on resources
customWeights.failureHistory = 0.1;      // Lower weight on history

scorer.UpdateWeights(customWeights);
```

## Integration Points

### With Stability Envelope
```cpp
// Risk scoring uses stability envelope status
auto status = envelope.GetStatus();
double instability = 1.0 - status.overallStability;
```

### With Oscillation Manager
```cpp
// Oscillation severity affects risk score
double oscillationRisk = 1.0 - oscillationManager.GetStabilityScore();
```

### With Decision History
```cpp
// Historical success rate affects risk
double successRate = history.GetSuccessRate(decisionType);
double failureRisk = 1.0 - successRate;
```

### With Rollback Engine
```cpp
// High rollback probability increases risk
assessment.rollbackProbability = risk * (1.0 - confidence);
```

## Safety Constraints

### Resource Constraints
- CPU usage < 80%
- Memory usage < 80%
- GPU usage < 90%
- Concurrent tasks < 100

### Cooldown Constraints
- Decisions: min 100ms between
- Mutations: min 500ms between
- Role changes: min 1000ms between
- Intent updates: min 200ms between

### Stability Constraints
- Mutations require stability > 0.6
- Mutations require convergence > 0.7
- Critical mutations require stability > 0.8

## Decision Assessment Output

```json
{
  "decisionId": "dec_001",
  "decisionType": "OPTIMIZE",
  "confidence": 0.85,
  "expectedReward": 0.75,
  "estimatedRisk": 0.25,
  "stabilityImpact": 0.1,
  "rollbackProbability": 0.04,
  "riskLevel": "CAUTION",
  "approved": true,
  "riskFactors": {
    "stateInstability": 0.2,
    "resourcePressure": 0.3,
    "failureHistory": 0.1,
    "mutationRisk": 0.0,
    "intentRisk": 0.0,
    "oscillationSeverity": 0.1
  }
}
```

## Testing

### Smoke Tests
1. Safe decision passes
2. Unsafe decision blocked
3. Borderline decision downgraded
4. Unsafe intent blocked
5. Unsafe mutation blocked
6. Risk scoring correctness
7. Oscillation-triggered blocking
8. Resource-pressure blocking
9. Safety profile enforcement
10. Cooldown enforcement
11. Historical pattern detection
12. Telemetry correctness

### Run Tests
```bash
./safety-gate --interactive
```

Commands:
- `status` - Show current status
- `test <type>` - Test decision type
- `profiles` - List safety profiles
- `enable/disable` - Toggle gate
- `quit` - Exit

## Performance Considerations

- Risk scoring is O(1) per decision
- Historical lookups use cached statistics
- Constraint checking uses hash maps
- Assessment history is bounded (1000 entries)

## Future Enhancements

1. Machine learning for risk prediction
2. Adaptive risk weights based on context
3. Multi-factor authentication for critical decisions
4. Real-time safety profile updates
5. Cross-subsystem constraint validation

## References

- Phase C.4 Batch 1/5: Stability Envelope Specification
- Phase C.4 Batch 2/5: Oscillation Detection & Dampening
- Phase C.4 Batch 3/5: Autonomous Rollback Engine
- Phase C.4 Batch 5/5: Autonomous Stability Validator (upcoming)
