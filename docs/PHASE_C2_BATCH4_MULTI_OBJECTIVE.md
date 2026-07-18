# Phase C.2 Batch 4/5 — Multi-Objective Scheduling Optimization

## Overview

Batch 4 implements multi-objective optimization for the AdaptiveScheduler, enabling simultaneous optimization of multiple conflicting objectives such as latency, throughput, resource usage, and reliability using NSGA-II and weighted sum approaches.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Multi-Objective Scheduling Layer                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐          │
│  │   NSGA-II       │    │ Weighted Sum    │    │ Constraint      │          │
│  │   Optimizer     │    │ Optimizer       │    │ Handler         │          │
│  │                 │    │                 │    │                 │          │
│  │ • Non-dominated │    │ • Linear        │    │ • Hard/soft     │          │
│  │   sorting       │    │   combination   │    │   constraints   │          │
│  │ • Crowding      │    │ • Adaptive      │    │ • Penalty       │          │
│  │   distance      │    │   weights       │    │   calculation   │          │
│  │ • Tournament    │    │ • Preference    │    │ • Feasibility   │          │
│  │   selection     │    │   handling      │    │   check         │          │
│  └────────┬────────┘    └────────┬────────┘    └────────┬────────┘          │
│           │                      │                      │                   │
│           └──────────────────────┼──────────────────────┘                   │
│                                  │                                          │
│                                  ▼                                          │
│                    ┌─────────────────────────┐                              │
│                    │ MultiObjectiveScheduler │                              │
│                    │                         │                              │
│                    │ • Orchestrates all      │                              │
│                    │ • Pareto front mgmt     │                              │
│                    │ • Selection strategies  │                              │
│                    │ • Statistics export     │                              │
│                    └─────────────────────────┘                              │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Components

### 1. Objective Definition

```cpp
enum class ObjectiveType {
    MINIMIZE_LATENCY,
    MAXIMIZE_THROUGHPUT,
    MINIMIZE_RESOURCE_USAGE,
    MAXIMIZE_RELIABILITY,
    MAXIMIZE_FAIRNESS,
    MINIMIZE_COST,
    MAXIMIZE_QUALITY,
    CUSTOM
};

struct Objective {
    ObjectiveType type;
    std::string name;
    double weight;
    double target_value;
    double tolerance;
    bool is_constraint;
    double constraint_threshold;
    double min_value, max_value;
    
    double Normalize(double value) const;
    double CalculateScore(double value) const;
    bool SatisfiesConstraint(double value) const;
};
```

### 2. Pareto Front Management

```cpp
struct ParetoPoint {
    std::map<std::string, double> objective_values;
    std::vector<uint64_t> task_ids;
    double dominance_count;
    double crowding_distance;
    int rank;
    
    bool Dominates(const ParetoPoint& other) const;
    double Distance(const ParetoPoint& other) const;
};

class ParetoFront {
public:
    void AddPoint(const ParetoPoint& point);
    std::vector<ParetoPoint> GetNonDominated() const;
    void CalculateCrowdingDistance(const std::vector<std::string>& objectives);
    ParetoPoint GetBest(const std::vector<double>& weights) const;
};
```

### 3. NSGA-II Optimizer

NSGA-II (Non-dominated Sorting Genetic Algorithm II) implementation:

```cpp
class NSGA2Optimizer {
public:
    void Initialize(const std::vector<ScheduledTask>& tasks);
    void Evolve(uint32_t generations);
    
    std::vector<TaskEncoding> GetParetoFront() const;
    TaskEncoding GetBestSolution() const;
    
    double GetHypervolume() const;
    bool HasConverged() const;
    
private:
    void NonDominatedSort();
    void CalculateCrowdingDistance(std::vector<TaskEncoding>& front);
    void TournamentSelection();
    void Crossover();
    void Mutate();
    void EnvironmentalSelection();
    
    bool Dominates(const TaskEncoding& a, const TaskEncoding& b) const;
};
```

**Algorithm Parameters:**
- Population size: 100
- Max generations: 50
- Crossover probability: 0.9
- Mutation probability: 0.1
- Tournament size: 2
- Elite count: 10

### 4. Weighted Sum Optimizer

Linear combination approach for fast optimization:

```cpp
class WeightedSumOptimizer {
public:
    void SetWeights(const std::vector<double>& weights);
    double Evaluate(const std::map<std::string, double>& objective_values) const;
    ScheduledTask Optimize(const std::vector<ScheduledTask>& candidates);
    std::vector<ScheduledTask> Rank(const std::vector<ScheduledTask>& candidates);
    void UpdateWeights(const std::map<std::string, double>& performance);
};
```

### 5. Constraint Handler

```cpp
class ConstraintHandler {
public:
    void AddConstraint(ObjectiveType type, double threshold, bool hard = false);
    double CalculatePenalty(const std::map<std::string, double>& values) const;
    bool IsFeasible(const std::map<std::string, double>& values) const;
    std::vector<std::string> GetViolatedConstraints(
        const std::map<std::string, double>& values) const;
};
```

### 6. Adaptive Weight Controller

```cpp
class AdaptiveWeightController {
public:
    void RecordOutcome(const std::map<std::string, double>& objectives,
                      const std::map<std::string, double>& outcomes);
    void UpdateWeights();
    std::vector<double> GetWeights() const;
    void SetPreference(ObjectiveType type, double preference);
};
```

## Multi-Objective Scheduler

### Main Interface

```cpp
class MultiObjectiveScheduler {
public:
    // Configuration
    void AddObjective(const Objective& objective);
    void SetObjectives(const std::vector<Objective>& objectives);
    
    // Optimization
    void Optimize(const std::vector<ScheduledTask>& tasks);
    std::vector<ScheduledTask> GetParetoOptimalSchedule() const;
    
    // Selection strategies
    ScheduledTask SelectByWeightedSum(const std::vector<ScheduledTask>& candidates);
    ScheduledTask SelectByNSGA2(const std::vector<ScheduledTask>& candidates);
    ScheduledTask SelectByConstraintSatisfaction(const std::vector<ScheduledTask>& candidates);
    
    // Pareto front
    ParetoFront GetParetoFront() const;
    
    // Adaptive control
    void EnableAdaptiveWeights(bool enable);
    void SetPreference(ObjectiveType type, double preference);
    
    // Statistics
    struct OptimizationStats {
        uint32_t generations_run;
        double final_hypervolume;
        double convergence_rate;
        uint32_t pareto_front_size;
        double average_constraint_violation;
    };
    
    OptimizationStats GetStats() const;
};
```

### Usage Example

```cpp
// Configure objectives
MultiObjectiveConfig config;

Objective latency_obj;
latency_obj.type = ObjectiveType::MINIMIZE_LATENCY;
latency_obj.name = "latency";
latency_obj.weight = 0.4;
latency_obj.target_value = 100.0; // ms

Objective throughput_obj;
throughput_obj.type = ObjectiveType::MAXIMIZE_THROUGHPUT;
throughput_obj.name = "throughput";
throughput_obj.weight = 0.3;
throughput_obj.target_value = 1000.0; // TPS

Objective resource_obj;
resource_obj.type = ObjectiveType::MINIMIZE_RESOURCE_USAGE;
resource_obj.name = "resources";
resource_obj.weight = 0.2;
resource_obj.is_constraint = true;
resource_obj.constraint_threshold = 16.0; // max workers

Objective reliability_obj;
reliability_obj.type = ObjectiveType::MAXIMIZE_RELIABILITY;
reliability_obj.name = "reliability";
reliability_obj.weight = 0.1;
reliability_obj.target_value = 0.99;

// Create scheduler
MultiObjectiveScheduler scheduler(config);
scheduler.AddObjective(latency_obj);
scheduler.AddObjective(throughput_obj);
scheduler.AddObjective(resource_obj);
scheduler.AddObjective(reliability_obj);

// Optimize
scheduler.Optimize(tasks);

// Get Pareto-optimal solutions
auto front = scheduler.GetParetoFront();

// Select best based on weights
std::vector<double> weights = {0.4, 0.3, 0.2, 0.1};
auto best_task = scheduler.GetBestTask(weights);

// Get statistics
auto stats = scheduler.GetStats();
std::cout << "Pareto front size: " << stats.pareto_front_size << std::endl;
std::cout << "Hypervolume: " << stats.final_hypervolume << std::endl;
```

## NSGA-II Algorithm

### Non-Dominated Sorting

```cpp
void NSGA2Optimizer::NonDominatedSort() {
    // For each individual p
    for (auto& p : population_) {
        p.domination_count = 0;
        p.dominated_solutions.clear();
        
        // Compare with every other individual q
        for (auto& q : population_) {
            if (p != q) {
                if (p.Dominates(q)) {
                    p.dominated_solutions.push_back(q);
                } else if (q.Dominates(p)) {
                    p.domination_count++;
                }
            }
        }
        
        // If no one dominates p, it's in the first front
        if (p.domination_count == 0) {
            p.rank = 1;
            fronts[0].push_back(p);
        }
    }
    
    // Build subsequent fronts
    int i = 0;
    while (!fronts[i].empty()) {
        std::vector<Individual> next_front;
        
        for (auto& p : fronts[i]) {
            for (auto& q : p.dominated_solutions) {
                q.domination_count--;
                if (q.domination_count == 0) {
                    q.rank = i + 2;
                    next_front.push_back(q);
                }
            }
        }
        
        fronts[++i] = next_front;
    }
}
```

### Crowding Distance

```cpp
void NSGA2Optimizer::CalculateCrowdingDistance(std::vector<TaskEncoding>& front) {
    if (front.size() < 3) {
        for (auto& point : front) {
            point.crowding_distance = INFINITY;
        }
        return;
    }
    
    // For each objective
    for (const auto& obj : objectives) {
        // Sort by objective
        sort(front by obj.value);
        
        // Boundary points have infinite distance
        front[0].crowding_distance = INFINITY;
        front.back().crowding_distance = INFINITY;
        
        // Calculate for intermediate points
        for (size_t i = 1; i < front.size() - 1; ++i) {
            double distance = (front[i+1].value - front[i-1].value) / 
                             (front.back().value - front[0].value);
            front[i].crowding_distance += distance;
        }
    }
}
```

## Performance Metrics

### Quality Indicators

| Metric | Description | Target |
|--------|-------------|--------|
| Hypervolume | Volume dominated by Pareto front | Maximize |
| Spacing | Evenness of front distribution | Minimize |
| Diversity | Average pairwise distance | Maximize |
| Convergence | Distance to true Pareto front | Minimize |

### Convergence Criteria

```cpp
bool NSGA2Optimizer::HasConverged() {
    // Check if fitness improvement has stalled
    if (fitness_history.size() < 2) return false;
    
    double current = fitness_history.back();
    double previous = fitness_history[fitness_history.size() - 2];
    
    if (abs(current - previous) < convergence_threshold) {
        stall_count++;
        return stall_count >= stall_generations;
    }
    
    stall_count = 0;
    return false;
}
```

## Utility Functions

### Distance Metrics

```cpp
namespace MultiObjectiveUtils {
    double EuclideanDistance(const std::map<std::string, double>& a,
                            const std::map<std::string, double>& b);
    double ManhattanDistance(const std::map<std::string, double>& a,
                             const std::map<std::string, double>& b);
    double ChebyshevDistance(const std::map<std::string, double>& a,
                             const std::map<std::string, double>& b);
}
```

### Utility Functions

```cpp
namespace MultiObjectiveUtils {
    // Linear weighted sum
    double LinearUtility(const std::map<std::string, double>& values,
                        const std::vector<double>& weights);
    
    // Chebyshev (minimax) utility
    double ChebyshevUtility(const std::map<std::string, double>& values,
                           const std::vector<double>& weights,
                           const std::map<std::string, double>& reference);
    
    // Hypervolume calculation
    double CalculateHypervolume(const std::vector<ParetoPoint>& front,
                                const std::vector<std::string>& objectives,
                                const std::map<std::string, double>& reference_point);
}
```

## Files

| File | Lines | Purpose |
|------|-------|---------|
| `MultiObjectiveScheduler.hpp` | ~550 | Interface definitions |
| `MultiObjectiveScheduler.cpp` | ~1,100 | Implementation |
| `PHASE_C2_BATCH4_MULTI_OBJECTIVE.md` | ~400 | Documentation |

**Total: ~2,050 lines**

## Integration

### With Phase C.2 Batch 1

```cpp
// Use AdaptiveScheduler as base
AdaptiveScheduler base_scheduler(config);

// Wrap with multi-objective layer
MultiObjectiveScheduler mo_scheduler(config);
mo_scheduler.SetObjectives(objectives);

// Optimize scheduling decisions
auto optimized_tasks = mo_scheduler.Optimize(pending_tasks);

// Submit to base scheduler
for (const auto& task : optimized_tasks) {
    base_scheduler.SubmitTask(task);
}
```

### With Phase C.2 Batch 2

```cpp
// Multi-objective routing in SEG
SEGSchedulerIntegrationManager integration(&seg, &scheduler, config);

// Optimize path selection
std::vector<std::vector<uint64_t>> path_candidates = ...;
auto best_path = mo_scheduler.SelectByNSGA2(path_candidates);
```

## Status

- ✅ NSGA-II optimizer complete
- ✅ Weighted sum optimizer complete
- ✅ Pareto front management
- ✅ Constraint handling
- ✅ Adaptive weight control
- ✅ Quality metrics (hypervolume, spacing, diversity)
- ✅ Multiple selection strategies
- ✅ Statistics export

## Next Steps

1. **Batch 5**: Distributed scheduling coordination

---

**Phase C.2 Batch 4/5 Complete** — Multi-objective scheduling optimization with NSGA-II and weighted sum approaches.
