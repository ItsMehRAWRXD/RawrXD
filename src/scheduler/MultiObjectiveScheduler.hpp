// MultiObjectiveScheduler.hpp
// Phase C.2 Batch 4/5 — Multi-Objective Scheduling Optimization

#ifndef MULTI_OBJECTIVE_SCHEDULER_HPP
#define MULTI_OBJECTIVE_SCHEDULER_HPP

#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <atomic>
#include <mutex>
#include <queue>
#include <random>
#include "AdaptiveScheduler.hpp"
#include "../emergent/EmergentPatterns.hpp"

namespace Scheduler {

// ============================================================================
// Objective Types
// ============================================================================

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

// ============================================================================
// Objective Definition
// ============================================================================

struct Objective {
    ObjectiveType type;
    std::string name;
    double weight;
    double target_value;
    double tolerance;
    bool is_constraint;
    double constraint_threshold;
    
    // Normalization
    double min_value;
    double max_value;
    
    Objective()
        : type(ObjectiveType::CUSTOM)
        , weight(1.0)
        , target_value(0.0)
        , tolerance(0.1)
        , is_constraint(false)
        , constraint_threshold(0.0)
        , min_value(0.0)
        , max_value(1.0)
    {}
    
    double Normalize(double value) const;
    double CalculateScore(double value) const;
    bool SatisfiesConstraint(double value) const;
};

// ============================================================================
// Pareto Front
// ============================================================================

struct ParetoPoint {
    std::map<std::string, double> objective_values;
    std::vector<uint64_t> task_ids;
    double dominance_count;
    double crowding_distance;
    int rank;
    
    ParetoPoint() : dominance_count(0), crowding_distance(0), rank(0) {}
    
    bool Dominates(const ParetoPoint& other) const;
    double Distance(const ParetoPoint& other) const;
};

class ParetoFront {
public:
    void AddPoint(const ParetoPoint& point);
    void RemovePoint(size_t index);
    void Clear();
    
    std::vector<ParetoPoint> GetNonDominated() const;
    std::vector<ParetoPoint> GetFront() const;
    
    void CalculateCrowdingDistance(const std::vector<std::string>& objectives);
    void SortByCrowdingDistance();
    
    size_t Size() const;
    bool Empty() const;
    
    ParetoPoint GetBest(const std::vector<double>& weights) const;
    
private:
    std::vector<ParetoPoint> points_;
    mutable std::mutex mutex_;
    
    bool IsDominated(const ParetoPoint& point, const ParetoPoint& by) const;
};

// ============================================================================
// Multi-Objective Configuration
// ============================================================================

struct MultiObjectiveConfig {
    // Objectives
    std::vector<Objective> objectives;
    
    // NSGA-II parameters
    uint32_t population_size = 100;
    uint32_t max_generations = 50;
    double crossover_probability = 0.9;
    double mutation_probability = 0.1;
    double mutation_rate = 0.1;
    
    // Selection
    uint32_t tournament_size = 2;
    bool use_elitism = true;
    uint32_t elite_count = 10;
    
    // Termination
    double convergence_threshold = 0.01;
    uint32_t stall_generations = 10;
    
    // Constraints
    bool enforce_constraints = true;
    double constraint_penalty = 1000.0;
    
    // Adaptive weights
    bool adaptive_weights = true;
    double weight_learning_rate = 0.1;
};

// ============================================================================
// Task Encoding for Evolutionary Algorithm
// ============================================================================

struct TaskEncoding {
    std::vector<double> genes; // Decision variables
    std::map<std::string, double> phenotype; // Actual values
    
    // Objective values
    std::map<std::string, double> objective_values;
    double fitness;
    double constraint_violation;
    
    // NSGA-II specific
    int rank;
    double crowding_distance;
    
    TaskEncoding() : fitness(0.0), constraint_violation(0.0), rank(0), crowding_distance(0.0) {}
    
    void Decode(const std::vector<Objective>& objectives);
    void Evaluate(const ScheduledTask& task, const std::vector<Objective>& objectives);
};

// ============================================================================
// NSGA-II Implementation
// ============================================================================

class NSGA2Optimizer {
public:
    NSGA2Optimizer(const MultiObjectiveConfig& config);
    
    void Initialize(const std::vector<ScheduledTask>& tasks);
    void Evolve();
    void Evolve(uint32_t generations);
    
    std::vector<TaskEncoding> GetParetoFront() const;
    TaskEncoding GetBestSolution() const;
    
    // Statistics
    double GetAverageFitness() const;
    double GetBestFitness() const;
    double GetHypervolume() const;
    
    // Convergence
    bool HasConverged() const;
    double GetConvergenceMetric() const;
    
private:
    MultiObjectiveConfig config_;
    
    std::vector<TaskEncoding> population_;
    std::vector<TaskEncoding> offspring_;
    std::vector<TaskEncoding> combined_;
    
    std::vector<std::vector<TaskEncoding>> fronts_;
    
    std::mt19937 rng_;
    
    // Statistics
    std::vector<double> fitness_history_;
    uint32_t stall_count_;
    
    void CreateInitialPopulation(const std::vector<ScheduledTask>& tasks);
    void NonDominatedSort();
    void CalculateCrowdingDistance(std::vector<TaskEncoding>& front);
    void TournamentSelection();
    void Crossover();
    void Mutate();
    void EnvironmentalSelection();
    
    bool Dominates(const TaskEncoding& a, const TaskEncoding& b) const;
    double CalculateCrowdingDistance(const TaskEncoding& point, 
                                      const std::vector<TaskEncoding>& front) const;
};

// ============================================================================
// Weighted Sum Optimizer
// ============================================================================

class WeightedSumOptimizer {
public:
    WeightedSumOptimizer(const std::vector<Objective>& objectives);
    
    void SetWeights(const std::vector<double>& weights);
    void NormalizeWeights();
    
    double Evaluate(const std::map<std::string, double>& objective_values) const;
    
    ScheduledTask Optimize(const std::vector<ScheduledTask>& candidates);
    std::vector<ScheduledTask> Rank(const std::vector<ScheduledTask>& candidates);
    
    void UpdateWeights(const std::map<std::string, double>& performance);
    
private:
    std::vector<Objective> objectives_;
    std::vector<double> weights_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Constraint Handler
// ============================================================================

class ConstraintHandler {
public:
    ConstraintHandler(double penalty_weight = 1000.0);
    
    void AddConstraint(ObjectiveType type, double threshold, bool hard = false);
    void RemoveConstraint(ObjectiveType type);
    
    double CalculatePenalty(const std::map<std::string, double>& values) const;
    bool IsFeasible(const std::map<std::string, double>& values) const;
    
    std::vector<std::string> GetViolatedConstraints(
        const std::map<std::string, double>& values) const;
    
private:
    struct Constraint {
        ObjectiveType type;
        double threshold;
        bool hard;
    };
    
    std::vector<Constraint> constraints_;
    double penalty_weight_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Adaptive Weight Controller
// ============================================================================

class AdaptiveWeightController {
public:
    AdaptiveWeightController(const std::vector<Objective>& objectives,
                             double learning_rate = 0.1);
    
    void RecordOutcome(const std::map<std::string, double>& objectives,
                      const std::map<std::string, double>& outcomes);
    
    void UpdateWeights();
    std::vector<double> GetWeights() const;
    
    void SetPreference(ObjectiveType type, double preference);
    void Reset();
    
private:
    std::vector<Objective> objectives_;
    double learning_rate_;
    std::vector<double> weights_;
    
    std::vector<std::map<std::string, double>> history_;
    mutable std::mutex mutex_;
    
    double CalculateSatisfaction(const std::map<std::string, double>& outcomes,
                                 const std::vector<double>& weights) const;
};

// ============================================================================
// Multi-Objective Scheduler
// ============================================================================

class MultiObjectiveScheduler {
public:
    MultiObjectiveScheduler(const MultiObjectiveConfig& config = MultiObjectiveConfig{});
    ~MultiObjectiveScheduler();
    
    // Configuration
    void AddObjective(const Objective& objective);
    void RemoveObjective(ObjectiveType type);
    void SetObjectives(const std::vector<Objective>& objectives);
    std::vector<Objective> GetObjectives() const;
    
    // Optimization
    void Optimize(const std::vector<ScheduledTask>& tasks);
    std::vector<ScheduledTask> GetParetoOptimalSchedule() const;
    ScheduledTask GetBestTask(const std::vector<double>& weights) const;
    
    // Selection strategies
    ScheduledTask SelectByWeightedSum(const std::vector<ScheduledTask>& candidates);
    ScheduledTask SelectByNSGA2(const std::vector<ScheduledTask>& candidates);
    ScheduledTask SelectByConstraintSatisfaction(const std::vector<ScheduledTask>& candidates);
    
    // Pareto front
    ParetoFront GetParetoFront() const;
    void UpdateParetoFront(const ScheduledTask& task);
    
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
    
    // Export
    void ExportParetoFront(const std::string& path) const;
    void ExportOptimizationHistory(const std::string& path) const;
    
private:
    MultiObjectiveConfig config_;
    std::vector<Objective> objectives_;
    
    std::unique_ptr<NSGA2Optimizer> nsga2_;
    std::unique_ptr<WeightedSumOptimizer> weighted_sum_;
    std::unique_ptr<ConstraintHandler> constraint_handler_;
    std::unique_ptr<AdaptiveWeightController> weight_controller_;
    
    ParetoFront pareto_front_;
    std::vector<ScheduledTask> optimized_schedule_;
    
    OptimizationStats stats_;
    mutable std::mutex mutex_;
    
    void InitializeOptimizers();
    double EvaluateTask(const ScheduledTask& task) const;
    std::map<std::string, double> CalculateObjectives(const ScheduledTask& task) const;
};

// ============================================================================
// Utility Functions
// ============================================================================

namespace MultiObjectiveUtils {
    // Distance metrics
    double EuclideanDistance(const std::map<std::string, double>& a,
                            const std::map<std::string, double>& b);
    double ManhattanDistance(const std::map<std::string, double>& a,
                             const std::map<std::string, double>& b);
    double ChebyshevDistance(const std::map<std::string, double>& a,
                             const std::map<std::string, double>& b);
    
    // Hypervolume calculation
    double CalculateHypervolume(const std::vector<ParetoPoint>& front,
                                const std::vector<std::string>& objectives,
                                const std::map<std::string, double>& reference_point);
    
    // Spacing metric
    double CalculateSpacing(const std::vector<ParetoPoint>& front);
    
    // Diversity metric
    double CalculateDiversity(const std::vector<ParetoPoint>& front);
    
    // Utility functions
    double LinearUtility(const std::map<std::string, double>& values,
                        const std::vector<double>& weights);
    double ChebyshevUtility(const std::map<std::string, double>& values,
                           const std::vector<double>& weights,
                           const std::map<std::string, double>& reference);
    
    // Normalization
    void NormalizeFront(std::vector<ParetoPoint>& front,
                       const std::vector<std::string>& objectives);
    void DenormalizeFront(std::vector<ParetoPoint>& front,
                         const std::vector<std::string>& objectives,
                         const std::map<std::string, std::pair<double, double>>& ranges);
} // namespace MultiObjectiveUtils

} // namespace Scheduler

#endif // MULTI_OBJECTIVE_SCHEDULER_HPP
