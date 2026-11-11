// MultiObjectiveScheduler.cpp
// Phase C.2 Batch 4/5 — Multi-Objective Scheduling Implementation

#include "MultiObjectiveScheduler.hpp"
#include <algorithm>
#include <cmath>
#include <limits>
#include <fstream>
#include <sstream>
#include <iomanip>

namespace Scheduler {

// ============================================================================
// Objective Implementation
// ============================================================================

double Objective::Normalize(double value) const {
    if (max_value - min_value < 1e-10) return 0.5;
    return (value - min_value) / (max_value - min_value);
}

double Objective::CalculateScore(double value) const {
    double normalized = Normalize(value);
    
    // For minimization objectives, invert
    if (type == ObjectiveType::MINIMIZE_LATENCY ||
        type == ObjectiveType::MINIMIZE_RESOURCE_USAGE ||
        type == ObjectiveType::MINIMIZE_COST) {
        normalized = 1.0 - normalized;
    }
    
    return normalized * weight;
}

bool Objective::SatisfiesConstraint(double value) const {
    if (!is_constraint) return true;
    
    if (type == ObjectiveType::MINIMIZE_LATENCY ||
        type == ObjectiveType::MINIMIZE_RESOURCE_USAGE ||
        type == ObjectiveType::MINIMIZE_COST) {
        return value <= constraint_threshold;
    } else {
        return value >= constraint_threshold;
    }
}

// ============================================================================
// ParetoPoint Implementation
// ============================================================================

bool ParetoPoint::Dominates(const ParetoPoint& other) const {
    bool strictly_better = false;
    
    for (const auto& [obj, value] : objective_values) {
        auto it = other.objective_values.find(obj);
        if (it == other.objective_values.end()) continue;
        
        if (value > it->second + 1e-10) {
            strictly_better = true;
        } else if (value < it->second - 1e-10) {
            return false;
        }
    }
    
    return strictly_better;
}

double ParetoPoint::Distance(const ParetoPoint& other) const {
    double sum = 0.0;
    
    for (const auto& [obj, value] : objective_values) {
        auto it = other.objective_values.find(obj);
        if (it != other.objective_values.end()) {
            sum += std::pow(value - it->second, 2);
        }
    }
    
    return std::sqrt(sum);
}

// ============================================================================
// ParetoFront Implementation
// ============================================================================

void ParetoFront::AddPoint(const ParetoPoint& point) {
    std::lock_guard<std::mutex> lock(mutex_);
    points_.push_back(point);
}

void ParetoFront::RemovePoint(size_t index) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (index < points_.size()) {
        points_.erase(points_.begin() + index);
    }
}

void ParetoFront::Clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    points_.clear();
}

std::vector<ParetoPoint> ParetoFront::GetNonDominated() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<ParetoPoint> non_dominated;
    
    for (const auto& point : points_) {
        bool dominated = false;
        
        for (const auto& other : points_) {
            if (&point != &other && other.Dominates(point)) {
                dominated = true;
                break;
            }
        }
        
        if (!dominated) {
            non_dominated.push_back(point);
        }
    }
    
    return non_dominated;
}

std::vector<ParetoPoint> ParetoFront::GetFront() const {
    return GetNonDominated();
}

void ParetoFront::CalculateCrowdingDistance(const std::vector<std::string>& objectives) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (points_.size() < 3) {
        for (auto& point : points_) {
            point.crowding_distance = std::numeric_limits<double>::infinity();
        }
        return;
    }
    
    // Reset distances
    for (auto& point : points_) {
        point.crowding_distance = 0.0;
    }
    
    // Calculate for each objective
    for (const auto& obj : objectives) {
        // Sort by this objective
        std::sort(points_.begin(), points_.end(),
            [&obj](const ParetoPoint& a, const ParetoPoint& b) {
                auto it_a = a.objective_values.find(obj);
                auto it_b = b.objective_values.find(obj);
                if (it_a == a.objective_values.end()) return false;
                if (it_b == b.objective_values.end()) return true;
                return it_a->second < it_b->second;
            });
        
        // Boundary points have infinite distance
        points_.front().crowding_distance = std::numeric_limits<double>::infinity();
        points_.back().crowding_distance = std::numeric_limits<double>::infinity();
        
        // Calculate for intermediate points
        double obj_min = points_.front().objective_values[obj];
        double obj_max = points_.back().objective_values[obj];
        double obj_range = obj_max - obj_min;
        
        if (obj_range > 1e-10) {
            for (size_t i = 1; i < points_.size() - 1; ++i) {
                double distance = (points_[i + 1].objective_values[obj] -
                                  points_[i - 1].objective_values[obj]) / obj_range;
                points_[i].crowding_distance += distance;
            }
        }
    }
}

void ParetoFront::SortByCrowdingDistance() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::sort(points_.begin(), points_.end(),
        [](const ParetoPoint& a, const ParetoPoint& b) {
            return a.crowding_distance > b.crowding_distance;
        });
}

size_t ParetoFront::Size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return points_.size();
}

bool ParetoFront::Empty() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return points_.empty();
}

ParetoPoint ParetoFront::GetBest(const std::vector<double>& weights) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (points_.empty()) {
        return ParetoPoint{};
    }
    
    // Get objective names
    std::vector<std::string> objectives;
    if (!points_.empty()) {
        for (const auto& [obj, _] : points_[0].objective_values) {
            objectives.push_back(obj);
        }
    }
    
    // Find point with best weighted sum
    size_t best_idx = 0;
    double best_score = -std::numeric_limits<double>::infinity();
    
    for (size_t i = 0; i < points_.size(); ++i) {
        double score = 0.0;
        size_t w = 0;
        
        for (const auto& [obj, value] : points_[i].objective_values) {
            if (w < weights.size()) {
                score += value * weights[w];
                ++w;
            }
        }
        
        if (score > best_score) {
            best_score = score;
            best_idx = i;
        }
    }
    
    return points_[best_idx];
}

bool ParetoFront::IsDominated(const ParetoPoint& point, const ParetoPoint& by) const {
    return by.Dominates(point);
}

// ============================================================================
// NSGA2Optimizer Implementation
// ============================================================================

NSGA2Optimizer::NSGA2Optimizer(const MultiObjectiveConfig& config)
    : config_(config)
    , rng_(std::random_device{}())
    , stall_count_(0) {}

void NSGA2Optimizer::Initialize(const std::vector<ScheduledTask>& tasks) {
    CreateInitialPopulation(tasks);
}

void NSGA2Optimizer::Evolve() {
    NonDominatedSort();
    TournamentSelection();
    Crossover();
    Mutate();
    EnvironmentalSelection();
}

void NSGA2Optimizer::Evolve(uint32_t generations) {
    for (uint32_t gen = 0; gen < generations; ++gen) {
        Evolve();
        
        // Check convergence
        if (HasConverged()) {
            break;
        }
    }
}

std::vector<TaskEncoding> NSGA2Optimizer::GetParetoFront() const {
    std::vector<TaskEncoding> front;
    
    for (const auto& individual : population_) {
        if (individual.rank == 1) {
            front.push_back(individual);
        }
    }
    
    return front;
}

TaskEncoding NSGA2Optimizer::GetBestSolution() const {
    if (population_.empty()) {
        return TaskEncoding{};
    }
    
    // Return first non-dominated solution with best fitness
    for (const auto& individual : population_) {
        if (individual.rank == 1) {
            return individual;
        }
    }
    
    return population_[0];
}

double NSGA2Optimizer::GetAverageFitness() const {
    if (population_.empty()) return 0.0;
    
    double sum = 0.0;
    for (const auto& individual : population_) {
        sum += individual.fitness;
    }
    
    return sum / population_.size();
}

double NSGA2Optimizer::GetBestFitness() const {
    if (population_.empty()) return 0.0;
    
    double best = -std::numeric_limits<double>::infinity();
    for (const auto& individual : population_) {
        if (individual.fitness > best) {
            best = individual.fitness;
        }
    }
    
    return best;
}

double NSGA2Optimizer::GetHypervolume() const {
    // Simplified hypervolume calculation
    auto front = GetParetoFront();
    if (front.empty()) return 0.0;
    
    // Use reference point at origin
    double hypervolume = 0.0;
    for (const auto& point : front) {
        double product = 1.0;
        for (const auto& [obj, value] : point.objective_values) {
            product *= std::max(0.0, value);
        }
        hypervolume += product;
    }
    
    return hypervolume / front.size();
}

bool NSGA2Optimizer::HasConverged() const {
    if (fitness_history_.size() < 2) return false;
    
    double current = fitness_history_.back();
    double previous = fitness_history_[fitness_history_.size() - 2];
    
    if (std::abs(current - previous) < config_.convergence_threshold) {
        return ++stall_count_ >= config_.stall_generations;
    }
    
    stall_count_ = 0;
    return false;
}

double NSGA2Optimizer::GetConvergenceMetric() const {
    if (fitness_history_.size() < 2) return 1.0;
    
    double current = fitness_history_.back();
    double previous = fitness_history_[fitness_history_.size() - 2];
    
    return std::abs(current - previous);
}

void NSGA2Optimizer::CreateInitialPopulation(const std::vector<ScheduledTask>& tasks) {
    population_.clear();
    
    std::uniform_real_distribution<double> dist(0.0, 1.0);
    
    for (uint32_t i = 0; i < config_.population_size; ++i) {
        TaskEncoding encoding;
        
        // Random genes
        for (size_t j = 0; j < config_.objectives.size(); ++j) {
            encoding.genes.push_back(dist(rng_));
        }
        
        // Decode and evaluate
        encoding.Decode(config_.objectives);
        if (!tasks.empty()) {
            encoding.Evaluate(tasks[i % tasks.size()], config_.objectives);
        }
        
        population_.push_back(encoding);
    }
}

void NSGA2Optimizer::NonDominatedSort() {
    // Clear previous fronts
    fronts_.clear();
    
    // Initialize
    for (auto& p : population_) {
        p.rank = 0;
    }
    
    // Fast non-dominated sort
    std::vector<std::vector<size_t>> dominated_by(population_.size());
    std::vector<size_t> domination_count(population_.size(), 0);
    std::vector<std::vector<size_t>> fronts;
    
    for (size_t i = 0; i < population_.size(); ++i) {
        for (size_t j = 0; j < population_.size(); ++j) {
            if (i == j) continue;
            
            if (Dominates(population_[i], population_[j])) {
                dominated_by[i].push_back(j);
            } else if (Dominates(population_[j], population_[i])) {
                domination_count[i]++;
            }
        }
        
        if (domination_count[i] == 0) {
            population_[i].rank = 1;
        }
    }
    
    // Build fronts
    size_t current_rank = 1;
    while (true) {
        std::vector<size_t> current_front;
        
        for (size_t i = 0; i < population_.size(); ++i) {
            if (population_[i].rank == current_rank) {
                current_front.push_back(i);
            }
        }
        
        if (current_front.empty()) break;
        
        fronts.push_back(current_front);
        
        // Update ranks for next front
        for (size_t i : current_front) {
            for (size_t j : dominated_by[i]) {
                domination_count[j]--;
                if (domination_count[j] == 0) {
                    population_[j].rank = current_rank + 1;
                }
            }
        }
        
        current_rank++;
    }
    
    // Store fronts
    for (const auto& front : fronts) {
        std::vector<TaskEncoding> front_encoding;
        for (size_t idx : front) {
            front_encoding.push_back(population_[idx]);
        }
        fronts_.push_back(front_encoding);
    }
}

void NSGA2Optimizer::CalculateCrowdingDistance(std::vector<TaskEncoding>& front) {
    if (front.size() < 3) {
        for (auto& point : front) {
            point.crowding_distance = std::numeric_limits<double>::infinity();
        }
        return;
    }
    
    // Reset
    for (auto& point : front) {
        point.crowding_distance = 0.0;
    }
    
    // For each objective
    for (const auto& obj : config_.objectives) {
        // Sort by objective
        std::sort(front.begin(), front.end(),
            [&obj](const TaskEncoding& a, const TaskEncoding& b) {
                auto it_a = a.objective_values.find(obj.name);
                auto it_b = b.objective_values.find(obj.name);
                if (it_a == a.objective_values.end()) return false;
                if (it_b == b.objective_values.end()) return true;
                return it_a->second < it_b->second;
            });
        
        // Boundary points
        front.front().crowding_distance = std::numeric_limits<double>::infinity();
        front.back().crowding_distance = std::numeric_limits<double>::infinity();
        
        // Intermediate points
        double obj_min = front.front().objective_values[obj.name];
        double obj_max = front.back().objective_values[obj.name];
        double range = obj_max - obj_min;
        
        if (range > 1e-10) {
            for (size_t i = 1; i < front.size() - 1; ++i) {
                double distance = (front[i + 1].objective_values[obj.name] -
                                  front[i - 1].objective_values[obj.name]) / range;
                front[i].crowding_distance += distance;
            }
        }
    }
}

void NSGA2Optimizer::TournamentSelection() {
    offspring_.clear();
    std::uniform_int_distribution<size_t> dist(0, population_.size() - 1);
    
    while (offspring_.size() < config_.population_size) {
        // Tournament
        std::vector<size_t> tournament;
        for (uint32_t i = 0; i < config_.tournament_size; ++i) {
            tournament.push_back(dist(rng_));
        }
        
        // Select winner (lower rank, then higher crowding distance)
        size_t winner = tournament[0];
        for (size_t i = 1; i < tournament.size(); ++i) {
            size_t candidate = tournament[i];
            
            if (population_[candidate].rank < population_[winner].rank ||
                (population_[candidate].rank == population_[winner].rank &&
                 population_[candidate].crowding_distance > population_[winner].crowding_distance)) {
                winner = candidate;
            }
        }
        
        offspring_.push_back(population_[winner]);
    }
}

void NSGA2Optimizer::Crossover() {
    std::uniform_real_distribution<double> prob_dist(0.0, 1.0);
    std::uniform_int_distribution<size_t> gene_dist(0, config_.objectives.size() - 1);
    
    for (size_t i = 0; i < offspring_.size() - 1; i += 2) {
        if (prob_dist(rng_) < config_.crossover_probability) {
            // Single-point crossover
            size_t crossover_point = gene_dist(rng_);
            
            for (size_t j = crossover_point; j < config_.objectives.size(); ++j) {
                std::swap(offspring_[i].genes[j], offspring_[i + 1].genes[j]);
            }
        }
    }
}

void NSGA2Optimizer::Mutate() {
    std::uniform_real_distribution<double> prob_dist(0.0, 1.0);
    std::uniform_real_distribution<double> gene_dist(0.0, 1.0);
    std::normal_distribution<double> mutation_dist(0.0, config_.mutation_rate);
    
    for (auto& individual : offspring_) {
        for (auto& gene : individual.genes) {
            if (prob_dist(rng_) < config_.mutation_probability) {
                gene += mutation_dist(rng_);
                gene = std::max(0.0, std::min(1.0, gene));
            }
        }
    }
}

void NSGA2Optimizer::EnvironmentalSelection() {
    // Combine parent and offspring
    combined_.clear();
    combined_.insert(combined_.end(), population_.begin(), population_.end());
    combined_.insert(combined_.end(), offspring_.begin(), offspring_.end());
    
    // Non-dominated sort on combined population
    // (Simplified - in practice would re-run full NSGA-II)
    
    // Select best individuals
    population_.clear();
    
    // Sort by rank and crowding distance
    std::sort(combined_.begin(), combined_.end(),
        [](const TaskEncoding& a, const TaskEncoding& b) {
            if (a.rank != b.rank) return a.rank < b.rank;
            return a.crowding_distance > b.crowding_distance;
        });
    
    // Take best N
    for (size_t i = 0; i < std::min(config_.population_size, combined_.size()); ++i) {
        population_.push_back(combined_[i]);
    }
    
    // Record fitness
    fitness_history_.push_back(GetBestFitness());
}

bool NSGA2Optimizer::Dominates(const TaskEncoding& a, const TaskEncoding& b) const {
    bool strictly_better = false;
    
    for (const auto& [obj, value] : a.objective_values) {
        auto it = b.objective_values.find(obj);
        if (it == b.objective_values.end()) continue;
        
        // Check if objective is minimization or maximization
        bool is_minimization = false;
        for (const auto& cfg_obj : config_.objectives) {
            if (cfg_obj.name == obj) {
                is_minimization = (cfg_obj.type == ObjectiveType::MINIMIZE_LATENCY ||
                                  cfg_obj.type == ObjectiveType::MINIMIZE_RESOURCE_USAGE ||
                                  cfg_obj.type == ObjectiveType::MINIMIZE_COST);
                break;
            }
        }
        
        if (is_minimization) {
            if (value < it->second - 1e-10) strictly_better = true;
            else if (value > it->second + 1e-10) return false;
        } else {
            if (value > it->second + 1e-10) strictly_better = true;
            else if (value < it->second - 1e-10) return false;
        }
    }
    
    return strictly_better;
}

double NSGA2Optimizer::CalculateCrowdingDistance(const TaskEncoding& point,
                                                  const std::vector<TaskEncoding>& front) const {
    // Simplified - would calculate full crowding distance
    return point.crowding_distance;
}

// ============================================================================
// TaskEncoding Implementation
// ============================================================================

void TaskEncoding::Decode(const std::vector<Objective>& objectives) {
    phenotype.clear();
    
    for (size_t i = 0; i < genes.size() && i < objectives.size(); ++i) {
        // Map gene [0,1] to objective range
        double value = objectives[i].min_value + 
                      genes[i] * (objectives[i].max_value - objectives[i].min_value);
        phenotype[objectives[i].name] = value;
    }
}

void TaskEncoding::Evaluate(const ScheduledTask& task, const std::vector<Objective>& objectives) {
    objective_values.clear();
    
    // Calculate each objective value
    for (const auto& obj : objectives) {
        double value = 0.0;
        
        switch (obj.type) {
            case ObjectiveType::MINIMIZE_LATENCY:
                value = task.priority.total_priority * 100.0; // Simulated latency
                break;
            case ObjectiveType::MAXIMIZE_THROUGHPUT:
                value = task.priority.total_priority * 200.0; // Simulated throughput
                break;
            case ObjectiveType::MINIMIZE_RESOURCE_USAGE:
                value = task.min_workers * 10.0; // Resource usage
                break;
            case ObjectiveType::MAXIMIZE_RELIABILITY:
                value = task.priority.confidence_factor;
                break;
            case ObjectiveType::MAXIMIZE_FAIRNESS:
                value = 1.0; // Placeholder
                break;
            default:
                value = 0.5;
                break;
        }
        
        objective_values[obj.name] = value;
    }
    
    // Calculate fitness (weighted sum)
    fitness = 0.0;
    for (const auto& obj : objectives) {
        auto it = objective_values.find(obj.name);
        if (it != objective_values.end()) {
            fitness += obj.CalculateScore(it->second);
        }
    }
}

// ============================================================================
// WeightedSumOptimizer Implementation
// ============================================================================

WeightedSumOptimizer::WeightedSumOptimizer(const std::vector<Objective>& objectives)
    : objectives_(objectives) {
    // Initialize equal weights
    weights_.resize(objectives.size(), 1.0 / objectives.size());
}

void WeightedSumOptimizer::SetWeights(const std::vector<double>& weights) {
    std::lock_guard<std::mutex> lock(mutex_);
    weights_ = weights;
}

void WeightedSumOptimizer::NormalizeWeights() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    double sum = std::accumulate(weights_.begin(), weights_.end(), 0.0);
    if (sum > 0.0) {
        for (auto& w : weights_) {
            w /= sum;
        }
    }
}

double WeightedSumOptimizer::Evaluate(const std::map<std::string, double>& objective_values) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    double score = 0.0;
    size_t i = 0;
    
    for (const auto& obj : objectives_) {
        auto it = objective_values.find(obj.name);
        if (it != objective_values.end() && i < weights_.size()) {
            score += weights_[i] * obj.CalculateScore(it->second);
        }
        ++i;
    }
    
    return score;
}

ScheduledTask WeightedSumOptimizer::Optimize(const std::vector<ScheduledTask>& candidates) {
    if (candidates.empty()) {
        return ScheduledTask{};
    }
    
    ScheduledTask best = candidates[0];
    double best_score = -std::numeric_limits<double>::infinity();
    
    for (const auto& task : candidates) {
        std::map<std::string, double> values;
        
        // Calculate objective values for this task
        for (const auto& obj : objectives_) {
            double value = 0.0;
            
            switch (obj.type) {
                case ObjectiveType::MINIMIZE_LATENCY:
                    value = task.priority.total_priority * 100.0;
                    break;
                case ObjectiveType::MAXIMIZE_THROUGHPUT:
                    value = task.priority.total_priority * 200.0;
                    break;
                case ObjectiveType::MINIMIZE_RESOURCE_USAGE:
                    value = task.min_workers * 10.0;
                    break;
                case ObjectiveType::MAXIMIZE_RELIABILITY:
                    value = task.priority.confidence_factor;
                    break;
                default:
                    value = 0.5;
                    break;
            }
            
            values[obj.name] = value;
        }
        
        double score = Evaluate(values);
        
        if (score > best_score) {
            best_score = score;
            best = task;
        }
    }
    
    return best;
}

std::vector<ScheduledTask> WeightedSumOptimizer::Rank(const std::vector<ScheduledTask>& candidates) {
    std::vector<std::pair<ScheduledTask, double>> scored;
    
    for (const auto& task : candidates) {
        std::map<std::string, double> values;
        
        // Calculate objective values
        for (const auto& obj : objectives_) {
            double value = 0.0;
            
            switch (obj.type) {
                case ObjectiveType::MINIMIZE_LATENCY:
                    value = task.priority.total_priority * 100.0;
                    break;
                case ObjectiveType::MAXIMIZE_THROUGHPUT:
                    value = task.priority.total_priority * 200.0;
                    break;
                case ObjectiveType::MINIMIZE_RESOURCE_USAGE:
                    value = task.min_workers * 10.0;
                    break;
                case ObjectiveType::MAXIMIZE_RELIABILITY:
                    value = task.priority.confidence_factor;
                    break;
                default:
                    value = 0.5;
                    break;
            }
            
            values[obj.name] = value;
        }
        
        double score = Evaluate(values);
        scored.push_back({task, score});
    }
    
    // Sort by score (descending)
    std::sort(scored.begin(), scored.end(),
        [](const auto& a, const auto& b) { return a.second > b.second; });
    
    // Extract tasks
    std::vector<ScheduledTask> ranked;
    for (const auto& [task, _] : scored) {
        ranked.push_back(task);
    }
    
    return ranked;
}

void WeightedSumOptimizer::UpdateWeights(const std::map<std::string, double>& performance) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Adjust weights based on performance
    size_t i = 0;
    for (const auto& obj : objectives_) {
        auto it = performance.find(obj.name);
        if (it != performance.end() && i < weights_.size()) {
            // Increase weight for underperforming objectives
            if (it->second < obj.target_value) {
                weights_[i] *= 1.1;
            } else {
                weights_[i] *= 0.95;
            }
        }
        ++i;
    }
    
    NormalizeWeights();
}

// ============================================================================
// ConstraintHandler Implementation
// ============================================================================

ConstraintHandler::ConstraintHandler(double penalty_weight)
    : penalty_weight_(penalty_weight) {}

void ConstraintHandler::AddConstraint(ObjectiveType type, double threshold, bool hard) {
    std::lock_guard<std::mutex> lock(mutex_);
    constraints_.push_back({type, threshold, hard});
}

void ConstraintHandler::RemoveConstraint(ObjectiveType type) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    constraints_.erase(
        std::remove_if(constraints_.begin(), constraints_.end(),
            [type](const Constraint& c) { return c.type == type; }),
        constraints_.end());
}

double ConstraintHandler::CalculatePenalty(const std::map<std::string, double>& values) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    double penalty = 0.0;
    
    for (const auto& constraint : constraints_) {
        // Find corresponding value
        double value = 0.0;
        std::string obj_name;
        
        switch (constraint.type) {
            case ObjectiveType::MINIMIZE_LATENCY:
                obj_name = "latency";
                break;
            case ObjectiveType::MAXIMIZE_THROUGHPUT:
                obj_name = "throughput";
                break;
            case ObjectiveType::MINIMIZE_RESOURCE_USAGE:
                obj_name = "resource";
                break;
            case ObjectiveType::MAXIMIZE_RELIABILITY:
                obj_name = "reliability";
                break;
            default:
                continue;
        }
        
        auto it = values.find(obj_name);
        if (it != values.end()) {
            value = it->second;
        }
        
        // Calculate violation
        double violation = 0.0;
        if (constraint.type == ObjectiveType::MINIMIZE_LATENCY ||
            constraint.type == ObjectiveType::MINIMIZE_RESOURCE_USAGE ||
            constraint.type == ObjectiveType::MINIMIZE_COST) {
            violation = std::max(0.0, value - constraint.threshold);
        } else {
            violation = std::max(0.0, constraint.threshold - value);
        }
        
        penalty += penalty_weight_ * violation * (constraint.hard ? 10.0 : 1.0);
    }
    
    return penalty;
}

bool ConstraintHandler::IsFeasible(const std::map<std::string, double>& values) const {
    return CalculatePenalty(values) == 0.0;
}

std::vector<std::string> ConstraintHandler::GetViolatedConstraints(
    const std::map<std::string, double>& values) const {
    
    std::vector<std::string> violated;
    
    for (const auto& constraint : constraints_) {
        double value = 0.0;
        
        // Get value (simplified)
        auto it = values.find("value");
        if (it != values.end()) {
            value = it->second;
        }
        
        // Check violation
        bool violated_constraint = false;
        if (constraint.type == ObjectiveType::MINIMIZE_LATENCY ||
            constraint.type == ObjectiveType::MINIMIZE_RESOURCE_USAGE ||
            constraint.type == ObjectiveType::MINIMIZE_COST) {
            violated_constraint = value > constraint.threshold;
        } else {
            violated_constraint = value < constraint.threshold;
        }
        
        if (violated_constraint) {
            violated.push_back("constraint_" + std::to_string(static_cast<int>(constraint.type)));
        }
    }
    
    return violated;
}

// ============================================================================
// AdaptiveWeightController Implementation
// ============================================================================

AdaptiveWeightController::AdaptiveWeightController(const std::vector<Objective>& objectives,
                                                     double learning_rate)
    : objectives_(objectives)
    , learning_rate_(learning_rate) {
    // Initialize equal weights
    weights_.resize(objectives.size(), 1.0 / objectives.size());
}

void AdaptiveWeightController::RecordOutcome(const std::map<std::string, double>& objectives,
                                             const std::map<std::string, double>& outcomes) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    history_.push_back(outcomes);
    
    // Keep only recent history
    while (history_.size() > 100) {
        history_.erase(history_.begin());
    }
}

void AdaptiveWeightController::UpdateWeights() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (history_.empty()) return;
    
    // Calculate average satisfaction for each objective
    std::vector<double> avg_satisfaction(weights_.size(), 0.0);
    
    for (const auto& outcomes : history_) {
        size_t i = 0;
        for (const auto& obj : objectives_) {
            auto it = outcomes.find(obj.name);
            if (it != outcomes.end()) {
                // Calculate satisfaction (0 to 1)
                double satisfaction = obj.CalculateScore(it->second);
                avg_satisfaction[i] += satisfaction;
            }
            ++i;
        }
    }
    
    for (auto& s : avg_satisfaction) {
        s /= history_.size();
    }
    
    // Adjust weights based on satisfaction
    for (size_t i = 0; i < weights_.size(); ++i) {
        // Increase weight for low satisfaction, decrease for high
        double adjustment = learning_rate_ * (0.5 - avg_satisfaction[i]);
        weights_[i] = std::max(0.01, std::min(0.99, weights_[i] + adjustment));
    }
    
    // Normalize
    double sum = std::accumulate(weights_.begin(), weights_.end(), 0.0);
    if (sum > 0.0) {
        for (auto& w : weights_) {
            w /= sum;
        }
    }
}

std::vector<double> AdaptiveWeightController::GetWeights() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return weights_;
}

void AdaptiveWeightController::SetPreference(ObjectiveType type, double preference) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Find objective and set weight
    size_t i = 0;
    for (const auto& obj : objectives_) {
        if (obj.type == type && i < weights_.size()) {
            weights_[i] = preference;
            break;
        }
        ++i;
    }
    
    // Normalize
    double sum = std::accumulate(weights_.begin(), weights_.end(), 0.0);
    if (sum > 0.0) {
        for (auto& w : weights_) {
            w /= sum;
        }
    }
}

void AdaptiveWeightController::Reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    weights_.assign(objectives_.size(), 1.0 / objectives_.size());
    history_.clear();
}

double AdaptiveWeightController::CalculateSatisfaction(
    const std::map<std::string, double>& outcomes,
    const std::vector<double>& weights) const {
    
    double satisfaction = 0.0;
    size_t i = 0;
    
    for (const auto& obj : objectives_) {
        auto it = outcomes.find(obj.name);
        if (it != outcomes.end() && i < weights.size()) {
            satisfaction += weights[i] * obj.CalculateScore(it->second);
        }
        ++i;
    }
    
    return satisfaction;
}

// ============================================================================
// MultiObjectiveScheduler Implementation
// ============================================================================

MultiObjectiveScheduler::MultiObjectiveScheduler(const MultiObjectiveConfig& config)
    : config_(config)
    , stats_{} {
    InitializeOptimizers();
}

MultiObjectiveScheduler::~MultiObjectiveScheduler() = default;

void MultiObjectiveScheduler::InitializeOptimizers() {
    nsga2_ = std::make_unique<NSGA2Optimizer>(config_);
    weighted_sum_ = std::make_unique<WeightedSumOptimizer>(objectives_);
    constraint_handler_ = std::make_unique<ConstraintHandler>(config_.constraint_penalty);
    weight_controller_ = std::make_unique<AdaptiveWeightController>(objectives_, config_.weight_learning_rate);
}

void MultiObjectiveScheduler::AddObjective(const Objective& objective) {
    std::lock_guard<std::mutex> lock(mutex_);
    objectives_.push_back(objective);
    InitializeOptimizers();
}

void MultiObjectiveScheduler::RemoveObjective(ObjectiveType type) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    objectives_.erase(
        std::remove_if(objectives_.begin(), objectives_.end(),
            [type](const Objective& o) { return o.type == type; }),
        objectives_.end());
    
    InitializeOptimizers();
}

void MultiObjectiveScheduler::SetObjectives(const std::vector<Objective>& objectives) {
    std::lock_guard<std::mutex> lock(mutex_);
    objectives_ = objectives;
    InitializeOptimizers();
}

std::vector<Objective> MultiObjectiveScheduler::GetObjectives() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return objectives_;
}

void MultiObjectiveScheduler::Optimize(const std::vector<ScheduledTask>& tasks) {
    if (tasks.empty() || objectives_.empty()) {
        return;
    }
    
    // Run NSGA-II optimization
    nsga2_->Initialize(tasks);
    nsga2_->Evolve(config_.max_generations);
    
    // Update statistics
    stats_.generations_run = config_.max_generations;
    stats_.final_hypervolume = nsga2_->GetHypervolume();
    stats_.convergence_rate = nsga2_->GetConvergenceMetric();
    
    auto front = nsga2_->GetParetoFront();
    stats_.pareto_front_size = front.size();
    
    // Update Pareto front
    pareto_front_.Clear();
    for (const auto& encoding : front) {
        ParetoPoint point;
        point.objective_values = encoding.objective_values;
        pareto_front_.AddPoint(point);
    }
}

std::vector<ScheduledTask> MultiObjectiveScheduler::GetParetoOptimalSchedule() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return optimized_schedule_;
}

ScheduledTask MultiObjectiveScheduler::GetBestTask(const std::vector<double>& weights) const {
    auto point = pareto_front_.GetBest(weights);
    
    // Find corresponding task (simplified)
    if (!optimized_schedule_.empty()) {
        return optimized_schedule_[0];
    }
    
    return ScheduledTask{};
}

ScheduledTask MultiObjectiveScheduler::SelectByWeightedSum(const std::vector<ScheduledTask>& candidates) {
    return weighted_sum_->Optimize(candidates);
}

ScheduledTask MultiObjectiveScheduler::SelectByNSGA2(const std::vector<ScheduledTask>& candidates) {
    Optimize(candidates);
    
    auto front = nsga2_->GetParetoFront();
    if (!front.empty()) {
        // Return first solution from Pareto front
        // In practice, would select based on user preference
        return candidates[0];
    }
    
    return ScheduledTask{};
}

ScheduledTask MultiObjectiveScheduler::SelectByConstraintSatisfaction(const std::vector<ScheduledTask>& candidates) {
    for (const auto& task : candidates) {
        auto objectives = CalculateObjectives(task);
        
        if (constraint_handler_->IsFeasible(objectives)) {
            return task;
        }
    }
    
    // Return task with minimum constraint violation
    ScheduledTask best = candidates[0];
    double min_violation = std::numeric_limits<double>::infinity();
    
    for (const auto& task : candidates) {
        auto objectives = CalculateObjectives(task);
        double violation = constraint_handler_->CalculatePenalty(objectives);
        
        if (violation < min_violation) {
            min_violation = violation;
            best = task;
        }
    }
    
    return best;
}

ParetoFront MultiObjectiveScheduler::GetParetoFront() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return pareto_front_;
}

void MultiObjectiveScheduler::UpdateParetoFront(const ScheduledTask& task) {
    ParetoPoint point;
    point.objective_values = CalculateObjectives(task);
    pareto_front_.AddPoint(point);
}

void MultiObjectiveScheduler::EnableAdaptiveWeights(bool enable) {
    config_.adaptive_weights = enable;
}

void MultiObjectiveScheduler::SetPreference(ObjectiveType type, double preference) {
    if (weight_controller_) {
        weight_controller_->SetPreference(type, preference);
    }
}

MultiObjectiveScheduler::OptimizationStats MultiObjectiveScheduler::GetStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

void MultiObjectiveScheduler::ExportParetoFront(const std::string& path) const {
    std::ofstream file(path);
    if (!file.is_open()) return;
    
    file << "Objective Values:\n";
    
    auto front = pareto_front_.GetFront();
    for (const auto& point : front) {
        for (const auto& [obj, value] : point.objective_values) {
            file << obj << "=" << value << " ";
        }
        file << "\n";
    }
}

void MultiObjectiveScheduler::ExportOptimizationHistory(const std::string& path) const {
    // Placeholder for history export
    (void)path;
}

std::map<std::string, double> MultiObjectiveScheduler::CalculateObjectives(const ScheduledTask& task) const {
    std::map<std::string, double> values;
    
    for (const auto& obj : objectives_) {
        double value = 0.0;
        
        switch (obj.type) {
            case ObjectiveType::MINIMIZE_LATENCY:
                value = task.priority.total_priority * 100.0;
                break;
            case ObjectiveType::MAXIMIZE_THROUGHPUT:
                value = task.priority.total_priority * 200.0;
                break;
            case ObjectiveType::MINIMIZE_RESOURCE_USAGE:
                value = task.min_workers * 10.0;
                break;
            case ObjectiveType::MAXIMIZE_RELIABILITY:
                value = task.priority.confidence_factor;
                break;
            case ObjectiveType::MAXIMIZE_FAIRNESS:
                value = 1.0;
                break;
            case ObjectiveType::MINIMIZE_COST:
                value = task.min_workers * 5.0;
                break;
            case ObjectiveType::MAXIMIZE_QUALITY:
                value = task.priority.stability_factor;
                break;
            default:
                value = 0.5;
                break;
        }
        
        values[obj.name] = value;
    }
    
    return values;
}

double MultiObjectiveScheduler::EvaluateTask(const ScheduledTask& task) const {
    auto values = CalculateObjectives(task);
    
    double score = 0.0;
    for (const auto& obj : objectives_) {
        auto it = values.find(obj.name);
        if (it != values.end()) {
            score += obj.CalculateScore(it->second);
        }
    }
    
    // Subtract constraint penalty
    score -= constraint_handler_->CalculatePenalty(values);
    
    return score;
}

// ============================================================================
// MultiObjectiveUtils Implementation
// ============================================================================

namespace MultiObjectiveUtils {

double EuclideanDistance(const std::map<std::string, double>& a,
                        const std::map<std::string, double>& b) {
    double sum = 0.0;
    
    for (const auto& [key, value_a] : a) {
        auto it = b.find(key);
        double value_b = (it != b.end()) ? it->second : 0.0;
        sum += std::pow(value_a - value_b, 2);
    }
    
    return std::sqrt(sum);
}

double ManhattanDistance(const std::map<std::string, double>& a,
                         const std::map<std::string, double>& b) {
    double sum = 0.0;
    
    for (const auto& [key, value_a] : a) {
        auto it = b.find(key);
        double value_b = (it != b.end()) ? it->second : 0.0;
        sum += std::abs(value_a - value_b);
    }
    
    return sum;
}

double ChebyshevDistance(const std::map<std::string, double>& a,
                         const std::map<std::string, double>& b) {
    double max_dist = 0.0;
    
    for (const auto& [key, value_a] : a) {
        auto it = b.find(key);
        double value_b = (it != b.end()) ? it->second : 0.0;
        max_dist = std::max(max_dist, std::abs(value_a - value_b));
    }
    
    return max_dist;
}

double CalculateHypervolume(const std::vector<ParetoPoint>& front,
                           const std::vector<std::string>& objectives,
                           const std::map<std::string, double>& reference_point) {
    // Simplified hypervolume calculation
    if (front.empty()) return 0.0;
    
    double hypervolume = 0.0;
    
    for (const auto& point : front) {
        double contribution = 1.0;
        
        for (const auto& obj : objectives) {
            auto it_point = point.objective_values.find(obj);
            auto it_ref = reference_point.find(obj);
            
            if (it_point != point.objective_values.end() && 
                it_ref != reference_point.end()) {
                contribution *= std::max(0.0, it_point->second - it_ref->second);
            }
        }
        
        hypervolume += contribution;
    }
    
    return hypervolume;
}

double CalculateSpacing(const std::vector<ParetoPoint>& front) {
    if (front.size() < 2) return 0.0;
    
    // Calculate average distance to nearest neighbor
    std::vector<double> distances;
    
    for (size_t i = 0; i < front.size(); ++i) {
        double min_dist = std::numeric_limits<double>::infinity();
        
        for (size_t j = 0; j < front.size(); ++j) {
            if (i != j) {
                min_dist = std::min(min_dist, front[i].Distance(front[j]));
            }
        }
        
        distances.push_back(min_dist);
    }
    
    double avg_dist = std::accumulate(distances.begin(), distances.end(), 0.0) / distances.size();
    
    // Calculate standard deviation
    double variance = 0.0;
    for (double d : distances) {
        variance += std::pow(d - avg_dist, 2);
    }
    variance /= distances.size();
    
    return std::sqrt(variance);
}

double CalculateDiversity(const std::vector<ParetoPoint>& front) {
    // Calculate average pairwise distance
    if (front.size() < 2) return 0.0;
    
    double total_dist = 0.0;
    size_t count = 0;
    
    for (size_t i = 0; i < front.size(); ++i) {
        for (size_t j = i + 1; j < front.size(); ++j) {
            total_dist += front[i].Distance(front[j]);
            ++count;
        }
    }
    
    return (count > 0) ? (total_dist / count) : 0.0;
}

double LinearUtility(const std::map<std::string, double>& values,
                    const std::vector<double>& weights) {
    double utility = 0.0;
    size_t i = 0;
    
    for (const auto& [key, value] : values) {
        if (i < weights.size()) {
            utility += weights[i] * value;
        }
        ++i;
    }
    
    return utility;
}

double ChebyshevUtility(const std::map<std::string, double>& values,
                       const std::vector<double>& weights,
                       const std::map<std::string, double>& reference) {
    double max_utility = -std::numeric_limits<double>::infinity();
    size_t i = 0;
    
    for (const auto& [key, value] : values) {
        if (i < weights.size()) {
            double ref = 0.0;
            auto it = reference.find(key);
            if (it != reference.end()) {
                ref = it->second;
            }
            
            double utility = weights[i] * std::abs(value - ref);
            max_utility = std::max(max_utility, utility);
        }
        ++i;
    }
    
    return max_utility;
}

void NormalizeFront(std::vector<ParetoPoint>& front,
                   const std::vector<std::string>& objectives) {
    // Find min/max for each objective
    std::map<std::string, std::pair<double, double>> ranges;
    
    for (const auto& obj : objectives) {
        double min_val = std::numeric_limits<double>::infinity();
        double max_val = -std::numeric_limits<double>::infinity();
        
        for (const auto& point : front) {
            auto it = point.objective_values.find(obj);
            if (it != point.objective_values.end()) {
                min_val = std::min(min_val, it->second);
                max_val = std::max(max_val, it->second);
            }
        }
        
        ranges[obj] = {min_val, max_val};
    }
    
    // Normalize
    for (auto& point : front) {
        for (const auto& [obj, range] : ranges) {
            auto it = point.objective_values.find(obj);
            if (it != point.objective_values.end()) {
                double normalized = (range.second - range.first > 1e-10) ?
                    (it->second - range.first) / (range.second - range.first) : 0.5;
                point.objective_values[obj] = normalized;
            }
        }
    }
}

void DenormalizeFront(std::vector<ParetoPoint>& front,
                     const std::vector<std::string>& objectives,
                     const std::map<std::string, std::pair<double, double>>& ranges) {
    for (auto& point : front) {
        for (const auto& obj : objectives) {
            auto it_range = ranges.find(obj);
            auto it_value = point.objective_values.find(obj);
            
            if (it_range != ranges.end() && it_value != point.objective_values.end()) {
                double denormalized = it_value->second * (it_range->second.second - it_range->second.first) +
                                     it_range->second.first;
                point.objective_values[obj] = denormalized;
            }
        }
    }
}

} // namespace MultiObjectiveUtils

} // namespace Scheduler
