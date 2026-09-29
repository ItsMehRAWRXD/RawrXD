// ============================================================================
// ConstraintSolver.hpp — Hard/soft constraint satisfaction
// Given constraints, find the minimal valid solution.
// ============================================================================
#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <functional>

namespace rawrxd::graph {

// ---------------------------------------------------------------------------
// Constraint types
// ---------------------------------------------------------------------------
enum class ConstraintType : uint8_t {
    Hard    = 0,  // Must be satisfied (violating = no solution)
    Soft    = 1,  // Should be satisfied (violating = penalty)
    Optimize= 2,  // Objective to minimize/maximize
};

// ---------------------------------------------------------------------------
// Constraint — a single rule governing the solution space
// ---------------------------------------------------------------------------
struct Constraint {
    std::string id;
    std::string name;
    ConstraintType type = ConstraintType::Hard;
    std::string variable;           // which variable this constrains
    std::string op;                 // "==", "!=", "<=", ">=", "min", "max"
    std::string value;              // the bound
    int penalty = 0;                // penalty for violating soft constraints
    std::function<bool(const std::unordered_map<std::string, std::string>&)> checker;
};

// ---------------------------------------------------------------------------
// Solution — a variable binding that satisfies constraints
// ---------------------------------------------------------------------------
struct Solution {
    std::unordered_map<std::string, std::string> variables;
    bool valid = false;
    int totalPenalty = 0;
    std::vector<std::string> violatedHard;
    std::vector<std::string> violatedSoft;

    bool allHardSatisfied() const { return violatedHard.empty(); }
};

// ---------------------------------------------------------------------------
// Constraint Solver — handwritten satisfaction engine
// ---------------------------------------------------------------------------
class ConstraintSolver {
public:
    // Register a constraint
    void addConstraint(Constraint c);

    // Clear
    void clear();

    // Solve: find a variable binding that satisfies all hard constraints
    // and minimizes penalty from soft constraints
    // Fail-closed: returns invalid solution if hard constraints conflict
    Solution solve(const std::unordered_map<std::string, std::vector<std::string>>& domains) const;

    // Quick check: are all hard constraints satisfied by a given binding?
    bool checkHard(const std::unordered_map<std::string, std::string>& binding) const;

    // Count constraints
    size_t count() const;

    // List constraints
    std::vector<Constraint> all() const;

private:
    std::vector<Constraint> constraints_;

    // Backtracking search with constraint propagation
    bool backtrack(std::unordered_map<std::string, std::string>& current,
                   const std::unordered_map<std::string, std::vector<std::string>>& domains,
                   const std::vector<std::string>& variables,
                   size_t idx) const;
};

} // namespace rawrxd::graph