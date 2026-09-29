// ============================================================================
// ConstraintSolver.cpp — Handwritten constraint satisfaction engine
// ============================================================================
#include "ConstraintSolver.hpp"
#include <algorithm>

namespace rawrxd::graph {

void ConstraintSolver::addConstraint(Constraint c) {
    constraints_.push_back(std::move(c));
}

void ConstraintSolver::clear() { constraints_.clear(); }

size_t ConstraintSolver::count() const { return constraints_.size(); }

std::vector<Constraint> ConstraintSolver::all() const { return constraints_; }

bool ConstraintSolver::checkHard(const std::unordered_map<std::string, std::string>& binding) const {
    for (const auto& c : constraints_) {
        if (c.type != ConstraintType::Hard) continue;
        if (c.checker) {
            if (!c.checker(binding)) return false;
        } else {
            // Simple variable check
            auto it = binding.find(c.variable);
            if (it == binding.end()) return false;
            if (c.op == "==" && it->second != c.value) return false;
            if (c.op == "!=" && it->second == c.value) return false;
        }
    }
    return true;
}

bool ConstraintSolver::backtrack(
    std::unordered_map<std::string, std::string>& current,
    const std::unordered_map<std::string, std::vector<std::string>>& domains,
    const std::vector<std::string>& variables,
    size_t idx) const {

    if (idx >= variables.size()) {
        // All variables assigned — check all hard constraints
        return checkHard(current);
    }

    const std::string& var = variables[idx];
    auto domIt = domains.find(var);
    if (domIt == domains.end()) return false;

    for (const auto& val : domIt->second) {
        current[var] = val;
        // Early pruning: check hard constraints that only involve assigned vars
        bool prune = false;
        for (const auto& c : constraints_) {
            if (c.type != ConstraintType::Hard || !c.checker) continue;
            // Only check if this constraint's variable is assigned
            if (current.find(c.variable) != current.end()) {
                if (c.op == "==" && current[c.variable] != c.value) { prune = true; break; }
                if (c.op == "!=" && current[c.variable] == c.value) { prune = true; break; }
            }
        }
        if (!prune) {
            if (backtrack(current, domains, variables, idx + 1)) return true;
        }
        current.erase(var);
    }
    return false;
}

Solution ConstraintSolver::solve(
    const std::unordered_map<std::string, std::vector<std::string>>& domains) const {

    Solution sol;
    std::vector<std::string> variables;
    for (const auto& [var, _] : domains) variables.push_back(var);
    std::sort(variables.begin(), variables.end());

    std::unordered_map<std::string, std::string> binding;
    bool found = backtrack(binding, domains, variables, 0);

    if (found) {
        sol.variables = binding;
        sol.valid = true;
        // Evaluate soft constraints
        for (const auto& c : constraints_) {
            if (c.type == ConstraintType::Soft) {
                bool violated = false;
                if (c.checker) { violated = !c.checker(binding); }
                else { auto it2 = binding.find(c.variable); if (it2 != binding.end()) { if (c.op == "==" && it2->second != c.value) violated = true; if (c.op == "!=" && it2->second == c.value) violated = true; } }
                if (violated) {
                    sol.violatedSoft.push_back(c.name);
                    sol.totalPenalty += c.penalty;
                }
        }
    } else {
        sol.valid = false;
        // Report which hard constraints can't be satisfied
        for (const auto& c : constraints_) {
            if (c.type == ConstraintType::Hard) {
                sol.violatedHard.push_back(c.name);
            }
        }
    }
    return sol;
}

} // namespace rawrxd::graph
