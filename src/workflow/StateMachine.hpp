/**
 * StateMachine.hpp
 *
 * Phase O Batch 2/5: State Machine & Business Rules
 *
 * Hierarchical state machines with business rules engine for
 * complex state management and decision automation.
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <optional>
#include <functional>
#include <chrono>
#include <any>

namespace Workflow {

// ============================================================================
// Forward Declarations
// ============================================================================

class State;
class Transition;
class StateMachine;
class BusinessRule;
class RulesEngine;

// ============================================================================
// Event
// ============================================================================

/**
 * State machine event.
 */
class StateMachineEvent {
public:
    struct Config {
        std::string name;
        std::map<std::string, std::any> payload;
        std::chrono::system_clock::time_point timestamp;
        std::optional<std::string> source;
        std::optional<std::string> correlationId;
    };
    
    explicit StateMachineEvent(const Config& config);
    
    // Factory methods
    static StateMachineEvent Create(const std::string& name);
    template<typename T>
    static StateMachineEvent Create(const std::string& name, const T& payload);
    
    // Accessors
    const std::string& GetName() const { return config_.name; }
    const std::map<std::string, std::any>& GetPayload() const { return config_.payload; }
    std::chrono::system_clock::time_point GetTimestamp() const { return config_.timestamp; }
    
    // Payload helpers
    template<typename T>
    std::optional<T> GetPayload(const std::string& key) const;
    void SetPayload(const std::string& key, std::any value);
    
private:
    Config config_;
};

// ============================================================================
// State
// ============================================================================

/**
 * State in a state machine.
 */
class State {
public:
    using EntryAction = std::function<void(const StateMachineEvent&)>;
    using ExitAction = std::function<void(const StateMachineEvent&)>;
    using Activity = std::function<void()>;
    
    struct Config {
        std::string id;
        std::string name;
        std::string description;
        std::optional<EntryAction> onEntry;
        std::optional<ExitAction> onExit;
        std::optional<Activity> doActivity;
        std::vector<std::shared_ptr<State>> substates;
        std::optional<std::shared_ptr<State>> initialSubstate;
        std::optional<std::shared_ptr<State>> parent;
        std::map<std::string, std::any> data;
        bool isFinal;
        bool isInitial;
    };
    
    explicit State(const Config& config);
    
    // Lifecycle
    void OnEntry(const StateMachineEvent& event);
    void OnExit(const StateMachineEvent& event);
    void DoActivity();
    
    // Hierarchy
    void AddSubstate(std::shared_ptr<State> state);
    void RemoveSubstate(const std::string& stateId);
    std::shared_ptr<State> GetSubstate(const std::string& stateId) const;
    std::vector<std::shared_ptr<State>> GetSubstates() const;
    bool HasSubstates() const;
    
    std::optional<std::shared_ptr<State>> GetParent() const;
    void SetParent(std::shared_ptr<State> parent);
    
    std::optional<std::shared_ptr<State>> GetInitialSubstate() const;
    void SetInitialSubstate(std::shared_ptr<State> state);
    
    // Properties
    bool IsComposite() const;
    bool IsSimple() const;
    bool IsFinal() const { return config_.isFinal; }
    bool IsInitial() const { return config_.isInitial; }
    bool IsAncestorOf(std::shared_ptr<State> state) const;
    
    // Accessors
    const std::string& GetId() const { return config_.id; }
    const std::string& GetName() const { return config_.name; }
    
    // Data
    void SetData(const std::string& key, std::any value);
    std::optional<std::any> GetData(const std::string& key) const;
    
private:
    Config config_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Transition
// ============================================================================

/**
 * Transition between states.
 */
class Transition {
public:
    using Guard = std::function<bool(const StateMachineEvent&, const std::map<std::string, std::any>&)>;
    using Action = std::function<void(const StateMachineEvent&)>;
    
    struct Config {
        std::string id;
        std::string name;
        std::string sourceStateId;
        std::string targetStateId;
        std::string eventName;
        std::optional<Guard> guard;
        std::optional<Action> action;
        std::chrono::milliseconds delay;
        bool isInternal;
    };
    
    explicit Transition(const Config& config);
    
    // Execution
    bool CanFire(const StateMachineEvent& event,
                 const std::map<std::string, std::any>& context) const;
    void Fire(const StateMachineEvent& event);
    
    // Accessors
    const std::string& GetSourceStateId() const { return config_.sourceStateId; }
    const std::string& GetTargetStateId() const { return config_.targetStateId; }
    const std::string& GetEventName() const { return config_.eventName; }
    bool IsInternal() const { return config_.isInternal; }
    
private:
    Config config_;
};

// ============================================================================
// State Machine
// ============================================================================

/**
 * Hierarchical state machine.
 */
class StateMachine {
public:
    enum class HistoryType {
        NONE,
        SHALLOW,
        DEEP
    };
    
    struct Config {
        std::string id;
        std::string name;
        std::string initialStateId;
        HistoryType historyType;
        bool enableAsync;
    };
    
    struct StateConfiguration {
        std::vector<std::string> activeStates;
        std::map<std::string, std::any> context;
        std::chrono::system_clock::time_point timestamp;
    };
    
    explicit StateMachine(const Config& config);
    
    // State management
    void AddState(std::shared_ptr<State> state);
    void RemoveState(const std::string& stateId);
    std::shared_ptr<State> GetState(const std::string& stateId) const;
    std::vector<std::shared_ptr<State>> GetStates() const;
    
    // Transition management
    void AddTransition(std::shared_ptr<Transition> transition);
    void RemoveTransition(const std::string& transitionId);
    std::vector<std::shared_ptr<Transition>> GetTransitions() const;
    std::vector<std::shared_ptr<Transition>> GetTransitionsFrom(const std::string& stateId) const;
    std::vector<std::shared_ptr<Transition>> GetTransitionsForEvent(const std::string& eventName) const;
    
    // Lifecycle
    void Initialize();
    void Start();
    void Stop();
    bool IsRunning() const;
    
    // Event handling
    void SendEvent(const StateMachineEvent& event);
    void SendEvent(const std::string& eventName);
    template<typename T>
    void SendEvent(const std::string& eventName, const T& payload);
    
    // State queries
    std::vector<std::string> GetActiveStates() const;
    bool IsInState(const std::string& stateId) const;
    bool CanHandleEvent(const std::string& eventName) const;
    
    // Context
    void SetContext(const std::string& key, std::any value);
    std::optional<std::any> GetContext(const std::string& key) const;
    
    // Persistence
    StateConfiguration GetConfiguration() const;
    void RestoreConfiguration(const StateConfiguration& config);
    
    // Visualization
    std::string ToGraphviz() const;
    std::string ToPlantUml() const;
    std::string ToScxml() const;
    
    // Events
    using StateChangeCallback = std::function<void(const std::string&, const std::string&)>;
    void OnStateChange(StateChangeCallback callback);
    
    using EventProcessedCallback = std::function<void(const StateMachineEvent&)>;
    void OnEventProcessed(EventProcessedCallback callback);
    
private:
    Config config_;
    std::map<std::string, std::shared_ptr<State>> states_;
    std::map<std::string, std::shared_ptr<Transition>> transitions_;
    std::vector<std::string> activeStates_;
    std::map<std::string, std::any> context_;
    std::atomic<bool> running_;
    mutable std::mutex mutex_;
    
    StateChangeCallback stateChangeCallback_;
    EventProcessedCallback eventProcessedCallback_;
    
    void ProcessEvent(const StateMachineEvent& event);
    void ExecuteTransition(std::shared_ptr<Transition> transition,
                           const StateMachineEvent& event);
    void EnterState(std::shared_ptr<State> state, const StateMachineEvent& event);
    void ExitState(std::shared_ptr<State> state, const StateMachineEvent& event);
    std::vector<std::string> GetStateHierarchy(std::shared_ptr<State> state) const;
};

// ============================================================================
// Business Rule
// ============================================================================

/**
 * Business rule definition.
 */
class BusinessRule {
public:
    enum class Operator {
        EQUALS,
        NOT_EQUALS,
        GREATER_THAN,
        LESS_THAN,
        GREATER_THAN_OR_EQUAL,
        LESS_THAN_OR_EQUAL,
        CONTAINS,
        STARTS_WITH,
        ENDS_WITH,
        MATCHES,
        IN,
        NOT_IN,
        EXISTS,
        NOT_EXISTS
    };
    
    struct Condition {
        std::string field;
        Operator op;
        std::any value;
        std::optional<std::string> type;  // string, number, date, boolean
    };
    
    struct Action {
        enum class Type {
            ASSERT,
            SET_VALUE,
            CALCULATE,
            VALIDATE,
            NOTIFY,
            EXECUTE
        };
        
        Type type;
        std::map<std::string, std::any> parameters;
    };
    
    struct Config {
        std::string id;
        std::string name;
        std::string description;
        int priority;
        std::vector<Condition> conditions;
        std::vector<Action> actions;
        bool active;
        std::optional<std::string> effectiveFrom;
        std::optional<std::string> effectiveTo;
        std::map<std::string, std::string> metadata;
    };
    
    explicit BusinessRule(const Config& config);
    
    // Evaluation
    bool Evaluate(const std::map<std::string, std::any>& facts) const;
    std::vector<Action> Execute(const std::map<std::string, std::any>& facts) const;
    
    // Validation
    bool Validate() const;
    std::vector<std::string> GetValidationErrors() const;
    
    // Accessors
    const Config& GetConfig() const { return config_; }
    const std::string& GetId() const { return config_.id; }
    bool IsActive() const { return config_.active; }
    
    // Lifecycle
    void Activate();
    void Deactivate();
    bool IsEffective() const;
    
private:
    Config config_;
    
    bool EvaluateCondition(const Condition& condition,
                           const std::map<std::string, std::any>& facts) const;
    bool CompareValues(const std::any& left, Operator op, const std::any& right) const;
};

// ============================================================================
// Rules Engine
// ============================================================================

/**
 * Business rules engine.
 */
class RulesEngine {
public:
    enum class ExecutionStrategy {
        SEQUENTIAL,
        PRIORITY_ORDERED,
        FIRST_MATCH,
        ALL_MATCH
    };
    
    struct Config {
        ExecutionStrategy strategy;
        bool skipOnFirstFailure;
        bool enableTracing;
        uint32_t maxRulesPerExecution;
    };
    
    struct ExecutionResult {
        bool success;
        std::vector<std::string> executedRules;
        std::vector<std::string> failedRules;
        std::vector<BusinessRule::Action> actions;
        std::map<std::string, std::any> output;
        std::chrono::milliseconds executionTime;
        std::optional<std::string> error;
    };
    
    struct ExecutionTrace {
        std::string ruleId;
        bool evaluated;
        bool matched;
        std::chrono::microseconds evaluationTime;
        std::optional<std::string> error;
    };
    
    explicit RulesEngine(const Config& config);
    
    // Rule management
    void AddRule(std::shared_ptr<BusinessRule> rule);
    void RemoveRule(const std::string& ruleId);
    std::shared_ptr<BusinessRule> GetRule(const std::string& ruleId) const;
    std::vector<std::shared_ptr<BusinessRule>> GetRules() const;
    std::vector<std::shared_ptr<BusinessRule>> GetActiveRules() const;
    
    // Rule sets
    void CreateRuleSet(const std::string& name,
                       const std::vector<std::string>& ruleIds);
    void RemoveRuleSet(const std::string& name);
    std::vector<std::string> GetRuleSet(const std::string& name) const;
    
    // Execution
    ExecutionResult Execute(const std::map<std::string, std::any>& facts);
    ExecutionResult Execute(const std::map<std::string, std::any>& facts,
                            const std::string& ruleSetName);
    ExecutionResult Execute(const std::map<std::string, std::any>& facts,
                            const std::vector<std::string>& ruleIds);
    
    // Validation
    bool ValidateFacts(const std::map<std::string, std::any>& facts) const;
    std::vector<std::string> GetValidationErrors(const std::map<std::string, std::any>& facts) const;
    
    // Tracing
    std::vector<ExecutionTrace> GetLastExecutionTrace() const;
    void ClearTrace();
    
    // Statistics
    struct EngineStats {
        uint64_t totalExecutions;
        uint64_t successfulExecutions;
        uint64_t failedExecutions;
        uint64_t rulesEvaluated;
        uint64_t rulesMatched;
        double averageExecutionTimeMs;
    };
    EngineStats GetStats() const;
    void ResetStats();
    
private:
    Config config_;
    std::map<std::string, std::shared_ptr<BusinessRule>> rules_;
    std::map<std::string, std::vector<std::string>> ruleSets_;
    mutable std::mutex mutex_;
    
    std::vector<ExecutionTrace> lastTrace_;
    mutable std::mutex traceMutex_;
    
    EngineStats stats_;
    mutable std::mutex statsMutex_;
    
    std::vector<std::shared_ptr<BusinessRule>> GetRulesForExecution(
        const std::vector<std::string>& ruleIds) const;
    void SortRulesByPriority(std::vector<std::shared_ptr<BusinessRule>>& rules) const;
};

// ============================================================================
// Decision Table
// ============================================================================

/**
 * Decision table for rule-based decisions.
 */
class DecisionTable {
public:
    struct Column {
        std::string name;
        std::string type;
        std::vector<std::string> allowedValues;
    };
    
    struct Row {
        std::map<std::string, std::string> conditions;
        std::map<std::string, std::string> actions;
        int priority;
        bool active;
    };
    
    struct Config {
        std::string name;
        std::string description;
        std::vector<Column> conditionColumns;
        std::vector<Column> actionColumns;
        std::vector<Row> rows;
        std::string hitPolicy;  // FIRST, UNIQUE, PRIORITY, ANY, COLLECT
    };
    
    explicit DecisionTable(const Config& config);
    
    // Evaluation
    std::vector<Row> Evaluate(const std::map<std::string, std::string>& inputs) const;
    std::optional<Row> EvaluateFirst(const std::map<std::string, std::string>& inputs) const;
    std::map<std::string, std::string> EvaluateAndExecute(
        const std::map<std::string, std::string>& inputs) const;
    
    // Validation
    bool Validate() const;
    bool IsComplete() const;
    bool IsConsistent() const;
    std::vector<std::string> GetValidationErrors() const;
    
    // Editing
    void AddRow(const Row& row);
    void RemoveRow(size_t index);
    void UpdateRow(size_t index, const Row& row);
    
    // Import/Export
    static DecisionTable FromCsv(const std::string& csv);
    std::string ToCsv() const;
    static DecisionTable FromExcel(const std::string& path);
    
private:
    Config config_;
    mutable std::mutex mutex_;
    
    bool RowMatches(const Row& row, const std::map<std::string, std::string>& inputs) const;
    bool ValueMatches(const std::string& pattern, const std::string& value) const;
    void SortByPriority(std::vector<Row>& rows) const;
};

} // namespace Workflow
