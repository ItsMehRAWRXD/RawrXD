// Phase U.2/5: Hybrid Quantum-Classical Interface
// RawrXD Hybrid Quantum-Classical - Bridging classical and quantum computation

#pragma once

#include <cstring>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>
#include <optional>
#include <unordered_map>

namespace RawrXD {
namespace Quantum {

// Task classification for hybrid execution
enum class TaskClass {
    CLASSICAL_ONLY,     // Classical only
    QUANTUM_ADVANTAGE,  // Quantum advantage expected
    HYBRID_OPTIMAL,     // Hybrid execution optimal
    VARIATIONAL,        // Variational quantum algorithm
    UNKNOWN             // Unknown classification
};

// Hybrid task
struct HybridTask {
    std::string task_id;
    std::string name;
    TaskClass classification;
    
    // Classical component
    struct ClassicalComponent {
        std::string function_name;
        std::vector<double> parameters;
        std::vector<double> expected_outputs;
        std::chrono::milliseconds estimated_time;
    } classical;
    
    // Quantum component
    struct QuantumComponent {
        std::string circuit_id;
        uint32_t num_qubits;
        uint32_t num_parameters;
        std::vector<double> parameter_bounds;
        uint32_t shots;
        std::chrono::milliseconds estimated_time;
    } quantum;
    
    // Execution plan
    struct ExecutionStep {
        enum class Type { CLASSICAL, QUANTUM, FEEDBACK } type;
        uint32_t step_number;
        std::string description;
        std::vector<uint32_t> depends_on;
    };
    std::vector<ExecutionStep> execution_plan;
    
    // Optimization
    struct OptimizationConfig {
        std::string optimizer_type;  // "COBYLA", "SPSA", "L-BFGS-B"
        uint32_t max_iterations;
        double convergence_tolerance;
        double learning_rate;
    } optimizer;
    
    // State
    enum class State {
        PENDING,
        CLASSICAL_RUNNING,
        QUANTUM_RUNNING,
        OPTIMIZING,
        COMPLETED,
        FAILED
    } state;
    
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point started_at;
    std::chrono::system_clock::time_point completed_at;
    
    // Results
    std::vector<double> optimal_parameters;
    double optimal_value;
    uint32_t iterations;
    std::string error_message;
};

// Variational quantum algorithm
struct VQAConfig {
    std::string algorithm_type;  // "VQE", "QAOA", "QML"
    
    // Ansatz
    std::string ansatz_type;     // "RY", "RYRZ", "UCCSD", "Custom"
    uint32_t ansatz_depth;
    std::vector<std::string> ansatz_gates;
    
    // Hamiltonian
    std::vector<std::tuple<std::string, double>> hamiltonian_terms;
    
    // Classical optimizer
    std::string optimizer;
    uint32_t max_iterations;
    double tolerance;
    
    // Execution
    uint32_t shots;
    bool use_error_mitigation;
    bool use_measurement_error_mitigation;
};

// Quantum feature map
struct QuantumFeatureMap {
    std::string map_type;  // "ZZ", "Z", "Pauli"
    uint32_t num_qubits;
    uint32_t reps;
    bool entanglement;
    std::string entanglement_pattern;
};

// Quantum kernel
struct QuantumKernel {
    std::string kernel_id;
    QuantumFeatureMap feature_map;
    
    // Kernel computation
    std::function<double(const std::vector<double>&, const std::vector<double>&)> kernel_function;
    
    // Training data
    std::vector<std::vector<double>> training_data;
    std::vector<int> training_labels;
    
    // Kernel matrix
    std::vector<std::vector<double>> kernel_matrix;
};

// Hybrid optimizer
class IHybridOptimizer {
public:
    virtual ~IHybridOptimizer() = default;
    
    // Optimization
    virtual std::vector<double> Optimize(
        std::function<double(const std::vector<double>&)> objective_function,
        const std::vector<double>& initial_params,
        const std::vector<std::pair<double, double>>& bounds) = 0;
    
    // Callback
    virtual void SetCallback(std::function<void(uint32_t, double, const std::vector<double>&)> callback) = 0;
    
    // Convergence
    virtual bool HasConverged() const = 0;
    virtual uint32_t GetIterationCount() const = 0;
    virtual double GetCurrentValue() const = 0;
};

// COBYLA optimizer
class CobylaOptimizer : public IHybridOptimizer {
public:
    CobylaOptimizer(uint32_t max_iterations, double tolerance);
    
    std::vector<double> Optimize(
        std::function<double(const std::vector<double>&)> objective_function,
        const std::vector<double>& initial_params,
        const std::vector<std::pair<double, double>>& bounds) override;
    
    void SetCallback(std::function<void(uint32_t, double, const std::vector<double>&)> callback) override;
    
    bool HasConverged() const override;
    uint32_t GetIterationCount() const override;
    double GetCurrentValue() const override;
    
private:
    uint32_t max_iterations_;
    double tolerance_;
    uint32_t iteration_count_ = 0;
    double current_value_ = 0.0;
    bool converged_ = false;
    std::function<void(uint32_t, double, const std::vector<double>&)> callback_;
};

// SPSA optimizer
class SpsaOptimizer : public IHybridOptimizer {
public:
    SpsaOptimizer(uint32_t max_iterations, double learning_rate, double perturbation);
    
    std::vector<double> Optimize(
        std::function<double(const std::vector<double>&)> objective_function,
        const std::vector<double>& initial_params,
        const std::vector<std::pair<double, double>>& bounds) override;
    
    void SetCallback(std::function<void(uint32_t, double, const std::vector<double>&)> callback) override;
    
    bool HasConverged() const override;
    uint32_t GetIterationCount() const override;
    double GetCurrentValue() const override;
    
private:
    uint32_t max_iterations_;
    double learning_rate_;
    double perturbation_;
    uint32_t iteration_count_ = 0;
    double current_value_ = 0.0;
    bool converged_ = false;
    std::function<void(uint32_t, double, const std::vector<double>&)> callback_;
};

// Hybrid quantum-classical interface
class IHybridQuantumClassical {
public:
    virtual ~IHybridQuantumClassical() = default;
    
    // Initialization
    virtual bool Initialize(const std::string& config_path) = 0;
    virtual void Shutdown() = 0;
    
    // Task management
    virtual std::string SubmitTask(const HybridTask& task) = 0;
    virtual bool CancelTask(const std::string& task_id) = 0;
    virtual std::optional<HybridTask> GetTask(const std::string& task_id) = 0;
    virtual std::vector<HybridTask> ListTasks(HybridTask::State state = HybridTask::State::PENDING) = 0;
    
    // Task classification
    virtual TaskClass ClassifyTask(const std::string& task_description) = 0;
    virtual bool ShouldUseQuantum(const std::vector<double>& problem_params) = 0;
    
    // VQA execution
    virtual std::string ExecuteVQA(const VQAConfig& config, 
                                      const std::vector<double>& initial_params) = 0;
    virtual std::optional<HybridTask> GetVQAResult(const std::string& execution_id) = 0;
    
    // Quantum kernel methods
    virtual std::string CreateQuantumKernel(const QuantumFeatureMap& feature_map) = 0;
    virtual bool TrainKernel(const std::string& kernel_id,
                              const std::vector<std::vector<double>>& data,
                              const std::vector<int>& labels) = 0;
    virtual double ComputeKernelValue(const std::string& kernel_id,
                                       const std::vector<double>& x1,
                                       const std::vector<double>& x2) = 0;
    virtual int Predict(const std::string& kernel_id, const std::vector<double>& x) = 0;
    
    // Classical preprocessing
    virtual std::vector<double> PreprocessForQuantum(const std::vector<double>& classical_data) = 0;
    virtual std::vector<double> PostprocessFromQuantum(const std::vector<double>& quantum_results) = 0;
    
    // Optimization
    virtual std::string CreateOptimizer(const std::string& optimizer_type,
                                         const std::unordered_map<std::string, double>& params) = 0;
    virtual bool DestroyOptimizer(const std::string& optimizer_id) = 0;
    
    // Error mitigation
    virtual bool EnableErrorMitigation(const std::string& task_id, bool enable) = 0;
    virtual bool EnableMeasurementErrorMitigation(const std::string& task_id, bool enable) = 0;
    
    // Statistics
    virtual struct HybridStatistics {
        uint64_t total_tasks_submitted;
        uint64_t total_tasks_completed;
        uint64_t total_tasks_failed;
        uint64_t vqa_executions;
        uint64_t kernel_evaluations;
        double average_optimization_time_ms;
        double average_quantum_time_ms;
        double average_classical_time_ms;
        std::unordered_map<TaskClass, uint64_t> tasks_by_class;
    } GetStatistics() = 0;
};

// Local hybrid quantum-classical interface
class LocalHybridQuantumClassical : public IHybridQuantumClassical {
public:
    LocalHybridQuantumClassical();
    ~LocalHybridQuantumClassical() override;
    
    bool Initialize(const std::string& config_path) override;
    void Shutdown() override;
    
    std::string SubmitTask(const HybridTask& task) override;
    bool CancelTask(const std::string& task_id) override;
    std::optional<HybridTask> GetTask(const std::string& task_id) override;
    std::vector<HybridTask> ListTasks(HybridTask::State state = HybridTask::State::PENDING) override;
    
    TaskClass ClassifyTask(const std::string& task_description) override;
    bool ShouldUseQuantum(const std::vector<double>& problem_params) override;
    
    std::string ExecuteVQA(const VQAConfig& config, 
                          const std::vector<double>& initial_params) override;
    std::optional<HybridTask> GetVQAResult(const std::string& execution_id) override;
    
    std::string CreateQuantumKernel(const QuantumFeatureMap& feature_map) override;
    bool TrainKernel(const std::string& kernel_id,
                      const std::vector<std::vector<double>>& data,
                      const std::vector<int>& labels) override;
    double ComputeKernelValue(const std::string& kernel_id,
                               const std::vector<double>& x1,
                               const std::vector<double>& x2) override;
    int Predict(const std::string& kernel_id, const std::vector<double>& x) override;
    
    std::vector<double> PreprocessForQuantum(const std::vector<double>& classical_data) override;
    std::vector<double> PostprocessFromQuantum(const std::vector<double>& quantum_results) override;
    
    std::string CreateOptimizer(const std::string& optimizer_type,
                               const std::unordered_map<std::string, double>& params) override;
    bool DestroyOptimizer(const std::string& optimizer_id) override;
    
    bool EnableErrorMitigation(const std::string& task_id, bool enable) override;
    bool EnableMeasurementErrorMitigation(const std::string& task_id, bool enable) override;
    
    HybridStatistics GetStatistics() override;
    
private:
    std::unordered_map<std::string, HybridTask> tasks_;
    std::unordered_map<std::string, QuantumKernel> kernels_;
    std::unordered_map<std::string, std::unique_ptr<IHybridOptimizer>> optimizers_;
    bool initialized_ = false;
    
    bool ExecuteClassicalStep(HybridTask& task, const HybridTask::ExecutionStep& step);
    bool ExecuteQuantumStep(HybridTask& task, const HybridTask::ExecutionStep& step);
    double EvaluateQuantumCircuit(const std::string& circuit_id, const std::vector<double>& params);
    TaskClass AnalyzeProblemStructure(const std::string& description);
};

// Global hybrid interface
extern std::unique_ptr<IHybridQuantumClassical> g_hybrid_quantum_classical;

// Initialize hybrid quantum-classical
bool InitializeHybridQuantumClassical(const std::string& config_path);
void ShutdownHybridQuantumClassical();
bool IsHybridQuantumClassicalEnabled();

} // namespace Quantum
} // namespace RawrXD
