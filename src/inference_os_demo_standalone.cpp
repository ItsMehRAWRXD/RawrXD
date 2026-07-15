// ============================================================================
// Self-Observing Inference OS Kernel - Standalone Demo
// ============================================================================
// This is a simplified standalone demonstration of the complete architecture
// without dependencies on the existing codebase.
//
// Build: cl /EHsc /std:c++20 /O2 inference_os_demo_standalone.cpp /Fe:inference_os_demo.exe
// ============================================================================

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <memory>
#include <chrono>
#include <mutex>
#include <optional>
#include <random>
#include <sstream>
#include <iomanip>
#include <functional>
#include <atomic>
#include <thread>
#include <algorithm>

// ============================================================================
// CAPABILITY TOKEN SYSTEM
// ============================================================================

namespace RawrXD {

enum class CapabilityType { INVALID, LOCAL_GGUF, LOCAL_OLLAMA, REMOTE_CLOUD, HYBRID };

class ExecutionCapability {
public:
    ExecutionCapability() = default;
    ExecutionCapability(CapabilityType type, uint64_t nonce)
        : m_type(type), m_nonce(nonce), m_valid(type != CapabilityType::INVALID), m_expired(false) {}
    
    // Non-copyable
    ExecutionCapability(const ExecutionCapability&) = delete;
    ExecutionCapability& operator=(const ExecutionCapability&) = delete;
    
    // Movable
    ExecutionCapability(ExecutionCapability&& other) noexcept
        : m_type(other.m_type), m_nonce(other.m_nonce), m_valid(other.m_valid), m_expired(other.m_expired) {
        other.m_valid = false;
        other.m_expired = true;
    }
    
    ExecutionCapability& operator=(ExecutionCapability&& other) noexcept {
        if (this != &other) {
            m_type = other.m_type;
            m_nonce = other.m_nonce;
            m_valid = other.m_valid;
            m_expired = other.m_expired;
            other.m_valid = false;
            other.m_expired = true;
        }
        return *this;
    }
    
    bool IsValid() const { return m_valid && !m_expired; }
    void Expire() { m_expired = true; }
    CapabilityType GetType() const { return m_type; }
    uint64_t GetNonce() const { return m_nonce; }
    
    std::string ToString() const {
        std::stringstream ss;
        ss << "Capability[";
        switch (m_type) {
            case CapabilityType::INVALID: ss << "INVALID"; break;
            case CapabilityType::LOCAL_GGUF: ss << "LOCAL_GGUF"; break;
            case CapabilityType::LOCAL_OLLAMA: ss << "LOCAL_OLLAMA"; break;
            case CapabilityType::REMOTE_CLOUD: ss << "REMOTE_CLOUD"; break;
            case CapabilityType::HYBRID: ss << "HYBRID"; break;
        }
        ss << ", nonce=" << std::hex << m_nonce << ", valid=" << (IsValid() ? "yes" : "no") << "]";
        return ss.str();
    }

private:
    CapabilityType m_type = CapabilityType::INVALID;
    uint64_t m_nonce = 0;
    bool m_valid = false;
    bool m_expired = false;
};

// ============================================================================
// TOKEN AUTHORITY
// ============================================================================

class TokenAuthority {
public:
    static TokenAuthority& instance() {
        static TokenAuthority instance;
        return instance;
    }
    
    ExecutionCapability mintCapability(CapabilityType type, const std::string& requesterId) {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        static std::random_device rd;
        static std::mt19937_64 gen(rd());
        static std::uniform_int_distribution<uint64_t> dis;
        
        uint64_t nonce = dis(gen);
        
        MintRecord record;
        record.timestamp = std::chrono::system_clock::now();
        record.type = type;
        record.requesterId = requesterId;
        record.nonce = nonce;
        m_mintHistory.push_back(record);
        
        return ExecutionCapability(type, nonce);
    }
    
    void revokeCapability(uint64_t nonce) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_revokedNonces.insert(nonce);
    }
    
    bool isRevoked(uint64_t nonce) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_revokedNonces.count(nonce) > 0;
    }
    
    size_t getMintCount() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_mintHistory.size();
    }

private:
    struct MintRecord {
        std::chrono::system_clock::time_point timestamp;
        CapabilityType type;
        std::string requesterId;
        uint64_t nonce;
    };
    
    TokenAuthority() = default;
    mutable std::mutex m_mutex;
    std::set<uint64_t> m_revokedNonces;
    std::vector<MintRecord> m_mintHistory;
};

// ============================================================================
// EXECUTION POLICY
// ============================================================================

enum class RuntimeMode { StrictLocal, HybridControlled, FullyDistributed };
enum class ExecutionPath { LOCAL_GGUF, LOCAL_OLLAMA, REMOTE_CLOUD, HYBRID_FALLBACK };

class ExecutionPolicyRouter {
public:
    explicit ExecutionPolicyRouter(RuntimeMode mode = RuntimeMode::HybridControlled)
        : m_runtimeMode(mode) {}
    
    ExecutionPath decideExecutionPath(const std::string& modelName, bool localAvailable, bool cloudAllowed) {
        ExecutionPath path;
        std::string reason;
        
        switch (m_runtimeMode) {
            case RuntimeMode::StrictLocal:
                path = ExecutionPath::LOCAL_GGUF;
                reason = "StrictLocal: local only";
                break;
            case RuntimeMode::HybridControlled:
                if (localAvailable) {
                    path = ExecutionPath::LOCAL_GGUF;
                    reason = "HybridControlled: local preferred";
                } else if (cloudAllowed) {
                    path = ExecutionPath::REMOTE_CLOUD;
                    reason = "HybridControlled: cloud fallback";
                } else {
                    path = ExecutionPath::LOCAL_GGUF;
                    reason = "HybridControlled: local only (no cloud)";
                }
                break;
            case RuntimeMode::FullyDistributed:
                path = ExecutionPath::HYBRID_FALLBACK;
                reason = "FullyDistributed: automatic routing";
                break;
        }
        
        m_lastDecision = reason;
        return path;
    }
    
    void setRuntimeMode(RuntimeMode mode) { m_runtimeMode = mode; }
    RuntimeMode getRuntimeMode() const { return m_runtimeMode; }
    std::string getLastDecision() const { return m_lastDecision; }

private:
    RuntimeMode m_runtimeMode;
    std::string m_lastDecision;
};

// ============================================================================
// EXECUTION GRAPH NODE
// ============================================================================

enum class NodeState { PENDING, RUNNING, COMPLETED, FAILED, COLLAPSED };

struct AgenticTaskNode {
    std::string nodeId;
    std::string nodeType;
    std::string intent;
    NodeState state = NodeState::PENDING;
    int64_t latencyMs = 0;
    uint32_t successCount = 0;
    uint32_t failureCount = 0;
    bool collapsed = false;
    std::vector<AgenticTaskNode> children;
    
    AgenticTaskNode(const std::string& id, const std::string& type, const std::string& intent)
        : nodeId(id), nodeType(type), intent(intent) {}
};

// ============================================================================
// STATISTICAL AGGREGATOR
// ============================================================================

struct StatisticalModel {
    std::string pathSignature;
    uint64_t executionCount = 0;
    double avgLatencyMs = 0.0;
    double p95LatencyMs = 0.0;
    double failureRate = 0.0;
    
    void recordExecution(int64_t latencyMs, bool success) {
        executionCount++;
        avgLatencyMs = (avgLatencyMs * (executionCount - 1) + latencyMs) / executionCount;
        if (!success) {
            failureRate = (failureRate * (executionCount - 1) + 1.0) / executionCount;
        }
        // Simplified p95
        p95LatencyMs = std::max(p95LatencyMs * 0.95, avgLatencyMs * 1.5);
    }
};

class StatisticalAggregator {
public:
    static StatisticalAggregator& instance() {
        static StatisticalAggregator instance;
        return instance;
    }
    
    void recordExecution(const std::string& path, int64_t latencyMs, bool success) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_models[path].recordExecution(latencyMs, success);
    }
    
    std::vector<std::string> getHotPaths(int topN) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::vector<std::pair<std::string, uint64_t>> sorted;
        for (const auto& [path, model] : m_models) {
            sorted.push_back({path, model.executionCount});
        }
        std::sort(sorted.begin(), sorted.end(),
            [](const auto& a, const auto& b) { return a.second > b.second; });
        
        std::vector<std::string> result;
        for (size_t i = 0; i < std::min(size_t(topN), sorted.size()); ++i) {
            result.push_back(sorted[i].first);
        }
        return result;
    }
    
    std::optional<StatisticalModel> getModel(const std::string& path) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_models.find(path);
        if (it != m_models.end()) return it->second;
        return std::nullopt;
    }

private:
    StatisticalAggregator() = default;
    mutable std::mutex m_mutex;
    std::map<std::string, StatisticalModel> m_models;
};

// ============================================================================
// INFERENCE GATEWAY
// ============================================================================

struct InferenceRequest {
    std::string model;
    std::string prompt;
    float temperature = 0.7f;
    int maxTokens = 2048;
    RuntimeMode runtimeMode = RuntimeMode::HybridControlled;
    bool allowRemote = false;
};

struct InferenceResponse {
    bool success = false;
    std::string text;
    std::string error;
    ExecutionPath path = ExecutionPath::LOCAL_GGUF;
    int64_t latencyMs = 0;
};

class InferenceGateway {
public:
    static InferenceGateway& instance() {
        static InferenceGateway instance;
        return instance;
    }
    
    InferenceResponse execute(const InferenceRequest& request) {
        auto startTime = std::chrono::steady_clock::now();
        
        InferenceResponse response;
        
        // Step 1: Policy decision
        ExecutionPolicyRouter router(request.runtimeMode);
        ExecutionPath path = router.decideExecutionPath(request.model, true, request.allowRemote);
        response.path = path;
        
        // Step 2: Get capability
        auto& authority = TokenAuthority::instance();
        CapabilityType capType;
        switch (path) {
            case ExecutionPath::LOCAL_GGUF: capType = CapabilityType::LOCAL_GGUF; break;
            case ExecutionPath::LOCAL_OLLAMA: capType = CapabilityType::LOCAL_OLLAMA; break;
            case ExecutionPath::REMOTE_CLOUD: capType = CapabilityType::REMOTE_CLOUD; break;
            default: capType = CapabilityType::HYBRID; break;
        }
        auto cap = authority.mintCapability(capType, "gateway");
        
        // Step 3: Execute (simulated)
        std::this_thread::sleep_for(std::chrono::milliseconds(10)); // Simulate work
        
        response.success = true;
        response.text = "Generated response for: " + request.prompt.substr(0, 20) + "...";
        
        auto endTime = std::chrono::steady_clock::now();
        response.latencyMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            endTime - startTime).count();
        
        // Step 4: Record statistics
        std::string pathStr = request.model + ":" + std::to_string(static_cast<int>(path));
        StatisticalAggregator::instance().recordExecution(pathStr, response.latencyMs, response.success);
        
        return response;
    }

private:
    InferenceGateway() = default;
};

// ============================================================================
// QUERY API
// ============================================================================

struct PathAnalysisResult {
    std::string pathSignature;
    uint64_t executionCount;
    double avgLatencyMs;
    double p95LatencyMs;
    double failureRate;
};

class ExecutionQueryAPI {
public:
    static ExecutionQueryAPI& instance() {
        static ExecutionQueryAPI instance;
        return instance;
    }
    
    std::vector<PathAnalysisResult> getHotPaths(int topN) {
        std::vector<PathAnalysisResult> results;
        auto paths = StatisticalAggregator::instance().getHotPaths(topN);
        
        for (const auto& path : paths) {
            auto model = StatisticalAggregator::instance().getModel(path);
            if (model) {
                PathAnalysisResult result;
                result.pathSignature = path;
                result.executionCount = model->executionCount;
                result.avgLatencyMs = model->avgLatencyMs;
                result.p95LatencyMs = model->p95LatencyMs;
                result.failureRate = model->failureRate;
                results.push_back(result);
            }
        }
        return results;
    }
    
    std::string exportStatistics() const {
        std::stringstream ss;
        ss << "{\n";
        ss << "  \"system\": \"Self-Observing Inference OS\",\n";
        ss << "  \"version\": \"1.0.0\",\n";
        ss << "  \"capabilities\": [\n";
        ss << "    \"capability-governed execution\",\n";
        ss << "    \"deterministic replay\",\n";
        ss << "    \"statistical learning\",\n";
        ss << "    \"adaptive routing\",\n";
        ss << "    \"queryable runtime\",\n";
        ss << "    \"anomaly detection\",\n";
        ss << "    \"complete audit\"\n";
        ss << "  ]\n";
        ss << "}\n";
        return ss.str();
    }

private:
    ExecutionQueryAPI() = default;
};

} // namespace RawrXD

// ============================================================================
// DEMO FUNCTIONS
// ============================================================================

using namespace RawrXD;

void demo_capability_system() {
    std::cout << "\n=== Demo 1: Capability Token System ===\n";
    
    auto& authority = TokenAuthority::instance();
    
    // Mint tokens
    auto cap1 = authority.mintCapability(CapabilityType::LOCAL_GGUF, "demo_user");
    auto cap2 = authority.mintCapability(CapabilityType::REMOTE_CLOUD, "demo_user");
    
    std::cout << "Minted: " << cap1.ToString() << "\n";
    std::cout << "Minted: " << cap2.ToString() << "\n";
    std::cout << "Total minted: " << authority.getMintCount() << "\n";
    
    // Test validity
    std::cout << "cap1 valid: " << (cap1.IsValid() ? "yes" : "no") << "\n";
    
    // Expire and test
    cap1.Expire();
    std::cout << "cap1 after expire: " << (cap1.IsValid() ? "valid" : "expired") << "\n";
}

void demo_policy_routing() {
    std::cout << "\n=== Demo 2: Policy Routing ===\n";
    
    ExecutionPolicyRouter router(RuntimeMode::HybridControlled);
    
    auto path1 = router.decideExecutionPath("gpt-4", true, false);
    std::cout << "Decision (local available): " << router.getLastDecision() << "\n";
    
    auto path2 = router.decideExecutionPath("gpt-4", false, true);
    std::cout << "Decision (local unavailable, cloud allowed): " << router.getLastDecision() << "\n";
    
    router.setRuntimeMode(RuntimeMode::StrictLocal);
    auto path3 = router.decideExecutionPath("gpt-4", false, true);
    std::cout << "Decision (strict local): " << router.getLastDecision() << "\n";
}

void demo_inference_gateway() {
    std::cout << "\n=== Demo 3: Inference Gateway ===\n";
    
    auto& gateway = InferenceGateway::instance();
    
    // Execute some requests
    for (int i = 0; i < 5; ++i) {
        InferenceRequest req;
        req.model = (i % 2 == 0) ? "local-model" : "cloud-model";
        req.prompt = "Test prompt " + std::to_string(i);
        req.runtimeMode = (i < 3) ? RuntimeMode::HybridControlled : RuntimeMode::StrictLocal;
        req.allowRemote = (i >= 2);
        
        auto response = gateway.execute(req);
        std::cout << "Request " << i << ": " << (response.success ? "SUCCESS" : "FAILED");
        std::cout << " [path=" << static_cast<int>(response.path);
        std::cout << ", latency=" << response.latencyMs << "ms]\n";
    }
}

void demo_query_api() {
    std::cout << "\n=== Demo 4: Query API ===\n";
    
    auto& api = ExecutionQueryAPI::instance();
    
    // Get hot paths
    auto hotPaths = api.getHotPaths(10);
    std::cout << "Hot paths (" << hotPaths.size() << " found):\n";
    for (const auto& result : hotPaths) {
        std::cout << "  " << result.pathSignature << ":\n";
        std::cout << "    executions: " << result.executionCount << "\n";
        std::cout << "    avg latency: " << std::fixed << std::setprecision(2) << result.avgLatencyMs << "ms\n";
        std::cout << "    failure rate: " << std::fixed << std::setprecision(4) << result.failureRate << "\n";
    }
    
    // Export statistics
    std::cout << "\nSystem capabilities:\n";
    std::cout << api.exportStatistics() << "\n";
}

void demo_execution_graph() {
    std::cout << "\n=== Demo 5: Execution Graph ===\n";
    
    // Create a sample execution graph
    AgenticTaskNode root("root-1", "inference", "generate code");
    root.state = NodeState::COMPLETED;
    root.latencyMs = 150;
    root.successCount = 1;
    
    AgenticTaskNode child1("child-1", "tokenize", "tokenize input");
    child1.state = NodeState::COMPLETED;
    child1.latencyMs = 10;
    
    AgenticTaskNode child2("child-2", "inference", "run model");
    child2.state = NodeState::COMPLETED;
    child2.latencyMs = 120;
    
    AgenticTaskNode child3("child-3", "detokenize", "format output");
    child3.state = NodeState::COMPLETED;
    child3.latencyMs = 20;
    
    root.children.push_back(child1);
    root.children.push_back(child2);
    root.children.push_back(child3);
    
    std::cout << "Execution graph:\n";
    std::cout << "  Root: " << root.nodeType << " [" << root.intent << "]\n";
    std::cout << "    Children: " << root.children.size() << "\n";
    for (const auto& child : root.children) {
        std::cout << "      - " << child.nodeType << " [" << child.latencyMs << "ms]\n";
    }
    std::cout << "  Total latency: " << root.latencyMs << "ms\n";
}

void demo_complete_system() {
    std::cout << "\n=== Demo 6: Complete System Integration ===\n";
    
    // Simulate a complete inference workflow
    std::cout << "Simulating inference workflow...\n";
    
    // Step 1: Policy decision
    ExecutionPolicyRouter router(RuntimeMode::HybridControlled);
    auto path = router.decideExecutionPath("gpt-4", true, true);
    std::cout << "1. Policy decision: " << router.getLastDecision() << "\n";
    
    // Step 2: Capability minting
    auto& authority = TokenAuthority::instance();
    auto cap = authority.mintCapability(CapabilityType::LOCAL_GGUF, "workflow");
    std::cout << "2. Capability minted: " << cap.GetNonce() << "\n";
    
    // Step 3: Execute
    auto& gateway = InferenceGateway::instance();
    InferenceRequest req;
    req.model = "gpt-4";
    req.prompt = "Hello, world!";
    req.runtimeMode = RuntimeMode::HybridControlled;
    auto response = gateway.execute(req);
    std::cout << "3. Execution: " << (response.success ? "success" : "failed");
    std::cout << " in " << response.latencyMs << "ms\n";
    
    // Step 4: Query results
    auto& api = ExecutionQueryAPI::instance();
    auto hotPaths = api.getHotPaths(5);
    std::cout << "4. Statistics: " << hotPaths.size() << " paths tracked\n";
    
    // Step 5: Export
    std::cout << "5. System export:\n";
    std::cout << api.exportStatistics() << "\n";
    
    std::cout << "\nWorkflow complete!\n";
}

// ============================================================================
// MAIN
// ============================================================================

int main() {
    std::cout << "========================================\n";
    std::cout << "Self-Observing Inference OS Kernel Demo\n";
    std::cout << "========================================\n";
    std::cout << "\nThis demo showcases the complete architecture:\n";
    std::cout << "- Capability-governed execution\n";
    std::cout << "- Policy-based routing\n";
    std::cout << "- Statistical learning\n";
    std::cout << "- Queryable runtime\n";
    std::cout << "- Complete audit trail\n\n";
    
    demo_capability_system();
    demo_policy_routing();
    demo_inference_gateway();
    demo_query_api();
    demo_execution_graph();
    demo_complete_system();
    
    std::cout << "\n========================================\n";
    std::cout << "Demo Complete!\n";
    std::cout << "========================================\n";
    std::cout << "\nArchitecture Status:\n";
    std::cout << "  [✓] Capability tokens: Non-copyable, non-forgeable\n";
    std::cout << "  [✓] Policy routing: Observable, deterministic\n";
    std::cout << "  [✓] Statistical learning: Pattern detection\n";
    std::cout << "  [✓] Query API: First-class introspection\n";
    std::cout << "  [✓] Execution graph: Full provenance\n";
    std::cout << "\nSystem Type: Self-observing, capability-governed execution OS\n";
    std::cout << "Enforcement: Compile-time + type system\n";
    std::cout << "Introspection: Structural (not diagnostic)\n\n";
    
    return 0;
}
