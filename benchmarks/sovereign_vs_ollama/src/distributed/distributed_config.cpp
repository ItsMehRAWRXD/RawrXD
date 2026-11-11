// distributed_config.cpp
// Batch 14: Distributed Configuration Management
//
// Configuration for distributed benchmarking setup
// Features: Node roles, network settings, consensus configuration

#include <string>
#include <vector>
#include <map>
#include <optional>
#include <fstream>
#include <sstream>

namespace Benchmark {
namespace Distributed {

// Node role
enum class NodeRole {
    COORDINATOR,
    WORKER,
    STANDALONE
};

// Network configuration
struct NetworkConfig {
    std::string bind_address = "0.0.0.0";
    int coordinator_port = 9090;
    int worker_port = 9091;
    int discovery_port = 9092;
    std::string coordinator_host;
    int connection_timeout_ms = 10000;
    int request_timeout_ms = 30000;
    int max_retries = 3;
    bool enable_ssl = false;
    std::string ssl_cert_path;
    std::string ssl_key_path;
};

// Consensus configuration
struct ConsensusConfig {
    int replication_factor = 3;
    int min_nodes = 2;
    int max_nodes = 100;
    int election_timeout_ms = 1000;
    int heartbeat_interval_ms = 100;
    bool strict_consensus = false;
    double consensus_threshold = 0.67;
};

// Resource limits
struct ResourceLimits {
    int max_concurrent_jobs = 4;
    int max_queue_size = 100;
    size_t max_memory_mb = 8192;
    int max_cpu_percent = 80;
    int disk_quota_gb = 100;
};

// Distributed configuration
struct DistributedConfig {
    NodeRole role = NodeRole::STANDALONE;
    std::string node_id;
    std::string cluster_name = "benchmark-cluster";
    std::string data_directory = "./distributed_data";

    NetworkConfig network;
    ConsensusConfig consensus;
    ResourceLimits resources;

    // Discovery settings
    bool enable_discovery = true;
    std::vector<std::string> seed_nodes;
    int discovery_interval_ms = 30000;

    // Fault tolerance
    bool enable_fault_tolerance = true;
    int job_retry_count = 3;
    bool enable_checkpointing = true;
    int checkpoint_interval_ms = 60000;

    // Performance tuning
    int worker_threads = 4;
    int io_threads = 2;
    bool enable_compression = true;
    int compression_level = 6;
};

// Configuration manager
class DistributedConfigManager {
public:
    // Load configuration from file
    bool LoadFromFile(const std::string& filename) {
        std::ifstream file(filename);
        if (!file.is_open()) {
            return false;
        }

        std::string line;
        while (std::getline(file, line)) {
            // Parse key=value pairs
            size_t pos = line.find('=');
            if (pos != std::string::npos) {
                std::string key = Trim(line.substr(0, pos));
                std::string value = Trim(line.substr(pos + 1));

                ParseConfigValue(key, value);
            }
        }

        return Validate();
    }

    // Save configuration to file
    bool SaveToFile(const std::string& filename) const {
        std::ofstream file(filename);
        if (!file.is_open()) {
            return false;
        }

        file << "# Distributed Benchmark Configuration" << std::endl;
        file << std::endl;

        file << "# Node Settings" << std::endl;
        file << "role=" << RoleToString(config_.role) << std::endl;
        file << "node_id=" << config_.node_id << std::endl;
        file << "cluster_name=" << config_.cluster_name << std::endl;
        file << std::endl;

        file << "# Network Settings" << std::endl;
        file << "bind_address=" << config_.network.bind_address << std::endl;
        file << "coordinator_port=" << config_.network.coordinator_port << std::endl;
        file << "worker_port=" << config_.network.worker_port << std::endl;
        file << std::endl;

        file << "# Consensus Settings" << std::endl;
        file << "replication_factor=" << config_.consensus.replication_factor << std::endl;
        file << "min_nodes=" << config_.consensus.min_nodes << std::endl;
        file << std::endl;

        file << "# Resource Limits" << std::endl;
        file << "max_concurrent_jobs=" << config_.resources.max_concurrent_jobs << std::endl;
        file << "max_memory_mb=" << config_.resources.max_memory_mb << std::endl;
        file << std::endl;

        return true;
    }

    // Get configuration
    const DistributedConfig& GetConfig() const {
        return config_;
    }

    // Set configuration
    void SetConfig(const DistributedConfig& config) {
        config_ = config;
    }

    // Update specific value
    void SetValue(const std::string& key, const std::string& value) {
        ParseConfigValue(key, value);
    }

    // Get value as string
    std::string GetValue(const std::string& key) const {
        if (key == "role") return RoleToString(config_.role);
        if (key == "node_id") return config_.node_id;
        if (key == "cluster_name") return config_.cluster_name;
        if (key == "bind_address") return config_.network.bind_address;
        if (key == "coordinator_port") return std::to_string(config_.network.coordinator_port);
        if (key == "worker_port") return std::to_string(config_.network.worker_port);
        if (key == "max_concurrent_jobs") return std::to_string(config_.resources.max_concurrent_jobs);
        return "";
    }

    // Validate configuration
    bool Validate() const {
        // Check required fields
        if (config_.node_id.empty()) {
            return false;
        }

        // Check port ranges
        if (config_.network.coordinator_port < 1024 ||
            config_.network.coordinator_port > 65535) {
            return false;
        }

        // Check resource limits
        if (config_.resources.max_concurrent_jobs < 1) {
            return false;
        }

        return true;
    }

    // Generate default configuration for role
    static DistributedConfig GenerateDefaultConfig(NodeRole role) {
        DistributedConfig config;
        config.role = role;
        config.node_id = GenerateNodeID();

        switch (role) {
            case NodeRole::COORDINATOR:
                config.network.coordinator_port = 9090;
                config.resources.max_concurrent_jobs = 0;  // Coordinator doesn't run jobs
                break;

            case NodeRole::WORKER:
                config.network.worker_port = 9091;
                config.resources.max_concurrent_jobs = 4;
                break;

            case NodeRole::STANDALONE:
                config.network.coordinator_port = 9090;
                config.resources.max_concurrent_jobs = 4;
                break;
        }

        return config;
    }

    // Export to environment variables
    std::map<std::string, std::string> ToEnvironment() const {
        std::map<std::string, std::string> env;

        env["BENCHMARK_ROLE"] = RoleToString(config_.role);
        env["BENCHMARK_NODE_ID"] = config_.node_id;
        env["BENCHMARK_CLUSTER_NAME"] = config_.cluster_name;
        env["BENCHMARK_BIND_ADDRESS"] = config_.network.bind_address;
        env["BENCHMARK_COORDINATOR_PORT"] = std::to_string(config_.network.coordinator_port);
        env["BENCHMARK_WORKER_PORT"] = std::to_string(config_.network.worker_port);

        return env;
    }

    // Import from environment variables
    void FromEnvironment() {
        const char* role = std::getenv("BENCHMARK_ROLE");
        if (role) {
            config_.role = ParseRole(role);
        }

        const char* node_id = std::getenv("BENCHMARK_NODE_ID");
        if (node_id) {
            config_.node_id = node_id;
        }

        const char* cluster = std::getenv("BENCHMARK_CLUSTER_NAME");
        if (cluster) {
            config_.cluster_name = cluster;
        }

        const char* bind = std::getenv("BENCHMARK_BIND_ADDRESS");
        if (bind) {
            config_.network.bind_address = bind;
        }

        const char* coord_port = std::getenv("BENCHMARK_COORDINATOR_PORT");
        if (coord_port) {
            config_.network.coordinator_port = std::stoi(coord_port);
        }

        const char* worker_port = std::getenv("BENCHMARK_WORKER_PORT");
        if (worker_port) {
            config_.network.worker_port = std::stoi(worker_port);
        }
    }

private:
    DistributedConfig config_;

    void ParseConfigValue(const std::string& key, const std::string& value) {
        if (key == "role") {
            config_.role = ParseRole(value);
        } else if (key == "node_id") {
            config_.node_id = value;
        } else if (key == "cluster_name") {
            config_.cluster_name = value;
        } else if (key == "bind_address") {
            config_.network.bind_address = value;
        } else if (key == "coordinator_port") {
            config_.network.coordinator_port = std::stoi(value);
        } else if (key == "worker_port") {
            config_.network.worker_port = std::stoi(value);
        } else if (key == "max_concurrent_jobs") {
            config_.resources.max_concurrent_jobs = std::stoi(value);
        } else if (key == "max_memory_mb") {
            config_.resources.max_memory_mb = std::stoul(value);
        } else if (key == "enable_discovery") {
            config_.enable_discovery = (value == "true" || value == "1");
        }
    }

    static std::string RoleToString(NodeRole role) {
        switch (role) {
            case NodeRole::COORDINATOR: return "coordinator";
            case NodeRole::WORKER: return "worker";
            case NodeRole::STANDALONE: return "standalone";
            default: return "unknown";
        }
    }

    static NodeRole ParseRole(const std::string& str) {
        if (str == "coordinator") return NodeRole::COORDINATOR;
        if (str == "worker") return NodeRole::WORKER;
        if (str == "standalone") return NodeRole::STANDALONE;
        return NodeRole::STANDALONE;
    }

    static std::string GenerateNodeID() {
        return "node_" + std::to_string(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
    }

    std::string Trim(const std::string& str) {
        size_t first = str.find_first_not_of(" \t\n\r");
        if (first == std::string::npos) return "";
        size_t last = str.find_last_not_of(" \t\n\r");
        return str.substr(first, last - first + 1);
    }
};

// Cluster topology manager
class ClusterTopology {
public:
    struct Topology {
        std::string cluster_id;
        int64_t created_at;
        std::vector<std::string> coordinator_nodes;
        std::vector<std::string> worker_nodes;
        std::map<std::string, std::vector<std::string>> rack_layout;
    };

    // Load topology from file
    bool Load(const std::string& filename) {
        // In production: Load from JSON/YAML
        return true;
    }

    // Save topology to file
    bool Save(const std::string& filename) const {
        // In production: Save to JSON/YAML
        return true;
    }

    // Get optimal worker for job
    std::optional<std::string> GetOptimalWorker(
        const std::vector<std::string>& available_workers,
        const std::map<std::string, double>& worker_loads) {

        if (available_workers.empty()) return std::nullopt;

        // Find worker with lowest load
        std::string best_worker;
        double min_load = std::numeric_limits<double>::max();

        for (const auto& worker : available_workers) {
            auto it = worker_loads.find(worker);
            double load = (it != worker_loads.end()) ? it->second : 0.0;

            if (load < min_load) {
                min_load = load;
                best_worker = worker;
            }
        }

        return best_worker;
    }

    // Get workers in same rack
    std::vector<std::string> GetRackWorkers(const std::string& rack_id) {
        auto it = topology_.rack_layout.find(rack_id);
        if (it != topology_.rack_layout.end()) {
            return it->second;
        }
        return {};
    }

private:
    Topology topology_;
};

} // namespace Distributed
} // namespace Benchmark
