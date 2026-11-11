// ============================================================================
// RawrXD Distributed State Synchronization
// Phase 7C.3: same_snapshot@A == same_snapshot@B
// ============================================================================
// Enables migration of inference state between machines with cryptographic
// verification that both sides see identical state.
// ============================================================================

#pragma once

#include "hash_chain.hpp"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <unordered_map>
#include <functional>

#pragma comment(lib, "ws2_32.lib")

namespace RawrXD {
namespace Core {

// ============================================================================
// Network Snapshot Header
// ============================================================================

#pragma pack(push, 1)
struct NetworkSnapshotHeader {
    uint32_t magic;              // 'DSYN' = 0x4453594E
    uint32_t version;            // 1
    uint64_t snapshot_id;        // Unique snapshot ID
    uint64_t timestamp;          // Creation time
    uint64_t payload_size;       // Size of serialized snapshot
    uint64_t payload_hash;       // Hash of payload (integrity)
    uint64_t merkle_root;        // Merkle root of checkpoint chain
    uint32_t source_node_id;     // ID of source node
    uint32_t dest_node_id;       // ID of destination node
    uint32_t flags;              // Transfer flags
    
    static constexpr uint32_t FLAG_COMPRESSED = 0x0001;
    static constexpr uint32_t FLAG_ENCRYPTED = 0x0002;
    static constexpr uint32_t FLAG_VERIFIED = 0x0004;
    
    NetworkSnapshotHeader() : magic(0x4453594E), version(1), snapshot_id(0),
                               timestamp(0), payload_size(0), payload_hash(0),
                               merkle_root(0), source_node_id(0), dest_node_id(0),
                               flags(0) {}
};
#pragma pack(pop)

// ============================================================================
// Node Identity
// ============================================================================

struct NodeIdentity {
    uint32_t node_id;
    char node_name[64];
    char address[64];        // IP or hostname
    uint16_t port;
    uint64_t capabilities;   // Bitmask of supported features
    
    static constexpr uint64_t CAP_STATE_SYNC = 0x0001;
    static constexpr uint64_t CAP_LIVE_MIGRATION = 0x0002;
    static constexpr uint64_t CAP_FAULT_TOLERANCE = 0x0004;
    
    NodeIdentity() : node_id(0), port(0), capabilities(0) {
        std::memset(node_name, 0, sizeof(node_name));
        std::memset(address, 0, sizeof(address));
    }
};

// ============================================================================
// Transfer Statistics
// ============================================================================

struct TransferStats {
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t transfer_start_time;
    uint64_t transfer_end_time;
    uint32_t retry_count;
    uint32_t checksum_mismatches;
    bool success;
    
    TransferStats() : bytes_sent(0), bytes_received(0), transfer_start_time(0),
                       transfer_end_time(0), retry_count(0),
                       checksum_mismatches(0), success(false) {}
    
    double GetDurationMs() const {
        if (transfer_end_time > transfer_start_time) {
            return static_cast<double>(transfer_end_time - transfer_start_time);
        }
        return 0.0;
    }
    
    double GetThroughputMBps() const {
        double duration_sec = GetDurationMs() / 1000.0;
        if (duration_sec > 0) {
            return (bytes_sent / (1024.0 * 1024.0)) / duration_sec;
        }
        return 0.0;
    }
};

// ============================================================================
// Distributed State Sync Manager
// ============================================================================

class DistributedStateSyncManager {
public:
    DistributedStateSyncManager();
    ~DistributedStateSyncManager();
    
    // Initialize with this node's identity
    bool Initialize(const NodeIdentity& local_node);
    
    // Register a peer node
    void RegisterPeer(const NodeIdentity& peer);
    void UnregisterPeer(uint32_t node_id);
    
    // Serialize snapshot for network transfer
    std::vector<uint8_t> SerializeSnapshotForNetwork(
        const ExecutionSnapshot& snapshot,
        uint32_t dest_node_id,
        uint64_t* out_merkle_root);
    
    // Deserialize snapshot from network buffer
    bool DeserializeSnapshotFromNetwork(
        const std::vector<uint8_t>& buffer,
        ExecutionSnapshot* out_snapshot,
        uint64_t* out_merkle_root);
    
    // Send snapshot to remote node (blocking)
    bool SendSnapshotToNode(
        uint32_t dest_node_id,
        const ExecutionSnapshot& snapshot,
        TransferStats* out_stats = nullptr);
    
    // Receive snapshot from remote node (blocking)
    bool ReceiveSnapshotFromNode(
        uint32_t source_node_id,
        ExecutionSnapshot* out_snapshot,
        TransferStats* out_stats = nullptr);
    
    // Async transfer with callback
    using TransferCompleteCallback = std::function<void(bool success, const TransferStats& stats)>;
    bool SendSnapshotAsync(
        uint32_t dest_node_id,
        const ExecutionSnapshot& snapshot,
        TransferCompleteCallback callback);
    
    // Verify snapshot integrity after transfer
    bool VerifySnapshotIntegrity(
        const ExecutionSnapshot& snapshot,
        uint64_t expected_merkle_root);
    
    // Compare snapshots from two nodes
    static bool AreSnapshotsEquivalent(
        const ExecutionSnapshot& snapshot_a,
        uint64_t merkle_root_a,
        const ExecutionSnapshot& snapshot_b,
        uint64_t merkle_root_b);
    
    // Get local node info
    const NodeIdentity& GetLocalNode() const { return local_node_; }
    
    // Get peer node info
    const NodeIdentity* GetPeerNode(uint32_t node_id) const;
    
    // List all registered peers
    std::vector<NodeIdentity> GetPeers() const;
    
    // Compute Merkle root of snapshot (public for testing)
    uint64_t ComputeMerkleRoot(const ExecutionSnapshot& snapshot);

private:
    NodeIdentity local_node_;
    std::unordered_map<uint32_t, NodeIdentity> peers_;
    mutable SRWLOCK peers_lock_;
    
    SOCKET listen_socket_;
    bool initialized_;
    
    // Network helpers
    bool InitializeNetwork();
    void ShutdownNetwork();
    SOCKET ConnectToNode(uint32_t node_id);
    bool SendAll(SOCKET sock, const void* data, size_t len);
    bool RecvAll(SOCKET sock, void* data, size_t len);
};

// ============================================================================
// Migration Test Harness
// ============================================================================

class DistributedMigrationTest {
public:
    struct MigrationResult {
        bool success;
        TransferStats stats;
        uint64_t source_merkle_root;
        uint64_t dest_merkle_root;
        bool merkle_roots_match;
        std::string error_message;
    };
    
    // Simulate A→B migration
    static bool SimulateMigration(
        const ExecutionSnapshot& source_snapshot,
        NodeIdentity node_a,
        NodeIdentity node_b,
        MigrationResult* out_result);
    
    // Full end-to-end test with actual network (if available)
    static bool RunEndToEndTest(
        const char* source_address,
        uint16_t source_port,
        const char* dest_address,
        uint16_t dest_port,
        MigrationResult* out_result);
    
    // Verify the invariant: same_snapshot@A == same_snapshot@B
    static bool VerifyInvariant(
        const ExecutionSnapshot& snapshot_a,
        const ExecutionSnapshot& snapshot_b,
        uint64_t merkle_root_a,
        uint64_t merkle_root_b);
    
    // Print migration report
    static void PrintReport(const MigrationResult& result);
};

// ============================================================================
// Convenience Macros
// ============================================================================

#define RAWRXD_DISTRIBUTED_SYNC_INIT(node_name, node_id, addr, port) \
    do { \
        RawrXD::Core::NodeIdentity node; \
        node.node_id = (node_id); \
        std::strncpy(node.node_name, (node_name), sizeof(node.node_name) - 1); \
        std::strncpy(node.address, (addr), sizeof(node.address) - 1); \
        node.port = (port); \
        node.capabilities = RawrXD::Core::NodeIdentity::CAP_STATE_SYNC; \
        RawrXD::Core::DistributedStateSyncManager::GetInstance()->Initialize(node); \
    } while(0)

} // namespace Core
} // namespace RawrXD
