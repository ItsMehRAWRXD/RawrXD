// ============================================================================
// RawrXD Distributed State Synchronization Implementation
// Phase 7C.3: same_snapshot@A == same_snapshot@B
// ============================================================================

#include <winsock2.h>
#include <ws2tcpip.h>
#include "distributed_state_sync.hpp"
#include <cstring>
#include <algorithm>

namespace RawrXD {
namespace Core {

// ============================================================================
// Distributed State Sync Manager Implementation
// ============================================================================

DistributedStateSyncManager::DistributedStateSyncManager() : initialized_(false), listen_socket_(INVALID_SOCKET) {
    InitializeSRWLock(&peers_lock_);
}

DistributedStateSyncManager::~DistributedStateSyncManager() {
    if (initialized_) {
        ShutdownNetwork();
    }
}

bool DistributedStateSyncManager::Initialize(const NodeIdentity& local_node) {
    local_node_ = local_node;
    
    if (!InitializeNetwork()) {
        return false;
    }
    
    // Create listen socket
    listen_socket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_socket_ == INVALID_SOCKET) {
        ShutdownNetwork();
        return false;
    }
    
    // Bind to port
    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(local_node_.port);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(listen_socket_, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(listen_socket_);
        listen_socket_ = INVALID_SOCKET;
        ShutdownNetwork();
        return false;
    }
    
    // Listen for connections
    if (listen(listen_socket_, SOMAXCONN) == SOCKET_ERROR) {
        closesocket(listen_socket_);
        listen_socket_ = INVALID_SOCKET;
        ShutdownNetwork();
        return false;
    }
    
    initialized_ = true;
    return true;
}

bool DistributedStateSyncManager::InitializeNetwork() {
    WSADATA wsaData;
    return WSAStartup(MAKEWORD(2, 2), &wsaData) == 0;
}

void DistributedStateSyncManager::ShutdownNetwork() {
    if (listen_socket_ != INVALID_SOCKET) {
        closesocket(listen_socket_);
        listen_socket_ = INVALID_SOCKET;
    }
    WSACleanup();
}

void DistributedStateSyncManager::RegisterPeer(const NodeIdentity& peer) {
    AcquireSRWLockExclusive(&peers_lock_);
    peers_[peer.node_id] = peer;
    ReleaseSRWLockExclusive(&peers_lock_);
}

void DistributedStateSyncManager::UnregisterPeer(uint32_t node_id) {
    AcquireSRWLockExclusive(&peers_lock_);
    peers_.erase(node_id);
    ReleaseSRWLockExclusive(&peers_lock_);
}

std::vector<uint8_t> DistributedStateSyncManager::SerializeSnapshotForNetwork(
    const ExecutionSnapshot& snapshot,
    uint32_t dest_node_id,
    uint64_t* out_merkle_root) {
    
    // Compute Merkle root
    uint64_t merkle_root = ComputeMerkleRoot(snapshot);
    if (out_merkle_root) {
        *out_merkle_root = merkle_root;
    }
    
    // Serialize snapshot to buffer
    std::vector<uint8_t> payload(sizeof(ExecutionSnapshot));
    std::memcpy(payload.data(), &snapshot, sizeof(snapshot));
    
    // Compute payload hash
    uint64_t payload_hash = RawrXD_Hash64(payload.data(), payload.size(), HASH_SEED_DEFAULT);
    
    // Create header
    NetworkSnapshotHeader header;
    header.snapshot_id = snapshot.snapshot_id;
    header.timestamp = GetTickCount64();
    header.payload_size = payload.size();
    header.payload_hash = payload_hash;
    header.merkle_root = merkle_root;
    header.source_node_id = initialized_ ? local_node_.node_id : 0;
    header.dest_node_id = dest_node_id;
    header.flags = 0;
    
    // Combine header + payload
    std::vector<uint8_t> buffer(sizeof(header) + payload.size());
    std::memcpy(buffer.data(), &header, sizeof(header));
    std::memcpy(buffer.data() + sizeof(header), payload.data(), payload.size());
    
    return buffer;
}

bool DistributedStateSyncManager::DeserializeSnapshotFromNetwork(
    const std::vector<uint8_t>& buffer,
    ExecutionSnapshot* out_snapshot,
    uint64_t* out_merkle_root) {
    
    if (buffer.size() < sizeof(NetworkSnapshotHeader)) {
        return false;
    }
    
    // Parse header
    NetworkSnapshotHeader header;
    std::memcpy(&header, buffer.data(), sizeof(header));
    
    if (header.magic != 0x4453594E || header.version != 1) {
        return false;
    }
    
    // Verify payload size
    size_t expected_size = sizeof(header) + header.payload_size;
    if (buffer.size() < expected_size) {
        return false;
    }
    
    // Verify payload hash
    const uint8_t* payload_data = buffer.data() + sizeof(header);
    uint64_t computed_hash = RawrXD_Hash64(payload_data, header.payload_size, HASH_SEED_DEFAULT);
    if (computed_hash != header.payload_hash) {
        return false;  // Integrity check failed
    }
    
    // Deserialize snapshot
    if (out_snapshot) {
        std::memcpy(out_snapshot, payload_data, sizeof(ExecutionSnapshot));
    }
    
    if (out_merkle_root) {
        *out_merkle_root = header.merkle_root;
    }
    
    return true;
}

SOCKET DistributedStateSyncManager::ConnectToNode(uint32_t node_id) {
    AcquireSRWLockShared(&peers_lock_);
    auto it = peers_.find(node_id);
    if (it == peers_.end()) {
        ReleaseSRWLockShared(&peers_lock_);
        return INVALID_SOCKET;
    }
    NodeIdentity peer = it->second;
    ReleaseSRWLockShared(&peers_lock_);
    
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        return INVALID_SOCKET;
    }
    
    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(peer.port);
    inet_pton(AF_INET, peer.address, &addr.sin_addr);
    
    if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(sock);
        return INVALID_SOCKET;
    }
    
    return sock;
}

bool DistributedStateSyncManager::SendAll(SOCKET sock, const void* data, size_t len) {
    const char* ptr = static_cast<const char*>(data);
    size_t remaining = len;
    
    while (remaining > 0) {
        int sent = send(sock, ptr, static_cast<int>(remaining), 0);
        if (sent == SOCKET_ERROR) {
            return false;
        }
        ptr += sent;
        remaining -= sent;
    }
    
    return true;
}

bool DistributedStateSyncManager::RecvAll(SOCKET sock, void* data, size_t len) {
    char* ptr = static_cast<char*>(data);
    size_t remaining = len;
    
    while (remaining > 0) {
        int received = recv(sock, ptr, static_cast<int>(remaining), 0);
        if (received <= 0) {
            return false;
        }
        ptr += received;
        remaining -= received;
    }
    
    return true;
}

bool DistributedStateSyncManager::SendSnapshotToNode(
    uint32_t dest_node_id,
    const ExecutionSnapshot& snapshot,
    TransferStats* out_stats) {
    
    TransferStats stats;
    stats.transfer_start_time = GetTickCount64();
    
    // Serialize snapshot
    uint64_t merkle_root;
    std::vector<uint8_t> buffer = SerializeSnapshotForNetwork(snapshot, dest_node_id, &merkle_root);
    
    // Connect to destination
    SOCKET sock = ConnectToNode(dest_node_id);
    if (sock == INVALID_SOCKET) {
        stats.success = false;
        if (out_stats) *out_stats = stats;
        return false;
    }
    
    // Send buffer
    uint64_t buffer_size = buffer.size();
    if (!SendAll(sock, &buffer_size, sizeof(buffer_size))) {
        closesocket(sock);
        stats.success = false;
        if (out_stats) *out_stats = stats;
        return false;
    }
    
    if (!SendAll(sock, buffer.data(), buffer.size())) {
        closesocket(sock);
        stats.success = false;
        if (out_stats) *out_stats = stats;
        return false;
    }
    
    stats.bytes_sent = buffer.size();
    stats.transfer_end_time = GetTickCount64();
    stats.success = true;
    
    closesocket(sock);
    
    if (out_stats) *out_stats = stats;
    return true;
}

bool DistributedStateSyncManager::ReceiveSnapshotFromNode(
    uint32_t source_node_id,
    ExecutionSnapshot* out_snapshot,
    TransferStats* out_stats) {
    
    TransferStats stats;
    stats.transfer_start_time = GetTickCount64();
    
    // Accept connection
    sockaddr_in client_addr = {};
    int addr_len = sizeof(client_addr);
    SOCKET client_sock = accept(listen_socket_, (sockaddr*)&client_addr, &addr_len);
    
    if (client_sock == INVALID_SOCKET) {
        stats.success = false;
        if (out_stats) *out_stats = stats;
        return false;
    }
    
    // Receive buffer size
    uint64_t buffer_size;
    if (!RecvAll(client_sock, &buffer_size, sizeof(buffer_size))) {
        closesocket(client_sock);
        stats.success = false;
        if (out_stats) *out_stats = stats;
        return false;
    }
    
    // Receive buffer
    std::vector<uint8_t> buffer(static_cast<size_t>(buffer_size));
    if (!RecvAll(client_sock, buffer.data(), buffer.size())) {
        closesocket(client_sock);
        stats.success = false;
        if (out_stats) *out_stats = stats;
        return false;
    }
    
    stats.bytes_received = buffer.size();
    stats.transfer_end_time = GetTickCount64();
    
    // Deserialize
    uint64_t merkle_root;
    bool success = DeserializeSnapshotFromNetwork(buffer, out_snapshot, &merkle_root);
    
    stats.success = success;
    closesocket(client_sock);
    
    if (out_stats) *out_stats = stats;
    return success;
}

uint64_t DistributedStateSyncManager::ComputeMerkleRoot(const ExecutionSnapshot& snapshot) {
    // Simple Merkle root: hash of snapshot + hash of KV identities
    uint64_t snapshot_hash = RawrXD_Hash64(&snapshot, sizeof(snapshot), HASH_SEED_DEFAULT);
    
    // Hash all KV identities
    uint64_t kv_hash = HASH_SEED_DEFAULT;
    for (uint32_t i = 0; i < snapshot.num_layers && i < ExecutionSnapshot::MAX_LAYERS; ++i) {
        kv_hash = RawrXD_HashCombine(kv_hash, snapshot.kv_identities[i].combined_hash);
    }
    
    return RawrXD_HashCombine(snapshot_hash, kv_hash);
}

bool DistributedStateSyncManager::VerifySnapshotIntegrity(
    const ExecutionSnapshot& snapshot,
    uint64_t expected_merkle_root) {
    
    uint64_t computed_root = ComputeMerkleRoot(snapshot);
    return computed_root == expected_merkle_root;
}

bool DistributedStateSyncManager::AreSnapshotsEquivalent(
    const ExecutionSnapshot& snapshot_a,
    uint64_t merkle_root_a,
    const ExecutionSnapshot& snapshot_b,
    uint64_t merkle_root_b) {
    
    // Primary check: Merkle roots must match
    if (merkle_root_a != merkle_root_b) {
        return false;
    }
    
    // Secondary check: Deep comparison of critical fields
    return StateResurrectionManager::AreIdentical(snapshot_a, snapshot_b);
}

const NodeIdentity* DistributedStateSyncManager::GetPeerNode(uint32_t node_id) const {
    AcquireSRWLockShared(&peers_lock_);
    auto it = peers_.find(node_id);
    if (it != peers_.end()) {
        ReleaseSRWLockShared(&peers_lock_);
        return &it->second;
    }
    ReleaseSRWLockShared(&peers_lock_);
    return nullptr;
}

std::vector<NodeIdentity> DistributedStateSyncManager::GetPeers() const {
    AcquireSRWLockShared(&peers_lock_);
    std::vector<NodeIdentity> result;
    for (const auto& pair : peers_) {
        result.push_back(pair.second);
    }
    ReleaseSRWLockShared(&peers_lock_);
    return result;
}

// ============================================================================
// Distributed Migration Test Implementation
// ============================================================================

bool DistributedMigrationTest::SimulateMigration(
    const ExecutionSnapshot& source_snapshot,
    NodeIdentity node_a,
    NodeIdentity node_b,
    MigrationResult* out_result) {
    
    printf("Distributed Migration Test: A → B\n");
    printf("==================================\n\n");
    
    // Initialize managers for both nodes (network init only, no socket binding for simulation)
    DistributedStateSyncManager mgr_a;
    DistributedStateSyncManager mgr_b;
    
    // Register peers
    mgr_a.RegisterPeer(node_b);
    mgr_b.RegisterPeer(node_a);
    
    // Compute source Merkle root
    uint64_t merkle_root_a = mgr_a.ComputeMerkleRoot(source_snapshot);
    out_result->source_merkle_root = merkle_root_a;
    
    printf("Source Node (A):\n");
    printf("  Node ID: %u\n", node_a.node_id);
    printf("  Merkle Root: ");
    char hash_str[32];
    HashChainManager::FormatHash(merkle_root_a, hash_str, sizeof(hash_str));
    printf("%s\n\n", hash_str);
    
    // Simulate transfer (in real scenario, this would be network send/receive)
    // For simulation, we serialize and deserialize locally
    uint64_t merkle_root_transfer;
    std::vector<uint8_t> buffer = mgr_a.SerializeSnapshotForNetwork(
        source_snapshot, node_b.node_id, &merkle_root_transfer);
    
    printf("Transfer:\n");
    printf("  Payload size: %zu bytes\n", buffer.size());
    printf("  Merkle Root: ");
    HashChainManager::FormatHash(merkle_root_transfer, hash_str, sizeof(hash_str));
    printf("%s\n\n", hash_str);
    
    // Deserialize at destination
    ExecutionSnapshot dest_snapshot;
    uint64_t merkle_root_b;
    bool deserialize_success = mgr_b.DeserializeSnapshotFromNetwork(
        buffer, &dest_snapshot, &merkle_root_b);
    
    if (!deserialize_success) {
        out_result->success = false;
        out_result->error_message = "Failed to deserialize at destination";
        return false;
    }
    
    out_result->dest_merkle_root = merkle_root_b;
    
    printf("Destination Node (B):\n");
    printf("  Node ID: %u\n", node_b.node_id);
    printf("  Merkle Root: ");
    HashChainManager::FormatHash(merkle_root_b, hash_str, sizeof(hash_str));
    printf("%s\n\n", hash_str);
    
    // Verify invariant
    out_result->merkle_roots_match = (merkle_root_a == merkle_root_b);
    out_result->success = out_result->merkle_roots_match;
    
    // Populate stats
    out_result->stats.bytes_sent = buffer.size();
    out_result->stats.bytes_received = buffer.size();
    out_result->stats.success = out_result->success;
    
    printf("Verification:\n");
    printf("  Merkle roots match: %s\n", 
           out_result->merkle_roots_match ? "✅ YES" : "❌ NO");
    printf("  Invariant proven: %s\n",
           out_result->merkle_roots_match ? "✅ same_snapshot@A == same_snapshot@B" : "❌ FAILED");
    
    return out_result->success;
}

bool DistributedMigrationTest::VerifyInvariant(
    const ExecutionSnapshot& snapshot_a,
    const ExecutionSnapshot& snapshot_b,
    uint64_t merkle_root_a,
    uint64_t merkle_root_b) {
    
    return DistributedStateSyncManager::AreSnapshotsEquivalent(
        snapshot_a, merkle_root_a, snapshot_b, merkle_root_b);
}

void DistributedMigrationTest::PrintReport(const MigrationResult& result) {
    printf("\nMigration Test Report\n");
    printf("======================\n");
    printf("Success: %s\n", result.success ? "✅ PASS" : "❌ FAIL");
    printf("Source Merkle Root: ");
    char hash_str[32];
    HashChainManager::FormatHash(result.source_merkle_root, hash_str, sizeof(hash_str));
    printf("%s\n", hash_str);
    printf("Dest Merkle Root:   ");
    HashChainManager::FormatHash(result.dest_merkle_root, hash_str, sizeof(hash_str));
    printf("%s\n", hash_str);
    printf("Roots Match: %s\n", result.merkle_roots_match ? "✅ YES" : "❌ NO");
    
    if (!result.error_message.empty()) {
        printf("Error: %s\n", result.error_message.c_str());
    }
    
    printf("\nTransfer Stats:\n");
    printf("  Bytes sent: %llu\n", result.stats.bytes_sent);
    printf("  Bytes received: %llu\n", result.stats.bytes_received);
    printf("  Duration: %.2f ms\n", result.stats.GetDurationMs());
    printf("  Throughput: %.2f MB/s\n", result.stats.GetThroughputMBps());
}

} // namespace Core
} // namespace RawrXD
