// Phase D.17 Batch 3/5: Distributed Ledger
// Blockchain state management and storage
// Copyright (c) 2026 RawrXD Team

#pragma once

#include <cstring>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>
#include <any>

namespace Sovereign {
namespace Blockchain {

// Forward declarations
struct LedgerState;
struct StateTransition;
struct MerkleTree;

// ============================================================================
// Distributed Ledger Types
// ============================================================================

enum class StateType {
    ACCOUNT = 0,
    CONTRACT = 1,
    VALIDATOR = 2,
    PROPOSAL = 3,
    CONFIG = 4
};

enum class TransitionType {
    TRANSFER = 0,
    CONTRACT_CALL = 1,
    VALIDATOR_UPDATE = 2,
    CONFIG_UPDATE = 3,
    SLASH = 4
};

struct AccountState {
    std::string address;
    uint64_t balance;
    uint64_t nonce;
    std::vector<uint8_t> code_hash;
    std::vector<uint8_t> storage_root;
    std::chrono::steady_clock::time_point last_activity;
};

struct StateTransition {
    TransitionType type;
    std::string from_address;
    std::string to_address;
    uint64_t amount;
    std::vector<uint8_t> data;
    std::map<std::string, std::any> pre_state;
    std::map<std::string, std::any> post_state;
    std::vector<uint8_t> proof;
    uint64_t block_number;
    std::string tx_hash;
};

struct MerkleNode {
    std::vector<uint8_t> hash;
    std::shared_ptr<MerkleNode> left;
    std::shared_ptr<MerkleNode> right;
    bool is_leaf;
    size_t index;
};

struct StateProof {
    std::vector<uint8_t> key;
    std::vector<uint8_t> value;
    std::vector<std::vector<uint8_t>> proof_path;
    std::vector<uint8_t> root_hash;
};

// ============================================================================
// State Manager
// ============================================================================

class StateManager {
public:
    struct Config {
        std::string backend = "leveldb";
        size_t cache_size = 256 * 1024 * 1024;  // 256MB
        bool prune_history = false;
        uint64_t retain_blocks = 86400;  // ~15 days at 15s block time
    };
    
    explicit StateManager(const Config& config);
    ~StateManager();
    
    bool Initialize();
    void Shutdown();
    
    // Account operations
    bool CreateAccount(const std::string& address, uint64_t initial_balance);
    bool DeleteAccount(const std::string& address);
    AccountState GetAccount(const std::string& address) const;
    bool UpdateAccount(const std::string& address, const AccountState& state);
    bool AccountExists(const std::string& address) const;
    
    // Balance operations
    bool AddBalance(const std::string& address, uint64_t amount);
    bool SubBalance(const std::string& address, uint64_t amount);
    uint64_t GetBalance(const std::string& address) const;
    
    // Nonce management
    uint64_t GetNonce(const std::string& address) const;
    bool IncrementNonce(const std::string& address);
    bool SetNonce(const std::string& address, uint64_t nonce);
    
    // State root
    std::vector<uint8_t> ComputeStateRoot() const;
    bool VerifyStateRoot(const std::vector<uint8_t>& root) const;
    
    // Snapshots
    std::vector<uint8_t> CreateSnapshot();
    bool RestoreSnapshot(const std::vector<uint8_t>& snapshot_root);
    
    // Revert
    bool RevertToBlock(uint64_t block_number);
    std::vector<StateTransition> GetTransitionsSince(uint64_t block_number) const;
    
private:
    Config config_;
    std::map<std::string, AccountState> account_cache_;
    mutable std::mutex state_mutex_;
    std::vector<uint8_t> current_root_;
    
    std::vector<uint8_t> HashAccount(const AccountState& account) const;
    void FlushCache();
};

// ============================================================================
// Merkle Patricia Tree
// ============================================================================

class MerklePatriciaTree {
public:
    struct Config {
        std::string db_path;
        bool cache_nodes = true;
        size_t node_cache_size = 10000;
    };
    
    struct Node {
        enum Type { BRANCH = 0, EXTENSION = 1, LEAF = 2 };
        Type type;
        std::vector<uint8_t> hash;
        std::vector<std::shared_ptr<Node>> children;
        std::vector<uint8_t> key;
        std::vector<uint8_t> value;
        bool dirty;
    };
    
    explicit MerklePatriciaTree(const Config& config);
    ~MerklePatriciaTree();
    
    bool Initialize(const std::vector<uint8_t>& root_hash = {});
    void Shutdown();
    
    // Operations
    bool Put(const std::vector<uint8_t>& key, const std::vector<uint8_t>& value);
    std::optional<std::vector<uint8_t>> Get(const std::vector<uint8_t>& key) const;
    bool Delete(const std::vector<uint8_t>& key);
    bool Has(const std::vector<uint8_t>& key) const;
    
    // Proofs
    StateProof GenerateProof(const std::vector<uint8_t>& key) const;
    bool VerifyProof(const StateProof& proof) const;
    
    // Root
    std::vector<uint8_t> Root() const;
    void Commit();
    void Rollback();
    
    // Iteration
    std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> Range(
        const std::vector<uint8_t>& start,
        const std::vector<uint8_t>& end,
        size_t limit = 1000) const;
    
private:
    Config config_;
    std::shared_ptr<Node> root_;
    mutable std::mutex tree_mutex_;
    std::map<std::vector<uint8_t>, std::shared_ptr<Node>> node_cache_;
    
    std::shared_ptr<Node> Insert(std::shared_ptr<Node> node, 
                                  const std::vector<uint8_t>& key,
                                  const std::vector<uint8_t>& value,
                                  size_t depth);
    std::shared_ptr<Node> Delete(std::shared_ptr<Node> node,
                                  const std::vector<uint8_t>& key,
                                  size_t depth);
    std::vector<uint8_t> HashNode(const Node& node) const;
    std::vector<uint8_t> EncodeNode(const Node& node) const;
    std::shared_ptr<Node> DecodeNode(const std::vector<uint8_t>& data) const;
    int CommonPrefixLength(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) const;
};

// ============================================================================
// Block Store
// ============================================================================

class BlockStore {
public:
    struct Config {
        std::string data_dir;
        size_t max_open_files = 64;
        size_t write_buffer_size = 64 * 1024 * 1024;  // 64MB
        bool compression = true;
    };
    
    struct BlockMetadata {
        uint64_t number;
        std::vector<uint8_t> hash;
        std::vector<uint8_t> parent_hash;
        uint64_t timestamp;
        uint64_t gas_used;
        uint64_t tx_count;
        bool finalized;
        std::chrono::steady_clock::time_point indexed_at;
    };
    
    explicit BlockStore(const Config& config);
    ~BlockStore();
    
    bool Initialize();
    void Shutdown();
    
    // Block storage
    bool StoreBlock(const Block& block);
    std::optional<Block> GetBlock(const std::vector<uint8_t>& hash) const;
    std::optional<Block> GetBlockByNumber(uint64_t number) const;
    bool HasBlock(const std::vector<uint8_t>& hash) const;
    
    // Metadata
    BlockMetadata GetBlockMetadata(const std::vector<uint8_t>& hash) const;
    std::vector<BlockMetadata> GetBlocksInRange(uint64_t start, uint64_t end) const;
    
    // Chain queries
    std::vector<uint8_t> GetCanonicalHash(uint64_t number) const;
    bool SetCanonicalHash(uint64_t number, const std::vector<uint8_t>& hash);
    uint64_t GetLatestBlockNumber() const;
    std::vector<uint8_t> GetLatestBlockHash() const;
    
    // Pruning
    bool PruneBlocksBefore(uint64_t block_number);
    bool IsPruned(uint64_t block_number) const;
    
    // Statistics
    struct StoreStats {
        uint64_t total_blocks;
        uint64_t total_transactions;
        size_t disk_usage;
        size_t index_size;
    };
    StoreStats GetStats() const;
    
private:
    Config config_;
    std::map<std::vector<uint8_t>, Block> block_cache_;
    std::map<uint64_t, std::vector<uint8_t>> hash_by_number_;
    mutable std::mutex store_mutex_;
    uint64_t latest_number_;
    
    void FlushBlock(const Block& block);
    std::optional<Block> LoadBlock(const std::vector<uint8_t>& hash) const;
};

// ============================================================================
// Transaction Pool
// ============================================================================

class TransactionPool {
public:
    struct Config {
        size_t max_size = 5000;
        uint64_t max_gas_price = 100000000000;  // 100 gwei
        uint64_t min_gas_price = 1000000000;     // 1 gwei
        std::chrono::seconds tx_ttl{1800};       // 30 minutes
        bool price_bump_required = true;
        uint64_t price_bump_percent = 10;
    };
    
    struct PooledTransaction {
        Transaction tx;
        std::chrono::steady_clock::time_point received_at;
        uint64_t price_bump_count;
    };
    
    explicit TransactionPool(const Config& config);
    ~TransactionPool();
    
    bool Initialize();
    void Shutdown();
    
    // Transaction management
    bool AddTransaction(const Transaction& tx);
    bool RemoveTransaction(const std::string& tx_hash);
    bool ReplaceTransaction(const Transaction& old_tx, const Transaction& new_tx);
    
    // Queries
    std::optional<Transaction> GetTransaction(const std::string& tx_hash) const;
    std::vector<Transaction> GetPendingTransactions() const;
    std::vector<Transaction> GetQueuedTransactions() const;
    std::vector<Transaction> GetTransactionsForBlock(size_t max_count, uint64_t gas_limit) const;
    
    // Validation
    bool ValidateTransaction(const Transaction& tx) const;
    bool CheckNonce(const Transaction& tx) const;
    bool CheckBalance(const Transaction& tx) const;
    
    // Status
    struct PoolStats {
        size_t pending_count;
        size_t queued_count;
        uint64_t total_gas;
        uint64_t min_gas_price;
        uint64_t max_gas_price;
    };
    PoolStats GetStats() const;
    
    // Cleanup
    void RemoveExpiredTransactions();
    void RemoveConfirmedTransactions(const std::vector<std::string>& tx_hashes);
    
private:
    Config config_;
    std::map<std::string, PooledTransaction> pending_;
    std::map<std::string, PooledTransaction> queued_;
    mutable std::mutex pool_mutex_;
    std::thread cleanup_thread_;
    std::atomic<bool> running_{false};
    
    void CleanupLoop();
    bool ShouldReplace(const Transaction& old_tx, const Transaction& new_tx) const;
    uint64_t CalculateEffectiveGasPrice(const Transaction& tx) const;
};

// ============================================================================
// Ledger Sync
// ============================================================================

class LedgerSync {
public:
    struct Config {
        int max_peers = 50;
        int min_peers = 5;
        uint64_t sync_chunk_size = 128;
        std::chrono::seconds sync_timeout{30};
        bool fast_sync = true;
    };
    
    enum class SyncMode {
        FULL = 0,
        FAST = 1,
        LIGHT = 2,
        SNAP = 3
    };
    
    enum class SyncState {
        IDLE = 0,
        FINDING_PEERS = 1,
        DOWNLOADING_HEADERS = 2,
        DOWNLOADING_BODIES = 3,
        DOWNLOADING_RECEIPTS = 4,
        PROCESSING = 5,
        COMPLETED = 6,
        FAILED = 7
    };
    
    explicit LedgerSync(const Config& config);
    ~LedgerSync();
    
    bool Initialize();
    void Shutdown();
    
    // Sync control
    bool StartSync(SyncMode mode);
    bool StopSync();
    bool PauseSync();
    bool ResumeSync();
    
    // State
    SyncState GetState() const;
    uint64_t GetCurrentHeight() const;
    uint64_t GetTargetHeight() const;
    float GetProgress() const;
    
    // Peer management
    bool AddPeer(const std::string& peer_id, uint64_t height);
    bool RemovePeer(const std::string& peer_id);
    std::vector<std::string> GetBestPeers(size_t count) const;
    
    // Block download
    bool RequestHeaders(const std::string& peer_id, uint64_t start, uint64_t count);
    bool RequestBodies(const std::string& peer_id, const std::vector<std::vector<uint8_t>>& hashes);
    bool ProcessHeaders(const std::vector<Block>& headers);
    bool ProcessBodies(const std::vector<Block>& blocks);
    
private:
    Config config_;
    SyncState state_;
    SyncMode mode_;
    uint64_t current_height_;
    uint64_t target_height_;
    mutable std::mutex sync_mutex_;
    
    struct PeerInfo {
        std::string id;
        uint64_t height;
        std::chrono::steady_clock::time_point last_seen;
        bool syncing;
    };
    std::map<std::string, PeerInfo> peers_;
    
    std::thread sync_thread_;
    std::atomic<bool> running_{false};
    
    void SyncLoop();
    bool FindCommonAncestor(const std::string& peer_id);
    bool DownloadChain(const std::string& peer_id, uint64_t start, uint64_t end);
    bool ValidateAndInsert(const std::vector<Block>& blocks);
};

// ============================================================================
// Distributed Ledger Runtime
// ============================================================================

class DistributedLedgerRuntime {
public:
    struct Config {
        StateManager::Config state;
        MerklePatriciaTree::Config tree;
        BlockStore::Config store;
        TransactionPool::Config pool;
        LedgerSync::Config sync;
    };
    
    explicit DistributedLedgerRuntime(const Config& config);
    ~DistributedLedgerRuntime();
    
    bool Initialize();
    void Shutdown();
    
    // Subsystem access
    StateManager* GetStateManager();
    MerklePatriciaTree* GetStateTree();
    BlockStore* GetBlockStore();
    TransactionPool* GetTransactionPool();
    LedgerSync* GetLedgerSync();
    
    // High-level API
    bool ProcessBlock(const Block& block);
    bool ProcessTransaction(const Transaction& tx);
    
    std::vector<uint8_t> GetStateRoot() const;
    uint64_t GetBlockHeight() const;
    
    bool SyncWithNetwork();
    bool IsSynced() const;
    
private:
    Config config_;
    std::atomic<bool> initialized_{false};
    
    std::unique_ptr<StateManager> state_manager_;
    std::unique_ptr<MerklePatriciaTree> state_tree_;
    std::unique_ptr<BlockStore> block_store_;
    std::unique_ptr<TransactionPool> tx_pool_;
    std::unique_ptr<LedgerSync> ledger_sync_;
};

} // namespace Blockchain
} // namespace Sovereign
