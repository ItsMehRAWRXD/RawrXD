#pragma once
#include <stdint.h>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <filesystem>
#include <mutex>
#include <atomic>
#include <unordered_map>
#include "../intent/intent_config.hpp"

// =============================================================================
// Patch Transaction System - Database-like transactions for code changes
// Toggleable at compile-time and runtime
// =============================================================================

namespace RawrXD {
namespace Hotpatch {

// Transaction states
enum class TransactionState : uint32_t {
    INVALID = 0,
    BEGIN = 1,           // Transaction created
    SNAPSHOT = 2,        // State captured
    PATCHING = 3,        // Changes applied
    VALIDATING = 4,      // Validation running
    COMMITTED = 5,       // Changes accepted
    ROLLING_BACK = 6,    // Rollback in progress
    ROLLED_BACK = 7,     // Changes reverted
    FAILED = 8,          // Transaction failed
};

// Patch types
enum class PatchType : uint32_t {
    UNKNOWN = 0,
    TEXT_EDIT = 1,       // Raw text replacement
    AST_MUTATION = 2,    // AST-level change
    FUNCTION_SWAP = 3,   // Function pointer swap
    BINARY_PATCH = 4,    // Runtime binary modification
};

// A single patch within a transaction
struct Patch {
    uint64_t patch_id = 0;
    PatchType type = PatchType::UNKNOWN;
    
    // Target
    std::filesystem::path file_path;
    std::string symbol_name;
    uint64_t address = 0;  // For runtime patches
    
    // Change
    std::vector<uint8_t> before_data;
    std::vector<uint8_t> after_data;
    std::string diff;      // Unified diff format
    
    // Validation
    bool validated = false;
    std::vector<std::string> validation_errors;
};

// Transaction configuration (toggleable)
struct TransactionConfig {
    // Master toggle
    bool enabled = true;
    
    // Feature toggles
    bool create_snapshots = true;
    bool validate_before_apply = true;
    bool require_compilation = true;
    bool require_tests = true;
    bool auto_rollback_on_failure = true;
    bool keep_journal = true;
    bool atomic_activation = true;
    
    // Limits
    uint32_t max_patches_per_transaction = 100;
    uint32_t max_file_size_mb = 10;
    uint32_t max_transaction_time_ms = 300000;  // 5 minutes
    uint32_t max_rollback_time_ms = 10000;        // 10 seconds
    
    // Paths
    std::filesystem::path journal_path = ".rawrxd/journal";
    std::filesystem::path snapshot_path = ".rawrxd/snapshots";
    std::filesystem::path sandbox_path = ".rawrxd/sandbox";
    
    // Singleton
    static TransactionConfig& Instance();
    
    // Load from config
    void LoadFromFile(const std::filesystem::path& path);
    void SaveToFile(const std::filesystem::path& path) const;
};

// A patch transaction
class PatchTransaction {
public:
    explicit PatchTransaction(uint64_t intent_id);
    ~PatchTransaction();
    
    // Disable copy, enable move
    PatchTransaction(const PatchTransaction&) = delete;
    PatchTransaction& operator=(const PatchTransaction&) = delete;
    PatchTransaction(PatchTransaction&&) noexcept;
    PatchTransaction& operator=(PatchTransaction&&) noexcept;
    
    // Transaction lifecycle
    bool Begin();
    bool CreateSnapshot();
    bool AddPatch(const Patch& patch);
    bool Validate();
    bool Apply();
    bool Commit();
    bool Rollback();
    
    // State queries
    TransactionState GetState() const { return state_.load(); }
    uint64_t GetTransactionId() const { return transaction_id_; }
    uint64_t GetIntentId() const { return intent_id_; }
    const std::vector<Patch>& GetPatches() const { return patches_; }
    bool CanCommit() const;
    bool CanRollback() const;
    
    // Toggle-aware execution
    bool ExecuteIfEnabled(std::function<bool()> operation);
    
private:
    uint64_t transaction_id_ = 0;
    uint64_t intent_id_ = 0;
    std::atomic<TransactionState> state_{TransactionState::INVALID};
    
    std::vector<Patch> patches_;
    std::filesystem::path snapshot_dir_;
    std::filesystem::path journal_file_;
    
    // Original state backup
    std::unordered_map<std::filesystem::path, std::vector<uint8_t>> file_backups_;
    
    // Timing
    uint64_t begin_time_us_ = 0;
    uint64_t commit_time_us_ = 0;
    
    bool IsFeatureEnabled() const;
    bool CreateFileSnapshot(const std::filesystem::path& path);
    bool RestoreFileSnapshot(const std::filesystem::path& path);
    bool WriteJournalEntry(const std::string& entry);
};

// Transaction manager
class TransactionManager {
public:
    static TransactionManager& Instance();
    
    // Create new transaction
    std::unique_ptr<PatchTransaction> BeginTransaction(uint64_t intent_id);
    
    // Get active transactions
    std::vector<PatchTransaction*> GetActiveTransactions();
    
    // Find transaction
    PatchTransaction* FindTransaction(uint64_t transaction_id);
    
    // Cleanup completed transactions
    void CleanupCompleted(uint64_t max_age_seconds = 3600);
    
    // Emergency rollback all
    void EmergencyRollbackAll();
    
    // Toggle
    void EnableTransactions(bool enable) { enabled_ = enable; }
    bool AreTransactionsEnabled() const { return enabled_.load(); }
    
private:
    TransactionManager() = default;
    
    std::unordered_map<uint64_t, std::unique_ptr<PatchTransaction>> transactions_;
    std::mutex transactions_mutex_;
    std::atomic<bool> enabled_{true};
    std::atomic<uint64_t> next_transaction_id_{1};
};

// Scoped transaction guard
class ScopedTransaction {
public:
    explicit ScopedTransaction(PatchTransaction& tx) : tx_(tx) {
        tx_.Begin();
    }
    
    ~ScopedTransaction() {
        if (!committed_) {
            tx_.Rollback();
        }
    }
    
    bool Commit() {
        committed_ = tx_.Commit();
        return committed_;
    }
    
private:
    PatchTransaction& tx_;
    bool committed_ = false;
};

// Macros for conditional transaction blocks
#define RAWR_PATCH_TX_BEGIN(intent_id) \
    auto __tx_ptr = RawrXD::Hotpatch::TransactionManager::Instance().BeginTransaction(intent_id); \
    auto& __tx = *__tx_ptr; \
    RawrXD::Hotpatch::ScopedTransaction __tx_guard(__tx); \
    do {

#define RAWR_PATCH_TX_COMMIT() \
        __tx_guard.Commit(); \
    } while(0)

#define RAWR_PATCH_TX_END() \
    } while(0)

// Compile-time conditional macros
#if RAWR_PATCH_TRANSACTION_ENABLED
    #define RAWR_CT_TX(code) code
#else
    #define RAWR_CT_TX(code)
#endif

} // namespace Hotpatch
} // namespace RawrXD
