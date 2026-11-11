#pragma once
#include <cstdint.h>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <optional>
#include <filesystem>

// =============================================================================
// Patch Transaction System
// Every agent mutation is a transaction with rollback capability
// =============================================================================

namespace RawrXD {
namespace Sovereign {
namespace Hotpatch {

// Forward declarations
class PatchTransaction;
class RollbackJournal;

// Transaction state
enum class TransactionState {
    PENDING,      // Created, not started
    ACTIVE,       // Currently applying
    VALIDATING,   // Running verification
    COMMITTED,    // Successfully applied
    ROLLED_BACK,  // Reverted
    FAILED        // Error during apply
};

// Hash for state verification
struct StateHash {
    std::string filesystem_hash;  // Git tree hash or similar
    std::string memory_hash;    // Process memory fingerprint
    std::string ast_hash;       // AST structure hash
    
    bool operator==(const StateHash& other) const {
        return filesystem_hash == other.filesystem_hash &&
               memory_hash == other.memory_hash &&
               ast_hash == other.ast_hash;
    }
};

// A single file change
struct FileChange {
    std::string path;
    std::string before_content;  // Snapshot
    std::string after_content;   // Proposed
    std::string diff;            // Unified diff format
    bool is_new_file = false;
    bool is_delete = false;
};

// AST-level mutation (semantic edit)
struct AstMutation {
    std::string target_symbol;
    std::string operation;       // "replace_body", "add_param", etc.
    std::string before_ast;
    std::string after_ast;
    std::vector<std::string> affected_symbols;
};

// Validation result
struct ValidationResult {
    bool compile_success = false;
    bool tests_pass = false;
    bool static_analysis_pass = false;
    bool security_scan_pass = false;
    double performance_delta = 0.0;  // Percentage
    std::vector<std::string> errors;
    std::vector<std::string> warnings;
};

// The complete transaction
class PatchTransaction {
public:
    PatchTransaction(uint64_t intent_id, const std::string& description);
    ~PatchTransaction();
    
    // Transaction lifecycle
    bool Begin();
    bool StageChange(const FileChange& change);
    bool StageAstMutation(const AstMutation& mutation);
    bool Validate();
    bool Commit();
    bool Rollback();
    
    // State
    TransactionState GetState() const { return state_; }
    uint64_t GetTransactionId() const { return txn_id_; }
    const ValidationResult& GetValidationResult() const { return validation_; }
    
    // Atomic activation
    bool ActivateFunctionPointer(const std::string& symbol_name, void* new_impl);
    
private:
    uint64_t txn_id_;
    uint64_t intent_id_;
    std::string description_;
    TransactionState state_ = TransactionState::PENDING;
    StateHash before_state_;
    StateHash after_state_;
    std::vector<FileChange> file_changes_;
    std::vector<AstMutation> ast_mutations_;
    ValidationResult validation_;
    std::filesystem::path journal_path_;
    
    bool CaptureBeforeState();
    bool CaptureAfterState();
    bool WriteJournal();
    bool RestoreFromJournal();
};

// =============================================================================
// Rollback Journal
// Persistent log of all transactions for recovery
// =============================================================================

class RollbackJournal {
public:
    static RollbackJournal& Instance();
    
    // Journal operations
    bool Initialize(const std::filesystem::path& journal_dir);
    bool LogTransaction(const PatchTransaction& txn);
    bool LogCommit(uint64_t txn_id);
    bool LogRollback(uint64_t txn_id);
    
    // Recovery
    std::vector<uint64_t> GetPendingTransactions();
    std::optional<PatchTransaction> LoadTransaction(uint64_t txn_id);
    bool Recover();
    
    // Cleanup
    bool ArchiveCommitted(uint64_t before_timestamp);
    bool PruneFailed(uint64_t before_timestamp);
    
private:
    RollbackJournal() = default;
    std::filesystem::path journal_dir_;
    bool initialized_ = false;
};

// =============================================================================
// Scoped Patch Guard
// RAII wrapper for automatic rollback on scope exit
// =============================================================================

class ScopedPatchGuard {
public:
    explicit ScopedPatchGuard(PatchTransaction& txn);
    ~ScopedPatchGuard();
    
    void Commit();  // Call to prevent rollback
    void Rollback(); // Force rollback
    
private:
    PatchTransaction& txn_;
    bool committed_ = false;
};

// =============================================================================
// Atomic Function Swap
// Hotpatch function pointers at runtime
// =============================================================================

template<typename FuncPtr>
class AtomicFunctionSwap {
public:
    explicit AtomicFunctionSwap(FuncPtr* target) : target_(target) {}
    
    bool Swap(FuncPtr replacement) {
        // Memory barrier + atomic store
        std::atomic_thread_fence(std::memory_order_release);
        *target_ = replacement;
        std::atomic_thread_fence(std::memory_order_acquire);
        return true;
    }
    
    FuncPtr GetCurrent() const {
        return *target_;
    }
    
private:
    FuncPtr* target_;
};

// =============================================================================
// Transaction Manager
// Central coordinator for all patch transactions
// =============================================================================

class TransactionManager {
public:
    static TransactionManager& Instance();
    
    // Transaction factory
    std::unique_ptr<PatchTransaction> CreateTransaction(uint64_t intent_id, 
                                                           const std::string& description);
    
    // Active transactions
    PatchTransaction* GetActiveTransaction(uint64_t txn_id);
    bool HasActiveTransactions() const;
    
    // Batch operations
    bool CommitAll();
    bool RollbackAll();
    
    // Configuration
    void SetAutoRollbackOnFailure(bool enabled) { auto_rollback_ = enabled; }
    void SetRequireValidation(bool required) { require_validation_ = required; }
    
private:
    TransactionManager() = default;
    std::unordered_map<uint64_t, std::unique_ptr<PatchTransaction>> active_txns_;
    uint64_t next_txn_id_ = 1;
    bool auto_rollback_ = true;
    bool require_validation_ = true;
};

} // namespace Hotpatch
} // namespace Sovereign
} // namespace RawrXD
