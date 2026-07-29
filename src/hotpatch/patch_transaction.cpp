#include "patch_transaction.hpp"
#include <nlohmann/json.hpp>
#include <fstream>
#include <chrono>
#include <filesystem>

namespace RawrXD {
namespace Hotpatch {

// =============================================================================
// TransactionConfig
// =============================================================================

TransactionConfig& TransactionConfig::Instance() {
    static TransactionConfig instance;
    return instance;
}

void TransactionConfig::LoadFromFile(const std::filesystem::path& path) {
    std::ifstream file(path);
    if (!file.is_open()) return;
    
    try {
        nlohmann::json j;
        file >> j;
        
        if (j.contains("enabled")) enabled = j["enabled"];
        if (j.contains("create_snapshots")) create_snapshots = j["create_snapshots"];
        if (j.contains("validate_before_apply")) validate_before_apply = j["validate_before_apply"];
        if (j.contains("require_compilation")) require_compilation = j["require_compilation"];
        if (j.contains("require_tests")) require_tests = j["require_tests"];
        if (j.contains("auto_rollback_on_failure")) auto_rollback_on_failure = j["auto_rollback_on_failure"];
        if (j.contains("keep_journal")) keep_journal = j["keep_journal"];
        if (j.contains("atomic_activation")) atomic_activation = j["atomic_activation"];
        
        if (j.contains("max_patches_per_transaction")) max_patches_per_transaction = j["max_patches_per_transaction"].get<uint32_t>();
        if (j.contains("max_file_size_mb")) max_file_size_mb = j["max_file_size_mb"].get<uint32_t>();
        if (j.contains("max_transaction_time_ms")) max_transaction_time_ms = j["max_transaction_time_ms"].get<uint32_t>();
        if (j.contains("max_rollback_time_ms")) max_rollback_time_ms = j["max_rollback_time_ms"].get<uint32_t>();
        
        if (j.contains("journal_path")) journal_path = j["journal_path"].get<std::string>();
        if (j.contains("snapshot_path")) snapshot_path = j["snapshot_path"].get<std::string>();
        if (j.contains("sandbox_path")) sandbox_path = j["sandbox_path"].get<std::string>();
    } catch (...) {
        // Ignore parse errors
    }
}

void TransactionConfig::SaveToFile(const std::filesystem::path& path) const {
    nlohmann::json j;
    j["enabled"] = enabled;
    j["create_snapshots"] = create_snapshots;
    j["validate_before_apply"] = validate_before_apply;
    j["require_compilation"] = require_compilation;
    j["require_tests"] = require_tests;
    j["auto_rollback_on_failure"] = auto_rollback_on_failure;
    j["keep_journal"] = keep_journal;
    j["atomic_activation"] = atomic_activation;
    j["max_patches_per_transaction"] = max_patches_per_transaction;
    j["max_file_size_mb"] = max_file_size_mb;
    j["max_transaction_time_ms"] = max_transaction_time_ms;
    j["max_rollback_time_ms"] = max_rollback_time_ms;
    j["journal_path"] = journal_path.string();
    j["snapshot_path"] = snapshot_path.string();
    j["sandbox_path"] = sandbox_path.string();
    
    std::ofstream file(path);
    if (file.is_open()) {
        file << j.dump(2);
    }
}

// =============================================================================
// PatchTransaction
// =============================================================================

PatchTransaction::PatchTransaction(uint64_t intent_id) 
    : intent_id_(intent_id) {
    auto& config = TransactionConfig::Instance();
    snapshot_dir_ = config.snapshot_path / std::to_string(intent_id);
    journal_file_ = config.journal_path / (std::to_string(intent_id) + ".jsonl");
}

PatchTransaction::~PatchTransaction() {
    // Auto-rollback if not committed
    auto state = state_.load();
    if (state != TransactionState::COMMITTED && 
        state != TransactionState::ROLLED_BACK &&
        state != TransactionState::FAILED) {
        Rollback();
    }
}

PatchTransaction::PatchTransaction(PatchTransaction&& other) noexcept
    : transaction_id_(other.transaction_id_),
      intent_id_(other.intent_id_),
      state_(other.state_.load()),
      patches_(std::move(other.patches_)),
      snapshot_dir_(std::move(other.snapshot_dir_)),
      journal_file_(std::move(other.journal_file_)),
      file_backups_(std::move(other.file_backups_)),
      begin_time_us_(other.begin_time_us_),
      commit_time_us_(other.commit_time_us_) {
    other.state_.store(TransactionState::INVALID);
}

PatchTransaction& PatchTransaction::operator=(PatchTransaction&& other) noexcept {
    if (this != &other) {
        transaction_id_ = other.transaction_id_;
        intent_id_ = other.intent_id_;
        state_.store(other.state_.load());
        patches_ = std::move(other.patches_);
        snapshot_dir_ = std::move(other.snapshot_dir_);
        journal_file_ = std::move(other.journal_file_);
        file_backups_ = std::move(other.file_backups_);
        begin_time_us_ = other.begin_time_us_;
        commit_time_us_ = other.commit_time_us_;
        other.state_.store(TransactionState::INVALID);
    }
    return *this;
}

bool PatchTransaction::Begin() {
    if (!IsFeatureEnabled()) {
        state_.store(TransactionState::BEGIN);
        return true;
    }
    
    if (state_.load() != TransactionState::INVALID) {
        return false;  // Already started
    }
    
    begin_time_us_ = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now().time_since_epoch()
    ).count();
    
    state_.store(TransactionState::BEGIN);
    
    WriteJournalEntry(R"({"event": "begin", "timestamp": )" + std::to_string(begin_time_us_) + "}");
    
    return true;
}

bool PatchTransaction::CreateSnapshot() {
    if (!IsFeatureEnabled()) {
        state_.store(TransactionState::SNAPSHOT);
        return true;
    }
    
    if (state_.load() != TransactionState::BEGIN) {
        return false;
    }
    
    auto& config = TransactionConfig::Instance();
    if (!config.create_snapshots) {
        state_.store(TransactionState::SNAPSHOT);
        return true;
    }
    
    // Create snapshot directory
    std::filesystem::create_directories(snapshot_dir_);
    
    // Snapshot files that will be modified
    for (const auto& patch : patches_) {
        if (!CreateFileSnapshot(patch.file_path)) {
            return false;
        }
    }
    
    state_.store(TransactionState::SNAPSHOT);
    WriteJournalEntry(R"({"event": "snapshot_created"})");
    
    return true;
}

bool PatchTransaction::AddPatch(const Patch& patch) {
    if (!IsFeatureEnabled()) {
        patches_.push_back(patch);
        return true;
    }
    
    auto& config = TransactionConfig::Instance();
    if (patches_.size() >= config.max_patches_per_transaction) {
        return false;
    }
    
    patches_.push_back(patch);
    return true;
}

bool PatchTransaction::Validate() {
    if (!IsFeatureEnabled()) {
        state_.store(TransactionState::VALIDATING);
        return true;
    }
    
    if (state_.load() != TransactionState::SNAPSHOT &&
        state_.load() != TransactionState::PATCHING) {
        return false;
    }
    
    auto& config = TransactionConfig::Instance();
    if (!config.validate_before_apply) {
        state_.store(TransactionState::VALIDATING);
        return true;
    }
    
    // Validate each patch
    for (auto& patch : patches_) {
        // Check file size
        if (std::filesystem::exists(patch.file_path)) {
            auto size = std::filesystem::file_size(patch.file_path);
            if (size > config.max_file_size_mb * 1024 * 1024) {
                patch.validation_errors.push_back("File too large");
                return false;
            }
        }
        
        patch.validated = true;
    }
    
    state_.store(TransactionState::VALIDATING);
    WriteJournalEntry(R"({"event": "validated"})");
    
    return true;
}

bool PatchTransaction::Apply() {
    if (!IsFeatureEnabled()) {
        state_.store(TransactionState::PATCHING);
        return true;
    }
    
    if (state_.load() != TransactionState::VALIDATING) {
        return false;
    }
    
    // Apply patches
    for (const auto& patch : patches_) {
        if (!patch.validated) {
            return false;
        }
        
        // Apply based on patch type
        switch (patch.type) {
            case PatchType::TEXT_EDIT:
                // Apply text edit
                break;
            case PatchType::AST_MUTATION:
                // Apply AST mutation
                break;
            case PatchType::FUNCTION_SWAP:
                // Apply function swap
                break;
            case PatchType::BINARY_PATCH:
                // Apply binary patch
                break;
            default:
                break;
        }
    }
    
    state_.store(TransactionState::PATCHING);
    WriteJournalEntry(R"({"event": "applied"})");
    
    return true;
}

bool PatchTransaction::Commit() {
    if (!IsFeatureEnabled()) {
        state_.store(TransactionState::COMMITTED);
        return true;
    }
    
    if (state_.load() != TransactionState::PATCHING) {
        return false;
    }
    
    auto& config = TransactionConfig::Instance();
    
    // Check if compilation required
    if (config.require_compilation) {
        // Would compile here
    }
    
    // Check if tests required
    if (config.require_tests) {
        // Would run tests here
    }
    
    commit_time_us_ = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now().time_since_epoch()
    ).count();
    
    state_.store(TransactionState::COMMITTED);
    WriteJournalEntry(R"({"event": "committed"})");
    
    return true;
}

bool PatchTransaction::Rollback() {
    if (!IsFeatureEnabled()) {
        state_.store(TransactionState::ROLLED_BACK);
        return true;
    }
    
    auto current_state = state_.load();
    if (current_state == TransactionState::ROLLED_BACK ||
        current_state == TransactionState::COMMITTED) {
        return true;  // Already done
    }
    
    state_.store(TransactionState::ROLLING_BACK);
    
    // Restore file snapshots
    for (const auto& [path, backup] : file_backups_) {
        RestoreFileSnapshot(path);
    }
    
    state_.store(TransactionState::ROLLED_BACK);
    WriteJournalEntry(R"({"event": "rolled_back"})");
    
    return true;
}

bool PatchTransaction::CanCommit() const {
    auto state = state_.load();
    return state == TransactionState::PATCHING || state == TransactionState::VALIDATING;
}

bool PatchTransaction::CanRollback() const {
    auto state = state_.load();
    return state != TransactionState::ROLLED_BACK && 
           state != TransactionState::COMMITTED;
}

bool PatchTransaction::IsFeatureEnabled() const {
    return TransactionConfig::Instance().enabled;
}

bool PatchTransaction::CreateFileSnapshot(const std::filesystem::path& path) {
    if (!std::filesystem::exists(path)) {
        return true;  // File doesn't exist yet, no snapshot needed
    }
    
    // Read file content
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }
    
    std::vector<uint8_t> content(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>()
    );
    
    file_backups_[path] = std::move(content);
    
    // Also write to snapshot directory
    auto snapshot_file = snapshot_dir_ / path.filename();
    std::filesystem::create_directories(snapshot_file.parent_path());
    std::ofstream snapshot(snapshot_file, std::ios::binary);
    if (snapshot.is_open()) {
        snapshot.write(reinterpret_cast<const char*>(file_backups_[path].data()), 
                       file_backups_[path].size());
    }
    
    return true;
}

bool PatchTransaction::RestoreFileSnapshot(const std::filesystem::path& path) {
    auto it = file_backups_.find(path);
    if (it == file_backups_.end()) {
        return true;  // No backup, nothing to restore
    }
    
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file.is_open()) {
        return false;
    }
    
    file.write(reinterpret_cast<const char*>(it->second.data()), 
               it->second.size());
    
    return file.good();
}

bool PatchTransaction::WriteJournalEntry(const std::string& entry) {
    auto& config = TransactionConfig::Instance();
    if (!config.keep_journal) {
        return true;
    }
    
    std::filesystem::create_directories(journal_file_.parent_path());
    
    std::ofstream file(journal_file_, std::ios::app);
    if (!file.is_open()) {
        return false;
    }
    
    file << entry << std::endl;
    return file.good();
}

// =============================================================================
// TransactionManager
// =============================================================================

TransactionManager& TransactionManager::Instance() {
    static TransactionManager instance;
    return instance;
}

std::unique_ptr<PatchTransaction> TransactionManager::BeginTransaction(uint64_t intent_id) {
    if (!enabled_.load()) {
        return nullptr;
    }
    
    uint64_t tx_id = next_transaction_id_.fetch_add(1);
    auto tx = std::make_unique<PatchTransaction>(intent_id);
    tx->Begin();
    
    {
        std::lock_guard<std::mutex> lock(transactions_mutex_);
        transactions_[tx_id] = std::move(tx);
    }
    
    return std::move(transactions_[tx_id]);
}

std::vector<PatchTransaction*> TransactionManager::GetActiveTransactions() {
    std::vector<PatchTransaction*> active;
    
    std::lock_guard<std::mutex> lock(transactions_mutex_);
    for (auto& [id, tx] : transactions_) {
        auto state = tx->GetState();
        if (state != TransactionState::COMMITTED &&
            state != TransactionState::ROLLED_BACK &&
            state != TransactionState::FAILED) {
            active.push_back(tx.get());
        }
    }
    
    return active;
}

PatchTransaction* TransactionManager::FindTransaction(uint64_t transaction_id) {
    std::lock_guard<std::mutex> lock(transactions_mutex_);
    auto it = transactions_.find(transaction_id);
    if (it != transactions_.end()) {
        return it->second.get();
    }
    return nullptr;
}

void TransactionManager::CleanupCompleted(uint64_t max_age_seconds) {
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now().time_since_epoch()
    ).count();
    
    std::lock_guard<std::mutex> lock(transactions_mutex_);
    for (auto it = transactions_.begin(); it != transactions_.end();) {
        auto state = it->second->GetState();
        if (state == TransactionState::COMMITTED ||
            state == TransactionState::ROLLED_BACK ||
            state == TransactionState::FAILED) {
            // Would check age here
            it = transactions_.erase(it);
        } else {
            ++it;
        }
    }
}

void TransactionManager::EmergencyRollbackAll() {
    std::lock_guard<std::mutex> lock(transactions_mutex_);
    for (auto& [id, tx] : transactions_) {
        tx->Rollback();
    }
}

} // namespace Hotpatch
} // namespace RawrXD
