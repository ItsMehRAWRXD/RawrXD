#pragma once
#include "WorkspaceGuard.hpp"
#include <map>

namespace rawrxd::closure {

class EditTransaction {
public:
    explicit EditTransaction(const WorkspaceGuard& guard) : guard_(guard) {}
    ~EditTransaction();

    bool stage_write(const std::filesystem::path& path,
                     std::string content,
                     std::string* error = nullptr);
    // Apply staged edits while retaining backups. This is the state in which
    // build/tests must run.
    bool apply(std::string* error = nullptr);

    // Make an already-applied transaction authoritative by deleting backups.
    bool finalize(std::string* error = nullptr);

    // Convenience for non-verified callers: apply + finalize.
    bool commit(std::string* error = nullptr);

    void rollback() noexcept;
    bool applied() const noexcept { return applied_; }
    bool committed() const noexcept { return committed_; }
    size_t staged_count() const noexcept { return staged_.size(); }

private:
    struct Entry {
        std::filesystem::path path;
        std::filesystem::path backup;
        std::filesystem::path temp;
        std::string content;
        bool existed{};
        bool applied{};
    };
    const WorkspaceGuard& guard_;
    std::vector<Entry> staged_;
    bool applied_{false};
    bool committed_{false};
};

} // namespace rawrxd::closure
