#include "rawrxd/closure/EditTransaction.hpp"
#include <fstream>

namespace rawrxd::closure {
namespace {
bool write_all(const std::filesystem::path& p, std::string_view content) {
    std::ofstream out(p, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    out.write(content.data(), static_cast<std::streamsize>(content.size()));
    out.flush();
    return static_cast<bool>(out);
}
}

EditTransaction::~EditTransaction() {
    if (!committed_) rollback();
}

bool EditTransaction::stage_write(const std::filesystem::path& path,
                                  std::string content,
                                  std::string* error) {
    if (applied_) { if (error) *error = "cannot stage after transaction apply"; return false; }

    std::filesystem::path resolved;
    if (!guard_.resolve(path, resolved, error)) return false;
    for (const auto& e : staged_) {
        if (e.path == resolved) {
            if (error) *error = "same file staged twice";
            return false;
        }
    }
    Entry e;
    e.path = resolved;
    e.content = std::move(content);
    const auto nonce = std::to_string(fnv1a64(e.path.generic_string() + e.content));
    e.temp = e.path;
    e.temp += ".rawrxd.new." + nonce;
    e.backup = e.path;
    e.backup += ".rawrxd.bak." + nonce;
    e.existed = std::filesystem::exists(e.path);
    staged_.push_back(std::move(e));
    return true;
}

bool EditTransaction::apply(std::string* error) {
    if (committed_ || applied_) return true;
    std::error_code ec;

    // Prepare all temporary payloads first. Nothing authoritative changes yet.
    for (auto& e : staged_) {
        std::filesystem::create_directories(e.path.parent_path(), ec);
        if (ec || !write_all(e.temp, e.content)) {
            if (error) *error = "failed writing staged temp file: " + e.temp.string();
            rollback();
            return false;
        }
    }

    // Swap each file while retaining recoverable backups.
    for (auto& e : staged_) {
        if (e.existed) {
            std::filesystem::rename(e.path, e.backup, ec);
            if (ec) {
                if (error) *error = "failed backing up: " + e.path.string();
                rollback();
                return false;
            }
        }
        std::filesystem::rename(e.temp, e.path, ec);
        if (ec) {
            if (error) *error = "failed applying: " + e.path.string();
            rollback();
            return false;
        }
        e.applied = true;
    }
    applied_ = true;
    return true;
}

bool EditTransaction::finalize(std::string* error) {
    if (committed_) return true;
    if (!applied_) {
        if (error) *error = "cannot finalize a transaction that has not been applied";
        return false;
    }

    std::error_code ec;
    for (auto& e : staged_) {
        if (e.existed) {
            std::filesystem::remove(e.backup, ec);
            if (ec) {
                if (error) *error = "failed deleting backup: " + e.backup.string();
                return false;
            }
        }
        std::filesystem::remove(e.temp, ec);
        ec.clear();
    }
    committed_ = true;
    return true;
}

bool EditTransaction::commit(std::string* error) {
    return apply(error) && finalize(error);
}

void EditTransaction::rollback() noexcept {
    if (committed_) return;
    std::error_code ec;
    for (auto it = staged_.rbegin(); it != staged_.rend(); ++it) {
        auto& e = *it;
        if (e.applied) {
            std::filesystem::remove(e.path, ec);
            ec.clear();
        }
        if (e.existed && std::filesystem::exists(e.backup)) {
            std::filesystem::rename(e.backup, e.path, ec);
            ec.clear();
        }
        std::filesystem::remove(e.temp, ec);
        ec.clear();
        e.applied = false;
    }
    applied_ = false;
}

} // namespace rawrxd::closure
