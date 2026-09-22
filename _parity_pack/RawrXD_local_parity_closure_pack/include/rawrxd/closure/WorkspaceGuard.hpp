#pragma once
#include "Common.hpp"

namespace rawrxd::closure {

class WorkspaceGuard {
public:
    explicit WorkspaceGuard(std::filesystem::path root);
    const std::filesystem::path& root() const noexcept { return root_; }

    bool resolve(std::filesystem::path candidate,
                 std::filesystem::path& resolved,
                 std::string* error = nullptr) const;

private:
    std::filesystem::path root_;
};

} // namespace rawrxd::closure
