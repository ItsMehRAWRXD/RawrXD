#pragma once
#include "WorkspaceGuard.hpp"
#include <functional>
#include <map>
#include <mutex>

namespace rawrxd::closure {

struct ToolRequest {
    std::string name;
    std::string argument;
    std::optional<std::filesystem::path> path;
    bool mutation{};
};

struct ToolResult {
    bool ok{};
    std::string output;
    int code{};
};

class IToolAuthority {
public:
    virtual ~IToolAuthority() = default;
    virtual bool registered(std::string_view name) const = 0;
    virtual ToolResult invoke(const ToolRequest&) = 0;
};

class ToolGateway {
public:
    ToolGateway(IToolAuthority& authority,
                WorkspaceGuard guard,
                std::filesystem::path receipt_path);

    ToolResult invoke(ToolRequest request);
    uint64_t invocation_count() const noexcept { return invocation_count_; }

private:
    void append_receipt(const ToolRequest&, const ToolResult&, uint64_t elapsed_us);

    IToolAuthority& authority_;
    WorkspaceGuard guard_;
    std::filesystem::path receipt_path_;
    mutable std::mutex receipt_mutex_;
    uint64_t invocation_count_{};
};

} // namespace rawrxd::closure
