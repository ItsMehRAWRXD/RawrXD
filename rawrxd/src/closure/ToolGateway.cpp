#include "rawrxd/closure/ToolGateway.hpp"
#include <fstream>

namespace rawrxd::closure {

ToolGateway::ToolGateway(IToolAuthority& authority,
                         WorkspaceGuard guard,
                         std::filesystem::path receipt_path)
    : authority_(authority), guard_(std::move(guard)), receipt_path_(std::move(receipt_path)) {}

ToolResult ToolGateway::invoke(ToolRequest request) {
    const auto start = std::chrono::steady_clock::now();
    ToolResult out;

    if (!authority_.registered(request.name)) {
        out = {false, "tool is not registered in authoritative registry", 404};
    } else if (request.path) {
        std::filesystem::path resolved;
        std::string error;
        if (!guard_.resolve(*request.path, resolved, &error)) {
            out = {false, "workspace policy denied path: " + error, 403};
        } else {
            request.path = resolved;
            out = authority_.invoke(request);
        }
    } else {
        out = authority_.invoke(request);
    }

    const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - start).count();
    ++invocation_count_;
    append_receipt(request, out, static_cast<uint64_t>(elapsed));
    return out;
}

void ToolGateway::append_receipt(const ToolRequest& req, const ToolResult& res, uint64_t elapsed_us) {
    std::lock_guard lock(receipt_mutex_);
    std::error_code ec;
    if (!receipt_path_.parent_path().empty())
        std::filesystem::create_directories(receipt_path_.parent_path(), ec);
    std::ofstream out(receipt_path_, std::ios::app);
    if (!out) return;
    out << "{\"tool\":\"" << json_escape(req.name)
        << "\",\"mutation\":" << (req.mutation ? "true" : "false")
        << ",\"ok\":" << (res.ok ? "true" : "false")
        << ",\"code\":" << res.code
        << ",\"elapsed_us\":" << elapsed_us
        << ",\"arg_hash\":\"" << std::hex << fnv1a64(req.argument) << std::dec << "\"";
    if (req.path) out << ",\"path\":\"" << json_escape(req.path->generic_string()) << "\"";
    out << "}\n";
}

} // namespace rawrxd::closure
