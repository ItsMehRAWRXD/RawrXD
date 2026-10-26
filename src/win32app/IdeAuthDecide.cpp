#include "IdeAuthBoundary.hpp"

namespace RawrXD::IdeAuth {
namespace {
std::string PathOnly(const std::string& path) {
    auto q = path.find('?');
    return q == std::string::npos ? path : path.substr(0, q);
}

bool PrivilegedPath(const std::string& path, const std::string& body) {
    if (path.rfind("/api/debug", 0) == 0) return true;
    if (path != "/api/tool") return false;
    return body.find("\"execute_command\"") != std::string::npos ||
           body.find("\"git_status\"") != std::string::npos;
}
}

HttpDecision DecideWin32(const std::string& method, const std::string& pathIn,
                         const std::string& headers, const std::string& body) {
    const std::string origin = HeaderField(headers, "origin:");
    if (!OriginAllowed(origin)) return HttpDecision::ForbiddenOrigin;
    NoteResponseOrigin(origin);
    const std::string path = PathOnly(pathIn);
    if (method == "OPTIONS") return HttpDecision::Allow;
    if (!(method == "GET" && path == "/gui") && !HeaderHasSession(headers))
        return HttpDecision::Unauthorized;
    if (PrivilegedPath(path, body) && !PrivilegedExecGranted())
        return HttpDecision::ExecDenied;
    return HttpDecision::Allow;
}
}
