// SafeWriteRollback.cpp — preview + rollback + status (own TU; not Phase10)
#include "SafeWriteAtomic.hpp"
#include "SafeWriteState.hpp"
#include "AgentSession.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace RawrXD {
namespace SafeWrite {

std::string PreviewFirstDiff() {
    std::string d = AgentSessionReviewFirst();
    if (!d.empty()) return d;
    std::lock_guard<std::mutex> lock(detail::Mu());
    if (detail::Stack().empty()) return {};
    const detail::Slot& s = detail::Stack().back();
    return "---\n" + s.prior + "\n+++\n(last atomic write id=" +
           std::to_string(s.id) + " path=" + s.path + ")\n";
}

bool RollbackLastWrite(std::string& errJson) {
    detail::Slot s;
    {
        std::lock_guard<std::mutex> lock(detail::Mu());
        if (detail::Stack().empty()) {
            errJson = "{\"error\":\"no_rollback\",\"message\":\"Rollback stack empty\"}";
            return false;
        }
        s = detail::Stack().back();
        detail::Stack().pop_back();
    }
    if (!s.hadFile) {
        if (!DeleteFileA(s.path.c_str()) && GetLastError() != ERROR_FILE_NOT_FOUND) {
            errJson = "{\"error\":\"rollback_delete_failed\",\"win32_error\":" +
                      std::to_string(GetLastError()) + "}";
            return false;
        }
    } else if (!AtomicWriteFile(s.path, s.prior, errJson)) {
        return false;
    }
    std::lock_guard<std::mutex> lock(detail::Mu());
    detail::Rollbacks()++;
    return true;
}

std::string StatusJson() {
    std::lock_guard<std::mutex> lock(detail::Mu());
    return "{\"initialized\":true,\"owner\":\"SafeWriteAtomic\","
           "\"atomic\":\"tmp+ReplaceFileA|MoveFileExA\","
           "\"phase10_independent\":true,"
           "\"writes\":" +
           std::to_string(detail::Writes()) +
           ",\"rollbacks\":" + std::to_string(detail::Rollbacks()) +
           ",\"stack\":" + std::to_string(detail::Stack().size()) +
           ",\"next_id\":" + std::to_string(detail::NextId()) + "}";
}

}  // namespace SafeWrite
}  // namespace RawrXD
