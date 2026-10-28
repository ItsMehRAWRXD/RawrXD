// SafeWriteAtomic.cpp — tmp+ReplaceFile atomic write + preview note
#include "SafeWriteAtomic.hpp"
#include "SafeWriteState.hpp"
#include "AgentSession.hpp"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace RawrXD {
namespace SafeWrite {
namespace {
bool readAll(const std::string& path, std::string& out) {
    HANDLE h = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER sz = {};
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart < 0 ||
        static_cast<uint64_t>(sz.QuadPart) > detail::kMaxWrite) {
        CloseHandle(h); return false;
    }
    out.assign(static_cast<size_t>(sz.QuadPart), '\0');
    DWORD n = 0;
    BOOL ok = ReadFile(h, out.empty() ? nullptr : &out[0],
                       static_cast<DWORD>(out.size()), &n, nullptr);
    CloseHandle(h);
    if (!ok) return false;
    out.resize(n); return true;
}
}  // namespace

bool AtomicWriteFile(const std::string& path, const std::string& content,
                     std::string& errJson) {
    if (content.size() > detail::kMaxWrite) {
        errJson = "{\"error\":\"content_too_large\",\"message\":\"Content exceeds 50MB write limit\"}";
        return false;
    }
    const std::string tmp = path + ".swa.tmp";
    HANDLE h = CreateFileA(tmp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        errJson = "{\"error\":\"write_failed\",\"message\":\"Cannot create tmp\",\"win32_error\":" +
            std::to_string(GetLastError()) + "}";
        return false;
    }
    DWORD written = 0;
    BOOL ok = WriteFile(h, content.data(), static_cast<DWORD>(content.size()),
                        &written, nullptr);
    CloseHandle(h);
    if (!ok || written != content.size()) {
        DeleteFileA(tmp.c_str());
        errJson = "{\"error\":\"write_failed\",\"message\":\"WriteFile tmp failed\"}";
        return false;
    }
    if (GetFileAttributesA(path.c_str()) != INVALID_FILE_ATTRIBUTES &&
        ReplaceFileA(path.c_str(), tmp.c_str(), nullptr,
                     REPLACEFILE_IGNORE_MERGE_ERRORS, nullptr, nullptr))
        return true;
    if (MoveFileExA(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING)) return true;
    errJson = "{\"error\":\"atomic_replace_failed\",\"win32_error\":" +
        std::to_string(GetLastError()) + "}";
    DeleteFileA(tmp.c_str());
    return false;
}

WriteResult WriteWithPreviewRollback(const std::string& path,
                                     const std::string& content) {
    WriteResult wr;
    std::string prior;
    const bool had = readAll(path, prior);
    if (!had) prior.clear();
    AgentSessionNoteWrite(path, prior, content);
    if (!AtomicWriteFile(path, content, wr.errJson)) return wr;
    std::lock_guard<std::mutex> lock(detail::Mu());
    if (detail::Stack().size() >= detail::kMaxRollback)
        detail::Stack().erase(detail::Stack().begin());
    detail::Slot s{detail::NextId()++, path, prior, had};
    detail::Stack().push_back(std::move(s));
    detail::Writes()++;
    wr.ok = wr.atomic = wr.previewed = true;
    wr.rollbackId = detail::Stack().back().id;
    return wr;
}
}  // namespace SafeWrite
}  // namespace RawrXD

