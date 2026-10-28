// SafeWriteAtomic.hpp — product atomic write + preview + rollback (own TU)
// Owner: A06 write-safety. Not SettingsManager / SwarmOrch.
#pragma once
#include <cstdint>
#include <string>

namespace RawrXD {
namespace SafeWrite {

struct WriteResult {
    bool ok = false;
    bool atomic = false;
    bool previewed = false;
    uint64_t rollbackId = 0;
    std::string errJson;
};

// tmp + ReplaceFileA / MoveFileExA (CREATE_ALWAYS direct write = forbidden here)
bool AtomicWriteFile(const std::string& path, const std::string& content,
                     std::string& errJson);

// Capture prior → AgentSessionNoteWrite preview → atomic write → local rollback slot
WriteResult WriteWithPreviewRollback(const std::string& path,
                                     const std::string& content);

std::string PreviewFirstDiff();
bool RollbackLastWrite(std::string& errJson);
std::string StatusJson();

}  // namespace SafeWrite
}  // namespace RawrXD
