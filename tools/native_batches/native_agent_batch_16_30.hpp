#pragma once
#include "native_agent_batch.hpp"
#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace RawrXD::NativeBridge {
struct FileInfo { std::string path; std::uintmax_t bytes=0; bool directory=false; };
Result readBounded(const std::filesystem::path& root,const std::string& relative,size_t limit);
Result listDirectory(const std::filesystem::path& root,const std::string& relative,size_t maxEntries);
Result replaceExact(const std::filesystem::path& root,const std::string& relative,
                    const std::string& before,const std::string& after);
Result insertLine(const std::filesystem::path& root,const std::string& relative,size_t lineNumber,const std::string& line);
Result eraseLine(const std::filesystem::path& root,const std::string& relative,size_t lineNumber);
Result diffLines(const std::string& before,const std::string& after,size_t maxLines);
std::string fnv1a64(const std::string& content);
Result fileFingerprint(const std::filesystem::path& root,const std::string& relative,size_t limit);
std::optional<FileInfo> statFile(const std::filesystem::path& root,const std::string& relative);
Result scanWorkspace(const std::filesystem::path& root,const std::string& suffix,size_t maxFiles);
struct ScheduleItem { Task task; enum class Status { Pending, Running, Succeeded, Failed, Skipped } status=Status::Pending; };
class TaskTracker {
public:
    Result load(const std::vector<Task>& tasks);
    std::vector<Task> ready() const;
    bool start(const std::string& id);
    bool finish(const std::string& id, bool success);
    std::map<std::string,ScheduleItem::Status> statuses() const;
    bool complete() const;
private:
    std::map<std::string,ScheduleItem> tasks_;
};
Result validateWorkspacePath(const std::filesystem::path& root,const std::string& relative);
Result registerWorkspaceTools(ToolRegistry& registry,const std::filesystem::path& root);
}
