#pragma once

#include <string>
#include <vector>

namespace RawrXD {
namespace Build {

struct CompileCommand {
    std::string filePath;
    std::string directory;
    std::string command;
    std::vector<std::string> arguments;
};

class BuildIntelligence {
public:
    BuildIntelligence() = default;
    ~BuildIntelligence() = default;

    bool LoadCompilationDatabase(const std::string& compileCommandsJson);
    CompileCommand GetCommand(const std::string& filePath) const;
    std::vector<std::string> GetDirtyFiles() const;
    std::vector<std::string> GetBuildOrder() const;
    bool TriggerBuild(const std::string& target);
    bool IsReady() const;

private:
    bool ready_ = false;
    std::vector<CompileCommand> commands_;
};

} // namespace Build
} // namespace RawrXD
