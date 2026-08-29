#include "BuildIntelligence.hpp"

namespace RawrXD {
namespace Build {

bool BuildIntelligence::LoadCompilationDatabase(const std::string& compileCommandsJson) {
    ready_ = !compileCommandsJson.empty();
    return ready_;
}

CompileCommand BuildIntelligence::GetCommand(const std::string& filePath) const {
    for (const auto& command : commands_) {
        if (command.filePath == filePath) {
            return command;
        }
    }
    return CompileCommand{filePath, {}, {}, {}};
}

std::vector<std::string> BuildIntelligence::GetDirtyFiles() const {
    return {};
}

std::vector<std::string> BuildIntelligence::GetBuildOrder() const {
    return {};
}

bool BuildIntelligence::TriggerBuild(const std::string& target) {
    return !target.empty();
}

bool BuildIntelligence::IsReady() const {
    return ready_;
}

} // namespace Build
} // namespace RawrXD
