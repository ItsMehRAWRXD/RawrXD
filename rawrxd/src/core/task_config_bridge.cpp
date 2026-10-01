// task_config_bridge.cpp — RAWRXD_TASK_CONFIG_001
//
// src/core/task_system.hpp is a 1190-line header-only TaskRunner with real
// process execution, output capture, problem matching, dependency resolution,
// variable expansion and CMake/Make/MSBuild/Ninja detection -- and it was in
// zero build targets with zero includers. Its loadConfig and saveConfig were the
// two functions that said `// TODO: Parse JSON/YAML config file`, which is why
// the capability was recorded as ABSENT: the runner could not read a tasks.json
// even if something had given it one.
//
// This translation unit exists so the header is actually compiled by the build
// rather than merely present on disk, and so the measured load result can be
// observed from a product path.
//
// It deliberately does not own a TaskRunner. The runner is stateful (task map,
// groups, problem matchers, a worker thread) and handing the IDE a second,
// private instance would give the product two task registries, which is the same
// mistake the git-safety registry work already had to undo. Instead:
//
//   LoadTaskConfigFor()   reads a config into a caller-owned TaskRunner
//   SaveTaskConfigFor()   writes one back out
//
// and the IDE keeps the single TaskRunner it owns.

#include "core/task_system.hpp"

namespace rawrxd {

TaskConfigLoadResult LoadTaskConfigFor(TaskRunner& runner, const std::string& path) {
    return runner.loadConfigWithResult(path);
}
void SaveTaskConfigFor(TaskRunner& runner, const std::string& path) {
    runner.saveConfig(path);
}

std::size_t TaskConfigTaskCount(const TaskRunner& runner) {
    return runner.getAllTasks().size();
}

std::vector<std::string> TaskConfigTaskLabels(const TaskRunner& runner) {
    std::vector<std::string> labels;
    for (const auto& t : runner.getAllTasks()) labels.push_back(t.label);
    return labels;
}

} // namespace rawrxd

