// rawr_exit_codes.hpp
#pragma once
namespace rawr {
enum ExitCode : int {
    Ok = 0,
    Usage = 1,
    ModelResolve = 3,   // MODEL_NOT_FOUND — model could not be resolved
    ModelLoad = 4,      // model resolved but failed to load
    Session = 5,
    ToolDenied = 6,
    PatchFail = 7,
    BuildFail = 8,
    SteerFail = 9,
    SafetyBlock = 10,
    QualityFail = 11,
    Runtime = 12,
};
} // namespace rawr
