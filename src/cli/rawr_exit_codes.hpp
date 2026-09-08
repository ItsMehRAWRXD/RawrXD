// rawr_exit_codes.hpp
#pragma once
namespace rawr {
enum ExitCode : int {
    Ok = 0,
    Usage = 1,
    ModelResolve = 2,
    ModelLoad = 3,
    Session = 4,
    ToolDenied = 5,
    PatchFail = 6,
    BuildFail = 7,
    SteerFail = 8,
    SafetyBlock = 9,
    QualityFail = 10,
    Runtime = 11,
};
} // namespace rawr
