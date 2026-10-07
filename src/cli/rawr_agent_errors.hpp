#pragma once
namespace rawr {
enum class AgentError : int {
    Ok = 0,
    Blocked = 1,
    ToolFail = 2,
    PlanEmpty = 3,
    BuildFail = 4,
    TestFail = 5,
};
} // namespace rawr
