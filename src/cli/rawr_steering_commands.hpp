#pragma once
namespace rawr {
inline bool IsSteerVerb(const char* v) {
    if (!v) return false;
    // pause continue stop show_plan show_diff undo run_test change_model
    // change_autonomy explain_blocker approve_action reject_action
    return true;
}
} // namespace rawr
