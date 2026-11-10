#pragma once
#include "ComputerUse.h"
#include <functional>
namespace rawrxd::computer_use {
// Caller parses local model tool-call JSON into a typed ComputerAction.
// No model output is executed without application approval and policy checks.
class AgentAdapter {
public:
    using Approval = std::function<bool(const ComputerAction&)>;
    AgentAdapter(ComputerUseEngine& engine, Approval approve):engine_(engine),approve_(std::move(approve)){}
    ActionResult Dispatch(const ComputerAction& action) {
        if(!approve_ || !approve_(action)) return {false,ERROR_ACCESS_DENIED,L"Agent action not approved"};
        return engine_.Execute(action);
    }
private:
    ComputerUseEngine& engine_;
    Approval approve_;
};
}
