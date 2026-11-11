#pragma once
// IDE bridge for native Computer Use. Policy default-deny for input/launch.
// Application approval required for mutating actions via AgentAdapter.
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "ComputerUse.h"
#include "AgentAdapter.h"
#include "../agentic/tool_core.hpp"
#include <memory>
#include <mutex>
#include <string>

namespace rawrxd::computer_use {

class ComputerUseBridge {
public:
    static ComputerUseBridge& Instance();

    void EnsureInitialized();
    void Cancel() noexcept;
    void ResetCancel() noexcept;
    void AllowOwnProcess();
    void SetMouseAllowed(bool v);
    void SetTypingAllowed(bool v);
    void SetKeyboardAllowed(bool v);
    void SetLaunchAllowed(bool v);

    // Registers computer_use.* tools on the shared tools::Registry.
    void RegisterTools(rawrxd::tools::Registry& reg);

    ActionResult DispatchApproved(const ComputerAction& action, bool approved);

private:
    ComputerUseBridge() = default;
    std::mutex mutex_;
    std::unique_ptr<ComputerUseEngine> engine_;
    SafetyPolicy policy_{};

    ComputerAction ParseAction(const rawrxd::tools::Request& r) const;
    rawrxd::tools::Result ToToolResult(const ComputerAction& a, const ActionResult& r) const;
    std::wstring Utf8ToWide(const std::string& s) const;
    std::string WideToUtf8(const std::wstring& s) const;
};

}  // namespace rawrxd::computer_use
