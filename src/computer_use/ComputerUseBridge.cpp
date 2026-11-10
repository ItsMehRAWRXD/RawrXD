#include "ComputerUseBridge.h"
#include <algorithm>
#include <cstdlib>
#include <sstream>

namespace rawrxd::computer_use {

ComputerUseBridge& ComputerUseBridge::Instance() {
    static ComputerUseBridge g;
    return g;
}

void ComputerUseBridge::EnsureInitialized() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (engine_) return;
    policy_.allowedProcessIds = {GetCurrentProcessId()};
    policy_.allowScreenshots = true;
    policy_.allowInspection = true;
    policy_.allowMouse = false;
    policy_.allowTyping = false;
    policy_.allowKeyboard = false;
    policy_.allowLaunch = false;
    policy_.requireForeground = true;
    engine_ = std::make_unique<ComputerUseEngine>(policy_);
}

void ComputerUseBridge::Cancel() noexcept {
    if (engine_) engine_->Cancel();
}
void ComputerUseBridge::ResetCancel() noexcept {
    if (engine_) engine_->ResetCancel();
}

void ComputerUseBridge::AllowOwnProcess() {
    EnsureInitialized();
    std::lock_guard<std::mutex> lock(mutex_);
    policy_.allowedProcessIds = {GetCurrentProcessId()};
    engine_ = std::make_unique<ComputerUseEngine>(policy_);
}

void ComputerUseBridge::AllowProcessId(DWORD pid) {
    if (!pid) return;
    EnsureInitialized();
    std::lock_guard<std::mutex> lock(mutex_);
    if (std::find(policy_.allowedProcessIds.begin(),
                  policy_.allowedProcessIds.end(),
                  pid) == policy_.allowedProcessIds.end()) {
        policy_.allowedProcessIds.push_back(pid);
    }
    engine_ = std::make_unique<ComputerUseEngine>(policy_);
}

void ComputerUseBridge::AllowOwnAndConfiguredParents() {
    EnsureInitialized();
    std::vector<DWORD> extra;
    if (const char* parent = std::getenv("RAWRXD_PARENT_PID")) {
        char* end = nullptr;
        const unsigned long v = std::strtoul(parent, &end, 10);
        if (end != parent && v != 0ul && v <= 0xFFFFFFFFul)
            extra.push_back(static_cast<DWORD>(v));
    }
    if (const char* list = std::getenv("RAWRXD_CU_ALLOW_PIDS")) {
        const char* p = list;
        while (*p) {
            while (*p == ',' || *p == ' ' || *p == ';') ++p;
            if (!*p) break;
            char* end = nullptr;
            const unsigned long v = std::strtoul(p, &end, 10);
            if (end == p) break;
            if (v != 0ul && v <= 0xFFFFFFFFul)
                extra.push_back(static_cast<DWORD>(v));
            p = end;
        }
    }
    std::lock_guard<std::mutex> lock(mutex_);
    policy_.allowedProcessIds = {GetCurrentProcessId()};
    for (DWORD pid : extra) {
        if (std::find(policy_.allowedProcessIds.begin(),
                      policy_.allowedProcessIds.end(),
                      pid) == policy_.allowedProcessIds.end()) {
            policy_.allowedProcessIds.push_back(pid);
        }
    }
    engine_ = std::make_unique<ComputerUseEngine>(policy_);
}

void ComputerUseBridge::SetMouseAllowed(bool v) {
    EnsureInitialized();
    std::lock_guard<std::mutex> lock(mutex_);
    policy_.allowMouse = v;
    engine_ = std::make_unique<ComputerUseEngine>(policy_);
}
void ComputerUseBridge::SetTypingAllowed(bool v) {
    EnsureInitialized();
    std::lock_guard<std::mutex> lock(mutex_);
    policy_.allowTyping = v;
    engine_ = std::make_unique<ComputerUseEngine>(policy_);
}
void ComputerUseBridge::SetKeyboardAllowed(bool v) {
    EnsureInitialized();
    std::lock_guard<std::mutex> lock(mutex_);
    policy_.allowKeyboard = v;
    engine_ = std::make_unique<ComputerUseEngine>(policy_);
}
void ComputerUseBridge::SetLaunchAllowed(bool v) {
    EnsureInitialized();
    std::lock_guard<std::mutex> lock(mutex_);
    policy_.allowLaunch = v;
    engine_ = std::make_unique<ComputerUseEngine>(policy_);
}

ActionResult ComputerUseBridge::DispatchApproved(
    const ComputerAction& action, bool approved) {
    EnsureInitialized();
    // AgentAdapter is the only execution entry; SafetyPolicy still applies.
    AgentAdapter adapter(*engine_,
        [approved](const ComputerAction&) { return approved; });
    return adapter.Dispatch(action);
}

rawrxd::tools::Result ComputerUseBridge::ToToolResult(
    const ComputerAction& a, const ActionResult& r) const {
    std::ostringstream out;
    out << WideToUtf8(FormatReceipt(a, r));
    if (!r.screenshotPath.empty())
        out << " screenshot=" << WideToUtf8(r.screenshotPath);
    if (r.window)
        out << " hwnd=" << reinterpret_cast<uintptr_t>(r.window);
    if (r.success) return {true, out.str(), ""};
    return {false, out.str(), WideToUtf8(r.message)};
}

void ComputerUseBridge::RegisterTools(rawrxd::tools::Registry& reg) {
    EnsureInitialized();
    // Registry.call already requires approval for Risk::Execute tools.
    // Invoke only runs after that gate; adapter still receives approved=true.
    // Caller must not register twice into the same Registry (duplicate throws).
    auto self = this;
    auto add = [&](const char* name, const char* desc, rawrxd::tools::Risk risk,
                   std::vector<std::string> req) {
        reg.add({name, desc, risk, std::move(req),
            [self](const rawrxd::tools::Request& r) -> rawrxd::tools::Result {
                const ComputerAction action = self->ParseAction(r);
                const ActionResult result = self->DispatchApproved(action, true);
                return self->ToToolResult(action, result);
            }});
    };
    add("computer_use.screenshot", "BMP capture of allowlisted window",
        rawrxd::tools::Risk::ReadOnly, {"hwnd"});
    add("computer_use.find_window", "Find allowlisted window by title",
        rawrxd::tools::Risk::ReadOnly, {"title"});
    add("computer_use.inspect", "Enumerate child controls",
        rawrxd::tools::Risk::ReadOnly, {"hwnd"});
    add("computer_use.click", "Click client coordinates",
        rawrxd::tools::Risk::Execute, {"hwnd", "x", "y"});
    add("computer_use.type", "Type Unicode text",
        rawrxd::tools::Risk::Execute, {"hwnd", "text"});
    add("computer_use.key", "Send virtual-key",
        rawrxd::tools::Risk::Execute, {"hwnd", "vk"});
    add("computer_use.scroll", "Scroll at client coordinates",
        rawrxd::tools::Risk::Execute, {"hwnd", "x", "y", "delta"});
    add("computer_use.launch", "Launch absolute executable (no shell)",
        rawrxd::tools::Risk::Execute, {"path"});
}

}  // namespace rawrxd::computer_use
