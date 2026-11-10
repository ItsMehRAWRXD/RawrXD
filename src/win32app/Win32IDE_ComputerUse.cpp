// Wire native Computer Use into Win32IDE Stop/Clear and agent tool list.
#include "Win32IDE.h"
#include "IDELogger.h"
#if defined(RAWRXD_HAS_COMPUTER_USE)
#include "ComputerUseBridge.h"
#include "agentic/tool_core.hpp"
#endif

void Win32IDE::ensureComputerUseReady() {
#if defined(RAWRXD_HAS_COMPUTER_USE)
    auto& cu = rawrxd::computer_use::ComputerUseBridge::Instance();
    cu.EnsureInitialized();
    cu.AllowOwnProcess();
    cu.ResetCancel();
    if (!m_computerUseToolsRegistered) {
        static rawrxd::tools::Registry s_cuReg;
        cu.RegisterTools(s_cuReg);
        m_computerUseRegistry = &s_cuReg;
        m_computerUseToolsRegistered = true;
        LOG_INFO("ComputerUse tools registered (default-deny input/launch)");
    }
#else
    LOG_INFO("ComputerUse not linked in this build");
#endif
}

void Win32IDE::cancelComputerUse() {
#if defined(RAWRXD_HAS_COMPUTER_USE)
    rawrxd::computer_use::ComputerUseBridge::Instance().Cancel();
    appendToOutput(" ComputerUse cancelled\n", "Output", OutputSeverity::Warning);
#endif
}

std::vector<std::string> Win32IDE::listComputerUseTools() const {
#if defined(RAWRXD_HAS_COMPUTER_USE)
    return {
        "computer_use.screenshot",
        "computer_use.find_window",
        "computer_use.inspect",
        "computer_use.click",
        "computer_use.type",
        "computer_use.key",
        "computer_use.scroll",
        "computer_use.launch",
    };
#else
    return {};
#endif
}
