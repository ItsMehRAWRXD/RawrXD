#include "Win32IDE.h"
#include "../ui/tool_action_status.h"
#include <windows.h>
#include <string>

void HandleToolActionStatus(void* idePtr) {
    Win32IDE* ide = static_cast<Win32IDE*>(idePtr);
    if (!ide) return;
    RawrXD::UI::ToolActionAccumulator acc;
    acc.addAction(
        RawrXD::UI::ToolActionStatus::RunTerminalAction("cmake --build .", 120));
    acc.addAction(RawrXD::UI::ToolActionStatus::FinishedAction(0));
    const std::string text = acc.renderPlainText();
    ide->appendToOutput(std::string("[ToolActionStatus]\n") + text + "\n",
                        "Tools", Win32IDE::OutputSeverity::Info);
}
