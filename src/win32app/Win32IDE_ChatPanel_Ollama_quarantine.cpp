// Fail-closed IDE Ollama panel stubs — linked only when RAWRXD_OPTIONAL_OLLAMA=OFF.
// Real TU: Win32IDE_ChatPanel_Ollama.cpp (optional adapter build only).
#include "Win32IDE.h"
#include <windows.h>

void Win32IDE::HandleCopilotSend_Ollama()
{
    appendToOutput(
        "LOCAL_ONLY: remote chat adapter not linked.\n",
        "Output", OutputSeverity::Warning);
}

void Win32IDE::initializeChatPanelOllama()
{
    // No WinHTTP / no :11434 probe — panel init is a no-op under default link.
}

void Win32IDE::onOllamaModelsUpdated(std::vector<std::string>* models)
{
    if (models)
        delete models;
}
