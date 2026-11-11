// Win32IDE_VoiceAssistantPanel.cpp — Voice Assistant (Batch 6 C04)
#include "Win32IDE.h"
#include <windows.h>
#include <string>

void Win32IDE::initVoiceAssistant() {
    appendToOutput("[VoiceAssistant] Voice assistant initialized.\n", "Output", Win32IDE::OutputSeverity::Info);
}

void Win32IDE::startVoiceListening() {
    appendToOutput("[VoiceAssistant] Listening...\n", "Output", Win32IDE::OutputSeverity::Info);
}

void Win32IDE::stopVoiceListening() {
    appendToOutput("[VoiceAssistant] Stopped listening.\n", "Output", Win32IDE::OutputSeverity::Info);
}

bool Win32IDE::isVoiceListening() const {
    return false;
}
