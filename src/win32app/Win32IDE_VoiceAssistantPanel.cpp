// Win32IDE_VoiceAssistantPanel.cpp — Voice Assistant (Batch 6 C04)
#include "Win32IDE.h"
#include "rawrxd/tts/TtsEngine.h"
#include <windows.h>
#include <string>

namespace {
rawrxd::tts::TtsEngine& ttsEngine() {
    static rawrxd::tts::TtsEngine engine;
    return engine;
}
} // namespace

void Win32IDE::initVoiceAssistant() {
    std::string error;
    if (ttsEngine().initialize(error)) {
        appendToOutput("[VoiceAssistant] SAPI TTS ready.\n", "Output", Win32IDE::OutputSeverity::Info);
    } else {
        appendToOutput("[VoiceAssistant] TTS unavailable: " + error + "\n", "Output", Win32IDE::OutputSeverity::Warning);
    }
}

void Win32IDE::speakText(const std::string& text) {
    std::string error;
    if (!ttsEngine().speak(text, 1.0f, 1.0f, error)) {
        appendToOutput("[TTS] failed: " + error + "\n", "Output", Win32IDE::OutputSeverity::Error);
        return;
    }
    appendToOutput("[TTS] speaking\n", "Output", Win32IDE::OutputSeverity::Info);
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
