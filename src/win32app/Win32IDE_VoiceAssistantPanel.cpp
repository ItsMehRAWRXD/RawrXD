// Win32IDE_VoiceAssistantPanel.cpp — Voice Assistant (Batch 6 C04)
#include "Win32IDE.h"
#include "rawrxd/tts/TtsEngine.h"
#include "rawrxd/stt/SttEngine.h"
#include <windows.h>
#include <string>

namespace {
rawrxd::tts::TtsEngine& ttsEngine() {
    static rawrxd::tts::TtsEngine engine;
    return engine;
}
rawrxd::stt::SttEngine& sttEngine() {
    static rawrxd::stt::SttEngine engine;
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
    if (sttEngine().initialize(error)) {
        appendToOutput("[VoiceAssistant] SAPI STT ready.\n", "Output", Win32IDE::OutputSeverity::Info);
    } else {
        appendToOutput("[VoiceAssistant] STT unavailable: " + error + "\n", "Output", Win32IDE::OutputSeverity::Warning);
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
    std::string error;
    if (!sttEngine().start([this](const std::string& text) {
            appendToOutput("[VoiceAssistant] heard: " + text + "\n", "Output", OutputSeverity::Info);
            speakText(text);
        }, error)) {
        appendToOutput("[VoiceAssistant] listen failed: " + error + "\n", "Output", OutputSeverity::Error);
        return;
    }
    appendToOutput("[VoiceAssistant] Listening...\n", "Output", OutputSeverity::Info);
}

void Win32IDE::stopVoiceListening() {
    sttEngine().stop();
    appendToOutput("[VoiceAssistant] Stopped listening.\n", "Output", OutputSeverity::Info);
}

bool Win32IDE::isVoiceListening() const {
    return sttEngine().listening();
}
