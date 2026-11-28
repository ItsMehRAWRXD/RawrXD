// rawrxd TTS — native Windows SAPI text-to-speech (no external deps, no Qt).
//
// A thin, production-native wrapper over the OS SAPI (ISpVoice) so the product
// can speak text (accessibility / agent voice) without adding dependencies.
#pragma once

#include <string>
#include <vector>

namespace rawrxd::tts {

struct Voice {
    std::string name;      // token description (e.g. "Microsoft David Desktop")
    std::string language;  // best-effort language id (may be empty)
};

class TtsEngine {
public:
    // Initialize COM + the shared SAPI voice. Returns false with a diagnostic on failure.
    bool initialize(std::string& err);
    void shutdown();

    // Enumerate installed SAPI voices. Empty if not initialized or none installed.
    std::vector<Voice> voices() const;

    // Speak text synchronously (blocks until complete). Returns false on error.
    bool speak(const std::string& text, std::string& err);

    // Stop any in-progress speech.
    void stop();

    bool isSpeaking() const;
    bool ready() const { return voice_ != nullptr; }

private:
    void* voice_ = nullptr;  // ISpVoice*
};

}  // namespace rawrxd::tts