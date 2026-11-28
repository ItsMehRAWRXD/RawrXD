#pragma once

#include <string>
#include <vector>

namespace rawrxd::tts {

struct VoiceInfo {
    std::string name;
    std::string language;
};

struct TtsStatus {
    bool available = false;
    bool speaking = false;
    std::string error;
};

// Native Windows SAPI text-to-speech (M-CFG voice completion).
// No Qt, no external dependencies. Fails closed: if SAPI cannot be created,
// available=false and every speak call returns false with an actionable error.
class TtsEngine {
public:
    TtsEngine();
    ~TtsEngine();

    TtsEngine(const TtsEngine&) = delete;
    TtsEngine& operator=(const TtsEngine&) = delete;

    bool initialize(std::string& error);
    std::vector<VoiceInfo> voices() const;
    bool speak(const std::string& text, float rate, float volume,
               std::string& error);
    void stop();
    TtsStatus status() const;

private:
    struct Impl;
    Impl* impl_ = nullptr;
};

} // namespace rawrxd::tts