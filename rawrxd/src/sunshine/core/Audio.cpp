#include "Audio.hpp"
#include <windows.h>

namespace Sunshine {

bool Audio::initialize() {
    // Minimum viable path: just mark ready.
    // A full XAudio2 backend can be wired later.
    m_ready = true;
    return true;
}

void Audio::shutdown() {
    m_ready = false;
}

void Audio::playTone(float frequency, float durationSeconds) {
    (void)frequency;
    (void)durationSeconds;
    // Placeholder for tone generation.
    // Real implementation would synthesize samples and play via XAudio2.
}

void Audio::update() {
    // No-op stub for now.
}

bool Audio::isReady() const {
    return m_ready;
}

} // namespace Sunshine
