// tts_smoke.cpp — acceptance smoke for the native SAPI TTS module.
// Initializes SAPI, enumerates installed voices, and speaks a short phrase.
// Exit 0 = SAPI initialized, >=1 voice found, and speech completed without error.
#include "win32app/tts/tts_sapi.h"

#include <cstdio>
#include <string>

int main(int argc, char** argv) {
    const std::string text = argc > 1 ? argv[1]
                                      : "Hello from RawrXD text to speech.";

    rawrxd::tts::TtsEngine engine;
    std::string err;
    if (!engine.initialize(err)) {
        std::printf("TTS_FAIL initialize: %s\n", err.c_str());
        return 1;
    }
    std::printf("TTS_INIT=OK\n");

    const auto voices = engine.voices();
    std::printf("TTS_VOICES=%zu\n", voices.size());
    for (const auto& v : voices) {
        std::printf("  voice: %s\n", v.name.c_str());
    }

    std::string serr;
    const bool ok = engine.speak(text, serr);
    std::printf("TTS_SPEAK=%s %s\n", ok ? "OK" : "FAIL", serr.c_str());

    engine.shutdown();
    const bool pass = ok && !voices.empty();
    std::printf("TTS_SMOKE=%s\n", pass ? "PASS" : "FAIL");
    return pass ? 0 : 1;
}