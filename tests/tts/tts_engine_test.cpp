#include "rawrxd/tts/TtsEngine.h"

#include <chrono>
#include <iostream>
#include <string>
#include <thread>

int main() {
    rawrxd::tts::TtsEngine engine;
    std::string error;
    if (!engine.initialize(error)) {
        std::cout << "SKIP: " << error << "\n";
        return 77;
    }

    if (!engine.speak("RawrXD native TTS acceptance.", 1.0f, 1.0f, error)) {
        std::cerr << "FAIL: " << error << "\n";
        return 1;
    }

    for (int i = 0; i < 50; ++i) {
        const auto st = engine.status();
        if (!st.speaking) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    const auto st = engine.status();
    if (!st.available) {
        std::cerr << "FAIL: SAPI voice became unavailable\n";
        return 1;
    }
    if (!st.error.empty()) {
        std::cerr << "FAIL: " << st.error << "\n";
        return 1;
    }
    std::cout << "TTS_OK speaking=" << (st.speaking ? 1 : 0) << "\n";
    return 0;
}