#include "rawrxd/stt/SttEngine.h"

#include <chrono>
#include <iostream>
#include <string>
#include <thread>

int main() {
    rawrxd::stt::SttEngine engine;
    std::string error;
    if (!engine.initialize(error)) {
        std::cout << "SKIP: " << error << "\n";
        return 77;
    }

    bool heard = false;
    if (!engine.start([&heard](const std::string& text) {
            heard = true;
            std::cout << "heard=" << text << "\n";
        }, error)) {
        std::cerr << "FAIL: " << error << "\n";
        return 1;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    engine.stop();
    if (engine.listening()) {
        std::cerr << "FAIL: still listening after stop\n";
        return 1;
    }
    std::cout << "STT_OK heard=" << (heard ? 1 : 0) << "\n";
    return 0;
}