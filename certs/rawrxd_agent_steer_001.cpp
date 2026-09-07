#include "../src/cli/rawr_steering_bus.hpp"
#include <atomic>
#include <chrono>
#include <cstdio>
#include <string>
#include <thread>
int main() {
    std::atomic<bool> got{false};
    std::string recv;
    std::thread server([&]() {
        std::string line;
        if (rawr::SteerServeOnce(line, 5000)) {
            recv = line;
            got = true;
        }
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    bool sent = rawr::SteerSend("pause");
    server.join();
    if (!sent || !got || recv.find("pause") == std::string::npos) {
        puts("RAWRXD_AGENT_STEER_001=FAIL");
        return 1;
    }
    puts("RAWRXD_AGENT_STEER_001=PASS");
    return 0;
}
