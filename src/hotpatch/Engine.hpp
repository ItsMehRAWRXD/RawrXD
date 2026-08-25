#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace RawrXD {
namespace Agentic {
namespace Hotpatch {

class Engine {
public:
    static Engine& instance();
    bool setModelTemperature(double temp);
    bool loadModel(const std::string& path);
    bool isReady() const;
    std::string generate(const std::string& prompt);
    void shutdown();
private:
    Engine() = default;
    ~Engine() = default;
    Engine(const Engine&) = delete;
    Engine& operator=(const Engine&) = delete;
    double m_temperature = 0.8;
    bool m_ready = false;
};

} // namespace Hotpatch
} // namespace Agentic
} // namespace RawrXD
