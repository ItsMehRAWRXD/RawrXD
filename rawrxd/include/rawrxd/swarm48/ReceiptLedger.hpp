#pragma once
#include "Common.hpp"
#include <fstream>

namespace rawrxd::swarm48 {

class ReceiptLedger {
public:
    explicit ReceiptLedger(std::string path = {}) : path_(std::move(path)) {}
    void emit(std::string_view event, AgentId agent, DeviceId device, std::string_view detail);
    const std::vector<std::string>& memory() const noexcept { return memory_; }
private:
    std::string path_;
    std::vector<std::string> memory_;
};

} // namespace rawrxd::swarm48
