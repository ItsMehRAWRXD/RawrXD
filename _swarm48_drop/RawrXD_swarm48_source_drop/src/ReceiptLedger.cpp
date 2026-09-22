#include "rawrxd/swarm48/ReceiptLedger.hpp"
#include <sstream>

namespace rawrxd::swarm48 {
static std::string esc(std::string_view s) {
    std::string out; out.reserve(s.size()+8);
    for (char c : s) {
        if (c == '\\' || c == '"') { out.push_back('\\'); out.push_back(c); }
        else if (c == '\n') out += "\\n";
        else out.push_back(c);
    }
    return out;
}

void ReceiptLedger::emit(std::string_view event, AgentId agent, DeviceId device, std::string_view detail) {
    std::ostringstream os;
    os << "{\"ts_us\":" << now_us() << ",\"event\":\"" << esc(event)
       << "\",\"agent\":" << agent << ",\"device\":" << device
       << ",\"detail\":\"" << esc(detail) << "\"}";
    memory_.push_back(os.str());
    if (!path_.empty()) { std::ofstream f(path_, std::ios::app); f << memory_.back() << '\n'; }
}
} // namespace rawrxd::swarm48
