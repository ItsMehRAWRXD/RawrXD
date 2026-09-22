#pragma once
#include "Common.hpp"
#include <functional>

namespace rawrxd::closure {

struct CertGate {
    std::string name;
    bool required{true};
    std::function<std::pair<bool, std::string>()> run;
};

struct CertificationReport {
    bool passed{};
    std::vector<GateReceipt> receipts;
};

class Certification {
public:
    void add(CertGate gate);
    CertificationReport run(bool stop_on_required_failure = true) const;
    static bool write_jsonl(const CertificationReport&,
                            const std::filesystem::path&,
                            std::string* error = nullptr);
private:
    std::vector<CertGate> gates_;
};

} // namespace rawrxd::closure
