#include "rawrxd/closure/Certification.hpp"
#include <fstream>

namespace rawrxd::closure {

void Certification::add(CertGate gate) { gates_.push_back(std::move(gate)); }

CertificationReport Certification::run(bool stop_on_required_failure) const {
    CertificationReport report;
    report.passed = true;
    for (const auto& g : gates_) {
        const auto start = std::chrono::steady_clock::now();
        GateReceipt r;
        r.name = g.name;
        try {
            auto [ok, detail] = g.run();
            r.status = ok ? Status::pass : Status::fail;
            r.detail = std::move(detail);
        } catch (const std::exception& e) {
            r.status = Status::fail;
            r.detail = e.what();
        } catch (...) {
            r.status = Status::fail;
            r.detail = "unknown exception";
        }
        r.elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start);
        if (g.required && r.status != Status::pass) {
            report.passed = false;
            report.receipts.push_back(std::move(r));
            if (stop_on_required_failure) break;
        } else {
            report.receipts.push_back(std::move(r));
        }
    }
    return report;
}

bool Certification::write_jsonl(const CertificationReport& report,
                                const std::filesystem::path& path,
                                std::string* error) {
    std::error_code ec;
    if (!path.parent_path().empty()) std::filesystem::create_directories(path.parent_path(), ec);
    std::ofstream out(path, std::ios::trunc);
    if (!out) { if (error) *error = "cannot open certification receipt"; return false; }
    for (const auto& r : report.receipts) {
        out << "{\"gate\":\"" << json_escape(r.name)
            << "\",\"status\":\"" << to_string(r.status)
            << "\",\"elapsed_ms\":" << r.elapsed.count()
            << ",\"detail\":\"" << json_escape(r.detail) << "\"}\n";
    }
    out << "{\"overall\":\"" << (report.passed ? "PASS" : "FAIL") << "\"}\n";
    return static_cast<bool>(out);
}

} // namespace rawrxd::closure
