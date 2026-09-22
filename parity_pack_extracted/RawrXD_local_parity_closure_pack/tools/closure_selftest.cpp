#include "rawrxd/closure/Certification.hpp"
#include "rawrxd/closure/ContextPlanner.hpp"
#include "rawrxd/closure/DevicePolicy.hpp"
#include "rawrxd/closure/EditTransaction.hpp"
#include "rawrxd/closure/PerformanceLedger.hpp"
#include "rawrxd/closure/WorkspaceGuard.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>

using namespace rawrxd::closure;

int main() {
    const auto temp = std::filesystem::temp_directory_path() / "rawrxd_closure_selftest";
    std::error_code ec;
    std::filesystem::remove_all(temp, ec);
    std::filesystem::create_directories(temp, ec);

    Certification c;

    c.add({"workspace_confinement", true, [&] {
        WorkspaceGuard guard(temp);
        std::filesystem::path out;
        std::string error;
        bool inside = guard.resolve("a/b.txt", out, &error);
        bool escape = guard.resolve("../escape.txt", out, &error);
        return std::pair{inside && !escape, inside && !escape ? "confined" : "guard failure"};
    }});

    c.add({"transactional_edit", true, [&] {
        WorkspaceGuard guard(temp);
        EditTransaction tx(guard);
        std::string err;
        if (!tx.stage_write("edit.txt", "rawrxd\n", &err)) return std::pair{false, err};
        if (!tx.commit(&err)) return std::pair{false, err};
        std::ifstream in(temp / "edit.txt");
        std::string s; std::getline(in, s);
        return std::pair<bool, std::string>{s == "rawrxd", s == "rawrxd" ? "atomic write PASS" : "content mismatch"};
    }});

    c.add({"device_policy", true, [&] {
        DeviceInfo devs[] = {
            {0, "r9700", "Radeon AI PRO R9700", 32ull<<30, 28ull<<30, true, true},
            {1, "7800xt", "Radeon RX 7800 XT", 16ull<<30, 14ull<<30, true, true}
        };
        ModelRequirements req{"unit-model", 6ull<<30, 1ull<<30, 1ull<<30};
        auto plan = DevicePolicy::choose(DeviceSelector::r9700, req, devs, {});
        return std::pair{plan.ok && plan.ordinals == std::vector<uint32_t>{0}, plan.reason};
    }});

    c.add({"context_budget", true, [&] {
        ContextCandidate x[] = {
            {"a","a.cpp","",100,1.0,1.0,1.0,true},
            {"b","b.cpp","",200,0.9,0.8,0.1,false},
            {"c","c.cpp","",500,1.0,1.0,1.0,false}
        };
        auto s = ContextPlanner::select(x, 300);
        return std::pair{s.estimated_tokens <= 300 && !s.indices.empty(), "budget respected"};
    }});

    auto report = c.run(false);
    Certification::write_jsonl(report, temp / "closure_selftest.jsonl");
    for (const auto& r : report.receipts)
        std::cout << r.name << '=' << to_string(r.status) << " " << r.detail << '\n';
    std::cout << "RAWRXD_LOCAL_PARITY_CLOSURE=" << (report.passed ? "PASS" : "FAIL") << '\n';
    return report.passed ? 0 : 1;
}
