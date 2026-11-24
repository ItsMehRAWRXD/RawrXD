// =============================================================================
// audit_log_test.cpp — S7 certification: SHA-256 vector + chain tamper detect.
// =============================================================================
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#include "security/audit_log.h"

static bool ReplaceLine(const std::string& path, int target, const std::string& repl) {
    std::ifstream in(path);
    if (!in) return false;
    std::vector<std::string> lines;
    std::string l;
    int i = 0;
    while (std::getline(in, l)) {
        if (i == target) l = repl;
        lines.push_back(l);
        ++i;
    }
    std::ofstream out(path);
    for (const auto& x : lines) out << x << "\n";
    return true;
}

int main() {
    int failures = 0;
    // SHA-256("abc") known answer.
    const std::string abc = rawrxd::security::Sha256::Hash("abc");
    if (abc != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") {
        std::printf("[FAIL] sha256(abc)=%s\n", abc.c_str());
        ++failures;
    }
    const std::string tmp = getenv("TEMP") ? getenv("TEMP") : ".";
    const std::string path = tmp + "/audit_log_test.jsonl";
    std::remove(path.c_str());
    rawrxd::security::AuditLog log(path);
    for (int i = 0; i < 3; ++i) {
        if (!log.Append("tester", "act" + std::to_string(i), "detail")) {
            std::printf("[FAIL] append %d\n", i);
            ++failures;
        }
    }
    std::string err;
    if (!log.Verify(&err) || log.Size() != 3) {
        std::printf("[FAIL] fresh chain verify: %s\n", err.c_str());
        ++failures;
    }
    // Tamper with the middle record's detail.
    if (!ReplaceLine(path, 1,
                     "{\"ts\":\"x\",\"actor\":\"tester\",\"action\":\"act1\","
                     "\"detail\":\"TAMPERED\",\"prev_hash\":\"" +
                         std::string(64, '0') +
                         "\",\"record_hash\":\"" + std::string(64, '0') +
                         "\"}")) {
        std::printf("[FAIL] tamper setup\n");
        ++failures;
    }
    if (log.Verify(&err)) {
        std::printf("[FAIL] tampered chain verified OK\n");
        ++failures;
    }
    // Append must be refused on a broken chain.
    if (log.Append("tester", "x", "y")) {
        std::printf("[FAIL] append accepted on broken chain\n");
        ++failures;
    }
    std::remove(path.c_str());
    std::printf("audit_log_test: failures=%d\n", failures);
    std::printf("AUDIT_LOG_TEST %s\n", failures == 0 ? "PASS" : "FAIL");
    return failures == 0 ? 0 : 1;
}