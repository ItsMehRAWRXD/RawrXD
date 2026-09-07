#pragma once
#include "audit_log.hpp"
#include "sandbox.hpp"
#include <fstream>
#include <sstream>
#include <string>
namespace rawr::product {

struct ToolRuntime {
    Sandbox box;
    int reads = 0;
    int writes = 0;
    int execs = 0;
    int denies = 0;

    bool readFile(const std::string& path, std::string& out) {
        if (!box.checkRead(path)) {
            denies++;
            AuditWrite(AuditRec{"read", path.c_str(), 1, 0});
            return false;
        }
        std::ifstream in(path, std::ios::binary);
        if (!in) return false;
        std::ostringstream ss;
        ss << in.rdbuf();
        out = ss.str();
        reads++;
        AuditWrite(AuditRec{"read", path.c_str(), 0, 1});
        return true;
    }

    bool writeFile(const std::string& path, const std::string& text) {
        if (!box.checkWrite(path)) {
            denies++;
            AuditWrite(AuditRec{"write", path.c_str(), 1, 0});
            return false;
        }
        std::ofstream out(path, std::ios::binary);
        if (!out) return false;
        out << text;
        writes++;
        AuditWrite(AuditRec{"write", path.c_str(), 0, 1});
        return true;
    }

    int execEcho(const std::string& msg, std::string& out) {
        if (!box.checkExec("echo " + msg)) {
            denies++;
            AuditWrite(AuditRec{"exec", msg.c_str(), 1, 0});
            return 3;
        }
        int rc = SandboxRunEcho(box, msg, out);
        execs++;
        AuditWrite(AuditRec{"exec", msg.c_str(), 0, rc == 0 ? 1 : 0});
        return rc;
    }
};

} // namespace rawr::product
