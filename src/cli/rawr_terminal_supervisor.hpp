// rawr_terminal_supervisor.hpp — named background terminals
#pragma once
#include "rawr_terminal_session.hpp"
#include "rawr_safety_policy.hpp"
#include "rawr_command_guard.hpp"
#include "rawr_network_guard.hpp"
#include "rawr_destructive_action_guard.hpp"
#include <memory>
#include <mutex>
#include <sstream>
#include <unordered_map>
#include <vector>

namespace rawr {

struct TerminalSupervisor {
    std::mutex mu;
    std::unordered_map<std::string, std::unique_ptr<TerminalSession>> map;

    static TerminalSupervisor& instance() {
        static TerminalSupervisor g;
        return g;
    }

    int start(const SafetyPolicy& p, const std::string& name,
              const std::string& command) {
        if (name.empty() || command.empty()) return -3;
        if (!p.mayBuild()) return -1;
        if (DestructiveBlocked(p, command)) return -4;
        if (NetworkGuardBlocks(p) &&
            (command.find("http") != std::string::npos ||
             command.find("curl ") != std::string::npos ||
             command.find("wget ") != std::string::npos))
            return -5;
        if (!CommandGuardOk(p, command)) return -2;
        std::lock_guard<std::mutex> g(mu);
        if (map.count(name)) return -6;
        auto s = std::make_unique<TerminalSession>();
        if (!TerminalSessionStart(*s, name, command)) return -7;
        map[name] = std::move(s);
        return 0;
    }

    bool stop(const std::string& name) {
        std::lock_guard<std::mutex> g(mu);
        auto it = map.find(name);
        if (it == map.end()) {
            DWORD pid = 0;
            int alive = 0;
            std::string cmd;
            if (!TerminalMetaRead(name, pid, alive, cmd) || !pid) return false;
#ifdef _WIN32
            HANDLE h = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pid);
            if (!h) return false;
            TerminateProcess(h, 1);
            WaitForSingleObject(h, 3000);
            CloseHandle(h);
            TerminalMetaWrite(name, pid, cmd, 0);
            return true;
#else
            return false;
#endif
        }
        bool ok = TerminalSessionStop(*it->second);
        map.erase(it);
        return ok;
    }

    bool send(const std::string& name, const std::string& input) {
        std::lock_guard<std::mutex> g(mu);
        auto it = map.find(name);
        if (it == map.end()) return false;
        return TerminalSessionSend(*it->second, input);
    }

    std::string tail(const std::string& name, size_t maxBytes = 8192) {
        {
            std::lock_guard<std::mutex> g(mu);
            auto it = map.find(name);
            if (it != map.end()) {
                TerminalSessionPoll(*it->second);
                return it->second->ring.tail(maxBytes);
            }
        }
        return TerminalLogReadTail(name, maxBytes);
    }

    std::string list() {
        std::lock_guard<std::mutex> g(mu);
        std::ostringstream os;
        for (auto& kv : map) {
            TerminalSessionPoll(*kv.second);
            os << kv.first << " pid=" << kv.second->pid
               << " alive=" << (kv.second->isAlive() ? 1 : 0)
               << " exit=" << kv.second->exitCode << "\n";
        }
        return os.str();
    }

    TerminalSession* get(const std::string& name) {
        auto it = map.find(name);
        return it == map.end() ? nullptr : it->second.get();
    }
};

} // namespace rawr
