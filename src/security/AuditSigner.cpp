// src/security/AuditSigner.cpp
// Creates signed audit trail entries for every backend operation.
// Each entry is timestamped, bound to a token, and optionally hashed.

#include "CapabilityToken.hpp"
#include <iostream>
#include <fstream>
#include <string>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <vector>
#include <cstdint>

// ---------------------------------------------------------------------------
// Single audit log entry
// ---------------------------------------------------------------------------
struct AuditEntry {
    uint64_t    timestamp;       // Unix ms
    std::string tokenId;         // Which token authorized this
    std::string backendName;     // Which backend executed
    std::string operation;      // "build", "audit", "gpu_dispatch", etc.
    std::string target;         // Build target / file path / GPU kernel
    bool        success;
    uint64_t    durationMs;
    std::string signature;      // Hex hash placeholder

    std::string ToJson() const {
        std::stringstream ss;
        ss << "  {\n";
        ss << "    \"timestamp\": " << timestamp << ",\n";
        ss << "    \"tokenId\": \"" << tokenId << "\",\n";
        ss << "    \"backendName\": \"" << backendName << "\",\n";
        ss << "    \"operation\": \"" << operation << "\",\n";
        ss << "    \"target\": \"" << target << "\",\n";
        ss << "    \"success\": " << (success ? "true" : "false") << ",\n";
        ss << "    \"durationMs\": " << durationMs << ",\n";
        ss << "    \"signature\": \"" << signature << "\"\n";
        ss << "  }";
        return ss.str();
    }
};

// ---------------------------------------------------------------------------
// Audit signer — appends signed entries to a JSON log file
// ---------------------------------------------------------------------------
class AuditSigner {
private:
    std::string m_logPath;
    std::vector<AuditEntry> m_pending;

    // Simple hash placeholder (in production, use SHA-256)
    std::string ComputeSignature(const AuditEntry& entry) {
        std::stringstream ss;
        ss << entry.timestamp << ":" << entry.tokenId << ":"
           << entry.backendName << ":" << entry.operation << ":"
           << entry.target << ":" << (entry.success ? "1" : "0");
        // Placeholder: return a hex-encoded "hash"
        std::string raw = ss.str();
        std::stringstream hex;
        hex << "SIG_";
        for (size_t i = 0; i < raw.size() && i < 8; i++) {
            hex << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(static_cast<unsigned char>(raw[i]));
        }
        return hex.str();
    }

public:
    AuditSigner(const std::string& logPath = "")
        : m_logPath(logPath) {
        if (m_logPath.empty()) {
            m_logPath = "C:\\Users\\HiH8e\\AppData\\Roaming\\RawrXD\\audit_log.json";
        }
    }

    // -----------------------------------------------------------------------
    // Record an operation
    // -----------------------------------------------------------------------
    void Record(const CapabilityToken& token,
                const std::string& operation,
                const std::string& target,
                bool success,
                uint64_t durationMs) {
        AuditEntry entry;
        entry.timestamp   = std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::system_clock::now().time_since_epoch()).count();
        entry.tokenId     = token.tokenId;
        entry.backendName = token.backendName;
        entry.operation   = operation;
        entry.target      = target;
        entry.success     = success;
        entry.durationMs  = durationMs;
        entry.signature   = ComputeSignature(entry);

        m_pending.push_back(entry);
        FlushOne(entry);
    }

    // -----------------------------------------------------------------------
    // Flush a single entry to disk
    // -----------------------------------------------------------------------
    void FlushOne(const AuditEntry& entry) {
        std::ofstream log(m_logPath, std::ios::app);
        if (!log.is_open()) {
            std::cerr << "[AuditSigner] Cannot write to " << m_logPath << "\n";
            return;
        }
        log << entry.ToJson() << ",\n";
        log.close();
    }

    // -----------------------------------------------------------------------
    // Flush all pending entries
    // -----------------------------------------------------------------------
    void Flush() {
        for (const auto& entry : m_pending) {
            FlushOne(entry);
        }
        m_pending.clear();
    }

    // -----------------------------------------------------------------------
    // Read back recent entries
    // -----------------------------------------------------------------------
    std::vector<AuditEntry> RecentEntries(int count = 10) const {
        std::vector<AuditEntry> entries;
        std::ifstream log(m_logPath);
        if (!log.is_open()) return entries;

        std::string line;
        while (std::getline(log, line)) {
            // Minimal parse — in production use a real JSON parser
            if (line.find("\"timestamp\"") != std::string::npos) {
                AuditEntry e;
                size_t pos;
                pos = line.find("\"timestamp\":");
                if (pos != std::string::npos) {
                    pos = line.find_first_of("0123456789", pos);
                    size_t end = line.find_first_of(",", pos);
                    e.timestamp = std::stoull(line.substr(pos, end - pos));
                }
                pos = line.find("\"backendName\":");
                if (pos != std::string::npos) {
                    pos = line.find("\"", pos + 14) + 1;
                    size_t end = line.find("\"", pos);
                    e.backendName = line.substr(pos, end - pos);
                }
                pos = line.find("\"operation\":");
                if (pos != std::string::npos) {
                    pos = line.find("\"", pos + 12) + 1;
                    size_t end = line.find("\"", pos);
                    e.operation = line.substr(pos, end - pos);
                }
                pos = line.find("\"success\":");
                if (pos != std::string::npos) {
                    e.success = (line.find("true", pos) != std::string::npos);
                }
                entries.push_back(e);
            }
        }
        log.close();

        // Return most recent N
        if (entries.size() > static_cast<size_t>(count)) {
            entries.erase(entries.begin(), entries.end() - count);
        }
        return entries;
    }

    std::string GetLogPath() const { return m_logPath; }
};
