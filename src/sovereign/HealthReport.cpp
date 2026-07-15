#include "sovereign/HealthReport.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <iostream>

namespace Sovereign {

void HealthReport::ProcessBeacons(BeaconismEmitter& emitter) {
    timestamp = std::time(nullptr);
    
    Beacon beacon;
    while (emitter.ReadNext(beacon)) {
        totalBeacons++;
        
        BeaconID id = static_cast<BeaconID>(beacon.id);
        
        // Check if start or done beacon
        if ((beacon.id & 0xFF) == 0x00) {
            // Start beacon
            lastStartBeacons[id] = beacon;
        } else if ((beacon.id & 0xFF) == 0x01) {
            // Done beacon - calculate duration
            BeaconID startId = static_cast<BeaconID>(beacon.id - 1);
            auto it = lastStartBeacons.find(startId);
            if (it != lastStartBeacons.end()) {
                uint64_t duration = beacon.timestamp - it->second.timestamp;
                
                // Map to subsystem
                std::string name = BeaconName(startId);
                UpdateSubsystem(name, HealthState::OK, duration, 1);
                
                lastDoneBeacons[startId] = beacon;
                passedTests++;
            }
        }
    }
    
    // Check for timeouts (started but not done)
    auto now = __rdtsc();
    for (const auto& pair : lastStartBeacons) {
        auto doneIt = lastDoneBeacons.find(pair.first);
        if (doneIt == lastDoneBeacons.end()) {
            // Not completed - check timeout (5 seconds @ 3GHz = 15B cycles)
            if (now - pair.second.timestamp > 15000000000ULL) {
                std::string name = BeaconName(pair.first);
                UpdateSubsystem(name, HealthState::FAIL, 0, 0);
                failedTests++;
            }
        }
    }
    
    CalculateHealth();
}

void HealthReport::UpdateSubsystem(const std::string& name, HealthState state,
                                   uint64_t duration, uint32_t count) {
    for (auto& sub : subsystems) {
        if (sub.name == name) {
            sub.state = state;
            sub.durationNs = duration;
            sub.beaconCount += count;
            sub.lastRun = std::time(nullptr);
            if (state == HealthState::OK) {
                sub.lastSuccess = sub.lastRun;
            }
            return;
        }
    }
    
    // New subsystem
    SubsystemHealth sub;
    sub.name = name;
    sub.state = state;
    sub.durationNs = duration;
    sub.beaconCount = count;
    sub.lastRun = std::time(nullptr);
    if (state == HealthState::OK) {
        sub.lastSuccess = sub.lastRun;
    }
    subsystems.push_back(sub);
}

void HealthReport::CalculateHealth() {
    if (subsystems.empty()) {
        summary = "No subsystems reported";
        return;
    }
    
    size_t ok = 0, warn = 0, fail = 0;
    for (const auto& sub : subsystems) {
        switch (sub.state) {
            case HealthState::OK: ok++; break;
            case HealthState::WARNING: warn++; break;
            case HealthState::FAIL: fail++; break;
            default: break;
        }
    }
    
    std::ostringstream ss;
    ss << ok << "/" << subsystems.size() << " healthy";
    if (warn > 0) ss << ", " << warn << " warning";
    if (fail > 0) ss << ", " << fail << " failed";
    summary = ss.str();
}

HealthState HealthReport::GetOverallHealth() const {
    if (subsystems.empty()) return HealthState::UNKNOWN;
    
    for (const auto& sub : subsystems) {
        if (sub.state == HealthState::FAIL) return HealthState::FAIL;
    }
    for (const auto& sub : subsystems) {
        if (sub.state == HealthState::WARNING) return HealthState::WARNING;
    }
    return HealthState::OK;
}

void HealthReport::GenerateHTML(const std::wstring& path) {
    std::ofstream html(path);
    if (!html) return;
    
    html << "<!DOCTYPE html>\n<html>\n<head>\n";
    html << "<meta charset=\"UTF-8\">\n";
    html << "<title>RawrXD Sovereign Health Report</title>\n";
    html << "<style>\n";
    html << "body{font-family:Consolas,monospace;background:#0d1117;color:#c9d1d9;padding:20px}\n";
    html << ".header{background:#161b22;padding:20px;border-radius:8px;margin-bottom:20px}\n";
    html << ".ok{color:#3fb950}.warn{color:#d29922}.fail{color:#f85149}\n";
    html << "table{width:100%;border-collapse:collapse;background:#161b22;border-radius:8px}\n";
    html << "th,td{padding:12px;text-align:left;border-bottom:1px solid #30363d}\n";
    html << "th{background:#21262d;color:#f0f6fc}\n";
    html << ".status{font-weight:bold}\n";
    html << "</style>\n</head>\n<body>\n";
    
    html << "<div class=\"header\">\n";
    html << "<h1>🛡️ RawrXD Sovereign Health Report</h1>\n";
    html << "<p>Generated: " << std::put_time(std::localtime(&timestamp), "%Y-%m-%d %H:%M:%S") << "</p>\n";
    html << "<p class=\"" << (GetOverallHealth() == HealthState::OK ? "ok" : 
                              GetOverallHealth() == HealthState::WARNING ? "warn" : "fail") << "\">";
    html << summary << "</p>\n";
    html << "</div>\n";
    
    html << "<table>\n";
    html << "<tr><th>Subsystem</th><th>Status</th><th>Duration</th><th>Beacons</th><th>Last Success</th></tr>\n";
    
    for (const auto& sub : subsystems) {
        html << "<tr>";
        html << "<td>" << sub.name << "</td>";
        html << "<td class=\"status " << (sub.state == HealthState::OK ? "ok" : 
                                            sub.state == HealthState::WARNING ? "warn" : "fail") << "\">";
        html << StateEmoji(sub.state) << " ";
        html << (sub.state == HealthState::OK ? "OK" : 
                 sub.state == HealthState::WARNING ? "WARNING" : "FAIL");
        html << "</td>";
        html << "<td>" << (sub.durationNs / 1000000) << " ms</td>";
        html << "<td>" << sub.beaconCount << "</td>";
        html << "<td>" << (sub.lastSuccess ? std::put_time(std::localtime(&sub.lastSuccess), "%H:%M:%S") : "Never") << "</td>";
        html << "</tr>\n";
    }
    
    html << "</table>\n</body>\n</html>";
}

void HealthReport::GenerateJSON(const std::wstring& path) {
    std::ofstream json(path);
    if (!json) return;
    
    json << "{\n";
    json << "  \"timestamp\": " << timestamp << ",\n";
    json << "  \"overall\": \"" << summary << "\",\n";
    json << "  \"health\": \"" << (GetOverallHealth() == HealthState::OK ? "ok" : 
                                     GetOverallHealth() == HealthState::WARNING ? "warning" : "fail") << "\",\n";
    json << "  \"summary\": {\n";
    json << "    \"total\": " << totalBeacons << ",\n";
    json << "    \"passed\": " << passedTests << ",\n";
    json << "    \"failed\": " << failedTests << "\n";
    json << "  },\n";
    json << "  \"subsystems\": [\n";
    
    for (size_t i = 0; i < subsystems.size(); i++) {
        const auto& sub = subsystems[i];
        json << "    {\n";
        json << "      \"name\": \"" << sub.name << "\",\n";
        json << "      \"state\": \"" << (sub.state == HealthState::OK ? "ok" : 
                                              sub.state == HealthState::WARNING ? "warning" : "fail") << "\",\n";
        json << "      \"duration_ms\": " << (sub.durationNs / 1000000) << ",\n";
        json << "      \"beacon_count\": " << sub.beaconCount << ",\n";
        json << "      \"last_run\": " << sub.lastRun << ",\n";
        json << "      \"last_success\": " << sub.lastSuccess << "\n";
        json << "    }" << (i < subsystems.size() - 1 ? "," : "") << "\n";
    }
    
    json << "  ]\n}";
}

void HealthReport::PrintConsole() {
    std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║        RAWRXD SOVEREIGN HEALTH REPORT                        ║\n";
    std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
    std::cout << "║ Generated: " << std::put_time(std::localtime(&timestamp), "%Y-%m-%d %H:%M:%S") << "                           ║\n";
    std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
    
    for (const auto& sub : subsystems) {
        std::cout << "║ " << StateEmoji(sub.state) << " ";
        std::cout << std::left << std::setw(20) << sub.name;
        std::cout << std::right << std::setw(10) << (sub.durationNs / 1000000) << " ms ║\n";
    }
    
    std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
    std::cout << "║ " << summary << std::string(61 - summary.length(), ' ') << "║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
}

const char* HealthReport::BeaconName(BeaconID id) const {
    switch (id) {
        case BeaconID::KV_START: return "KV Cache";
        case BeaconID::EXPERT_START: return "Expert Cache";
        case BeaconID::ATTENTION_START: return "Attention";
        case BeaconID::MOE_START: return "MoE Router";
        case BeaconID::NVME_START: return "NVMe I/O";
        case BeaconID::VULKAN_START: return "Vulkan Compute";
        case BeaconID::QUANT_START: return "Quantization";
        case BeaconID::MODEL_START: return "Model Loader";
        case BeaconID::REPLAY_START: return "Replay System";
        case BeaconID::TELEMETRY_START: return "Telemetry";
        default: return "Unknown";
    }
}

const char* HealthReport::StateEmoji(HealthState state) const {
    switch (state) {
        case HealthState::OK: return "✅";
        case HealthState::WARNING: return "⚠️";
        case HealthState::FAIL: return "❌";
        default: return "❓";
    }
}

} // namespace Sovereign
