#include <iostream>
#include <fstream>
#include <string>
#include <sstream>

// Simple JSON parser for health data
struct HealthData {
    int overallScore = 0;
    struct Subsystem {
        std::string state;
        std::string message;
    };
    Subsystem kv, experts, attention, moe, nvme, vulkan, model, quant, telemetry, replay;
};

std::string extractValue(const std::string& json, const std::string& key) {
    size_t pos = json.find("\"" + key + "\"");
    if (pos == std::string::npos) return "";
    pos = json.find(":", pos);
    if (pos == std::string::npos) return "";
    pos = json.find("\"", pos);
    if (pos == std::string::npos) return "";
    size_t end = json.find("\"", pos + 1);
    if (end == std::string::npos) return "";
    return json.substr(pos + 1, end - pos - 1);
}

int extractInt(const std::string& json, const std::string& key) {
    size_t pos = json.find("\"" + key + "\"");
    if (pos == std::string::npos) return 0;
    pos = json.find(":", pos);
    if (pos == std::string::npos) return 0;
    pos++;
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\n' || json[pos] == '\t')) pos++;
    size_t end = pos;
    while (end < json.size() && (json[end] >= '0' && json[end] <= '9')) end++;
    return std::stoi(json.substr(pos, end - pos));
}

HealthData parseHealthJson(const std::string& json) {
    HealthData data;
    data.overallScore = extractInt(json, "overallScore");
    
    // Extract subsystem states
    auto extractSub = [&json](const std::string& name, HealthData::Subsystem& sub) {
        size_t pos = json.find("\"" + name + "\"");
        if (pos == std::string::npos) return;
        size_t start = json.find("{", pos);
        size_t end = json.find("}", start);
        if (start == std::string::npos || end == std::string::npos) return;
        std::string subJson = json.substr(start, end - start + 1);
        sub.state = extractValue(subJson, "state");
        sub.message = extractValue(subJson, "message");
    };
    
    extractSub("kv", data.kv);
    extractSub("experts", data.experts);
    extractSub("attention", data.attention);
    extractSub("moe", data.moe);
    extractSub("nvme", data.nvme);
    extractSub("vulkan", data.vulkan);
    extractSub("model", data.model);
    extractSub("quant", data.quant);
    extractSub("telemetry", data.telemetry);
    extractSub("replay", data.replay);
    
    return data;
}

std::string generateDashboardHtml(const HealthData& health) {
    std::stringstream html;
    
    auto getStateClass = [](const std::string& state) -> const char* {
        if (state == "ok") return "ok";
        if (state == "degraded") return "degraded";
        return "broken";
    };
    
    auto getStateEmoji = [](const std::string& state) -> const char* {
        if (state == "ok") return "✅";
        if (state == "degraded") return "⚠️";
        return "❌";
    };
    
    auto emitCard = [&](const std::string& name, const HealthData::Subsystem& sub) {
        html << "<div class=\"card " << getStateClass(sub.state) << "\">\n";
        html << "  <div class=\"title\">" << getStateEmoji(sub.state) << " " << name << "</div>\n";
        html << "  <div class=\"status\">" << sub.state << "</div>\n";
        html << "  <div class=\"msg\">" << sub.message << "</div>\n";
        html << "</div>\n";
    };
    
    const char* overallClass = health.overallScore >= 90 ? "ok" : 
                               health.overallScore >= 50 ? "degraded" : "broken";
    
    html << R"(<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>RawrXD Sovereign Health Dashboard</title>
<style>
body { background:#0d1117; color:#c9d1d9; font-family:'Segoe UI', Consolas, monospace; padding:40px; margin:0; }
.header { text-align:center; margin-bottom:40px; }
h1 { color:#58a6ff; margin-bottom:10px; }
.score { font-size:72px; font-weight:bold; margin:20px 0; }
.score.ok { color:#3fb950; text-shadow:0 0 20px #3fb950; }
.score.degraded { color:#f0883e; text-shadow:0 0 20px #f0883e; }
.score.broken { color:#f85149; text-shadow:0 0 20px #f85149; }
.grid { display:grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap:20px; max-width:1600px; margin:0 auto; }
.card { padding:24px; border-radius:12px; border:2px solid #30363d; background:#161b22; transition:transform 0.2s; }
.card:hover { transform:translateY(-4px); }
.card.ok { border-color:#3fb950; background:#163; }
.card.degraded { border-color:#f0883e; background:#663; }
.card.broken { border-color:#f85149; background:#633; }
.title { font-weight:bold; margin-bottom:12px; font-size:18px; display:flex; align-items:center; gap:10px; }
.status { font-size:14px; opacity:0.8; margin-bottom:8px; text-transform:uppercase; letter-spacing:1px; }
.msg { font-size:13px; opacity:0.9; line-height:1.5; }
.timestamp { text-align:center; margin-top:40px; color:#8b949e; font-size:14px; }
.live-indicator { display:inline-flex; align-items:center; gap:10px; color:#3fb950; font-size:14px; margin-bottom:20px; }
.live-dot { width:10px; height:10px; background:#3fb950; border-radius:50%; animation:pulse 2s infinite; }
@keyframes pulse { 0%,100% { opacity:1; } 50% { opacity:0.3; } }
</style>
</head>
<body>
<div class="header">
<div class="live-indicator"><span class="live-dot"></span> LIVE</div>
<h1>🛡️ RawrXD Sovereign Health Dashboard</h1>
<div class="score )" << overallClass << "\">" << health.overallScore << "%</div>
</div>
<div class="grid">
";
    
    emitCard("KV Cache", health.kv);
    emitCard("Expert Cache", health.experts);
    emitCard("Attention", health.attention);
    emitCard("MoE Router", health.moe);
    emitCard("NVMe I/O", health.nvme);
    emitCard("Vulkan Compute", health.vulkan);
    emitCard("Model Loader", health.model);
    emitCard("Quantization", health.quant);
    emitCard("Telemetry", health.telemetry);
    emitCard("Replay System", health.replay);
    
    html << R"(</div>
<div class="timestamp">Generated: )" << __TIME__ << " " << __DATE__ << R"(</div>
</body>
</html>)";
    
    return html.str();
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <health.json>\n";
        return 1;
    }
    
    std::ifstream in(argv[1]);
    if (!in.is_open()) {
        std::cerr << "Failed to open " << argv[1] << "\n";
        return 1;
    }
    
    std::string json((std::istreambuf_iterator<char>(in)),
                      std::istreambuf_iterator<char>());
    in.close();
    
    HealthData health = parseHealthJson(json);
    std::string html = generateDashboardHtml(health);
    
    std::ofstream out("health.html");
    if (!out.is_open()) {
        std::cerr << "Failed to create health.html\n";
        return 1;
    }
    out << html;
    out.close();
    
    std::cout << "Health dashboard generated: health.html\n";
    return 0;
}
