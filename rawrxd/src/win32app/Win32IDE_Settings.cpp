// Win32IDE_Settings.cpp — persistent settings backed by ini file
#include <windows.h>
#include <string>
#include <unordered_map>
#include <fstream>
#include <sstream>

namespace RawrXD::IDE {

static std::unordered_map<std::string, std::string> g_settings;
static std::string g_settingsPath;

void Settings_Load(const std::string& path)
{
    g_settingsPath = path;
    std::ifstream f(path);
    if (!f) return;
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#' || line[0] == '[') continue;
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string k = line.substr(0, eq);
        std::string v = line.substr(eq + 1);
        // trim
        while (!k.empty() && k.back() == ' ') k.pop_back();
        while (!v.empty() && v.front() == ' ') v.erase(v.begin());
        g_settings[k] = v;
    }
}

void Settings_Save()
{
    if (g_settingsPath.empty()) return;
    std::ofstream f(g_settingsPath);
    if (!f) return;
    f << "# RawrXD Settings\n";
    for (auto& [k, v] : g_settings) f << k << " = " << v << "\n";
}

void Settings_Set(const std::string& key, const std::string& value)
{
    g_settings[key] = value;
}

std::string Settings_Get(const std::string& key, const std::string& def)
{
    auto it = g_settings.find(key);
    return it != g_settings.end() ? it->second : def;
}

int Settings_GetInt(const std::string& key, int def)
{
    auto it = g_settings.find(key);
    if (it == g_settings.end()) return def;
    try { return std::stoi(it->second); } catch (...) { return def; }
}

bool Settings_GetBool(const std::string& key, bool def)
{
    auto it = g_settings.find(key);
    if (it == g_settings.end()) return def;
    return it->second == "1" || it->second == "true" || it->second == "yes";
}

void Settings_SetInt (const std::string& k, int  v) { g_settings[k] = std::to_string(v); }
void Settings_SetBool(const std::string& k, bool v) { g_settings[k] = v ? "1" : "0"; }

} // namespace RawrXD::IDE
