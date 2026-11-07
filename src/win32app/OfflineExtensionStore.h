#pragma once
// Dependency-free, offline extension INVENTORY for Win32IDE and CLI.
// Operates only on unpacked extension directories. Does not execute JS or VSIX.
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace RawrXD { namespace OfflineExtensions {
namespace fs = std::filesystem;

// Single default root shared by GUI and CLI. Explicit --root overrides this.
inline fs::path defaultRoot() {
    const char* local = std::getenv("LOCALAPPDATA");
    if (local && *local) return fs::path(local) / "RawrXD" / "extensions";
    const char* xdg = std::getenv("XDG_DATA_HOME");
    if (xdg && *xdg) return fs::path(xdg) / "RawrXD" / "extensions";
    const char* home = std::getenv("HOME");
    if (home && *home) return fs::path(home) / ".local" / "share" / "RawrXD" / "extensions";
    return fs::current_path() / "extensions";
}

struct Extension {
    std::string id, name, version, description, publisher;
    bool enabled = true;
};

inline void require(bool ok, const char* msg) {
    if (!ok) throw std::runtime_error(msg);
}

inline bool safeComponent(const std::string& s) {
    if (s.empty() || s.size() > 128 || s.front() == '.' || s.back() == '.' ||
        s.find("..") != std::string::npos) return false;
    std::string head = s.substr(0, s.find('.'));
    for (char& c : head) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    if (head == "CON" || head == "PRN" || head == "AUX" || head == "NUL" ||
        (head.size() == 4 && (head.substr(0, 3) == "COM" || head.substr(0, 3) == "LPT") &&
         head[3] >= '1' && head[3] <= '9')) return false;
    for (unsigned char c : s) {
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-')) return false;
    }
    return true;
}

// Minimal parser for top-level STRING keys in package.json.
// Rejects syntax errors, nesting overflows and malformed escapes.
class JsonFields {
    const std::string& s_;
    size_t p_ = 0;
    void ws() { while (p_ < s_.size() && std::isspace(static_cast<unsigned char>(s_[p_]))) ++p_; }
    bool take(char ch) { ws(); if (p_ < s_.size() && s_[p_] == ch) { ++p_; return true; } return false; }
    std::string str() {
        require(take('"'), "JSON string expected");
        std::string out;
        while (p_ < s_.size()) {
            unsigned char c = static_cast<unsigned char>(s_[p_++]);
            if (c == '"') return out;
            require(c >= 0x20, "Invalid JSON control character");
            if (c != '\\') { out += static_cast<char>(c); continue; }
            require(p_ < s_.size(), "Truncated JSON escape");
            char e = s_[p_++];
            switch (e) {
                case '"': out += '"'; break;
                case '\\': out += '\\'; break;
                case '/': out += '/'; break;
                case 'n': out += '\n'; break;
                case 'r': out += '\r'; break;
                case 't': out += '\t'; break;
                case 'b': out += '\b'; break;
                case 'f': out += '\f'; break;
                case 'u': {
                    require(p_ + 4 <= s_.size(), "Truncated Unicode escape");
                    unsigned value = 0;
                    for (int j = 0; j < 4; ++j) {
                        char h = s_[p_++];
                        int d = (h >= '0' && h <= '9') ? h - '0' :
                                (h >= 'a' && h <= 'f') ? h - 'a' + 10 :
                                (h >= 'A' && h <= 'F') ? h - 'A' + 10 : -1;
                        require(d >= 0, "Invalid Unicode escape");
                        value = value * 16u + static_cast<unsigned>(d);
                    }
                    if (value <= 0x7f) out += static_cast<char>(value);
                    else if (value < 0x800) {
                        out += static_cast<char>(0xc0 | (value >> 6));
                        out += static_cast<char>(0x80 | (value & 0x3f));
                    } else {
                        out += static_cast<char>(0xe0 | (value >> 12));
                        out += static_cast<char>(0x80 | ((value >> 6) & 0x3f));
                        out += static_cast<char>(0x80 | (value & 0x3f));
                    }
                    break;
                }
                default: throw std::runtime_error("Unknown JSON escape");
            }
        }
        throw std::runtime_error("Unterminated JSON string");
    }
    static bool validNumber(const std::string& v) {
        size_t i = 0;
        if (i < v.size() && v[i] == '-') ++i;
        if (i == v.size()) return false;
        if (v[i] == '0') ++i;
        else if (v[i] >= '1' && v[i] <= '9') {
            while (i < v.size() && v[i] >= '0' && v[i] <= '9') ++i;
        } else return false;
        if (i < v.size() && v[i] == '.') {
            ++i;
            if (i == v.size() || v[i] < '0' || v[i] > '9') return false;
            while (i < v.size() && v[i] >= '0' && v[i] <= '9') ++i;
        }
        if (i < v.size() && (v[i] == 'e' || v[i] == 'E')) {
            ++i;
            if (i < v.size() && (v[i] == '+' || v[i] == '-')) ++i;
            if (i == v.size() || v[i] < '0' || v[i] > '9') return false;
            while (i < v.size() && v[i] >= '0' && v[i] <= '9') ++i;
        }
        return i == v.size();
    }
    void skip(int depth = 0) {
        require(depth < 32, "JSON nested too deeply");
        ws();
        require(p_ < s_.size(), "Missing JSON value");
        if (s_[p_] == '"') { (void)str(); return; }
        if (take('{')) {
            if (take('}')) return;
            do {
                (void)str(); require(take(':'), "JSON colon expected");
                skip(depth + 1);
                if (take('}')) return;
                require(take(','), "JSON comma expected");
            } while (true);
        }
        if (take('[')) {
            if (take(']')) return;
            do {
                skip(depth + 1);
                if (take(']')) return;
                require(take(','), "JSON comma expected");
            } while (true);
        }
        const size_t begin = p_;
        while (p_ < s_.size() && s_[p_] != ',' && s_[p_] != '}' &&
               s_[p_] != ']' && !std::isspace(static_cast<unsigned char>(s_[p_]))) ++p_;
        require(p_ > begin, "Missing JSON primitive");
        const auto v = s_.substr(begin, p_ - begin);
        require(v == "true" || v == "false" || v == "null" ||
                validNumber(v), "Invalid JSON primitive");
    }
public:
    explicit JsonFields(const std::string& s) : s_(s) {}
    std::map<std::string, std::string> parse() {
        require(take('{'), "package.json must be an object");
        std::map<std::string, std::string> result;
        std::set<std::string> keys;
        if (!take('}')) {
            do {
                std::string key = str();
                require(keys.insert(key).second, "Duplicate JSON manifest key");
                require(take(':'), "JSON colon expected");
                ws(); require(p_ < s_.size(), "Missing JSON field");
                if (s_[p_] == '"') result[key] = str();
                else skip();
                if (take('}')) break;
                require(take(','), "JSON comma expected");
            } while (true);
        }
        ws(); require(p_ == s_.size(), "Trailing package.json content");
        return result;
    }
};

inline fs::path manifestPath(const fs::path& dir) {
    const auto nested = dir / "extension" / "package.json";
    if (fs::is_regular_file(nested)) return nested;
    return dir / "package.json";
}

inline Extension manifest(const fs::path& dir) {
    require(!fs::is_symlink(fs::symlink_status(dir)), "Extension package directory is a symlink");
    require(!fs::is_symlink(fs::symlink_status(dir / "extension")), "Nested extension directory is a symlink");
    const fs::path file = manifestPath(dir);
    require(fs::is_regular_file(file) && !fs::is_symlink(fs::symlink_status(file)), "Invalid manifest");
    require(fs::file_size(file) <= 65536, "Manifest too large");
    std::ifstream in(file, std::ios::binary);
    require(static_cast<bool>(in), "Manifest not readable");
    const std::string body(std::istreambuf_iterator<char>{in}, std::istreambuf_iterator<char>{});
    const auto fields = JsonFields(body).parse();
    auto value = [&](const char* key) -> std::string {
        const auto i = fields.find(key);
        return i == fields.end() ? std::string{} : i->second;
    };
    Extension e;
    e.name = value("name"); e.publisher = value("publisher");
    e.version = value("version"); e.description = value("description");
    require(safeComponent(e.name) && safeComponent(e.publisher) &&
            safeComponent(e.version), "Invalid extension manifest fields");
    e.id = e.publisher + "." + e.name;
    require(safeComponent(e.id), "Invalid extension ID");
    return e;
}

class Store {
    fs::path root_;
    void rootSafe() const {
        require(!fs::is_symlink(fs::symlink_status(root_)), "Extension root is a symlink");
    }
    void mkdirRoot() const {
        rootSafe(); fs::create_directories(root_);
        require(fs::is_directory(root_), "Extension root not a directory");
    }
    fs::path checked(const std::string& id) const {
        require(safeComponent(id), "Invalid extension ID");
        rootSafe();
        const fs::path p = root_ / id;
        require(!fs::is_symlink(fs::symlink_status(p)), "Extension directory is a symlink");
        return p;
    }
    static void checkTree(const fs::path& src) {
        require(fs::is_directory(src) && !fs::is_symlink(fs::symlink_status(src)), "Unpacked source directory required");
        size_t files = 0;
        std::uintmax_t bytes = 0;
        for (const auto& ent : fs::recursive_directory_iterator(src)) {
            require(!ent.is_symlink(), "Package symlinks are forbidden");
            require(ent.is_directory() || ent.is_regular_file(), "Unsupported package entry");
            require(++files <= 4096, "Package has too many files");
            if (ent.is_regular_file()) {
                bytes += ent.file_size();
                require(bytes <= 128ull * 1024ull * 1024ull, "Package exceeds 128 MiB");
            }
        }
    }
    static bool isDisabled(const fs::path& dir) {
        const fs::path marker = dir / ".rawrxd-disabled";
        require(!fs::is_symlink(fs::symlink_status(marker)), "State marker is a symlink");
        if (!fs::exists(marker)) return false;
        require(fs::is_regular_file(marker) && fs::file_size(marker) == 9,
                "Invalid extension state marker");
        std::ifstream in(marker, std::ios::binary);
        require(static_cast<bool>(in), "Unreadable extension state marker");
        const std::string content(std::istreambuf_iterator<char>{in}, std::istreambuf_iterator<char>{});
        require(content == "disabled\n", "Corrupt extension state marker");
        return true;
    }
    static void state(const fs::path& dir, bool enabled) {
        const fs::path marker = dir / ".rawrxd-disabled";
        const bool wasDisabled = isDisabled(dir);
        if (enabled) {
            if (wasDisabled) fs::remove(marker);
            return;
        }
        if (wasDisabled) return; // Already disabled; idempotent on Windows.
        const fs::path temp = dir / ".rawrxd-disabled-new";
        require(!fs::exists(temp) && !fs::is_symlink(fs::symlink_status(temp)), "State transaction already exists");
        {
            std::ofstream out(temp, std::ios::binary);
            require(static_cast<bool>(out), "Cannot save state");
            out << "disabled\n";
            require(static_cast<bool>(out), "Cannot flush state");
        }
        try { fs::rename(temp, marker); }
        catch (...) { fs::remove(temp); throw; }
    }
    static void copyStage(const fs::path& from, const fs::path& to) {
        require(!fs::exists(to), "Staging directory exists");
        fs::create_directory(to);
        try {
            fs::copy(from, to, fs::copy_options::recursive);
            checkTree(to);
        } catch (...) { fs::remove_all(to); throw; }
    }
    fs::path sourceChecked(const fs::path& source) const {
        checkTree(source);
        // Package authors cannot inject private management markers into their
        // archives: only the store may create disabled/staging/backup state.
        for (const auto& ent : fs::recursive_directory_iterator(source)) {
            const std::string filename = ent.path().filename().string();
            require(filename.rfind(".rawrxd-", 0) != 0,
                    "Package contains reserved RawrXD state filename");
        }
        const fs::path realSource = fs::canonical(source);
        // Prevent recursively staging an extension folder into itself.
        const fs::path relative = realSource.lexically_relative(root_);
        require(relative.empty() || relative.is_absolute() ||
                *relative.begin() == fs::path(".."), "Source must be outside installation root");
        return realSource;
    }
public:
    explicit Store(fs::path root) : root_(fs::absolute(std::move(root)).lexically_normal()) {}
    const fs::path& root() const { return root_; }
    std::vector<Extension> list() const {
        rootSafe();
        std::vector<Extension> result;
        if (!fs::exists(root_)) return result;
        for (const auto& dir : fs::directory_iterator(root_)) {
            if (dir.is_symlink() || !dir.is_directory()) continue;
            try {
                Extension e = manifest(dir.path());
                if (e.id != dir.path().filename().string()) continue;
                e.enabled = !isDisabled(dir.path());
                result.push_back(std::move(e));
            } catch (const std::exception&) { /* Corrupt packages never appear as installed. */ }
        }
        std::sort(result.begin(), result.end(), [](const Extension& a, const Extension& b) { return a.id < b.id; });
        return result;
    }
    Extension get(const std::string& id) const {
        const auto dir = checked(id);
        require(fs::is_directory(dir), "Extension is not installed");
        Extension e = manifest(dir);
        require(e.id == id, "Installed extension ID mismatch");
        e.enabled = !isDisabled(dir);
        return e;
    }
    Extension install(const fs::path& source) {
        mkdirRoot();
        const auto from = sourceChecked(source);
        const auto e = manifest(from);
        const auto dst = checked(e.id);
        require(!fs::exists(dst), "Extension already installed");
        const auto staging = checked(e.id + ".rawrxd-stage");
        copyStage(from, staging);
        try { fs::rename(staging, dst); }
        catch (...) { fs::remove_all(staging); throw; }
        return get(e.id);
    }
    Extension setEnabled(const std::string& id, bool enabled) {
        auto e = get(id);
        state(checked(id), enabled);
        e.enabled = enabled;
        return e;
    }
    void remove(const std::string& id) {
        (void)get(id);
        fs::remove_all(checked(id));
    }
    Extension update(const fs::path& source) {
        mkdirRoot();
        const auto from = sourceChecked(source);
        const auto replacement = manifest(from);
        const auto prior = get(replacement.id);
        const auto dest = checked(prior.id);
        const auto stage = checked(prior.id + ".rawrxd-stage");
        const auto backup = checked(prior.id + ".rawrxd-backup");
        require(!fs::exists(stage) && !fs::exists(backup), "Pending update: recover before retry");
        copyStage(from, stage);
        try {
            if (!prior.enabled) state(stage, false);
            fs::rename(dest, backup);
            try { fs::rename(stage, dest); }
            catch (...) { fs::rename(backup, dest); throw; }
            fs::remove_all(backup);
        } catch (...) {
            if (fs::exists(stage)) fs::remove_all(stage);
            throw;
        }
        return get(prior.id);
    }
    size_t recover() {
        mkdirRoot();
        // Enumerate first: removing/renaming entries during directory iteration
        // has implementation-dependent behavior on Windows and Unix.
        struct Pending { std::string id; fs::path path; bool backup; };
        std::vector<Pending> pending;
        for (const auto& entry : fs::directory_iterator(root_)) {
            if (entry.is_symlink() || !entry.is_directory()) continue;
            const std::string name = entry.path().filename().string();
            for (const auto& suffix : {std::string(".rawrxd-backup"),
                                       std::string(".rawrxd-stage")}) {
                if (name.size() <= suffix.size() ||
                    name.compare(name.size() - suffix.size(), suffix.size(), suffix) != 0)
                    continue;
                const std::string id = name.substr(0, name.size() - suffix.size());
                if (safeComponent(id))
                    pending.push_back({id, entry.path(), suffix == ".rawrxd-backup"});
                break;
            }
        }
        // Restore any pre-update originals before discarding unfinished stages.
        std::stable_sort(pending.begin(), pending.end(),
            [](const Pending& a, const Pending& b) { return a.backup && !b.backup; });
        size_t recovered = 0;
        for (const auto& entry : pending) {
            try {
                const fs::path dest = checked(entry.id);
                require(manifest(entry.path).id == entry.id, "Recovery manifest ID mismatch");
                checkTree(entry.path); // Do not follow or delete links in invalid stages.
                if (entry.backup && !fs::exists(dest)) {
                    fs::rename(entry.path, dest); // Interrupted rename: restore original.
                } else {
                    if (entry.backup) {
                        // The replacement was already published; validate it
                        // before discarding the old version.
                        require(manifest(dest).id == entry.id,
                                "Published extension ID mismatch");
                        checkTree(dest);
                    }
                    // Orphaned stage is never auto-installed. A validated backup
                    // is removed only when its validated replacement exists.
                    fs::remove_all(entry.path);
                }
                ++recovered;
            } catch (const std::exception&) {
                // Preserve suspicious/corrupt transaction folders for diagnosis.
            }
        }
        return recovered;
    }
};
}} // RawrXD::OfflineExtensions
