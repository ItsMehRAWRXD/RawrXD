// snapshot/SnapshotEngine.cpp
//
// RawrXD Snapshot Engine -- transactional autonomous experimentation.
//
// Provides incremental snapshots, agent checkpoints, hotpatch rollback,
// and performance experiment tracking. No full-tree scans on startup.

#include "snapshot/SnapshotEngine.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <random>
#include <algorithm>
#include <filesystem>
#include <iostream>
#include <windows.h>
#include <shellapi.h>

namespace kartgib {

bool SnapshotEngine::Initialize(const SnapshotConfig& config) {
    config_ = config;

    // Set default storage path if not provided
    if (config_.storage_path.empty()) {
        config_.storage_path = config_.repository_root / ".rawrxd" / "snapshots";
    }

    // Initialize storage
    if (!storage_.Initialize(config_)) {
        return false;
    }

    // Initialize journal
    if (config_.journal_enabled && !journal_.Initialize(config_)) {
        return false;
    }

    // Recover from journal if enabled
    if (config_.journal_enabled) {
        journal_.Recover(storage_, manifests_);
    }

    // Load existing manifests
    std::filesystem::path manifestsDir = config_.storage_path / "manifests";
    if (std::filesystem::exists(manifestsDir)) {
        for (const auto& entry : std::filesystem::directory_iterator(manifestsDir)) {
            if (entry.path().extension() == ".json") {
                LoadManifest(entry.path());
            }
        }
    }

    return true;
}

void SnapshotEngine::Shutdown() {
    // Save all manifests
    std::filesystem::path manifestsDir = config_.storage_path / "manifests";
    std::error_code ec;
    std::filesystem::create_directories(manifestsDir, ec);

    for (const auto& manifest : manifests_) {
        SaveManifest(manifest);
    }

    // Flush journal
    if (config_.journal_enabled) {
        journal_.Truncate(std::chrono::system_clock::now() - std::chrono::hours(24 * config_.retention_days));
    }
}

void SnapshotEngine::SaveManifest(const SnapshotManifest& manifest) {
    std::filesystem::path manifestPath = config_.storage_path / "manifests" / (manifest.id + ".json");
    std::ofstream out(manifestPath);
    if (!out) return;

    auto timeToISO = [](std::chrono::system_clock::time_point tp) -> std::string {
        if (tp == std::chrono::system_clock::time_point{}) return "";
        auto time_t = std::chrono::system_clock::to_time_t(tp);
        std::ostringstream oss;
        oss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%SZ");
        return oss.str();
    };

    auto sha256ToHex = [](const std::array<uint8_t, 32>& arr) -> std::string {
        std::ostringstream hex;
        hex << std::hex << std::setfill('0');
        for (uint8_t b : arr) {
            hex << std::setw(2) << static_cast<int>(b);
        }
        return hex.str();
    };

    out << "{\n";
    out << "  \"id\": \"" << manifest.id << "\",\n";
    out << "  \"name\": \"" << manifest.name << "\",\n";
    out << "  \"description\": \"" << manifest.description << "\",\n";
    out << "  \"mode\": " << static_cast<int>(manifest.mode) << ",\n";
    out << "  \"status\": " << static_cast<int>(manifest.status) << ",\n";
    out << "  \"created_time\": \"" << timeToISO(manifest.created_time) << "\",\n";
    out << "  \"committed_time\": \"" << timeToISO(manifest.committed_time) << "\",\n";
    out << "  \"git_commit\": \"" << manifest.git_commit << "\",\n";
    out << "  \"git_branch\": \"" << manifest.git_branch << "\",\n";
    out << "  \"git_dirty\": " << (manifest.git_dirty ? "true" : "false") << ",\n";
    out << "  \"agent_id\": \"" << manifest.agent_id << "\",\n";
    out << "  \"task_id\": \"" << manifest.task_id << "\",\n";
    out << "  \"parent_snapshot_id\": \"" << manifest.parent_snapshot_id << "\",\n";
    out << "  \"benchmark_data\": \"" << manifest.benchmark_data << "\",\n";
    out << "  \"files\": [\n";

    for (size_t i = 0; i < manifest.files.size(); ++i) {
        const auto& f = manifest.files[i];
        out << "    {\n";
        out << "      \"path\": \"" << f.path << "\",\n";
        out << "      \"sha256_before\": \"" << sha256ToHex(f.sha256_before) << "\",\n";
        out << "      \"sha256_after\": \"" << sha256ToHex(f.sha256_after) << "\",\n";
        out << "      \"size_before\": " << f.size_before << ",\n";
        out << "      \"size_after\": " << f.size_after << ",\n";
        out << "      \"modified_time\": \"" << timeToISO(f.modified_time) << "\",\n";
        out << "      \"agent_id\": \"" << f.agent_id << "\",\n";
        out << "      \"task_id\": \"" << f.task_id << "\"\n";
        out << "    }";
        if (i + 1 < manifest.files.size()) out << ",";
        out << "\n";
    }

    out << "  ]\n";
    out << "}\n";
}

void SnapshotEngine::LoadManifest(const std::filesystem::path& path) {
    std::ifstream file(path);
    if (!file) return;

    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    
    // Simple JSON parsing for our manifest format
    // This is a simplified parser - in production use a proper JSON library
    SnapshotManifest manifest;
    
    auto extractString = [&](const std::string& key, const std::string& json) -> std::string {
        std::string searchKey = "\"" + key + "\"";
        size_t pos = json.find(searchKey);
        if (pos == std::string::npos) return "";
        pos = json.find(':', pos);
        if (pos == std::string::npos) return "";
        pos = json.find('"', pos);
        if (pos == std::string::npos) return "";
        size_t endPos = json.find('"', pos + 1);
        if (endPos == std::string::npos) return "";
        return json.substr(pos + 1, endPos - pos - 1);
    };
    
    auto extractInt = [&](const std::string& key, const std::string& json) -> int {
        std::string searchKey = "\"" + key + "\"";
        size_t pos = json.find(searchKey);
        if (pos == std::string::npos) return 0;
        pos = json.find(':', pos);
        if (pos == std::string::npos) return 0;
        pos = json.find_first_not_of(" \t\n\r", pos + 1);
        if (pos == std::string::npos) return 0;
        size_t endPos = json.find_first_of(",}\n", pos);
        if (endPos == std::string::npos) return 0;
        try {
            return std::stoi(json.substr(pos, endPos - pos));
        } catch (...) {
            return 0;
        }
    };
    
    auto extractBool = [&](const std::string& key, const std::string& json) -> bool {
        std::string searchKey = "\"" + key + "\"";
        size_t pos = json.find(searchKey);
        if (pos == std::string::npos) return false;
        pos = json.find(':', pos);
        if (pos == std::string::npos) return false;
        pos = json.find_first_not_of(" \t\n\r", pos + 1);
        if (pos == std::string::npos) return false;
        return json.substr(pos, 4) == "true";
    };
    
    auto parseISOTime = [&](const std::string& isoStr) -> std::chrono::system_clock::time_point {
        if (isoStr.empty()) return std::chrono::system_clock::time_point{};
        std::tm tm = {};
        std::istringstream iss(isoStr);
        iss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
        if (iss.fail()) return std::chrono::system_clock::time_point{};
        return std::chrono::system_clock::from_time_t(std::mktime(&tm));
    };
    
    auto parseHexSHA256 = [&](const std::string& hexStr) -> std::array<uint8_t, 32> {
        std::array<uint8_t, 32> arr = {};
        if (hexStr.size() != 64) return arr;
        for (size_t i = 0; i < 32; ++i) {
            std::string byteStr = hexStr.substr(i * 2, 2);
            arr[i] = static_cast<uint8_t>(std::stoul(byteStr, nullptr, 16));
        }
        return arr;
    };
    
    manifest.id = extractString("id", content);
    manifest.name = extractString("name", content);
    manifest.description = extractString("description", content);
    manifest.mode = static_cast<SnapshotMode>(extractInt("mode", content));
    manifest.status = static_cast<SnapshotStatus>(extractInt("status", content));
    manifest.created_time = parseISOTime(extractString("created_time", content));
    manifest.committed_time = parseISOTime(extractString("committed_time", content));
    manifest.git_commit = extractString("git_commit", content);
    manifest.git_branch = extractString("git_branch", content);
    manifest.git_dirty = extractBool("git_dirty", content);
    manifest.agent_id = extractString("agent_id", content);
    manifest.task_id = extractString("task_id", content);
    manifest.parent_snapshot_id = extractString("parent_snapshot_id", content);
    manifest.benchmark_data = extractString("benchmark_data", content);
    
    // Parse files array
    size_t filesStart = content.find("\"files\": [");
    if (filesStart != std::string::npos) {
        size_t arrStart = content.find('[', filesStart);
        size_t arrEnd = content.find(']', arrStart);
        if (arrEnd != std::string::npos) {
            std::string filesContent = content.substr(arrStart + 1, arrEnd - arrStart - 1);
            // Parse each file object { ... }
            size_t objStart = 0;
            while ((objStart = filesContent.find('{', objStart)) != std::string::npos) {
                size_t objEnd = filesContent.find('}', objStart);
                if (objEnd == std::string::npos) break;
                std::string fileObj = filesContent.substr(objStart, objEnd - objStart + 1);
                
                FileSnapshot fs;
                fs.path = extractString("path", fileObj);
                
                auto parseHexArray = [&](const std::string& key, std::array<uint8_t, 32>& arr) -> void {
                    std::string hex = extractString(key, fileObj);
                    if (hex.size() == 64) {
                        for (size_t i = 0; i < 32; ++i) {
                            std::string byteStr = hex.substr(i * 2, 2);
                            arr[i] = static_cast<uint8_t>(std::stoul(byteStr, nullptr, 16));
                        }
                    }
                };
                parseHexArray("sha256_before", fs.sha256_before);
                parseHexArray("sha256_after", fs.sha256_after);
                
                auto extractSize = [&](const std::string& key) -> uint64_t {
                    std::string searchKey = "\"" + key + "\"";
                    size_t pos = fileObj.find(searchKey);
                    if (pos == std::string::npos) return 0;
                    pos = fileObj.find(':', pos);
                    if (pos == std::string::npos) return 0;
                    pos = fileObj.find_first_not_of(" \t\n\r", pos + 1);
                    if (pos == std::string::npos) return 0;
                    size_t endPos = fileObj.find_first_of(",}\n", pos);
                    if (endPos == std::string::npos) return 0;
                    try {
                        return std::stoull(fileObj.substr(pos, endPos - pos));
                    } catch (...) {
                        return 0;
                    }
                };
                fs.size_before = extractSize("size_before");
                fs.size_after = extractSize("size_after");
                
                manifest.files.push_back(fs);
                objStart = objEnd + 1;
            }
        }
    }
    
    if (!manifest.id.empty()) {
        manifests_.push_back(manifest);
    }
}

std::string SnapshotEngine::GenerateUUID() {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    static std::uniform_int_distribution<uint64_t> dis;

    uint64_t part1 = dis(gen);
    uint64_t part2 = dis(gen);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0')
        << std::setw(8) << (part1 >> 32)
        << std::setw(4) << ((part1 >> 16) & 0xFFFF)
        << std::setw(4) << (((part1 & 0x0FFF) | 0x4000))  // Version 4
        << std::setw(4) << (((part2 >> 48) & 0x3FFF) | 0x8000)  // Variant
        << std::setw(12) << (part2 & 0xFFFFFFFFFFFF);
    return oss.str();
}

std::string SnapshotEngine::GetCurrentTimeISO() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

bool SnapshotEngine::IsPathExcluded(const std::filesystem::path& path) {
    std::string pathStr = path.lexically_normal().string();

    for (const auto& pattern : config_.excluded_patterns) {
        // Simple glob matching
        if (pattern == pathStr) return true;
        if (pattern.back() == '*' && pattern.size() > 1) {
            std::string prefix = pattern.substr(0, pattern.size() - 1);
            if (pathStr.rfind(prefix, 0) == 0) return true;
        }
        if (pattern.find("**") != std::string::npos) {
            // Simplified ** matching
            std::string simplified = pattern;
            size_t pos = 0;
            while ((pos = simplified.find("**", pos)) != std::string::npos) {
                simplified.replace(pos, 2, "*");
                pos += 1;
            }
            // Convert to regex-like matching
            // For simplicity, just check if path contains the non-wildcard parts
        }
    }
    return false;
}

bool SnapshotEngine::CaptureGitState(SnapshotManifest& manifest) {
    std::string output;
    int exitCode;

    // Get commit hash
    if (RunCommand("git rev-parse HEAD", output, exitCode) && exitCode == 0) {
        manifest.git_commit = output;
        if (!manifest.git_commit.empty() && manifest.git_commit.back() == '\n') {
            manifest.git_commit.pop_back();
        }
    }

    // Get branch name
    if (RunCommand("git rev-parse --abbrev-ref HEAD", output, exitCode) && exitCode == 0) {
        manifest.git_branch = output;
        if (!manifest.git_branch.empty() && manifest.git_branch.back() == '\n') {
            manifest.git_branch.pop_back();
        }
    }

    // Check if dirty
    if (RunCommand("git status --porcelain", output, exitCode) && exitCode == 0) {
        manifest.git_dirty = !output.empty();
    }

    return true;
}

bool SnapshotEngine::RunCommand(const std::string& command, std::string& output, int& exit_code) {
    std::string cmd = "cmd /c " + command;

    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE };
    HANDLE hReadPipe, hWritePipe;
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) return false;

    STARTUPINFOA si = { sizeof(STARTUPINFOA) };
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

    PROCESS_INFORMATION pi = {};
    std::string cmdLine = cmd;
    if (!CreateProcessA(nullptr, cmdLine.data(), nullptr, nullptr, TRUE, 0, nullptr, nullptr, &si, &pi)) {
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return false;
    }

    CloseHandle(hWritePipe);

    char buffer[4096];
    DWORD bytesRead;
    output.clear();
    while (ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, nullptr) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        output += buffer;
    }

    DWORD waitResult = WaitForSingleObject(pi.hProcess, 30000); // 30 second timeout
    if (waitResult == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, 1);
    }
    DWORD exitCode;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    exit_code = static_cast<int>(exitCode);

    CloseHandle(hReadPipe);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return true;
}

SnapshotManifest SnapshotEngine::CreateSnapshot(const std::string& name, SnapshotMode mode, const std::string& agent_id, const std::string& task_id, const std::string& description) {
    SnapshotManifest manifest;
    manifest.id = GenerateUUID();
    manifest.name = name;
    manifest.description = description;
    manifest.mode = mode;
    manifest.status = SnapshotStatus::Pending;
    manifest.created_time = std::chrono::system_clock::now();
    manifest.agent_id = agent_id;
    manifest.task_id = task_id;

    CaptureGitState(manifest);

    // Walk the repository and capture all non-excluded source files
    std::error_code ec;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(config_.repository_root, ec)) {
        if (ec) continue;
        if (!entry.is_regular_file()) continue;

        std::filesystem::path relativePath = std::filesystem::relative(entry.path(), config_.repository_root);
        if (IsPathExcluded(relativePath)) continue;

        CaptureFile(relativePath, &manifest);
    }

    // Save manifest to disk
    std::filesystem::path manifestsDir = config_.storage_path / "manifests";
    std::error_code ec2;
    std::filesystem::create_directories(manifestsDir, ec2);

    SaveManifest(manifest);

    // Add to in-memory index
    manifests_.push_back(manifest);

    // Journal the creation
    if (config_.journal_enabled) {
        JournalEntry entry;
        entry.id = GenerateUUID();
        entry.snapshot_id = manifest.id;
        entry.operation = "create";
        entry.file_path = "";
        entry.timestamp = std::chrono::system_clock::now();
        entry.completed = true;
        journal_.Write(entry);
    }

    return manifest;
}

bool SnapshotEngine::BeginTransaction(const std::string& name, const std::string& agent_id, const std::string& task_id) {
    if (current_transaction_.has_value()) {
        return false; // Already in a transaction
    }

    SnapshotManifest manifest;
    manifest.id = GenerateUUID();
    manifest.name = name;
    manifest.mode = SnapshotMode::AgentTransaction;
    manifest.status = SnapshotStatus::Pending;
    manifest.created_time = std::chrono::system_clock::now();
    manifest.agent_id = agent_id;
    manifest.task_id = task_id;

    CaptureGitState(manifest);
    current_transaction_ = manifest;
    return true;
}

bool SnapshotEngine::CaptureFile(const std::filesystem::path& path, SnapshotManifest* targetManifest) {
    std::filesystem::path fullPath = config_.repository_root / path;
    if (!std::filesystem::exists(fullPath)) return false;

    if (IsPathExcluded(path)) return false;

    std::string sha256 = storage_.StoreFile(fullPath);
    if (sha256.empty()) return false;

    FileSnapshot fileSnap;
    fileSnap.path = path.lexically_normal().string();
    fileSnap.sha256_before = {};
    fileSnap.sha256_after = {};

    // Convert hex to array
    for (size_t i = 0; i < 32 && i * 2 < sha256.size(); ++i) {
        std::string byteStr = sha256.substr(i * 2, 2);
        fileSnap.sha256_before[i] = static_cast<uint8_t>(std::stoul(byteStr, nullptr, 16));
        fileSnap.sha256_after[i] = fileSnap.sha256_before[i];
    }

    fileSnap.size_before = std::filesystem::file_size(fullPath);
    fileSnap.size_after = fileSnap.size_before;
    fileSnap.modified_time = std::chrono::system_clock::now();
    fileSnap.agent_id = current_transaction_ ? current_transaction_->agent_id : (targetManifest ? targetManifest->agent_id : "");
    fileSnap.task_id = current_transaction_ ? current_transaction_->task_id : (targetManifest ? targetManifest->task_id : "");

    if (current_transaction_) {
        current_transaction_->files.push_back(fileSnap);

        // Journal the capture
        if (config_.journal_enabled) {
            JournalEntry entry;
            entry.id = GenerateUUID();
            entry.snapshot_id = current_transaction_->id;
            entry.operation = "capture";
            entry.file_path = fileSnap.path;
            entry.sha256_before = fileSnap.sha256_before;
            entry.sha256_after = fileSnap.sha256_after;
            entry.timestamp = std::chrono::system_clock::now();
            entry.completed = true;
            journal_.Write(entry);
        }
    }

    if (targetManifest) {
        targetManifest->files.push_back(fileSnap);
    }

    return true;
}

bool SnapshotEngine::CaptureFiles(const std::vector<std::filesystem::path>& paths, SnapshotManifest* targetManifest) {
    bool allOk = true;
    for (const auto& path : paths) {
        if (!CaptureFile(path, targetManifest)) {
            allOk = false;
        }
    }
    return allOk;
}

SnapshotManifest SnapshotEngine::CommitTransaction() {
    if (!current_transaction_) {
        return SnapshotManifest{};
    }

    auto manifest = *current_transaction_;
    manifest.status = SnapshotStatus::Committed;
    manifest.committed_time = std::chrono::system_clock::now();

    // Update file snapshots with after-state hashes
    for (auto& fileSnap : manifest.files) {
        std::filesystem::path fullPath = config_.repository_root / fileSnap.path;
        if (std::filesystem::exists(fullPath)) {
            std::string sha256 = storage_.StoreFile(fullPath);
            if (!sha256.empty()) {
                for (size_t i = 0; i < 32 && i * 2 < sha256.size(); ++i) {
                    std::string byteStr = sha256.substr(i * 2, 2);
                    fileSnap.sha256_after[i] = static_cast<uint8_t>(std::stoul(byteStr, nullptr, 16));
                }
                fileSnap.size_after = std::filesystem::file_size(fullPath);
            }
        }
    }

    // Save manifest
    std::filesystem::path manifestsDir = config_.storage_path / "manifests";
    std::error_code ec;
    std::filesystem::create_directories(manifestsDir, ec);

    SaveManifest(manifest);

    // Add to index
    manifests_.push_back(manifest);
    current_transaction_.reset();

    // Journal the commit
    if (config_.journal_enabled) {
        JournalEntry entry;
        entry.id = GenerateUUID();
        entry.snapshot_id = manifest.id;
        entry.operation = "commit";
        entry.file_path = "";
        entry.timestamp = std::chrono::system_clock::now();
        entry.completed = true;
        journal_.Write(entry);
    }

    // Enforce quota
    storage_.EnforceQuota();

    return manifest;
}

bool SnapshotEngine::RollbackTransaction() {
    if (!current_transaction_) {
        return false;
    }

    // Restore all captured files to their before state
    for (const auto& fileSnap : current_transaction_->files) {
        std::string sha256_before_hex;
        {
            std::ostringstream hex;
            hex << std::hex << std::setfill('0');
            for (uint8_t b : fileSnap.sha256_before) {
                hex << std::setw(2) << static_cast<int>(b);
            }
            sha256_before_hex = hex.str();
        }

        if (storage_.Exists(sha256_before_hex)) {
            std::filesystem::path fullPath = config_.repository_root / fileSnap.path;
            storage_.RetrieveToFile(sha256_before_hex, fullPath);
        }
    }

    // Journal the rollback
    if (config_.journal_enabled) {
        JournalEntry entry;
        entry.id = GenerateUUID();
        entry.snapshot_id = current_transaction_->id;
        entry.operation = "rollback";
        entry.file_path = "";
        entry.timestamp = std::chrono::system_clock::now();
        entry.completed = true;
        journal_.Write(entry);
    }

    current_transaction_.reset();
    return true;
}

bool SnapshotEngine::RestoreSnapshot(const std::string& snapshot_id, ConflictPolicy policy) {
    auto manifestOpt = GetSnapshot(snapshot_id);
    if (!manifestOpt) return false;

    const auto& manifest = *manifestOpt;

    // Check for conflicts
    if (policy == ConflictPolicy::Abort) {
        for (const auto& fileSnap : manifest.files) {
            std::filesystem::path fullPath = config_.repository_root / fileSnap.path;
            if (std::filesystem::exists(fullPath)) {
                std::string currentSha = storage_.StoreFile(fullPath);
                std::string expectedSha;
                {
                    std::ostringstream hex;
                    hex << std::hex << std::setfill('0');
                    for (uint8_t b : fileSnap.sha256_after) {
                        hex << std::setw(2) << static_cast<int>(b);
                    }
                    expectedSha = hex.str();
                }
                if (currentSha != expectedSha) {
                    return false; // Conflict detected
                }
            }
        }
    }

    // Restore files
    for (const auto& fileSnap : manifest.files) {
        std::string sha256_after_hex;
        {
            std::ostringstream hex;
            hex << std::hex << std::setfill('0');
            for (uint8_t b : fileSnap.sha256_after) {
                hex << std::setw(2) << static_cast<int>(b);
            }
            sha256_after_hex = hex.str();
        }

        if (storage_.Exists(sha256_after_hex)) {
            std::filesystem::path fullPath = config_.repository_root / fileSnap.path;
            std::error_code ec;
            std::filesystem::create_directories(fullPath.parent_path(), ec);
            storage_.RetrieveToFile(sha256_after_hex, fullPath);
        }
    }

    // Update manifest status
    for (auto& m : manifests_) {
        if (m.id == snapshot_id) {
            m.status = SnapshotStatus::RolledBack;
            break;
        }
    }

    return true;
}

std::string SnapshotEngine::DiffSnapshot(const std::string& snapshot_id) {
    auto manifestOpt = GetSnapshot(snapshot_id);
    if (!manifestOpt) return "";

    const auto& manifest = *manifestOpt;
    std::ostringstream diff;

    diff << "Snapshot: " << manifest.name << " (" << manifest.id << ")\n";
    diff << "Mode: " << static_cast<int>(manifest.mode) << "\n";
    diff << "Status: " << static_cast<int>(manifest.status) << "\n";
    diff << "Files changed: " << manifest.files.size() << "\n\n";

    for (const auto& fileSnap : manifest.files) {
        diff << "--- a/" << fileSnap.path << "\n";
        diff << "+++ b/" << fileSnap.path << "\n";

        std::string beforeHex, afterHex;
        {
            std::ostringstream hex;
            hex << std::hex << std::setfill('0');
            for (uint8_t b : fileSnap.sha256_before) hex << std::setw(2) << static_cast<int>(b);
            beforeHex = hex.str();
        }
        {
            std::ostringstream hex;
            hex << std::hex << std::setfill('0');
            for (uint8_t b : fileSnap.sha256_after) hex << std::setw(2) << static_cast<int>(b);
            afterHex = hex.str();
        }

        diff << "@@ -1 +" << " @@\n";
        diff << "- " << beforeHex << " (" << fileSnap.size_before << " bytes)\n";
        diff << "+ " << afterHex << " (" << fileSnap.size_after << " bytes)\n";
    }

    return diff.str();
}

std::vector<SnapshotManifest> SnapshotEngine::ListSnapshots(const std::string& agent_id) {
    std::vector<SnapshotManifest> result;
    for (const auto& manifest : manifests_) {
        if (agent_id.empty() || manifest.agent_id == agent_id) {
            result.push_back(manifest);
        }
    }
    return result;
}

std::optional<SnapshotManifest> SnapshotEngine::GetSnapshot(const std::string& id) {
    for (const auto& manifest : manifests_) {
        if (manifest.id == id) {
            return manifest;
        }
    }
    return std::nullopt;
}

bool SnapshotEngine::DeleteSnapshot(const std::string& id) {
    auto it = std::find_if(manifests_.begin(), manifests_.end(),
        [&id](const SnapshotManifest& m) { return m.id == id; });

    if (it == manifests_.end()) return false;

    // Decrement refcounts for all files in the snapshot
    for (const auto& fileSnap : it->files) {
        std::string sha256_after_hex;
        {
            std::ostringstream hex;
            hex << std::hex << std::setfill('0');
            for (uint8_t b : fileSnap.sha256_after) {
                hex << std::setw(2) << static_cast<int>(b);
            }
            sha256_after_hex = hex.str();
        }
        storage_.DecRef(sha256_after_hex);
    }

    // Remove manifest file
    std::filesystem::path manifestPath = config_.storage_path / "manifests" / (id + ".json");
    std::error_code ec;
    std::filesystem::remove(manifestPath, ec);

    // Remove from index
    manifests_.erase(it);

    // Run garbage collection
    storage_.GarbageCollect();

    return true;
}

bool SnapshotEngine::ParseBenchmarkOutput(const std::string& output, double& metric_value) {
    // Simple parsing: look for "TPS:" or "tps:" or "FPS:" or "fps:" in output
    std::string lower = output;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    size_t pos = lower.find("tps:");
    if (pos == std::string::npos) pos = lower.find("fps:");
    if (pos == std::string::npos) pos = lower.find("throughput:");

    if (pos != std::string::npos) {
        // Extract number after the keyword
        size_t start = pos;
        while (start < lower.size() && !isdigit(lower[start]) && lower[start] != '.') start++;
        if (start < lower.size()) {
            size_t end = start;
            while (end < lower.size() && (isdigit(lower[end]) || lower[end] == '.')) end++;
            std::string numStr = output.substr(start, end - start);
            try {
                metric_value = std::stod(numStr);
                return true;
            } catch (...) {}
        }
    }
    return false;
}

SnapshotManifest SnapshotEngine::RunPerformanceExperiment(const std::string& name, const std::string& agent_id, const std::string& task_id, const std::string& build_command, const std::string& test_command, const std::string& benchmark_command, double acceptance_threshold) {
    // Create a performance experiment snapshot
    SnapshotManifest manifest = CreateSnapshot(name, SnapshotMode::PerformanceExperiment, agent_id, task_id, "Performance experiment");

    // Capture all relevant source files before experiment
    // In practice, this would capture the specific files being optimized

    // Run build
    std::string buildOutput;
    int buildExitCode;
    if (!RunCommand(build_command, buildOutput, buildExitCode) || buildExitCode != 0) {
        manifest.status = SnapshotStatus::Failed;
        manifest.benchmark_data = "{\"build_failed\": true, \"output\": \"" + buildOutput + "\"}";
        return manifest;
    }

    // Run tests
    std::string testOutput;
    int testExitCode;
    if (!RunCommand(test_command, testOutput, testExitCode) || testExitCode != 0) {
        manifest.status = SnapshotStatus::Failed;
        manifest.benchmark_data = "{\"test_failed\": true, \"output\": \"" + testOutput + "\"}";
        // Rollback on test failure
        RestoreSnapshot(manifest.id);
        return manifest;
    }

    // Run benchmark
    std::string benchOutput;
    int benchExitCode;
    if (!RunCommand(benchmark_command, benchOutput, benchExitCode) || benchExitCode != 0) {
        manifest.status = SnapshotStatus::Failed;
        manifest.benchmark_data = "{\"benchmark_failed\": true, \"output\": \"" + benchOutput + "\"}";
        RestoreSnapshot(manifest.id);
        return manifest;
    }

    // Parse benchmark result
    double metricValue = 0.0;
    bool parsed = ParseBenchmarkOutput(benchOutput, metricValue);

    // Store benchmark data
    std::ostringstream benchData;
    benchData << "{\"metric_value\": " << metricValue << ", \"parsed\": " << (parsed ? "true" : "false") << ", \"output\": \"" << benchOutput << "\", \"acceptance_threshold\": " << acceptance_threshold << "}";
    manifest.benchmark_data = benchData.str();

    if (parsed && metricValue >= acceptance_threshold) {
        manifest.status = SnapshotStatus::Committed;
        CommitTransaction(); // This will finalize the experiment
    } else {
        manifest.status = SnapshotStatus::Failed;
        RestoreSnapshot(manifest.id); // Rollback on regression
    }

    return manifest;
}

std::string SnapshotEngine::GetGitState() {
    std::string commit, branch;
    bool dirty = false;
    std::string output;
    int exitCode;

    RunCommand("git rev-parse HEAD", output, exitCode);
    if (exitCode == 0) commit = output;

    RunCommand("git rev-parse --abbrev-ref HEAD", output, exitCode);
    if (exitCode == 0) branch = output;

    RunCommand("git status --porcelain", output, exitCode);
    if (exitCode == 0) dirty = !output.empty();

    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"commit\": \"" << commit << "\",\n";
    oss << "  \"branch\": \"" << branch << "\",\n";
    oss << "  \"dirty\": " << (dirty ? "true" : "false") << "\n";
    oss << "}";
    return oss.str();
}

bool SnapshotEngine::VerifyIntegrity(const std::string& snapshot_id) {
    auto manifestOpt = GetSnapshot(snapshot_id);
    if (!manifestOpt) return false;

    const auto& manifest = *manifestOpt;

    for (const auto& fileSnap : manifest.files) {
        std::string sha256_after_hex;
        {
            std::ostringstream hex;
            hex << std::hex << std::setfill('0');
            for (uint8_t b : fileSnap.sha256_after) {
                hex << std::setw(2) << static_cast<int>(b);
            }
            sha256_after_hex = hex.str();
        }

        if (!storage_.Exists(sha256_after_hex)) {
            return false;
        }

        if (config_.verify_checksums) {
            std::filesystem::path fullPath = config_.repository_root / fileSnap.path;
            if (std::filesystem::exists(fullPath)) {
                std::string currentSha = storage_.StoreFile(fullPath);
                if (currentSha != sha256_after_hex) {
                    return false; // Checksum mismatch
                }
            }
        }
    }

    return true;
}

} // namespace kartgib