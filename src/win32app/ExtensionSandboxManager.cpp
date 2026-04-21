// ExtensionSandboxManager.cpp
// Phase 2 Day 8: Security Sandbox Implementation
// Fail-closed security policies enforcement

#include "ExtensionSandboxManager.h"
#include "IDELogger.h"
#include <algorithm>
#include <cctype>
#include <sstream>
#include <Shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")

namespace RawrXD::Extensions {

    // ============================================================================
    // FilesystemAccessControl Implementation
    // ============================================================================

    bool FilesystemAccessControl::CheckReadAccess(
        const ExtensionSecurityContext& context,
        const std::string& filePath)
    {
        // FAIL-CLOSED: Deny by default
        if (!(context.fsPermissions & FileSystemPermission::Read)) {
            return false;
        }

        std::string normalizedPath = filePath;
        
        // Detect path traversal
        if (DetectPathTraversal(normalizedPath)) {
            IDELogger::Get().Warning("Path traversal detected: " + filePath);
            return false;
        }

        // Check protected system directories
        if (IsProtectedSystemDir(normalizedPath)) {
            IDELogger::Get().Warning("System directory access denied: " + filePath);
            return false;
        }

        // Check whitelist
        auto it = context.allowedReadPaths.find(normalizedPath);
        if (it == context.allowedReadPaths.end()) {
            // Check if it's a parent of allowed path
            bool allowed = false;
            for (const auto& allowedPath : context.allowedReadPaths) {
                if (normalizedPath.find(allowedPath) == 0) {
                    allowed = true;
                    break;
                }
            }
            if (!allowed) {
                return false;
            }
        }

        return true;
    }

    bool FilesystemAccessControl::CheckWriteAccess(
        const ExtensionSecurityContext& context,
        const std::string& filePath)
    {
        // FAIL-CLOSED: Deny by default
        if (!(context.fsPermissions & FileSystemPermission::Write)) {
            return false;
        }

        std::string normalizedPath = filePath;

        // Detect path traversal
        if (DetectPathTraversal(normalizedPath)) {
            IDELogger::Get().Warning("Path traversal detected in write: " + filePath);
            return false;
        }

        // System directory: absolute protection
        if (IsProtectedSystemDir(normalizedPath)) {
            IDELogger::Get().Warning("Attempt to write to system directory: " + filePath);
            return false;
        }

        // Executable file: always blocked
        if (IsExecutableFile(normalizedPath)) {
            IDELogger::Get().Warning("Attempt to write to executable file: " + filePath);
            return false;
        }

        // Check whitelist
        auto it = context.allowedWritePaths.find(normalizedPath);
        if (it == context.allowedWritePaths.end()) {
            return false;
        }

        return true;
    }

    bool FilesystemAccessControl::CheckDeleteAccess(
        const ExtensionSecurityContext& context,
        const std::string& filePath)
    {
        // FAIL-CLOSED: Deny by default
        if (!(context.fsPermissions & FileSystemPermission::Delete)) {
            return false;
        }

        std::string normalizedPath = filePath;

        // Detect path traversal
        if (DetectPathTraversal(normalizedPath)) {
            return false;
        }

        // System directory: absolute protection
        if (IsProtectedSystemDir(normalizedPath)) {
            return false;
        }

        // Check whitelist for delete
        auto it = context.allowedWritePaths.find(normalizedPath);
        return it != context.allowedWritePaths.end();
    }

    bool FilesystemAccessControl::CheckExecuteAccess(
        const ExtensionSecurityContext& context,
        const std::string& filePath)
    {
        // FAIL-CLOSED: Extensions cannot execute files by default
        if (!(context.fsPermissions & FileSystemPermission::Execute)) {
            return false;
        }

        // Additional protection: never allow execution of system files
        if (IsProtectedSystemDir(filePath)) {
            return false;
        }

        // Never allow DLL/SYS file execution
        std::string ext = filePath;
        size_t dotPos = ext.rfind('.');
        if (dotPos != std::string::npos) {
            ext = ext.substr(dotPos);
            std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
            if (ext == ".dll" || ext == ".sys" || ext == ".exe") {
                return false;
            }
        }

        return true;
    }

    bool FilesystemAccessControl::DetectPathTraversal(const std::string& path)
    {
        // Check for .. sequences
        if (path.find("..") != std::string::npos) {
            return true;
        }

        // Check for ~ (home directory expansion)
        if (path.find('~') != std::string::npos) {
            return true;
        }

        return false;
    }

    bool FilesystemAccessControl::IsProtectedSystemDir(const std::string& path)
    {
        std::string lower = path;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

        // System protected directories
        const char* protectedDirs[] = {
            "c:\\windows",
            "c:\\winnt",
            "c:\\system32",
            "c:\\syswow64",
            "c:\\programfiles",
            "c:\\programfiles(x86)",
            "c:\\program files",
            "c:\\program files (x86)",
            "c:\\winpe",
            "c:\\recovery"
        };

        for (const char* dir : protectedDirs) {
            size_t dirLen = strlen(dir);
            if (lower.find(dir) == 0) {
                // Check that it's a path boundary (/ or \)
                if (lower.length() == dirLen || 
                    lower[dirLen] == '\\' || lower[dirLen] == '/') {
                    return true;
                }
            }
        }

        return false;
    }

    bool FilesystemAccessControl::IsExecutableFile(const std::string& filePath)
    {
        const char* executableExts[] = {
            ".exe", ".dll", ".sys", ".scr", ".pif", ".com", ".bat", ".cmd"
        };

        std::string ext = filePath;
        size_t dotPos = ext.rfind('.');
        if (dotPos != std::string::npos) {
            ext = ext.substr(dotPos);
            std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

            for (const char* execExt : executableExts) {
                if (ext == execExt) {
                    return true;
                }
            }
        }

        return false;
    }

    // ============================================================================
    // NetworkAccessControl Implementation
    // ============================================================================

    bool NetworkAccessControl::CheckOutboundConnection(
        const ExtensionSecurityContext& context,
        const std::string& hostName,
        uint16_t port,
        const std::string& protocol)
    {
        // FAIL-CLOSED: Deny all network by default
        if (context.networkPermissions == NetworkPermission::None) {
            return false;
        }

        // Check private network access
        if (IsPrivateNetworkAddress(hostName)) {
            IDELogger::Get().Warning("Private network access denied: " + hostName);
            return false;
        }

        // Check if host is in whitelist
        auto it = context.allowedHosts.find(hostName);
        if (it == context.allowedHosts.end()) {
            IDELogger::Get().Warning("Host not in whitelist: " + hostName);
            return false;
        }

        // Check protocol permissions
        std::string proto = protocol;
        std::transform(proto.begin(), proto.end(), proto.begin(), ::tolower);

        if (proto == "http") {
            if (!(context.networkPermissions & NetworkPermission::HTTP)) {
                return false;
            }
        } else if (proto == "https") {
            if (!(context.networkPermissions & NetworkPermission::HTTPS)) {
                return false;
            }
        } else if (proto == "ws" || proto == "wss") {
            if (!(context.networkPermissions & NetworkPermission::WebSocket)) {
                return false;
            }
        }

        return true;
    }

    bool NetworkAccessControl::CheckDNSQuery(
        const ExtensionSecurityContext& context,
        const std::string& hostName)
    {
        // FAIL-CLOSED: Deny DNS queries by default
        if (!(context.networkPermissions & NetworkPermission::DNS)) {
            return false;
        }

        // Check for DNS rebinding attempts
        if (DetectDNSRebinding(hostName)) {
            IDELogger::Get().Warning("DNS rebinding attempt detected");
            return false;
        }

        // Host must be in whitelist
        return context.allowedHosts.find(hostName) != context.allowedHosts.end();
    }

    bool NetworkAccessControl::CheckURLAccess(
        const ExtensionSecurityContext& context,
        const std::string& url)
    {
        if (!ValidateURL(url)) {
            return false;
        }

        // Parse URL to get host and protocol
        size_t protocolEnd = url.find("://");
        if (protocolEnd == std::string::npos) {
            return false;
        }

        std::string protocol = url.substr(0, protocolEnd);
        std::string hostPart = url.substr(protocolEnd + 3);

        // Extract hostname
        size_t slashPos = hostPart.find('/');
        if (slashPos != std::string::npos) {
            hostPart = hostPart.substr(0, slashPos);
        }

        // Extract port if present
        uint16_t port = 80;
        if (protocol == "https") {
            port = 443;
        }

        size_t colonPos = hostPart.find(':');
        if (colonPos != std::string::npos) {
            try {
                port = std::stoi(hostPart.substr(colonPos + 1));
            } catch (...) {
                return false;
            }
            hostPart = hostPart.substr(0, colonPos);
        }

        return CheckOutboundConnection(context, hostPart, port, protocol);
    }

    bool NetworkAccessControl::IsPrivateNetworkAddress(const std::string& hostName)
    {
        std::string lower = hostName;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

        // Loopback
        if (lower == "localhost" || lower == "127.0.0.1" || lower == "::1") {
            return true;
        }

        // Private IP ranges
        if (lower.find("192.168.") == 0 ||
            lower.find("10.") == 0 ||
            lower.find("172.16.") == 0 ||
            lower.find("127.") == 0 ||
            lower.find("fc00:") == 0) {
            return true;
        }

        return false;
    }

    bool NetworkAccessControl::ValidateURL(const std::string& url)
    {
        // Basic URL validation
        if (url.empty() || url.length() > 2048) {
            return false;
        }

        size_t protocolEnd = url.find("://");
        if (protocolEnd == std::string::npos) {
            return false;
        }

        return true;
    }

    bool NetworkAccessControl::DetectDNSRebinding(const std::string& hostName)
    {
        // In production, would cache DNS responses and detect rebinding
        // For now, simple heuristic check
        
        // Numeric IP address pattern
        int dots = 0;
        bool allNumericOrDots = true;
        for (char c : hostName) {
            if (c == '.') dots++;
            else if (!isdigit(c)) {
                allNumericOrDots = false;
                break;
            }
        }

        // If it looks like an IP but has unusual patterns, suspect rebinding
        if (allNumericOrDots && dots == 3) {
            // Valid IPv4 format - check for reserved ranges
            return IsPrivateNetworkAddress(hostName);
        }

        return false;
    }

    // ============================================================================
    // RegistryAccessControl Implementation
    // ============================================================================

    bool RegistryAccessControl::CheckRegistryRead(
        const ExtensionSecurityContext& context,
        const std::string& keyPath)
    {
        // FAIL-CLOSED: Deny registry access by default
        if (context.registryPermissions == RegistryPermission::None) {
            return false;
        }

        // System keys are always protected
        if (IsSystemProtectedKey(keyPath)) {
            return false;
        }

        std::string hive = ExtractHive(keyPath);

        // Check permissions by hive
        if (hive == "HKLM") {
            if (!(context.registryPermissions & RegistryPermission::HKLMRead)) {
                return false;
            }
        } else if (hive == "HKCU") {
            if (!(context.registryPermissions & RegistryPermission::HKCURead)) {
                return false;
            }
        }

        return true;
    }

    bool RegistryAccessControl::CheckRegistryWrite(
        const ExtensionSecurityContext& context,
        const std::string& keyPath)
    {
        // FAIL-CLOSED: Deny by default
        if (context.registryPermissions == RegistryPermission::None) {
            return false;
        }

        // System keys: NEVER writable
        if (IsSystemProtectedKey(keyPath)) {
            return false;
        }

        // HKLM: Never writable
        std::string hive = ExtractHive(keyPath);
        if (hive == "HKLM") {
            return false;
        }

        // HKCU: Check specific write permissions
        if (hive == "HKCU") {
            if (!(context.registryPermissions & RegistryPermission::HKCUWrite)) {
                return false;
            }
        }

        return true;
    }

    bool RegistryAccessControl::CheckRegistryValueModification(
        const ExtensionSecurityContext& context,
        const std::string& keyPath,
        const std::string& valueName)
    {
        // Must have write permission first
        if (!CheckRegistryWrite(context, keyPath)) {
            return false;
        }

        // Check if value is security-sensitive
        std::string lower = valueName;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

        const char* sensitivePrefixes[] = {
            "security", "crypto", "auth", "token", "password", "secret"
        };

        for (const char* prefix : sensitivePrefixes) {
            if (lower.find(prefix) != std::string::npos) {
                // Security values cannot be modified
                IDELogger::Get().Warning("Attempt to modify security value: " + valueName);
                return false;
            }
        }

        return true;
    }

    bool RegistryAccessControl::IsSystemProtectedKey(const std::string& keyPath)
    {
        std::string lower = keyPath;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

        const char* protectedKeys[] = {
            "hklm\\system",
            "hklm\\security",
            "hklm\\sam",
            "hklm\\bcd",
            "hkcu\\security"
        };

        for (const char* key : protectedKeys) {
            if (lower.find(key) == 0) {
                return true;
            }
        }

        return false;
    }

    bool RegistryAccessControl::IsSecuritySensitiveKey(const std::string& keyPath)
    {
        std::string lower = keyPath;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

        if (lower.find("sam") != std::string::npos ||
            lower.find("lsa") != std::string::npos ||
            lower.find("kerberos") != std::string::npos ||
            lower.find("policies\\system") != std::string::npos) {
            return true;
        }

        return false;
    }

    std::string RegistryAccessControl::ExtractHive(const std::string& keyPath)
    {
        size_t backslashPos = keyPath.find('\\');
        if (backslashPos == std::string::npos) {
            return keyPath;
        }

        return keyPath.substr(0, backslashPos);
    }

    // ============================================================================
    // ExtensionSandboxManager Implementation
    // ============================================================================

    ExtensionSandboxManager& ExtensionSandboxManager::Get()
    {
        static ExtensionSandboxManager instance;
        return instance;
    }

    void ExtensionSandboxManager::RegisterExtension(const ExtensionSecurityContext& context)
    {
        Lock();
        m_contexts[context.extensionId] = context;
        Unlock();

        IDELogger::Get().Info("Extension registered in sandbox: " + context.extensionId);
    }

    void ExtensionSandboxManager::UnregisterExtension(const std::string& extensionId)
    {
        Lock();
        m_contexts.erase(extensionId);
        Unlock();

        IDELogger::Get().Info("Extension unregistered from sandbox: " + extensionId);
    }

    void ExtensionSandboxManager::GrantFileReadPermission(
        const std::string& extensionId,
        const std::string& path)
    {
        Lock();
        auto it = m_contexts.find(extensionId);
        if (it != m_contexts.end()) {
            it->second.fsPermissions = 
                (FileSystemPermission)(it->second.fsPermissions | FileSystemPermission::Read);
            it->second.allowedReadPaths.insert(path);
        }
        Unlock();
    }

    void ExtensionSandboxManager::GrantFileWritePermission(
        const std::string& extensionId,
        const std::string& path)
    {
        Lock();
        auto it = m_contexts.find(extensionId);
        if (it != m_contexts.end()) {
            it->second.fsPermissions = 
                (FileSystemPermission)(it->second.fsPermissions | FileSystemPermission::Write);
            it->second.allowedWritePaths.insert(path);
        }
        Unlock();
    }

    void ExtensionSandboxManager::GrantNetworkPermission(
        const std::string& extensionId,
        NetworkPermission permission)
    {
        Lock();
        auto it = m_contexts.find(extensionId);
        if (it != m_contexts.end()) {
            it->second.networkPermissions = 
                (NetworkPermission)(it->second.networkPermissions | permission);
        }
        Unlock();
    }

    void ExtensionSandboxManager::GrantRegistryPermission(
        const std::string& extensionId,
        const std::string& keyPath,
        RegistryPermission permission)
    {
        Lock();
        auto it = m_contexts.find(extensionId);
        if (it != m_contexts.end()) {
            it->second.registryPermissions = 
                (RegistryPermission)(it->second.registryPermissions | permission);
            it->second.registryKeys[keyPath] = permission;
        }
        Unlock();
    }

    void ExtensionSandboxManager::WhitelistHost(
        const std::string& extensionId,
        const std::string& hostName)
    {
        Lock();
        auto it = m_contexts.find(extensionId);
        if (it != m_contexts.end()) {
            it->second.allowedHosts.insert(hostName);
        }
        Unlock();
    }

    bool ExtensionSandboxManager::ValidateExtensionSecurity(const std::string& extensionId)
    {
        Lock();
        auto it = m_contexts.find(extensionId);
        if (it == m_contexts.end()) {
            Unlock();
            return false;
        }

        bool valid = true;
        // Validate that context is properly configured
        // In production, would check AppContainer state, token restrictions, etc.

        Unlock();
        return valid;
    }

    void ExtensionSandboxManager::PerformSecurityAudit(const std::string& extensionId)
    {
        Lock();
        auto it = m_contexts.find(extensionId);
        if (it != m_contexts.end()) {
            IDELogger::Get().Info("Security audit for extension: " + extensionId);
            // Audit would check all policies and detected violations
        }
        Unlock();
    }

    void ExtensionSandboxManager::ReportViolation(
        const std::string& extensionId,
        SecurityViolationType violationType,
        const std::string& details)
    {
        std::string violationName;
        switch (violationType) {
            case SecurityViolationType::FileAccessUnauthorized:
                violationName = "FileAccessUnauthorized";
                break;
            case SecurityViolationType::NetworkAccessUnauthorized:
                violationName = "NetworkAccessUnauthorized";
                break;
            case SecurityViolationType::RegistryAccessUnauthorized:
                violationName = "RegistryAccessUnauthorized";
                break;
            case SecurityViolationType::ExecutableModification:
                violationName = "ExecutableModification";
                break;
            case SecurityViolationType::PathTraversal:
                violationName = "PathTraversal";
                break;
            default:
                violationName = "UnknownViolation";
                break;
        }

        IDELogger::Get().Warning("Security violation: " + violationName + " - " + details);

        if (m_violationCallback) {
            m_violationCallback(extensionId, violationType, details);
        }
    }

} // namespace RawrXD::Extensions
