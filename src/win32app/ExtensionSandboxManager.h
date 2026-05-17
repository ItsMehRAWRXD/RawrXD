// ExtensionSandboxManager.h
// Phase 2 Day 8: Security Sandbox Enforcement
// Fail-closed security policies for filesystem, network, registry, and process access

#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <functional>

namespace RawrXD::Extensions {

    // Forward declarations
    struct ExtensionSecurityContext;
    class ExtensionSandboxManager;

    // Security permission flags
    enum class FileSystemPermission : uint32_t {
        None = 0x0000,
        Read = 0x0001,
        Write = 0x0002,
        Execute = 0x0004,
        Delete = 0x0008
    };

    enum class NetworkPermission : uint32_t {
        None = 0x0000,
        HTTP = 0x0001,
        HTTPS = 0x0002,
        DNS = 0x0004,
        WebSocket = 0x0008
    };

    enum class RegistryPermission : uint32_t {
        None = 0x0000,
        HKCURead = 0x0001,
        HKCUWrite = 0x0002,
        HKLMRead = 0x0004
    };

    // Security violation types
    enum class SecurityViolationType {
        FileAccessUnauthorized,
        NetworkAccessUnauthorized,
        RegistryAccessUnauthorized,
        ProcessPrivilegeEscalation,
        ExecutableModification,
        PathTraversal,
        PrivateNetworkAccess,
        SystemDirectoryAccess
    };

    // Violation callback
    using OnSecurityViolationCallback = std::function<void(
        const std::string& extensionId,
        SecurityViolationType violationType,
        const std::string& details)>;

    // ============================================================================
    // Extension Security Context
    // ============================================================================
    struct ExtensionSecurityContext {
        std::string extensionId;
        FileSystemPermission fsPermissions;
        NetworkPermission networkPermissions;
        RegistryPermission registryPermissions;
        
        // Path whitelist for file access
        std::unordered_set<std::string> allowedReadPaths;
        std::unordered_set<std::string> allowedWritePaths;
        
        // Network host whitelist
        std::unordered_set<std::string> allowedHosts;
        
        // Registry key permissions
        std::unordered_map<std::string, RegistryPermission> registryKeys;
        
        ExtensionSecurityContext() 
            : fsPermissions(FileSystemPermission::None),
              networkPermissions(NetworkPermission::None),
              registryPermissions(RegistryPermission::None) {}
    };

    // ============================================================================
    // FilesystemAccessControl - Path-based access enforcement
    // ============================================================================
    class FilesystemAccessControl {
    public:
        /// Check if file read is allowed
        static bool CheckReadAccess(
            const ExtensionSecurityContext& context,
            const std::string& filePath);

        /// Check if file write is allowed
        static bool CheckWriteAccess(
            const ExtensionSecurityContext& context,
            const std::string& filePath);

        /// Check if file/directory can be deleted
        static bool CheckDeleteAccess(
            const ExtensionSecurityContext& context,
            const std::string& filePath);

        /// Check if file is executable and access is allowed
        static bool CheckExecuteAccess(
            const ExtensionSecurityContext& context,
            const std::string& filePath);

    private:
        /// Normalize and validate path
        static bool NormalizePath(std::string& path);

        /// Check for path traversal attempts  
        static bool DetectPathTraversal(const std::string& path);

        /// Check if path is in protected system directory
        static bool IsProtectedSystemDir(const std::string& path);

        /// Check if file has executable extension
        static bool IsExecutableFile(const std::string& filePath);
    };

    // ============================================================================
    // NetworkAccessControl - Connection-level access enforcement
    // ============================================================================
    class NetworkAccessControl {
    public:
        /// Check if outbound connection is allowed
        static bool CheckOutboundConnection(
            const ExtensionSecurityContext& context,
            const std::string& hostName,
            uint16_t port,
            const std::string& protocol);

        /// Check if DNS query is allowed
        static bool CheckDNSQuery(
            const ExtensionSecurityContext& context,
            const std::string& hostName);

        /// Check if URL is allowed
        static bool CheckURLAccess(
            const ExtensionSecurityContext& context,
            const std::string& url);

    private:
        /// Check if host is in private IP ranges
        static bool IsPrivateNetworkAddress(const std::string& hostName);

        /// Parse and validate URL
        static bool ValidateURL(const std::string& url);

        /// Check for DNS rebinding attempts
        static bool DetectDNSRebinding(const std::string& hostName);
    };

    // ============================================================================
    // RegistryAccessControl - Registry key access enforcement
    // ============================================================================
    class RegistryAccessControl {
    public:
        /// Check if registry key read is allowed
        static bool CheckRegistryRead(
            const ExtensionSecurityContext& context,
            const std::string& keyPath);

        /// Check if registry key write is allowed
        static bool CheckRegistryWrite(
            const ExtensionSecurityContext& context,
            const std::string& keyPath);

        /// Check if value modification is allowed
        static bool CheckRegistryValueModification(
            const ExtensionSecurityContext& context,
            const std::string& keyPath,
            const std::string& valueName);

    private:
        /// Check if key is system-protected
        static bool IsSystemProtectedKey(const std::string& keyPath);

        /// Check if key is security-sensitive
        static bool IsSecuritySensitiveKey(const std::string& keyPath);

        /// Extract hive from full key path
        static std::string ExtractHive(const std::string& keyPath);
    };

    // ============================================================================
    // ProcessAccessControl - Process privilege enforcement
    // ============================================================================
    class ProcessAccessControl {
    public:
        /// Check if process enumeration is allowed
        static bool CheckProcessEnumeration(const ExtensionSecurityContext& context);

        /// Check if handle can be opened
        static bool CheckProcessHandleAccess(
            const ExtensionSecurityContext& context,
            DWORD targetProcessId,
            DWORD desiredAccess);

        /// Check if system service access is allowed
        static bool CheckServiceAccess(
            const ExtensionSecurityContext& context,
            const std::string& serviceName);

        /// Check for privilege escalation attempts
        static bool CheckPrivilegeEscalation(
            const ExtensionSecurityContext& context,
            HANDLE processToken);

    private:
        /// Check if process is system critical
        static bool IsSystemCriticalProcess(DWORD processId);

        /// Validate token elevation level
        static bool ValidateTokenElevation(HANDLE token);
    };

    // ============================================================================
    // ExtensionSandboxManager - Central orchestrator
    // ============================================================================
    class ExtensionSandboxManager {
    public:
        static ExtensionSandboxManager& Get();

        /// Register extension with security context
        void RegisterExtension(const ExtensionSecurityContext& context);

        /// Unregister extension
        void UnregisterExtension(const std::string& extensionId);

        /// Grant file read permission
        void GrantFileReadPermission(
            const std::string& extensionId,
            const std::string& path);

        /// Grant file write permission
        void GrantFileWritePermission(
            const std::string& extensionId,
            const std::string& path);

        /// Grant network permission
        void GrantNetworkPermission(
            const std::string& extensionId,
            NetworkPermission permission);

        /// Grant registry permission
        void GrantRegistryPermission(
            const std::string& extensionId,
            const std::string& keyPath,
            RegistryPermission permission);

        /// Whitelist network host
        void WhitelistHost(
            const std::string& extensionId,
            const std::string& hostName);

        /// Validate security context
        bool ValidateExtensionSecurity(const std::string& extensionId);

        /// Perform security audit
        void PerformSecurityAudit(const std::string& extensionId);

        /// Set violation callback
        void SetViolationCallback(OnSecurityViolationCallback callback) {
            m_violationCallback = callback;
        }

        /// Report violation (internal)
        void ReportViolation(
            const std::string& extensionId,
            SecurityViolationType violationType,
            const std::string& details);

    private:
        ExtensionSandboxManager() = default;

        std::unordered_map<std::string, ExtensionSecurityContext> m_contexts;
        CRITICAL_SECTION m_lock;
        OnSecurityViolationCallback m_violationCallback;

        void Lock() { EnterCriticalSection(&m_lock); }
        void Unlock() { LeaveCriticalSection(&m_lock); }
    };

} // namespace RawrXD::Extensions
