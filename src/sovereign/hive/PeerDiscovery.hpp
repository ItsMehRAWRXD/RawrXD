// ============================================================================
// PeerDiscovery.hpp - Peer Discovery & Remote Aperture Mount
// ============================================================================

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>

namespace Sovereign {

// Discovery method
enum class DiscoveryMethod {
    MULTICAST,
    DNS_SD,
    SEED_LIST,
    BROADCAST,
    MANUAL
};

// Service announcement
struct ServiceAnnouncement {
    uint64_t nodeId;
    std::string serviceName;
    std::string address;
    uint16_t port;
    std::vector<std::string> protocols;
    uint64_t ttl;
};

// Remote aperture mount
struct RemoteAperture {
    uint64_t nodeId;
    std::string mountPath;
    uint64_t baseAddress;
    uint64_t size;
    uint32_t protection;
    bool isMounted;
    uint64_t latencyUs;
    uint64_t bandwidthMBs;
};

// Peer discovery
class PeerDiscovery {
public:
    PeerDiscovery();
    ~PeerDiscovery();

    bool Initialize(DiscoveryMethod method, uint16_t port = 42069);
    void Shutdown();
    bool IsInitialized() const { return initialized_; }

    void StartDiscovery();
    void StopDiscovery();
    void SetDiscoveryCallback(std::function<void(const ServiceAnnouncement&)> callback);

    std::vector<ServiceAnnouncement> GetDiscoveredServices() const;
    bool AnnounceService(const std::string& name, uint16_t port);

private:
    bool initialized_ = false;
    DiscoveryMethod method_;
    uint16_t port_;
    std::function<void(const ServiceAnnouncement&)> callback_;
    std::vector<ServiceAnnouncement> discovered_;
    mutable std::mutex mutex_;
    std::thread discoveryThread_;
    std::atomic<bool> running_{false};
    
    void DiscoveryLoop();
    void MulticastProbe();
    void DNSSDProbe();
};

// Remote aperture manager
class RemoteApertureManager {
public:
    RemoteApertureManager();
    ~RemoteApertureManager();

    bool Initialize();
    void Shutdown();

    bool Mount(uint64_t nodeId, const std::string& path, uint64_t size);
    bool Unmount(uint64_t nodeId);
    bool Unmount(const std::string& path);
    bool IsMounted(uint64_t nodeId) const;
    bool IsMounted(const std::string& path) const;

    std::vector<RemoteAperture> GetMountedApertures() const;
    RemoteAperture GetAperture(uint64_t nodeId) const;

    bool Read(uint64_t nodeId, uint64_t offset, void* data, size_t size);
    bool Write(uint64_t nodeId, uint64_t offset, const void* data, size_t size);

    uint64_t GetTotalMountedSize() const;
    uint64_t GetTotalTransferred() const { return totalTransferred_; }

private:
    std::unordered_map<uint64_t, RemoteAperture> apertures_;
    uint64_t totalTransferred_ = 0;
    mutable std::mutex mutex_;
};

// Distributed epoch lock
class DistributedEpochLock {
public:
    DistributedEpochLock();
    ~DistributedEpochLock();

    bool Initialize(uint64_t nodeId, const std::vector<uint64_t>& clusterNodes);
    void Shutdown();

    bool Acquire(const std::string& resource, uint64_t timeoutMs = 5000);
    bool Release(const std::string& resource);
    bool IsHeld(const std::string& resource) const;

    struct LockStats {
        uint64_t acquisitions;
        uint64_t releases;
        uint64_t contentions;
        uint64_t timeouts;
        double avgAcquireTimeMs;
    };
    LockStats GetStats() const;

private:
    uint64_t nodeId_;
    std::vector<uint64_t> clusterNodes_;
    std::unordered_map<std::string, bool> heldLocks_;
    LockStats stats_;
    mutable std::mutex mutex_;
    
    bool RequestLock(const std::string& resource);
    bool ReleaseLock(const std::string& resource);
};

} // namespace Sovereign
