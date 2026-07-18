// Phase D.12 Batch 2/5: Marketplace
// Discovery, installation, and management of extensions
// Copyright (c) 2026 RawrXD Team

#pragma once

#include <cstring>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>

namespace Sovereign {
namespace Ecosystem {

// Forward declaration
struct PluginManifest;

// ============================================================================
// Marketplace Types
// ============================================================================

enum class PackageStatus {
    DRAFT = 0,
    PENDING_REVIEW = 1,
    PUBLISHED = 2,
    REJECTED = 3,
    DEPRECATED = 4,
    SUSPENDED = 5
};

enum class PricingModel {
    FREE = 0,
    PAID = 1,
    SUBSCRIPTION = 2,
    FREEMIUM = 3
};

struct PackageInfo {
    std::string id;
    std::string name;
    std::string description;
    std::string short_description;
    std::string version;
    std::string author;
    std::string author_id;
    std::string publisher;
    std::string license;
    PackageStatus status;
    PricingModel pricing;
    double price = 0.0;
    std::string currency = "USD";
    std::vector<std::string> tags;
    std::vector<std::string> categories;
    std::map<std::string, std::string> screenshots;
    std::string icon_url;
    std::string readme_url;
    std::string changelog_url;
    std::string download_url;
    std::string package_hash;
    size_t package_size = 0;
    int download_count = 0;
    double rating = 0.0;
    int rating_count = 0;
    std::chrono::steady_clock::time_point published_at;
    std::chrono::steady_clock::time_point updated_at;
    std::vector<std::string> supported_versions;
    std::map<std::string, std::string> dependencies;
    std::map<std::string, std::string> metadata;
};

struct Review {
    std::string id;
    std::string package_id;
    std::string user_id;
    std::string user_name;
    int rating = 5;
    std::string title;
    std::string content;
    std::chrono::steady_clock::time_point created_at;
    std::chrono::steady_clock::time_point updated_at;
    int helpful_count = 0;
    int unhelpful_count = 0;
    std::vector<std::string> replies;
    bool verified_purchase = false;
};

// ============================================================================
// Package Registry
// ============================================================================

class PackageRegistry {
public:
    struct Config {
        std::string registry_url;
        std::string api_key;
        std::chrono::seconds cache_ttl{3600};
        bool enable_offline_mode = false;
        std::string local_cache_path;
    };
    
    explicit PackageRegistry(const Config& config);
    ~PackageRegistry();
    
    bool Initialize();
    void Shutdown();
    
    // Package operations
    bool PublishPackage(const PackageInfo& package_info, const std::string& package_path);
    bool UpdatePackage(const std::string& package_id, const PackageInfo& package_info);
    bool DeprecatePackage(const std::string& package_id, const std::string& reason);
    bool DeletePackage(const std::string& package_id);
    
    // Retrieval
    PackageInfo GetPackage(const std::string& package_id) const;
    std::vector<PackageInfo> GetPackagesByAuthor(const std::string& author_id) const;
    std::vector<PackageInfo> GetPackagesByCategory(const std::string& category) const;
    std::vector<PackageInfo> GetPackagesByTag(const std::string& tag) const;
    std::vector<PackageInfo> GetAllPackages() const;
    
    // Search
    std::vector<PackageInfo> Search(const std::string& query) const;
    std::vector<PackageInfo> SearchAdvanced(
        const std::string& query,
        const std::vector<std::string>& categories,
        const std::vector<std::string>& tags,
        PricingModel pricing,
        double min_rating = 0.0) const;
    
    // Versions
    std::vector<std::string> GetVersions(const std::string& package_id) const;
    PackageInfo GetVersion(const std::string& package_id, const std::string& version) const;
    bool IsVersionCompatible(const std::string& package_id, const std::string& version,
                             const std::string& sovereign_version) const;
    
    // Download
    bool DownloadPackage(const std::string& package_id, const std::string& version,
                         const std::string& output_path);
    bool VerifyPackage(const std::string& package_path, const std::string& expected_hash);
    
    // Sync
    bool SyncWithRemote();
    bool UpdateCache();
    
private:
    Config config_;
    std::map<std::string, PackageInfo> packages_;
    mutable std::mutex packages_mutex_;
    
    std::thread sync_thread_;
    
    void SyncLoop();
    bool FetchFromRemote();
    bool LoadFromCache();
    bool SaveToCache();
};

// ============================================================================
// Review System
// ============================================================================

class ReviewSystem {
public:
    struct Config {
        bool require_verified_purchase = false;
        bool moderate_reviews = true;
        int min_review_length = 10;
        int max_review_length = 5000;
    };
    
    explicit ReviewSystem(const Config& config);
    
    // Review management
    std::string SubmitReview(const Review& review);
    bool UpdateReview(const std::string& review_id, const Review& review);
    bool DeleteReview(const std::string& review_id);
    bool ModerateReview(const std::string& review_id, bool approved);
    
    // Retrieval
    Review GetReview(const std::string& review_id) const;
    std::vector<Review> GetReviewsForPackage(const std::string& package_id) const;
    std::vector<Review> GetReviewsByUser(const std::string& user_id) const;
    std::vector<Review> GetPendingReviews() const;
    
    // Filtering
    std::vector<Review> GetReviewsByRating(const std::string& package_id, int rating) const;
    std::vector<Review> GetVerifiedReviews(const std::string& package_id) const;
    std::vector<Review> GetRecentReviews(const std::string& package_id, int limit = 10) const;
    
    // Helpfulness
    bool MarkHelpful(const std::string& review_id);
    bool MarkUnhelpful(const std::string& review_id);
    
    // Statistics
    struct ReviewStats {
        double average_rating = 0.0;
        int total_reviews = 0;
        std::map<int, int> rating_distribution;
        int verified_reviews = 0;
    };
    
    ReviewStats GetStats(const std::string& package_id) const;
    
private:
    Config config_;
    std::map<std::string, Review> reviews_;
    mutable std::mutex reviews_mutex_;
};

// ============================================================================
// License Manager
// ============================================================================

struct License {
    std::string id;
    std::string package_id;
    std::string user_id;
    std::string license_key;
    std::string license_type;  // perpetual, subscription, trial
    std::chrono::steady_clock::time_point issued_at;
    std::chrono::steady_clock::time_point expires_at;
    bool active = true;
    int max_activations = 1;
    int current_activations = 0;
    std::vector<std::string> activated_devices;
    std::map<std::string, std::string> metadata;
};

class LicenseManager {
public:
    struct Config {
        std::string license_server_url;
        std::string encryption_key;
        bool enable_offline_validation = true;
        std::chrono::hours validation_interval{24};
    };
    
    explicit LicenseManager(const Config& config);
    
    // License operations
    License GenerateLicense(const std::string& package_id, const std::string& user_id,
                            const std::string& license_type);
    bool ActivateLicense(const std::string& license_key, const std::string& device_id);
    bool DeactivateLicense(const std::string& license_key, const std::string& device_id);
    bool RevokeLicense(const std::string& license_id);
    
    // Validation
    bool ValidateLicense(const std::string& license_key);
    bool ValidateLicenseForPackage(const std::string& license_key, 
                                    const std::string& package_id);
    License GetLicenseInfo(const std::string& license_key);
    
    // Queries
    std::vector<License> GetLicensesForUser(const std::string& user_id) const;
    std::vector<License> GetLicensesForPackage(const std::string& package_id) const;
    
    // Offline
    bool GenerateOfflineLicense(const std::string& license_key, 
                                  const std::string& output_path);
    bool ValidateOfflineLicense(const std::string& license_path);
    
private:
    Config config_;
    std::map<std::string, License> licenses_;
    mutable std::mutex licenses_mutex_;
    
    std::string GenerateLicenseKey();
    bool EncryptLicense(License& license);
    bool DecryptLicense(License& license);
};

// ============================================================================
// Payment Gateway
// ============================================================================

class PaymentGateway {
public:
    struct Config {
        std::string provider;  // stripe, paypal, etc.
        std::string api_key;
        std::string webhook_secret;
        std::string currency = "USD";
        bool sandbox_mode = true;
    };
    
    struct PaymentIntent {
        std::string id;
        std::string package_id;
        std::string user_id;
        double amount = 0.0;
        std::string currency;
        std::string status;  // pending, completed, failed, refunded
        std::chrono::steady_clock::time_point created_at;
        std::chrono::steady_clock::time_point completed_at;
        std::string payment_method;
        std::map<std::string, std::string> metadata;
    };
    
    explicit PaymentGateway(const Config& config);
    
    bool Initialize();
    void Shutdown();
    
    // Payment operations
    PaymentIntent CreatePaymentIntent(const std::string& package_id,
                                       const std::string& user_id,
                                       double amount);
    bool ConfirmPayment(const std::string& intent_id, const std::string& payment_method);
    bool RefundPayment(const std::string& intent_id, const std::string& reason);
    
    // Subscriptions
    std::string CreateSubscription(const std::string& package_id,
                                    const std::string& user_id,
                                    const std::string& plan_id);
    bool CancelSubscription(const std::string& subscription_id);
    bool UpdateSubscription(const std::string& subscription_id, 
                            const std::string& new_plan_id);
    
    // Webhooks
    void HandleWebhook(const std::string& payload, const std::string& signature);
    
    // History
    std::vector<PaymentIntent> GetPaymentHistory(const std::string& user_id) const;
    std::vector<PaymentIntent> GetSalesForPackage(const std::string& package_id) const;
    
private:
    Config config_;
    std::map<std::string, PaymentIntent> payments_;
    mutable std::mutex payments_mutex_;
};

// ============================================================================
// Marketplace Manager
// ============================================================================

class MarketplaceManager {
public:
    struct Config {
        PackageRegistry::Config registry;
        ReviewSystem::Config reviews;
        LicenseManager::Config licenses;
        PaymentGateway::Config payments;
        std::string marketplace_name;
        std::string terms_of_service_url;
        std::string privacy_policy_url;
    };
    
    explicit MarketplaceManager(const Config& config);
    ~MarketplaceManager();
    
    bool Initialize();
    void Shutdown();
    
    // Subsystem access
    PackageRegistry* GetRegistry();
    ReviewSystem* GetReviewSystem();
    LicenseManager* GetLicenseManager();
    PaymentGateway* GetPaymentGateway();
    
    // Package lifecycle
    bool PublishPackage(const PackageInfo& info, const std::string& package_path);
    bool PurchasePackage(const std::string& package_id, const std::string& user_id);
    bool InstallPackage(const std::string& package_id, const std::string& version);
    bool UpdatePackage(const std::string& package_id);
    bool UninstallPackage(const std::string& package_id);
    
    // Discovery
    std::vector<PackageInfo> GetFeaturedPackages() const;
    std::vector<PackageInfo> GetTrendingPackages() const;
    std::vector<PackageInfo> GetNewReleases() const;
    std::vector<PackageInfo> GetTopRated() const;
    std::vector<PackageInfo> GetRecommendedForUser(const std::string& user_id) const;
    
    // User packages
    std::vector<PackageInfo> GetInstalledPackages(const std::string& user_id) const;
    std::vector<PackageInfo> GetPurchasedPackages(const std::string& user_id) const;
    bool IsPackageInstalled(const std::string& package_id) const;
    bool IsPackageLicensed(const std::string& package_id, const std::string& user_id) const;
    
    // Analytics
    struct MarketplaceStats {
        int total_packages = 0;
        int total_downloads = 0;
        int total_reviews = 0;
        double average_rating = 0.0;
        std::map<std::string, int> packages_by_category;
        std::map<std::string, int> downloads_by_month;
    };
    
    MarketplaceStats GetStats() const;
    
private:
    Config config_;
    std::atomic<bool> initialized_{false};
    
    std::unique_ptr<PackageRegistry> registry_;
    std::unique_ptr<ReviewSystem> reviews_;
    std::unique_ptr<LicenseManager> licenses_;
    std::unique_ptr<PaymentGateway> payments_;
    
    std::map<std::string, std::string> installed_packages_;
    mutable std::mutex installed_mutex_;
};

} // namespace Ecosystem
} // namespace Sovereign
