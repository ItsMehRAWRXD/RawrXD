/**
 * SubscriptionManager.hpp
 *
 * Phase P Batch 2/5: Subscription & Billing Management
 *
 * Subscription management, billing, invoicing, and payment processing
 * for SaaS platform monetization.
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <optional>
#include <functional>
#include <chrono>

namespace MultiTenancy {

// ============================================================================
// Forward Declarations
// ============================================================================

class Subscription;
class Plan;
class PricingTier;
class SubscriptionManager;
class BillingEngine;

// ============================================================================
// Billing Interval
// ============================================================================

enum class BillingInterval {
    HOURLY,
    DAILY,
    WEEKLY,
    MONTHLY,
    QUARTERLY,
    YEARLY,
    CUSTOM
};

std::string BillingIntervalToString(BillingInterval interval);
BillingInterval BillingIntervalFromString(const std::string& str);

// ============================================================================
// Pricing Model
// ============================================================================

enum class PricingModel {
    FLAT_RATE,
    PER_USER,
    PER_USAGE,
    TIERED,
    VOLUME,
    FREEMIUM,
    HYBRID
};

// ============================================================================
// Plan
// ============================================================================

/**
 * Subscription plan definition.
 */
class Plan {
public:
    struct Config {
        std::string planId;
        std::string name;
        std::string description;
        PricingModel pricingModel;
        std::map<std::string, double> prices;  // currency -> amount
        BillingInterval interval;
        std::optional<uint32_t> trialDays;
        std::optional<uint32_t> setupFee;
        std::map<std::string, std::string> features;
        std::map<std::string, ResourceQuota::Limits> limits;
        bool isPublic;
        bool isActive;
        std::optional<std::chrono::system_clock::time_point> validFrom;
        std::optional<std::chrono::system_clock::time_point> validUntil;
        std::map<std::string, std::string> metadata;
    };
    
    struct Tier {
        std::string name;
        uint64_t minQuantity;
        uint64_t maxQuantity;
        double unitPrice;
        std::optional<double> flatPrice;
    };
    
    explicit Plan(const Config& config);
    
    // Accessors
    const std::string& GetPlanId() const { return config_.planId; }
    const std::string& GetName() const { return config_.name; }
    PricingModel GetPricingModel() const { return config_.pricingModel; }
    BillingInterval GetInterval() const { return config_.interval; }
    
    // Pricing
    double GetPrice(const std::string& currency = "USD") const;
    void SetPrice(const std::string& currency, double amount);
    
    // Tiers
    void AddTier(const Tier& tier);
    void RemoveTier(const std::string& name);
    double CalculatePrice(uint64_t quantity) const;
    
    // Features
    void AddFeature(const std::string& feature, const std::string& description);
    void RemoveFeature(const std::string& feature);
    bool HasFeature(const std::string& feature) const;
    std::vector<std::string> GetFeatures() const;
    
    // Limits
    void SetLimit(const std::string& resource, const ResourceQuota::Limits& limits);
    ResourceQuota::Limits GetLimits() const;
    
    // Validation
    bool IsValid() const;
    bool IsAvailable() const;
    
    // Comparison
    struct Comparison {
        std::string feature;
        bool inThisPlan;
        bool inOtherPlan;
        std::optional<std::string> difference;
    };
    std::vector<Comparison> CompareTo(const Plan& other) const;
    
    // Serialization
    std::string ToJson() const;
    static Plan FromJson(const std::string& json);
    
private:
    Config config_;
    std::vector<Tier> tiers_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Subscription Status
// ============================================================================

enum class SubscriptionStatus {
    TRIALING,
    ACTIVE,
    PAST_DUE,
    UNPAID,
    CANCELLED,
    EXPIRED,
    PAUSED
};

// ============================================================================
// Subscription
// ============================================================================

/**
 * Tenant subscription.
 */
class Subscription {
public:
    struct Config {
        std::string subscriptionId;
        std::string tenantId;
        std::string planId;
        SubscriptionStatus status;
        std::chrono::system_clock::time_point createdAt;
        std::optional<std::chrono::system_clock::time_point> trialEndsAt;
        std::optional<std::chrono::system_clock::time_point> currentPeriodStart;
        std::optional<std::chrono::system_clock::time_point> currentPeriodEnd;
        std::optional<std::chrono::system_clock::time_point> cancelledAt;
        std::optional<std::chrono::system_clock::time_point> endedAt;
        std::optional<std::string> cancellationReason;
        bool cancelAtPeriodEnd;
        std::map<std::string, std::string> metadata;
        std::optional<std::string> paymentMethodId;
        std::optional<std::string> couponCode;
        double discountPercent;
    };
    
    struct UsageRecord {
        std::string metric;
        uint64_t quantity;
        std::chrono::system_clock::time_point timestamp;
        std::map<std::string, std::string> metadata;
    };
    
    explicit Subscription(const Config& config);
    
    // Lifecycle
    void StartTrial(std::chrono::days duration);
    void Activate();
    void Cancel(const std::string& reason = "");
    void CancelAtPeriodEnd();
    void Uncancel();
    void Pause();
    void Resume();
    void MarkPastDue();
    void MarkUnpaid();
    void MarkPaid();
    void Expire();
    
    // Status
    SubscriptionStatus GetStatus() const { return config_.status; }
    bool IsActive() const { return config_.status == SubscriptionStatus::ACTIVE; }
    bool IsTrialing() const { return config_.status == SubscriptionStatus::TRIALING; }
    bool IsCancelled() const { return config_.status == SubscriptionStatus::CANCELLED; }
    bool WillCancelAtPeriodEnd() const { return config_.cancelAtPeriodEnd; }
    
    // Period management
    void StartNewPeriod();
    void EndCurrentPeriod();
    bool IsInTrial() const;
    bool IsInGracePeriod() const;
    std::chrono::days DaysUntilRenewal() const;
    
    // Usage tracking
    void RecordUsage(const std::string& metric, uint64_t quantity);
    void RecordUsage(const UsageRecord& record);
    uint64_t GetUsage(const std::string& metric,
                       const std::optional<std::chrono::system_clock::time_point>& start = std::nullopt,
                       const std::optional<std::chrono::system_clock::time_point>& end = std::nullopt) const;
    std::vector<UsageRecord> GetUsageRecords() const;
    
    // Plan changes
    void ChangePlan(const std::string& newPlanId);
    void SchedulePlanChange(const std::string& newPlanId,
                            std::chrono::system_clock::time_point effectiveDate);
    std::optional<std::string> GetPendingPlanChange() const;
    
    // Discounts
    void ApplyCoupon(const std::string& couponCode, double discountPercent);
    void RemoveCoupon();
    double CalculateDiscount(double amount) const;
    
    // Accessors
    const std::string& GetSubscriptionId() const { return config_.subscriptionId; }
    const std::string& GetTenantId() const { return config_.tenantId; }
    const std::string& GetPlanId() const { return config_.planId; }
    
    // Serialization
    std::string ToJson() const;
    static Subscription FromJson(const std::string& json);
    
private:
    Config config_;
    std::vector<UsageRecord> usageRecords_;
    std::optional<std::string> pendingPlanChange_;
    mutable std::mutex mutex_;
    
    void UpdateStatus(SubscriptionStatus newStatus);
};

// ============================================================================
// Invoice
// ============================================================================

/**
 * Invoice for subscription billing.
 */
class Invoice {
public:
    enum class Status {
        DRAFT,
        OPEN,
        PAID,
        UNCOLLECTIBLE,
        VOID
    };
    
    struct LineItem {
        std::string description;
        uint64_t quantity;
        double unitPrice;
        double amount;
        std::optional<std::string> periodStart;
        std::optional<std::string> periodEnd;
        std::map<std::string, std::string> metadata;
    };
    
    struct Config {
        std::string invoiceId;
        std::string tenantId;
        std::string subscriptionId;
        Status status;
        std::chrono::system_clock::time_point createdAt;
        std::optional<std::chrono::system_clock::time_point> dueDate;
        std::optional<std::chrono::system_clock::time_point> paidAt;
        std::vector<LineItem> lineItems;
        double subtotal;
        double taxPercent;
        double taxAmount;
        double discountAmount;
        double total;
        double amountPaid;
        double amountDue;
        std::string currency;
        std::optional<std::string> description;
        std::map<std::string, std::string> metadata;
    };
    
    explicit Invoice(const Config& config);
    
    // Line items
    void AddLineItem(const LineItem& item);
    void RemoveLineItem(size_t index);
    std::vector<LineItem> GetLineItems() const;
    
    // Calculations
    void CalculateTotals();
    double GetSubtotal() const { return config_.subtotal; }
    double GetTaxAmount() const { return config_.taxAmount; }
    double GetTotal() const { return config_.total; }
    double GetAmountDue() const { return config_.amountDue; }
    
    // Status
    void MarkAsOpen();
    void MarkAsPaid(double amount, const std::string& paymentMethod);
    void MarkAsUncollectible();
    void Void(const std::string& reason);
    Status GetStatus() const { return config_.status; }
    bool IsPaid() const { return config_.status == Status::PAID; }
    bool IsOverdue() const;
    
    // Accessors
    const std::string& GetInvoiceId() const { return config_.invoiceId; }
    const std::string& GetTenantId() const { return config_.tenantId; }
    
    // Serialization
    std::string ToJson() const;
    std::string ToPdf() const;
    static Invoice FromJson(const std::string& json);
    
private:
    Config config_;
    mutable std::mutex mutex_;
    
    void Recalculate();
};

// ============================================================================
// Payment Method
// ============================================================================

/**
 * Payment method for billing.
 */
class PaymentMethod {
public:
    enum class Type {
        CREDIT_CARD,
        DEBIT_CARD,
        BANK_TRANSFER,
        PAYPAL,
        STRIPE,
        INVOICE,
        CRYPTOCURRENCY
    };
    
    enum class Status {
        ACTIVE,
        EXPIRED,
        CANCELLED,
        FAILED
    };
    
    struct Config {
        std::string paymentMethodId;
        std::string tenantId;
        Type type;
        Status status;
        std::string lastFour;
        std::optional<std::string> brand;
        std::optional<uint32_t> expiryMonth;
        std::optional<uint32_t> expiryYear;
        std::optional<std::string> billingName;
        std::optional<std::string> billingEmail;
        std::optional<std::string> billingAddress;
        bool isDefault;
        std::chrono::system_clock::time_point createdAt;
        std::map<std::string, std::string> metadata;
    };
    
    explicit PaymentMethod(const Config& config);
    
    // Validation
    bool IsValid() const;
    bool IsExpired() const;
    
    // Status
    void MarkAsExpired();
    void MarkAsFailed();
    void Cancel();
    
    // Default
    void SetAsDefault();
    bool IsDefault() const { return config_.isDefault; }
    
    // Accessors
    const std::string& GetPaymentMethodId() const { return config_.paymentMethodId; }
    const std::string& GetTenantId() const { return config_.tenantId; }
    Type GetType() const { return config_.type; }
    
    // Masked info
    std::string GetMaskedNumber() const;
    std::string GetDisplayName() const;
    
    // Serialization
    std::string ToJson() const;
    static PaymentMethod FromJson(const std::string& json);
    
private:
    Config config_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Billing Engine
// ============================================================================

/**
 * Billing engine for subscription management.
 */
class BillingEngine {
public:
    struct Config {
        std::string defaultCurrency;
        double defaultTaxPercent;
        std::chrono::days gracePeriodDays;
        std::chrono::days retryAttempts;
        std::chrono::hours retryInterval;
        bool autoCharge;
        bool sendInvoiceEmails;
        bool sendPaymentEmails;
    };
    
    explicit BillingEngine(const Config& config);
    ~BillingEngine();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // Invoice generation
    std::shared_ptr<Invoice> GenerateInvoice(const std::string& subscriptionId);
    std::shared_ptr<Invoice> GenerateInvoice(const std::string& subscriptionId,
                                                  std::chrono::system_clock::time_point periodStart,
                                                  std::chrono::system_clock::time_point periodEnd);
    std::vector<std::shared_ptr<Invoice>> GenerateUpcomingInvoices(
        const std::string& subscriptionId,
        uint32_t periods);
    
    // Invoice management
    std::shared_ptr<Invoice> GetInvoice(const std::string& invoiceId);
    std::vector<std::shared_ptr<Invoice>> GetInvoicesForTenant(
        const std::string& tenantId);
    std::vector<std::shared_ptr<Invoice>> GetUnpaidInvoices(
        const std::string& tenantId);
    
    // Payment processing
    struct PaymentResult {
        bool success;
        std::optional<std::string> transactionId;
        std::optional<std::string> error;
        double amountProcessed;
    };
    
    PaymentResult ProcessPayment(const std::string& invoiceId,
                                  const std::string& paymentMethodId);
    PaymentResult ProcessPayment(const std::string& invoiceId);
    PaymentResult RefundPayment(const std::string& invoiceId,
                                   double amount);
    
    // Automatic billing
    void EnableAutoBilling(const std::string& tenantId);
    void DisableAutoBilling(const std::string& tenantId);
    void RunBillingCycle();
    void RetryFailedPayments();
    
    // Proration
    double CalculateProration(const std::string& subscriptionId,
                               const std::string& newPlanId);
    
    // Tax calculation
    double CalculateTax(const std::string& tenantId,
                        double amount,
                        const std::optional<std::string>& taxId = std::nullopt);
    
    // Usage-based billing
    void RecordUsage(const std::string& subscriptionId,
                     const std::string& metric,
                     uint64_t quantity);
    double CalculateUsageCharges(const std::string& subscriptionId);
    
    // Reporting
    struct BillingReport {
        std::chrono::system_clock::time_point periodStart;
        std::chrono::system_clock::time_point periodEnd;
        double totalRevenue;
        double totalTax;
        double totalDiscounts;
        uint64_t invoiceCount;
        uint64_t paidInvoiceCount;
        uint64_t unpaidInvoiceCount;
        double outstandingAmount;
        std::map<std::string, double> revenueByPlan;
    };
    
    BillingReport GenerateReport(const std::chrono::system_clock::time_point& start,
                                  const std::chrono::system_clock::time_point& end);
    
    // Statistics
    struct BillingStats {
        uint64_t totalInvoicesGenerated;
        uint64_t totalPaymentsProcessed;
        uint64_t totalPaymentsFailed;
        double totalRevenue;
        double totalRefunded;
        double averageInvoiceAmount;
        double collectionRate;
    };
    BillingStats GetStats() const;
    
private:
    Config config_;
    bool initialized_;
    
    std::map<std::string, std::shared_ptr<Invoice>> invoices_;
    mutable std::mutex invoicesMutex_;
    
    BillingStats stats_;
    mutable std::mutex statsMutex_;
    
    std::thread billingThread_;
    std::atomic<bool> stopBilling_;
    
    void BillingLoop();
    void ProcessBillingCycle();
    PaymentResult ChargePaymentMethod(const std::string& paymentMethodId,
                                       double amount);
};

// ============================================================================
// Subscription Manager
// ============================================================================

/**
 * Central subscription manager.
 */
class SubscriptionManager {
public:
    struct Config {
        std::chrono::seconds checkInterval;
        bool enableAutoRenewal;
        bool enableDunning;
        uint32_t dunningRetries;
        std::chrono::days dunningInterval;
    };
    
    explicit SubscriptionManager(const Config& config,
                                  std::shared_ptr<BillingEngine> billing);
    ~SubscriptionManager();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // Plan management
    void CreatePlan(const Plan::Config& config);
    void UpdatePlan(const std::string& planId, const Plan::Config& config);
    void DeletePlan(const std::string& planId);
    std::shared_ptr<Plan> GetPlan(const std::string& planId) const;
    std::vector<std::shared_ptr<Plan>> GetPlans() const;
    std::vector<std::shared_ptr<Plan>> GetPublicPlans() const;
    std::vector<std::shared_ptr<Plan>> GetPlansForTier(TenantTier tier) const;
    
    // Subscription management
    std::shared_ptr<Subscription> CreateSubscription(
        const std::string& tenantId,
        const std::string& planId);
    std::shared_ptr<Subscription> CreateTrialSubscription(
        const std::string& tenantId,
        const std::string& planId,
        std::chrono::days trialDuration);
    void CancelSubscription(const std::string& subscriptionId,
                            const std::string& reason = "");
    void ChangePlan(const std::string& subscriptionId,
                    const std::string& newPlanId);
    
    std::shared_ptr<Subscription> GetSubscription(const std::string& subscriptionId) const;
    std::shared_ptr<Subscription> GetSubscriptionForTenant(
        const std::string& tenantId) const;
    std::vector<std::shared_ptr<Subscription>> GetAllSubscriptions() const;
    std::vector<std::shared_ptr<Subscription>> GetActiveSubscriptions() const;
    std::vector<std::shared_ptr<Subscription>> GetExpiringSubscriptions(
        std::chrono::days within) const;
    
    // Payment methods
    void AddPaymentMethod(const PaymentMethod::Config& config);
    void RemovePaymentMethod(const std::string& paymentMethodId);
    void SetDefaultPaymentMethod(const std::string& tenantId,
                                  const std::string& paymentMethodId);
    std::shared_ptr<PaymentMethod> GetDefaultPaymentMethod(
        const std::string& tenantId) const;
    std::vector<std::shared_ptr<PaymentMethod>> GetPaymentMethods(
        const std::string& tenantId) const;
    
    // Coupons
    struct Coupon {
        std::string code;
        std::string description;
        double discountPercent;
        std::optional<double> maxDiscountAmount;
        std::optional<uint32_t> maxUses;
        uint32_t usesCount;
        std::optional<std::chrono::system_clock::time_point> validFrom;
        std::optional<std::chrono::system_clock::time_point> validUntil;
        std::vector<std::string> applicablePlans;
        bool isActive;
    };
    
    void CreateCoupon(const Coupon& coupon);
    void DeleteCoupon(const std::string& code);
    std::optional<Coupon> GetCoupon(const std::string& code) const;
    bool ValidateCoupon(const std::string& code,
                        const std::string& planId) const;
    void ApplyCoupon(const std::string& subscriptionId,
                     const std::string& couponCode);
    
    // Webhooks
    using WebhookHandler = std::function<void(const std::string& event,
                                                const std::string& payload)>;
    void RegisterWebhook(const std::string& event, WebhookHandler handler);
    
    // Statistics
    struct SubscriptionStats {
        uint32_t totalSubscriptions;
        uint32_t activeSubscriptions;
        uint32_t trialingSubscriptions;
        uint32_t pastDueSubscriptions;
        uint32_t cancelledSubscriptions;
        double monthlyRecurringRevenue;
        double annualRecurringRevenue;
        double averageRevenuePerUser;
        double churnRate;
        std::map<std::string, uint32_t> subscriptionsByPlan;
    };
    SubscriptionStats GetStats() const;
    
private:
    Config config_;
    bool initialized_;
    std::shared_ptr<BillingEngine> billing_;
    
    std::map<std::string, std::shared_ptr<Plan>> plans_;
    std::map<std::string, std::shared_ptr<Subscription>> subscriptions_;
    std::map<std::string, std::vector<std::shared_ptr<PaymentMethod>>> paymentMethods_;
    std::map<std::string, Coupon> coupons_;
    mutable std::mutex mutex_;
    
    std::map<std::string, std::vector<WebhookHandler>> webhooks_;
    mutable std::mutex webhookMutex_;
    
    std::thread monitorThread_;
    std::atomic<bool> stopMonitor_;
    
    void MonitorLoop();
    void CheckExpiringSubscriptions();
    void CheckFailedPayments();
    void EmitWebhook(const std::string& event, const std::string& payload);
};

} // namespace MultiTenancy
