/**
 * @file FeedbackSystem.hpp
<<<<<<< HEAD
 * @brief Community Feedback & Telemetry Consent — pure C++20/Win32 (zero Qt).
 *
 * Provides: FeedbackDialog, TelemetryConsentDialog, ContributionDialog,
 * and FeedbackManager — all using native Win32 dialogs/controls.
 *
 * @copyright RawrXD IDE 2026
 */
#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <commctrl.h>

#include <string>
#include <vector>
#include <optional>
#include <functional>
#include <memory>
#include <unordered_map>
#include <chrono>
#include <cstdint>

namespace rawrxd::feedback {

// ═══════════════════════════════════════════════════════════════════════════════
// Enumerations
// ═══════════════════════════════════════════════════════════════════════════════

enum class FeedbackCategory : int {
    BugReport, FeatureRequest, PerformanceIssue, ThermalIssue,
    UIFeedback, Documentation, Security, Other
};

enum class FeedbackPriority : int { Low, Medium, High, Critical };

enum class SubmissionStatus : int {
    Draft, Pending, Submitted, Acknowledged, InProgress, Resolved, Closed
};

// ═══════════════════════════════════════════════════════════════════════════════
// Data Structures
// ═══════════════════════════════════════════════════════════════════════════════

=======
 * @brief Community Feedback and Contribution System
 * 
 * Provides user feedback collection, telemetry consent, and community
 * contribution framework for RawrXD IDE thermal management.
 * 
 * @copyright RawrXD IDE 2026
 */

#pragma once

#include <memory>
#include <vector>
#include <functional>
#include <string>
#include <optional>
#include <unordered_map>
#include <any>

namespace rawrxd::feedback {

// Type aliases for replaced Qt types
using anyMap = std::unordered_map<std::string, std::string>; // Simplified for now
using stringList = std::vector<std::string>;

// ...existing code...

/**
 * @brief Feedback category enumeration
 */
enum class FeedbackCategory {
    BugReport,
    FeatureRequest,
    PerformanceIssue,
    ThermalIssue,
    UIFeedback,
    Documentation,
    Security,
    Other
};

/**
 * @brief Feedback priority level
 */
enum class FeedbackPriority {
    Low,
    Medium,
    High,
    Critical
};

/**
 * @brief Feedback submission status
 */
enum class SubmissionStatus {
    Draft,
    Pending,
    Submitted,
    Acknowledged,
    InProgress,
    Resolved,
    Closed
};

/**
 * @brief Single feedback entry
 */
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
struct FeedbackEntry {
    std::string id;
    std::string title;
    std::string description;
<<<<<<< HEAD
    FeedbackCategory category  = FeedbackCategory::Other;
    FeedbackPriority priority  = FeedbackPriority::Medium;
    SubmissionStatus status    = SubmissionStatus::Draft;

    std::string userEmail;
    std::string userName;
    bool consentToContact = false;

    std::unordered_map<std::string, std::string> systemInfo;
    bool includedSystemInfo = false;

    std::vector<std::string> attachmentPaths;
    std::vector<std::string> screenshotPaths;

    std::optional<double> currentTemperature;
    std::optional<double> averageTemperature;
    std::optional<int>    throttleCount;
    std::unordered_map<std::string, std::string> thermalSnapshot;

    std::string createdISO;     // ISO-8601 timestamp
    std::string modifiedISO;
    std::string submittedISO;
    std::string responseText;
};

struct TelemetryConsent {
    bool basicTelemetry       = false;
    bool performanceTelemetry = false;
    bool thermalTelemetry     = false;
    bool crashReporting       = false;
    bool featureUsage         = false;
    bool hardwareInfo         = false;
    std::string consentVersion;
    std::string consentDateISO;

    bool hasAnyConsent() const {
        return basicTelemetry || performanceTelemetry || thermalTelemetry ||
               crashReporting || featureUsage || hardwareInfo;
    }
};

=======
    FeedbackCategory category;
    FeedbackPriority priority;
    SubmissionStatus status;
    
    // User info (optional, consent-based)
    std::string userEmail;
    std::string userName;
    bool consentToContact;
    
    // System info (optional, consent-based)
    std::anyMap systemInfo;
    bool includedSystemInfo;
    
    // Attachments
    std::stringList attachmentPaths;
    std::stringList screenshotPaths;
    
    // Thermal-specific data
    std::optional<double> currentTemperature;
    std::optional<double> averageTemperature;
    std::optional<int> throttleCount;
    std::anyMap thermalSnapshot;
    
    // Timestamps
    int64_t created = 0;
    int64_t modified = 0;
    int64_t submitted = 0;
    
    // Response
    std::string responseText;
    // DateTime responseDate;
    
    /**
     * @brief Convert to JSON for submission
     */
    void* toJson() const {
        void* obj;
        obj["id"] = id;
        obj["title"] = title;
        obj["description"] = description;
        obj["category"] = static_cast<int>(category);
        obj["priority"] = static_cast<int>(priority);
        obj["status"] = static_cast<int>(status);
        obj["created"] = created.toString(ISODate);
        obj["modified"] = modified.toString(ISODate);
        
        if (consentToContact) {
            obj["userEmail"] = userEmail;
            obj["userName"] = userName;
        }
        
        if (includedSystemInfo) {
            obj["systemInfo"] = void*::fromVariantMap(systemInfo);
        }
        
        if (currentTemperature) {
            obj["currentTemperature"] = *currentTemperature;
        }
        if (averageTemperature) {
            obj["averageTemperature"] = *averageTemperature;
        }
        if (throttleCount) {
            obj["throttleCount"] = *throttleCount;
        }
        if (!thermalSnapshot.empty()) {
            obj["thermalSnapshot"] = void*::fromVariantMap(thermalSnapshot);
        }
        
        return obj;
    }
    
    /**
     * @brief Create from JSON response
     */
    static FeedbackEntry fromJson(const void*& obj) {
        FeedbackEntry entry;
        entry.id = obj["id"].toString();
        entry.title = obj["title"].toString();
        entry.description = obj["description"].toString();
        entry.category = static_cast<FeedbackCategory>(obj["category"]);
        entry.priority = static_cast<FeedbackPriority>(obj["priority"]);
        entry.status = static_cast<SubmissionStatus>(obj["status"]);
        entry.created = // DateTime::fromString(obj["created"].toString(), ISODate);
        entry.modified = // DateTime::fromString(obj["modified"].toString(), ISODate);
        
        if (obj.contains("responseText")) {
            entry.responseText = obj["responseText"].toString();
            entry.responseDate = // DateTime::fromString(obj["responseDate"].toString(), ISODate);
        }
        
        return entry;
    }
};

/**
 * @brief Telemetry consent settings
 */
struct TelemetryConsent {
    bool basicTelemetry = false;           // Anonymous usage stats
    bool performanceTelemetry = false;     // Performance metrics
    bool thermalTelemetry = false;         // Thermal data
    bool crashReporting = false;           // Crash dumps
    bool featureUsage = false;             // Feature usage tracking
    bool hardwareInfo = false;             // Hardware specs
    
    // DateTime consentDate;
    std::string consentVersion;
    
    int64_t getConsentDate() const { return 0; }
    
    // Serialization removed for now or should use json
    // ...
};

/**
 * @brief Community contribution entry
 */
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
struct ContributionEntry {
    std::string id;
    std::string title;
    std::string description;
    std::string contributorName;
    std::string contributorEmail;
<<<<<<< HEAD

    enum class Type : int {
        ThermalProfile, DriveConfiguration, Algorithm,
        Documentation, Translation, Other
    } type = Type::Other;

    std::vector<uint8_t> fileContent;
    std::string fileName;
    std::string fileChecksum;
    std::string license;
    bool agreedToTerms = false;
    SubmissionStatus status = SubmissionStatus::Draft;
=======
    
    enum class Type {
        ThermalProfile,
        DriveConfiguration,
        Algorithm,
        Documentation,
        Translation,
        Other
    } type;
    
    std::vector<uint8_t> fileContent;
    std::string fileName;
    std::string fileChecksum;
    
    std::string license;
    bool agreedToTerms;
    
    // DateTime submitted;
    SubmissionStatus status;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
};

// ═══════════════════════════════════════════════════════════════════════════════
// Callbacks
// ═══════════════════════════════════════════════════════════════════════════════

<<<<<<< HEAD
using FeedbackSubmittedCallback  = std::function<void(const FeedbackEntry&, bool)>;
using TelemetryConsentCallback   = std::function<void(const TelemetryConsent&)>;
using ContributionCallback       = std::function<void(const ContributionEntry&, bool)>;

// ═══════════════════════════════════════════════════════════════════════════════
// FeedbackDialog — multi-tab Win32 dialog
=======
using FeedbackSubmittedCallback = std::function<void(const FeedbackEntry& entry, bool success)>;
using TelemetryConsentCallback = std::function<void(const TelemetryConsent& consent)>;
using ContributionCallback = std::function<void(const ContributionEntry& entry, bool success)>;

// ═══════════════════════════════════════════════════════════════════════════════
// Feedback Dialog (Abstract/Headless Representation)
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
// ═══════════════════════════════════════════════════════════════════════════════

class FeedbackDialog {
public:
<<<<<<< HEAD
    explicit FeedbackDialog(HWND hwndParent = nullptr);
    ~FeedbackDialog();

    FeedbackDialog(const FeedbackDialog&) = delete;
    FeedbackDialog& operator=(const FeedbackDialog&) = delete;

    INT_PTR showModal();

    void setThermalData(double currentTemp, double avgTemp, int throttles);
    void setThermalSnapshot(const std::unordered_map<std::string,std::string>& snap);
    void setSystemInfo(const std::unordered_map<std::string,std::string>& info);
    FeedbackEntry getFeedback() const;
    void setSubmitCallback(FeedbackSubmittedCallback cb) { m_submitCb = std::move(cb); }

private:
    static INT_PTR CALLBACK DlgProc(HWND, UINT, WPARAM, LPARAM);
    INT_PTR handleMsg(HWND, UINT, WPARAM, LPARAM);
    void initControls(HWND hDlg);
    void collectSystemInfo();
    bool validateInput();
    void onSubmit();
    void onSaveDraft();

    HWND m_hwndParent = nullptr;
    HWND m_hDlg       = nullptr;

    // Tab 0: Feedback
    HWND m_hwndCategoryCombo = nullptr;
    HWND m_hwndPriorityCombo = nullptr;
    HWND m_hwndTitleEdit     = nullptr;
    HWND m_hwndDescEdit      = nullptr;

    // Tab 1: Contact
    HWND m_hwndNameEdit      = nullptr;
    HWND m_hwndEmailEdit     = nullptr;
    HWND m_hwndConsentCheck  = nullptr;

    // Tab 2: System Info
    HWND m_hwndSysInfoCheck  = nullptr;
    HWND m_hwndThermalCheck  = nullptr;
    HWND m_hwndSysPreview    = nullptr;

    // Buttons
    HWND m_hwndSubmitBtn     = nullptr;
    HWND m_hwndDraftBtn      = nullptr;
    HWND m_hwndProgress      = nullptr;
    HWND m_hwndStatusLabel   = nullptr;

    FeedbackEntry   m_entry;
    FeedbackSubmittedCallback m_submitCb;
    std::unordered_map<std::string,std::string> m_sysInfo;
    std::unordered_map<std::string,std::string> m_thermalSnap;

    enum {
        IDC_FB_CATEGORY = 4001, IDC_FB_PRIORITY, IDC_FB_TITLE, IDC_FB_DESC,
        IDC_FB_NAME, IDC_FB_EMAIL, IDC_FB_CONSENT,
        IDC_FB_SYSINFO, IDC_FB_THERMAL, IDC_FB_PREVIEW,
        IDC_FB_SUBMIT = 4020, IDC_FB_DRAFT, IDC_FB_PROGRESS, IDC_FB_STATUS,
    };
};

// ═══════════════════════════════════════════════════════════════════════════════
// TelemetryConsentDialog
=======
    explicit FeedbackDialog(void* parent = nullptr);
    virtual ~FeedbackDialog();

    void setThermalData(double currentTemp, double avgTemp, int throttleCount);
    void setThermalSnapshot(const anyMap& snapshot);
    void setSystemInfo(const anyMap& sysInfo);
    
    FeedbackEntry getFeedback() const;
    void setSubmitCallback(FeedbackSubmittedCallback callback);

    void show(); // Logic to show native dialog or log

private:
    FeedbackEntry m_entry;
    anyMap m_systemInfo;
    anyMap m_thermalSnapshot;
    FeedbackSubmittedCallback m_submitCallback;
    void* m_nativeHandle = nullptr;
};

// ═══════════════════════════════════════════════════════════════════════════════
// Telemetry Consent Dialog
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
// ═══════════════════════════════════════════════════════════════════════════════

class TelemetryConsentDialog {
public:
<<<<<<< HEAD
    explicit TelemetryConsentDialog(HWND hwndParent = nullptr);
    ~TelemetryConsentDialog();

    INT_PTR showModal();

    void setCurrentConsent(const TelemetryConsent& c) { m_consent = c; }
    TelemetryConsent getConsent() const { return m_consent; }
    void setConsentCallback(TelemetryConsentCallback cb) { m_consentCb = std::move(cb); }

private:
    static INT_PTR CALLBACK DlgProc(HWND, UINT, WPARAM, LPARAM);
    INT_PTR handleMsg(HWND, UINT, WPARAM, LPARAM);
    void initControls(HWND hDlg);

    HWND m_hwndParent = nullptr;
    HWND m_hDlg       = nullptr;

    HWND m_hwndBasic    = nullptr;
    HWND m_hwndPerf     = nullptr;
    HWND m_hwndThermal  = nullptr;
    HWND m_hwndCrash    = nullptr;
    HWND m_hwndFeature  = nullptr;
    HWND m_hwndHardware = nullptr;
    HWND m_hwndPrivacy  = nullptr;

    TelemetryConsent m_consent;
    TelemetryConsentCallback m_consentCb;

    enum {
        IDC_TC_BASIC = 4101, IDC_TC_PERF, IDC_TC_THERMAL,
        IDC_TC_CRASH, IDC_TC_FEATURE, IDC_TC_HARDWARE,
        IDC_TC_PRIVACY, IDC_TC_ALL, IDC_TC_NONE, IDC_TC_SAVE,
    };
};

// ═══════════════════════════════════════════════════════════════════════════════
// ContributionDialog
=======
    explicit TelemetryConsentDialog(void* parent = nullptr);
    virtual ~TelemetryConsentDialog();

    void setCurrentConsent(const TelemetryConsent& consent);
    TelemetryConsent getConsent() const;
    void setConsentCallback(TelemetryConsentCallback callback);
    void show(); 

private:
    TelemetryConsent m_consent;
    TelemetryConsentCallback m_consentCallback;
    void* m_nativeHandle = nullptr;
};

// ═══════════════════════════════════════════════════════════════════════════════
// Contribution Dialog
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
// ═══════════════════════════════════════════════════════════════════════════════

class ContributionDialog {
public:
<<<<<<< HEAD
    explicit ContributionDialog(HWND hwndParent = nullptr);
    ~ContributionDialog();

    INT_PTR showModal();
    ContributionEntry getContribution() const { return m_entry; }
    void setContributionCallback(ContributionCallback cb) { m_cb = std::move(cb); }

private:
    static INT_PTR CALLBACK DlgProc(HWND, UINT, WPARAM, LPARAM);
    INT_PTR handleMsg(HWND, UINT, WPARAM, LPARAM);
    void initControls(HWND hDlg);
    bool validateInput();

    HWND m_hwndParent = nullptr;
    HWND m_hDlg       = nullptr;

    HWND m_hwndTitleEdit   = nullptr;
    HWND m_hwndDescEdit    = nullptr;
    HWND m_hwndTypeCombo   = nullptr;
    HWND m_hwndNameEdit    = nullptr;
    HWND m_hwndEmailEdit   = nullptr;
    HWND m_hwndFileEdit    = nullptr;
    HWND m_hwndBrowseBtn   = nullptr;
    HWND m_hwndLicenseCombo = nullptr;
    HWND m_hwndAgreeCheck  = nullptr;

    ContributionEntry m_entry;
    ContributionCallback m_cb;

    enum {
        IDC_CT_TITLE = 4201, IDC_CT_DESC, IDC_CT_TYPE,
        IDC_CT_NAME, IDC_CT_EMAIL, IDC_CT_FILE, IDC_CT_BROWSE,
        IDC_CT_LICENSE, IDC_CT_AGREE, IDC_CT_SUBMIT,
    };
};

// ═══════════════════════════════════════════════════════════════════════════════
// FeedbackManager — singleton coordinator
=======
    explicit ContributionDialog(void* parent = nullptr);
    virtual ~ContributionDialog();

    void setContributionCallback(ContributionCallback callback);
    ContributionEntry getContribution() const;
    void show();

private:
    ContributionEntry m_entry;
    ContributionCallback m_contributionCallback;
    void* m_nativeHandle = nullptr;
};

// ═══════════════════════════════════════════════════════════════════════════════
// Feedback Manager
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
// ═══════════════════════════════════════════════════════════════════════════════

class FeedbackManager {
public:
    static FeedbackManager& instance();
<<<<<<< HEAD

    void showFeedbackDialog(HWND parent = nullptr);
    void showTelemetryConsentDialog(HWND parent = nullptr);
    void showContributionDialog(HWND parent = nullptr);

    void submitQuickFeedback(const std::string& message, FeedbackCategory cat);
    void reportBug(const std::string& title, const std::string& desc);
    void requestFeature(const std::string& title, const std::string& desc);

    void setTelemetryConsent(const TelemetryConsent& c);
    TelemetryConsent getTelemetryConsent() const { return m_consent; }
    bool hasTelemetryConsent() const { return m_consent.hasAnyConsent(); }

    void saveDraft(const FeedbackEntry& e);
    std::vector<FeedbackEntry> loadDrafts();
    void deleteDraft(const std::string& id);

    void setApiEndpoint(const std::string& ep) { m_apiEndpoint = ep; }
    void setApiKey(const std::string& key)      { m_apiKey = key; }
=======
    
    void showFeedbackDialog(void* parent = nullptr);
    void showTelemetryConsentDialog(void* parent = nullptr);
    void showContributionDialog(void* parent = nullptr);
    
    void submitQuickFeedback(const std::string& message, FeedbackCategory category);
    void reportBug(const std::string& title, const std::string& description);
    void requestFeature(const std::string& title, const std::string& description);
    void reportThermalIssue(const std::string& description, const anyMap& thermalData);
    
    void setTelemetryConsent(const TelemetryConsent& consent);
    TelemetryConsent getTelemetryConsent() const;
    bool hasTelemetryConsent() const;
    
    void sendTelemetry(const std::string& eventName, const anyMap& data);
    void sendPerformanceMetrics(const anyMap& metrics);
    void sendThermalData(const anyMap& thermalData);
    void sendCrashReport(const std::string& crashDump, const anyMap& context);
    
    void saveDraft(const FeedbackEntry& entry);
    std::vector<FeedbackEntry> loadDrafts();
    void deleteDraft(const std::string& id);
    
    std::vector<FeedbackEntry> getSubmissionHistory();
    FeedbackEntry getSubmission(const std::string& id);
    
    void setApiEndpoint(const std::string& endpoint);
    void setApiKey(const std::string& key);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

private:
    FeedbackManager();
    ~FeedbackManager();
    FeedbackManager(const FeedbackManager&) = delete;
    FeedbackManager& operator=(const FeedbackManager&) = delete;
<<<<<<< HEAD

    void loadSettings();
    void saveSettings();

=======
    
    void loadSettings();
    void saveSettings();
    anyMap collectSystemInfo();
    
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    TelemetryConsent m_consent;
    std::string m_apiEndpoint;
    std::string m_apiKey;
    std::string m_settingsPath;
<<<<<<< HEAD

=======
    
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    std::vector<FeedbackEntry> m_drafts;
    std::vector<FeedbackEntry> m_history;
};

} // namespace rawrxd::feedback
<<<<<<< HEAD
=======

>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
