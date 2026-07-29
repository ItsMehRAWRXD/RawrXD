<<<<<<< HEAD
// agentic_puppeteer.hpp - Response correction via pattern matching (Qt-free)
=======
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
#pragma once

#include <string>
#include <vector>
#include <mutex>
<<<<<<< HEAD
#include <unordered_map>
#include <nlohmann/json.hpp>
#include <cstdint>
=======
#include <memory>
#include <algorithm>
#include <nlohmann/json.hpp>
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

enum class FailureType {
    RefusalResponse, Hallucination, FormatViolation, InfiniteLoop,
    TokenLimitExceeded, None
};

struct CorrectionResult {
    bool success = false;
    std::string correctedOutput;
<<<<<<< HEAD
    FailureType detectedFailure = FailureType::None;
    std::string diagnosticMessage;
    static CorrectionResult ok(const std::string& output, FailureType failure) {
        return CorrectionResult{true, output, failure, "Correction applied"};
    }
    static CorrectionResult error(FailureType failureType, const std::string& diagnostic) {
        return CorrectionResult{false, "", failureType, diagnostic};
    }
};

class AgenticPuppeteer {
public:
    AgenticPuppeteer();
    virtual ~AgenticPuppeteer();

    CorrectionResult correctResponse(const std::string& originalResponse, const std::string& userPrompt = "");
    CorrectionResult correctJsonResponse(const nlohmann::json& response, const std::string& context = "");
    FailureType detectFailure(const std::string& response);
    std::string diagnoseFailure(const std::string& response);
    void addRefusalPattern(const std::string& pattern);
    void addHallucinationPattern(const std::string& pattern);
    void addLoopPattern(const std::string& pattern);
    std::vector<std::string> getRefusalPatterns() const;
    std::vector<std::string> getHallucinationPatterns() const;

    struct Stats {
        int64_t responsesAnalyzed = 0;
        int64_t failuresDetected = 0;
        int64_t successfulCorrections = 0;
        int64_t failedCorrections = 0;
        std::unordered_map<int, int64_t> failureTypeCount;
    };

    Stats getStatistics() const;
    void resetStatistics();
    void setEnabled(bool enable);
    bool isEnabled() const;

    // Callbacks (replace Qt signals) — raw function pointers, no std::function
    void (*onFailureDetected)(FailureType type, const char* detail, void* ctx) = nullptr;
    void (*onCorrectionApplied)(const char* correctedOutput, void* ctx) = nullptr;
    void (*onCorrectionFailed)(FailureType type, const char* diagnostic, void* ctx) = nullptr;
    void* callbackContext = nullptr;  // Opaque user context for all callbacks

protected:
=======
    FailureType originalFailure = FailureType::None;
    std::string reason;

    static CorrectionResult ok(const std::string& output, FailureType fail) {
        CorrectionResult r;
        r.success = true;
        r.correctedOutput = output;
        r.originalFailure = fail;
        return r;
    }

    static CorrectionResult error(FailureType fail, const std::string& reason) {
        CorrectionResult r;
        r.success = false;
        r.originalFailure = fail;
        r.reason = reason;
        return r;
    }
};

struct PuppeteerStats {
    uint64_t responsesAnalyzed = 0;
    uint64_t failuresDetected = 0;
    std::vector<int> failureTypeCount = std::vector<int>(6, 0);
    uint64_t successfulCorrections = 0;
    uint64_t failedCorrections = 0;
};

class AgenticPuppeteer {
public:
    AgenticPuppeteer();
    ~AgenticPuppeteer();

    CorrectionResult correctResponse(const std::string& originalResponse, const std::string& userPrompt);
    CorrectionResult correctJsonResponse(const nlohmann::json& response, const std::string& context);
    
    // Setters
    void setEnabled(bool enabled) { m_enabled = enabled; }
    
    // Explicit Logic: Allow re-prompting via callback
    void setRepromptCallback(std::function<std::string(const std::string&)> callback) {
        m_repromptCallback = callback;
    }

private:
    std::function<std::string(const std::string&)> m_repromptCallback;
    
    FailureType detectFailure(const std::string& response);
    std::string diagnoseFailure(const std::string& response);
    
    // Correction strategies
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    std::string applyRefusalBypass(const std::string& response);
    std::string correctHallucination(const std::string& response);
    std::string enforceFormat(const std::string& response);
    std::string handleInfiniteLoop(const std::string& response);

<<<<<<< HEAD
    mutable std::mutex m_mutex;
    std::vector<std::string> m_refusalPatterns;
    std::vector<std::string> m_hallucinationPatterns;
    std::vector<std::string> m_loopPatterns;
    Stats m_stats;
    bool m_enabled = true;
};

class RefusalBypassPuppeteer : public AgenticPuppeteer {
public:
    RefusalBypassPuppeteer();
    CorrectionResult bypassRefusal(const std::string& refusedResponse, const std::string& originalPrompt);
    std::string reframePrompt(const std::string& refusedResponse);
private:
    std::string generateAlternativePrompt(const std::string& original);
};

class HallucinationCorrectorPuppeteer : public AgenticPuppeteer {
public:
    HallucinationCorrectorPuppeteer();
    CorrectionResult detectAndCorrectHallucination(const std::string& response, const std::vector<std::string>& knownFacts);
    std::string validateFactuality(const std::string& claim);
private:
    std::vector<std::string> m_knownFactDatabase;
};

class FormatEnforcerPuppeteer : public AgenticPuppeteer {
public:
    FormatEnforcerPuppeteer();
    CorrectionResult enforceJsonFormat(const std::string& response);
    CorrectionResult enforceMarkdownFormat(const std::string& response);
    CorrectionResult enforceCodeBlockFormat(const std::string& response);
    void setRequiredJsonSchema(const nlohmann::json& schema);
    nlohmann::json getRequiredJsonSchema() const;
private:
    nlohmann::json m_requiredSchema;
=======
    // Event Callbacks
    std::function<void(FailureType, const std::string&)> m_onFailureDetected;
    std::function<void(const std::string&)> m_onCorrectionApplied;
    std::function<void(FailureType, const std::string&)> m_onCorrectionFailed;

    void setFailureCallback(std::function<void(FailureType, const std::string&)> cb) { m_onFailureDetected = cb; }
    void setCorrectionCallback(std::function<void(const std::string&)> cb) { m_onCorrectionApplied = cb; }
    void setErrorCallback(std::function<void(FailureType, const std::string&)> cb) { m_onCorrectionFailed = cb; }

    // Internal notification implementations
    void failureDetected(FailureType type, const std::string& diagnosis);
    void correctionApplied(const std::string& corrected);
    void correctionFailed(FailureType type, const std::string& reason);

    bool m_enabled = true;
    mutable std::mutex m_mutex;
    PuppeteerStats m_stats;
    
    std::vector<std::string> m_refusalPatterns;
    std::vector<std::string> m_hallucinationPatterns;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
};
