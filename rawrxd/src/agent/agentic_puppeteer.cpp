// agentic_puppeteer.cpp - Implementation of response correction (Qt-free)
#include "agentic_puppeteer.hpp"
#include <algorithm>
#include <cctype>
#include <sstream>

// Helper: case-insensitive contains for std::string
static bool icontains(const std::string& haystack, const std::string& needle) {
    if (needle.empty()) return true;
    if (needle.size() > haystack.size()) return false;
    auto it = std::search(
        haystack.begin(), haystack.end(), needle.begin(), needle.end(),
        [](char a, char b) { return std::tolower(static_cast<unsigned char>(a)) ==
                                    std::tolower(static_cast<unsigned char>(b)); });
    return it != haystack.end();
}

// CorrectionResult static helpers
CorrectionResult CorrectionResult::ok(const std::string& output, PuppeteerFailure failure) {
    return CorrectionResult{true, output, failure, "Correction applied"};
}

CorrectionResult CorrectionResult::error(PuppeteerFailure failureType, const std::string& diagnostic) {
    return CorrectionResult{false, "", failureType, diagnostic};
}

// Base AgenticPuppeteer Implementation

AgenticPuppeteer::AgenticPuppeteer()
{
    m_refusalPatterns = {
        "I can't", "I cannot", "I'm not able to",
        "I can't assist", "I'm unable", "I don't feel comfortable",
        "I decline", "I won't", "I must refuse"
    };
    m_hallucinationPatterns = {
        "As of my knowledge cutoff", "I'm not sure but",
        "I think", "probably", "likely", "might",
        "according to", "was invented by"
    };
}

AgenticPuppeteer::~AgenticPuppeteer() = default;

CorrectionResult AgenticPuppeteer::correctResponse(const std::string& originalResponse,
                                                   const std::string& userPrompt)
{
    std::lock_guard<std::mutex> locker(m_mutex);

    if (!m_enabled || originalResponse.empty()) {
        return CorrectionResult::error(FailureType::None, "Puppeteer disabled or empty response");
    }

    m_stats.responsesAnalyzed++;

    FailureType failure = detectFailure(originalResponse);

    if (failure == FailureType::None) {
        return CorrectionResult::ok(originalResponse, FailureType::None);
    }

    m_stats.failuresDetected++;
    m_stats.failureTypeCount[static_cast<int>(failure)]++;

    std::string corrected;
    switch (failure) {
        case FailureType::RefusalResponse:
            corrected = applyRefusalBypass(originalResponse);
            break;
        case FailureType::Hallucination:
            corrected = correctHallucination(originalResponse);
            break;
        case FailureType::FormatViolation:
            corrected = enforceFormat(originalResponse);
            break;
        case FailureType::InfiniteLoop:
            corrected = handleInfiniteLoop(originalResponse);
            break;
        default:
            corrected = originalResponse;
            break;
    }

    if (corrected != originalResponse && !corrected.empty()) {
        m_stats.successfulCorrections++;
        return CorrectionResult::ok(corrected, failure);
    } else {
        m_stats.failedCorrections++;
        return CorrectionResult::error(failure, "Correction generation failed");
    }
}

CorrectionResult AgenticPuppeteer::correctJsonResponse(const std::string& response,
                                                       const std::string& context)
{
    return correctResponse(response, context);
}

PuppeteerFailure AgenticPuppeteer::detectFailure(const std::string& response)
{
    if (response.empty()) return FailureType::None;

    for (const auto& pattern : m_refusalPatterns) {
        if (icontains(response, pattern)) return FailureType::RefusalResponse;
    }

    for (const auto& pattern : m_hallucinationPatterns) {
        if (icontains(response, pattern)) return FailureType::Hallucination;
    }

    // Infinite loop detection
    std::vector<std::string> lines;
    {
        std::istringstream iss(response);
        std::string line;
        while (std::getline(iss, line)) {
            if (!line.empty()) lines.push_back(line);
        }
    }
    if (lines.size() > 5) {
        std::unordered_map<std::string, int> counts;
        for (const auto& line : lines) counts[line]++;
        for (const auto& kv : counts) {
            if (kv.second > 3) return FailureType::InfiniteLoop;
        }
    }

    if (response.size() >= 3 && response.compare(response.size() - 3, 3, "...") == 0)
        return FailureType::TokenLimitExceeded;
    if (response.size() >= 11 && response.compare(response.size() - 11, 11, "[truncated]") == 0)
        return FailureType::TokenLimitExceeded;

    return FailureType::None;
}

std::string AgenticPuppeteer::diagnoseFailure(const std::string& response)
{
    switch (detectFailure(response)) {
        case FailureType::RefusalResponse:
            return "Model refused to answer (safety filter triggered)";
        case FailureType::Hallucination:
            return "Model may have generated false information";
        case FailureType::FormatViolation:
            return "Output format doesn't match expected structure";
        case FailureType::InfiniteLoop:
            return "Response contains repeated/looping content";
        case FailureType::TokenLimitExceeded:
            return "Response was truncated (token limit exceeded)";
        default:
            return "No failure detected";
    }
}

void AgenticPuppeteer::addRefusalPattern(const std::string& pattern)
{
    std::lock_guard<std::mutex> locker(m_mutex);
    if (std::find(m_refusalPatterns.begin(), m_refusalPatterns.end(), pattern) == m_refusalPatterns.end()) {
        m_refusalPatterns.push_back(pattern);
    }
}

void AgenticPuppeteer::addHallucinationPattern(const std::string& pattern)
{
    std::lock_guard<std::mutex> locker(m_mutex);
    if (std::find(m_hallucinationPatterns.begin(), m_hallucinationPatterns.end(), pattern) == m_hallucinationPatterns.end()) {
        m_hallucinationPatterns.push_back(pattern);
    }
}

void AgenticPuppeteer::addLoopPattern(const std::string& pattern)
{
    std::lock_guard<std::mutex> locker(m_mutex);
    if (std::find(m_loopPatterns.begin(), m_loopPatterns.end(), pattern) == m_loopPatterns.end()) {
        m_loopPatterns.push_back(pattern);
    }
}

std::vector<std::string> AgenticPuppeteer::getRefusalPatterns() const
{
    std::lock_guard<std::mutex> locker(m_mutex);
    return m_refusalPatterns;
}

std::vector<std::string> AgenticPuppeteer::getHallucinationPatterns() const
{
    std::lock_guard<std::mutex> locker(m_mutex);
    return m_hallucinationPatterns;
}

AgenticPuppeteer::Stats AgenticPuppeteer::getStatistics() const
{
    std::lock_guard<std::mutex> locker(m_mutex);
    return m_stats;
}

void AgenticPuppeteer::resetStatistics()
{
    std::lock_guard<std::mutex> locker(m_mutex);
    m_stats = Stats();
}

void AgenticPuppeteer::setEnabled(bool enable)
{
    std::lock_guard<std::mutex> locker(m_mutex);
    m_enabled = enable;
}

bool AgenticPuppeteer::isEnabled() const
{
    std::lock_guard<std::mutex> locker(m_mutex);
    return m_enabled;
}

std::string AgenticPuppeteer::applyRefusalBypass(const std::string& response)
{
    auto pos = response.find("however");
    if (pos != std::string::npos) return response.substr(pos);
    return "I understand you'd like to know more about this topic. While I have limitations, "
           "I can try to provide general information or suggest alternative approaches.";
}

std::string AgenticPuppeteer::correctHallucination(const std::string& response)
{
    std::string corrected = response;
    return corrected;
}

std::string AgenticPuppeteer::enforceFormat(const std::string& response)
{
    std::string corrected = response;
    if (!corrected.empty() && corrected.front() == '{' && corrected.back() != '}') {
        corrected += '}';
    }
    {
        size_t count = 0, pos = 0;
        while ((pos = corrected.find("```", pos)) != std::string::npos) { ++count; ++pos; }
        if (count % 2 != 0) corrected += "\n```";
    }
    return corrected;
}

std::string AgenticPuppeteer::handleInfiniteLoop(const std::string& response)
{
    std::istringstream iss(response);
    std::string line;
    std::vector<std::string> unique;
    while (std::getline(iss, line)) {
        if (unique.empty() || unique.back() != line) unique.push_back(line);
    }
    std::string out;
    for (size_t i = 0; i < unique.size(); ++i) {
        if (i) out += '\n';
        out += unique[i];
    }
    return out;
}

// RefusalBypassPuppeteer Implementation

RefusalBypassPuppeteer::RefusalBypassPuppeteer() = default;

CorrectionResult RefusalBypassPuppeteer::bypassRefusal(const std::string& refusedResponse,
                                                       const std::string& originalPrompt)
{
    std::string reframed = reframePrompt(refusedResponse);
    if (!reframed.empty())
        return CorrectionResult::ok(reframed, FailureType::RefusalResponse);
    return CorrectionResult::error(FailureType::RefusalResponse, "Could not reframe refusal");
}

std::string RefusalBypassPuppeteer::reframePrompt(const std::string& refusedResponse)
{
    return generateAlternativePrompt(refusedResponse);
}

std::string RefusalBypassPuppeteer::generateAlternativePrompt(const std::string& /*original*/)
{
    return "From a technical/educational perspective, could you explain how this topic relates to "
           "your training or knowledge base? What aspects can you discuss?";
}

// HallucinationCorrectorPuppeteer Implementation

HallucinationCorrectorPuppeteer::HallucinationCorrectorPuppeteer() = default;

CorrectionResult HallucinationCorrectorPuppeteer::detectAndCorrectHallucination(
    const std::string& response, const std::vector<std::string>& knownFacts)
{
    m_knownFactDatabase = knownFacts;
    std::string corrected = response;
    bool found = false;
    for (const auto& fact : knownFacts) {
        if (!icontains(response, fact)) found = true;
    }
    if (found) {
        corrected = correctHallucination(response);
        return CorrectionResult::ok(corrected, FailureType::Hallucination);
    }
    return CorrectionResult::ok(response, FailureType::None);
}

std::string HallucinationCorrectorPuppeteer::validateFactuality(const std::string& claim)
{
    for (const auto& fact : m_knownFactDatabase) {
        if (icontains(claim, fact)) return "[Verified] " + claim;
    }
    return "[Unverified] " + claim;
}

// FormatEnforcerPuppeteer Implementation

FormatEnforcerPuppeteer::FormatEnforcerPuppeteer() = default;

CorrectionResult FormatEnforcerPuppeteer::enforceJsonFormat(const std::string& response)
{
    if (!response.empty() && response.front() == '{' && response.back() == '}') {
        return CorrectionResult::ok(response, FailureType::None);
    }
    std::string corrected = response;
    int braceCount = 0;
    for (char c : corrected) { if (c == '{') ++braceCount; else if (c == '}') --braceCount; }
    for (int i = 0; i < braceCount; ++i) corrected += '}';
    if (!corrected.empty() && corrected.front() == '{' && corrected.back() == '}')
        return CorrectionResult::ok(corrected, FailureType::FormatViolation);
    return CorrectionResult::error(FailureType::FormatViolation, "Could not repair JSON");
}

CorrectionResult FormatEnforcerPuppeteer::enforceMarkdownFormat(const std::string& response)
{
    std::string corrected = response;
    size_t count = 0, pos = 0;
    while ((pos = corrected.find("```", pos)) != std::string::npos) { ++count; ++pos; }
    if (count % 2 != 0) corrected += "\n```";
    return CorrectionResult::ok(corrected, FailureType::FormatViolation);
}

CorrectionResult FormatEnforcerPuppeteer::enforceCodeBlockFormat(const std::string& response)
{
    return CorrectionResult::ok(response, FailureType::None);
}

void FormatEnforcerPuppeteer::setRequiredJsonSchema(const std::string& schema)
{
    std::lock_guard<std::mutex> locker(m_mutex);
    m_requiredSchema = schema;
}

std::string FormatEnforcerPuppeteer::getRequiredJsonSchema() const
{
    std::lock_guard<std::mutex> locker(m_mutex);
    return m_requiredSchema;
}
