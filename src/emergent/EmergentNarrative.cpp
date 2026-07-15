/**
 * EmergentNarrative.cpp
 *
 * Phase C.2 Batch 5/5: Emergent Narrative Layer Implementation
 */

#include "EmergentNarrative.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <numeric>
#include <random>
#include <fstream>
#include <chrono>

namespace Emergent {

// NarrativeElement implementation
std::string NarrativeElement::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"elementId\":\"" << elementId << "\",";
    json << "\"type\":" << static_cast<int>(type) << ",";
    json << "\"timestamp\":\"" << timestamp << "\",";
    json << "\"title\":\"" << title << "\",";
    json << "\"description\":\"" << description << "\",";
    json << "\"naturalLanguage\":\"" << naturalLanguage << "\",";
    json << "\"importance\":" << std::fixed << std::setprecision(4) << importance << ",";
    json << "\"confidence\":" << confidence << ",";
    json << "\"isKeyEvent\":" << (isKeyEvent ? "true" : "false") << ",";
    json << "\"causalParent\":\"" << causalParent << "\",";
    json << "\"relatedElements\":[";
    for (size_t i = 0; i < relatedElements.size(); ++i) {
        if (i > 0) json << ",";
        json << "\"" << relatedElements[i] << "\"";
    }
    json << "]}";
    return json.str();
}

std::string NarrativeElement::ToNaturalLanguage() const {
    return naturalLanguage;
}

// CausalChain implementation
std::string CausalChain::ToNaturalLanguage() const {
    std::ostringstream nl;
    nl << "The effect '" << effect << "' was caused by: ";
    for (size_t i = 0; i < causes.size(); ++i) {
        if (i > 0) nl << (i == causes.size() - 1 ? ", and ultimately by " : ", which was caused by ");
        nl << "'" << causes[i] << "'";
    }
    nl << ". The root cause was '" << rootCause << "'.";
    return nl.str();
}

// SystemNarrative implementation
std::string SystemNarrative::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"narrativeId\":\"" << narrativeId << "\",";
    json << "\"title\":\"" << title << "\",";
    json << "\"summary\":\"" << summary << "\",";
    json << "\"startTimeMs\":" << startTimeMs << ",";
    json << "\"endTimeMs\":" << endTimeMs << ",";
    json << "\"eventCount\":" << eventCount << ",";
    json << "\"decisionCount\":" << decisionCount << ",";
    json << "\"correctionCount\":" << correctionCount << ",";
    json << "\"averageConfidence\":" << averageConfidence << ",";
    json << "\"themes\":[";
    for (size_t i = 0; i < themes.size(); ++i) {
        if (i > 0) json << ",";
        json << "\"" << themes[i] << "\"";
    }
    json << "],";
    json << "\"elements\":[";
    for (size_t i = 0; i < elements.size(); ++i) {
        if (i > 0) json << ",";
        json << elements[i].ToJson();
    }
    json << "]}";
    return json.str();
}

std::string SystemNarrative::ToMarkdown() const {
    std::ostringstream md;
    md << "# " << title << "\n\n";
    md << "**Narrative ID:** " << narrativeId << "\n\n";
    md << "**Period:** " << FormatTimestamp(startTimeMs) << " to " << FormatTimestamp(endTimeMs) << "\n\n";
    md << "## Summary\n\n";
    md << summary << "\n\n";
    md << "## Statistics\n\n";
    md << "- **Events:** " << eventCount << "\n";
    md << "- **Decisions:** " << decisionCount << "\n";
    md << "- **Corrections:** " << correctionCount << "\n";
    md << "- **Average Confidence:** " << std::fixed << std::setprecision(2) << (averageConfidence * 100) << "%\n\n";
    md << "## Themes\n\n";
    for (const auto& theme : themes) {
        md << "- " << theme << "\n";
    }
    md << "\n## Key Events\n\n";
    for (const auto& element : elements) {
        if (element.isKeyEvent) {
            md << "### " << element.title << "\n\n";
            md << element.naturalLanguage << "\n\n";
        }
    }
    return md.str();
}

void SystemNarrative::PrintSummary() const {
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║           EMERGENT NARRATIVE                                     ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Title: " << std::left << std::setw(52) << title << " ║\n";
    std::cout << "║  Period: " << std::setw(52) << (FormatTimestamp(startTimeMs) + " to " + FormatTimestamp(endTimeMs)) << " ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Summary:                                                        ║\n";
    // Wrap summary text
    std::string wrapped = summary;
    size_t pos = 0;
    while (pos < wrapped.length()) {
        std::string line = wrapped.substr(pos, 60);
        std::cout << "║  " << std::left << std::setw(60) << line << " ║\n";
        pos += 60;
    }
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Statistics:                                                   ║\n";
    std::cout << "║    Events:      " << std::setw(10) << eventCount << std::string(36, ' ') << "║\n";
    std::cout << "║    Decisions:   " << std::setw(10) << decisionCount << std::string(36, ' ') << "║\n";
    std::cout << "║    Corrections: " << std::setw(10) << correctionCount << std::string(36, ' ') << "║\n";
    std::cout << "║    Confidence:  " << std::setw(10) << std::fixed << std::setprecision(1) << (averageConfidence * 100) << "%" << std::string(35, ' ') << "║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Themes:                                                       ║\n";
    for (const auto& theme : themes) {
        std::cout << "║    - " << std::left << std::setw(55) << theme << " ║\n";
    }
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Key Events:                                                     ║\n";
    int keyCount = 0;
    for (const auto& element : elements) {
        if (element.isKeyEvent && keyCount < 3) {
            std::cout << "║    " << std::left << std::setw(15) << element.timestamp << ": " 
                      << std::setw(42) << element.title << " ║\n";
            keyCount++;
        }
    }
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
}

std::string SystemNarrative::FormatTimestamp(int64_t ms) const {
    auto time = std::chrono::system_clock::time_point(std::chrono::milliseconds(ms));
    auto time_t = std::chrono::system_clock::to_time_t(time);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%H:%M:%S");
    return ss.str();
}

// EmergentNarrative implementation
EmergentNarrative::EmergentNarrative() = default;
EmergentNarrative::~EmergentNarrative() = default;

bool EmergentNarrative::Initialize(const NarrativeConfig& config) {
    config_ = config;
    eventHistory_.clear();
    currentNarrative_ = SystemNarrative{};
    std::cout << "[EmergentNarrative] Initialized\n";
    return true;
}

void EmergentNarrative::FeedEvent(const SystemEvent& event) {
    eventHistory_.push_back(event);
}

void EmergentNarrative::FeedEvents(const std::vector<SystemEvent>& events) {
    for (const auto& event : events) {
        FeedEvent(event);
    }
}

SystemNarrative EmergentNarrative::GenerateNarrative() {
    if (eventHistory_.empty()) {
        return SystemNarrative{};
    }
    
    SystemNarrative narrative;
    narrative.narrativeId = GenerateNarrativeId();
    narrative.startTimeMs = eventHistory_.front().timestampMs;
    narrative.endTimeMs = eventHistory_.back().timestampMs;
    
    // Generate elements from events
    narrative.elements = GenerateElements(eventHistory_);
    
    // Generate causal chains
    narrative.causalChains = GenerateCausalChains(narrative.elements);
    
    // Extract themes
    auto themeStrengths = ExtractThemes(narrative.elements);
    for (const auto& [theme, strength] : themeStrengths) {
        if (strength >= config_.minThemeStrength) {
            narrative.themes.push_back(theme);
            narrative.themeStrengths[theme] = strength;
        }
    }
    
    // Calculate statistics
    narrative.eventCount = static_cast<int>(eventHistory_.size());
    narrative.decisionCount = 0;
    narrative.correctionCount = 0;
    double totalConfidence = 0.0;
    
    for (const auto& element : narrative.elements) {
        if (element.type == NarrativeElementType::DECISION) narrative.decisionCount++;
        if (element.type == NarrativeElementType::CORRECTION) narrative.correctionCount++;
        totalConfidence += element.confidence;
    }
    
    narrative.averageConfidence = narrative.elements.empty() ? 0.0 : totalConfidence / narrative.elements.size();
    
    // Generate title and summary
    narrative.title = "System Narrative: " + std::to_string(narrative.eventCount) + " Events";
    narrative.summary = GenerateSummary(narrative);
    
    currentNarrative_ = narrative;
    
    std::cout << "[EmergentNarrative] Generated narrative with " << narrative.elements.size() << " elements\n";
    
    return narrative;
}

std::vector<NarrativeElement> EmergentNarrative::GenerateElements(const std::vector<SystemEvent>& events) {
    std::vector<NarrativeElement> elements;
    
    for (const auto& event : events) {
        if (event.significance < config_.minImportanceForNarrative) continue;
        
        NarrativeElement element;
        element.elementId = GenerateElementId();
        element.type = ClassifyEvent(event);
        element.timestamp = FormatTimestamp(event.timestampMs);
        element.title = event.eventType;
        element.description = event.description;
        element.importance = event.significance;
        element.confidence = 0.8 + (0.2 * event.significance);
        element.isKeyEvent = event.significance > 0.8;
        element.naturalLanguage = GenerateNaturalLanguage(element);
        
        // Add context
        for (const auto& [key, value] : event.attributes) {
            element.context[key] = value;
        }
        
        elements.push_back(element);
    }
    
    // Link related elements
    for (size_t i = 0; i < elements.size(); ++i) {
        for (size_t j = i + 1; j < elements.size(); ++j) {
            if (CalculateThematicSimilarity(elements[i], elements[j]) > 0.7) {
                elements[i].relatedElements.push_back(elements[j].elementId);
                elements[j].relatedElements.push_back(elements[i].elementId);
            }
        }
    }
    
    return elements;
}

std::vector<CausalChain> EmergentNarrative::GenerateCausalChains(const std::vector<NarrativeElement>& elements) {
    std::vector<CausalChain> chains;
    
    // Find elements that look like effects (corrections, decisions)
    for (const auto& effect : elements) {
        if (effect.type == NarrativeElementType::CORRECTION || 
            effect.type == NarrativeElementType::DECISION) {
            
            CausalChain chain;
            chain.chainId = GenerateChainId();
            chain.effect = effect.title;
            chain.causes = FindCauses(effect, elements);
            chain.rootCause = chain.causes.empty() ? "unknown" : chain.causes.back();
            chain.explanationConfidence = effect.confidence;
            
            if (!chain.causes.empty()) {
                chains.push_back(chain);
            }
        }
    }
    
    return chains;
}

std::string EmergentNarrative::GenerateSummary(const SystemNarrative& narrative) {
    std::ostringstream summary;
    summary << "During this period, the system processed " << narrative.eventCount 
            << " events and made " << narrative.decisionCount << " decisions. ";
    
    if (narrative.correctionCount > 0) {
        summary << "It applied " << narrative.correctionCount << " self-corrections to maintain stability. ";
    }
    
    if (!narrative.themes.empty()) {
        summary << "Key themes included: ";
        for (size_t i = 0; i < std::min(narrative.themes.size(), size_t(3)); ++i) {
            if (i > 0) summary << (i == narrative.themes.size() - 1 ? " and " : ", ");
            summary << narrative.themes[i];
        }
        summary << ".";
    }
    
    return summary.str();
}

std::map<std::string, double> EmergentNarrative::ExtractThemes(const std::vector<NarrativeElement>& elements) {
    std::map<std::string, double> themes;
    
    // Simple theme extraction based on element types
    for (const auto& element : elements) {
        std::string theme;
        switch (element.type) {
            case NarrativeElementType::ACTION: theme = "action"; break;
            case NarrativeElementType::DECISION: theme = "decision-making"; break;
            case NarrativeElementType::OBSERVATION: theme = "observation"; break;
            case NarrativeElementType::CORRECTION: theme = "self-correction"; break;
            case NarrativeElementType::GOAL_FORMATION: theme = "goal-formation"; break;
            default: theme = "general"; break;
        }
        themes[theme] += element.importance;
    }
    
    // Normalize
    double total = 0.0;
    for (const auto& [theme, strength] : themes) {
        total += strength;
    }
    if (total > 0) {
        for (auto& [theme, strength] : themes) {
            strength /= total;
        }
    }
    
    return themes;
}

std::string EmergentNarrative::ExplainDecision(const std::string& decisionId) {
    for (const auto& element : currentNarrative_.elements) {
        if (element.elementId == decisionId && element.type == NarrativeElementType::DECISION) {
            return "The decision '" + element.title + "' was made because: " + element.description;
        }
    }
    return "Decision not found in narrative.";
}

std::string EmergentNarrative::ExplainPattern(const std::string& patternId) {
    return "Pattern explanation would analyze the narrative elements related to pattern " + patternId;
}

std::string EmergentNarrative::PredictNextEvents(int count) {
    std::ostringstream prediction;
    prediction << "Based on the current narrative trajectory, the next " << count 
               << " events are likely to involve: ";
    
    // Simple prediction based on recent themes
    if (!currentNarrative_.themes.empty()) {
        for (size_t i = 0; i < std::min(currentNarrative_.themes.size(), size_t(count)); ++i) {
            if (i > 0) prediction << ", ";
            prediction << currentNarrative_.themes[i];
        }
    }
    prediction << ".";
    
    return prediction.str();
}

bool EmergentNarrative::SaveNarrative(const std::string& path) const {
    std::ofstream file(path);
    if (!file.is_open()) return false;
    file << currentNarrative_.ToJson();
    return true;
}

bool EmergentNarrative::LoadNarrative(const std::string& path) {
    // Simplified load
    return false;
}

// Helper methods
NarrativeElementType EmergentNarrative::ClassifyEvent(const SystemEvent& event) {
    if (event.eventType.find("decision") != std::string::npos) {
        return NarrativeElementType::DECISION;
    } else if (event.eventType.find("correction") != std::string::npos) {
        return NarrativeElementType::CORRECTION;
    } else if (event.eventType.find("pattern") != std::string::npos) {
        return NarrativeElementType::OBSERVATION;
    } else if (event.eventType.find("goal") != std::string::npos) {
        return NarrativeElementType::GOAL_FORMATION;
    } else if (event.eventType.find("action") != std::string::npos) {
        return NarrativeElementType::ACTION;
    } else {
        return NarrativeElementType::EVENT;
    }
}

std::string EmergentNarrative::GenerateNaturalLanguage(const NarrativeElement& element) {
    std::ostringstream nl;
    
    switch (element.type) {
        case NarrativeElementType::EVENT:
            nl << "At " << element.timestamp << ", " << element.description;
            break;
        case NarrativeElementType::ACTION:
            nl << "The system took action: " << element.title << ". " << element.description;
            break;
        case NarrativeElementType::DECISION:
            nl << "The system decided to " << element.title << " because " << element.description;
            break;
        case NarrativeElementType::OBSERVATION:
            nl << "The system observed: " << element.description;
            break;
        case NarrativeElementType::CORRECTION:
            nl << "The system self-corrected by " << element.title << " to address " << element.description;
            break;
        case NarrativeElementType::GOAL_FORMATION:
            nl << "The system formed the goal: " << element.title;
            break;
        default:
            nl << element.description;
            break;
    }
    
    return nl.str();
}

std::vector<std::string> EmergentNarrative::FindCauses(const NarrativeElement& effect, 
                                                        const std::vector<NarrativeElement>& candidates) {
    std::vector<std::string> causes;
    
    // Simple causal inference: look for elements before this one that are related
    for (const auto& candidate : candidates) {
        if (candidate.elementId == effect.elementId) continue;
        
        // Check if candidate is in related elements
        for (const auto& related : effect.relatedElements) {
            if (candidate.elementId == related) {
                causes.push_back(candidate.title);
                break;
            }
        }
        
        if (causes.size() >= static_cast<size_t>(config_.maxCausalDepth)) break;
    }
    
    return causes;
}

double EmergentNarrative::CalculateThematicSimilarity(const NarrativeElement& a, const NarrativeElement& b) {
    if (a.type == b.type) return 0.8;
    
    // Check context overlap
    int sharedContext = 0;
    for (const auto& [key, val] : a.context) {
        auto it = b.context.find(key);
        if (it != b.context.end() && it->second == val) {
            sharedContext++;
        }
    }
    
    double contextSimilarity = a.context.empty() ? 0.0 : 
                               static_cast<double>(sharedContext) / a.context.size();
    
    return contextSimilarity * 0.5;
}

std::string EmergentNarrative::GenerateElementId() const {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(1000, 9999);
    
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    
    std::ostringstream id;
    id << "elem-" << ms << "-" << dis(gen);
    return id.str();
}

std::string EmergentNarrative::GenerateChainId() const {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(1000, 9999);
    
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    
    std::ostringstream id;
    id << "chain-" << ms << "-" << dis(gen);
    return id.str();
}

std::string EmergentNarrative::GenerateNarrativeId() const {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(1000, 9999);
    
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    
    std::ostringstream id;
    id << "narr-" << ms << "-" << dis(gen);
    return id.str();
}

std::string EmergentNarrative::FormatTimestamp(int64_t ms) const {
    auto time = std::chrono::system_clock::time_point(std::chrono::milliseconds(ms));
    auto time_t = std::chrono::system_clock::to_time_t(time);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%H:%M:%S");
    return ss.str();
}

// CLI Implementation
void EmergentNarrativeCLI::PrintBanner() {
    std::cout << "╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                                                                ║\n";
    std::cout << "║     EMERGENT NARRATIVE - Phase C.2                             ║\n";
    std::cout << "║     System Self-Explanation & Story Generation                   ║\n";
    std::cout << "║                                                                ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n\n";
}

void EmergentNarrativeCLI::PrintUsage() {
    std::cout << "Usage: emergent-narrative [OPTIONS]\n\n";
    std::cout << "Options:\n";
    std::cout << "  --events N          Number of events to generate\n";
    std::cout << "  --min-importance X  Minimum importance threshold (0-1)\n";
    std::cout << "  --output PATH       Save narrative to file\n";
    std::cout << "  --markdown          Output as Markdown\n";
    std::cout << "  --json              Output as JSON\n";
    std::cout << "  --help              Show this help\n\n";
}

NarrativeConfig EmergentNarrativeCLI::ParseArgs(int argc, char* argv[]) {
    NarrativeConfig config;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "--min-importance" && i + 1 < argc) {
            config.minImportanceForNarrative = std::stod(argv[++i]);
        } else if (arg == "--help" || arg == "-h") {
            PrintUsage();
            exit(0);
        }
    }
    
    return config;
}

int EmergentNarrativeCLI::Run(int argc, char* argv[]) {
    PrintBanner();
    
    if (argc > 1 && (std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h")) {
        PrintUsage();
        return 0;
    }
    
    NarrativeConfig config = ParseArgs(argc, argv);
    
    // Create narrative generator
    EmergentNarrative narrative;
    narrative.Initialize(config);
    
    // Generate synthetic events
    std::cout << "[Demo] Generating synthetic system events...\n";
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> significanceDist(0.3, 1.0);
    
    std::vector<std::string> eventTypes = {
        "pattern_detected", "goal_formed", "action_taken", 
        "decision_made", "correction_applied", "observation_made"
    };
    
    auto baseTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    for (int i = 0; i < 20; ++i) {
        SystemEvent event;
        event.timestampMs = baseTime + (i * 5000);
        event.eventType = eventTypes[i % eventTypes.size()];
        event.description = "System " + event.eventType + " at cycle " + std::to_string(i);
        event.significance = significanceDist(gen);
        event.attributes["cycle"] = std::to_string(i);
        narrative.FeedEvent(event);
    }
    
    // Generate narrative
    std::cout << "[Demo] Generating narrative...\n";
    auto result = narrative.GenerateNarrative();
    
    // Print summary
    result.PrintSummary();
    
    // Check for output options
    bool outputMarkdown = false;
    std::string outputPath;
    
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--markdown") {
            outputMarkdown = true;
        } else if (std::string(argv[i]) == "--output" && i + 1 < argc) {
            outputPath = argv[i + 1];
        }
    }
    
    if (!outputPath.empty()) {
        if (outputMarkdown) {
            std::ofstream file(outputPath);
            if (file.is_open()) {
                file << result.ToMarkdown();
                std::cout << "Narrative saved to: " << outputPath << "\n";
            }
        } else {
            if (narrative.SaveNarrative(outputPath)) {
                std::cout << "Narrative saved to: " << outputPath << "\n";
            }
        }
    }
    
    // Output JSON if requested
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--json") {
            std::cout << "\n" << result.ToJson() << "\n";
        }
    }
    
    return 0;
}

} // namespace Emergent
