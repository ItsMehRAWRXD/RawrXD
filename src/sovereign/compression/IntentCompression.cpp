// IntentCompression.cpp
// Implementation of the Intent Compression Protocol

#include "IntentCompression.hpp"
#include <cstring>
#include <chrono>

namespace Sovereign {

// IntentCompression constructor/destructor
IntentCompression::IntentCompression() = default;
IntentCompression::~IntentCompression() = default;

// IntentRouter constructor/destructor
IntentRouter::IntentRouter() = default;
IntentRouter::~IntentRouter() = default;

CompressedIntent IntentCompression::Compress(const FullIntent& intent) {
    CompressedIntent compressed{};
    compressed.version = 1;
    compressed.intent_type = static_cast<uint8_t>(intent.type);
    compressed.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    compressed.context_hash = HashContext(intent.original_prompt);
    
    // Truncate goal to fit
    std::string goal = intent.interpreted_goal;
    if (goal.length() > 63) goal = goal.substr(0, 63);
    std::strncpy(compressed.goal_summary, goal.c_str(), 63);
    compressed.goal_summary[63] = '\0';
    
    // Truncate target file to fit
    std::string target = intent.target_file;
    if (target.length() > 127) target = target.substr(0, 127);
    std::strncpy(compressed.target_file, target.c_str(), 127);
    compressed.target_file[127] = '\0';
    
    compressed.priority = intent.priority;
    compressed.complexity = EstimateComplexity(intent);
    compressed.evidence_count = static_cast<uint16_t>(intent.evidence.size());
    compressed.blocker_count = static_cast<uint16_t>(intent.blockers.size());
    compressed.flags = 0;
    
    return compressed;
}

FullIntent IntentCompression::Decompress(const CompressedIntent& compressed) {
    FullIntent intent;
    intent.type = static_cast<IntentType>(compressed.intent_type);
    intent.interpreted_goal = compressed.goal_summary;
    intent.priority = compressed.priority;
    
    if (compressed.target_file[0] != '\0') {
        intent.target_file = std::string(compressed.target_file);
    }
    
    return intent;
}

std::vector<uint8_t> IntentCompression::Serialize(const CompressedIntent& compressed) {
    std::vector<uint8_t> result;
    result.resize(sizeof(CompressedIntent));
    std::memcpy(result.data(), &compressed, sizeof(CompressedIntent));
    return result;
}

CompressedIntent IntentCompression::Deserialize(const std::vector<uint8_t>& data) {
    CompressedIntent compressed{};
    if (data.size() >= sizeof(CompressedIntent)) {
        std::memcpy(&compressed, data.data(), sizeof(CompressedIntent));
    }
    return compressed;
}

uint64_t IntentCompression::HashContext(const std::string& context) {
    // Simple FNV-1a hash
    const uint64_t FNV_OFFSET_BASIS = 14695981039346656037ULL;
    const uint64_t FNV_PRIME = 1099511628211ULL;
    
    uint64_t hash = FNV_OFFSET_BASIS;
    
    for (char c : context) {
        hash ^= static_cast<uint64_t>(c);
        hash *= FNV_PRIME;
    }
    
    return hash;
}

uint32_t IntentCompression::EstimateComplexity(const FullIntent& intent) {
    // Simple complexity estimation based on evidence and blockers
    uint32_t complexity = 1;
    complexity += static_cast<uint32_t>(intent.evidence.size());
    complexity += static_cast<uint32_t>(intent.blockers.size()) * 2;
    return complexity;
}

IntentType IntentCompression::Classify(const std::string& prompt) {
    std::string lower;
    for (char c : prompt) {
        lower += static_cast<char>(std::tolower(c));
    }
    
    if (lower.find("edit") != std::string::npos) return IntentType::FILE_EDIT;
    if (lower.find("create") != std::string::npos) return IntentType::FILE_CREATE;
    if (lower.find("delete") != std::string::npos) return IntentType::FILE_DELETE;
    if (lower.find("build") != std::string::npos) return IntentType::BUILD_REQUEST;
    if (lower.find("terminal") != std::string::npos) return IntentType::TERMINAL_COMMAND;
    if (lower.find("search") != std::string::npos) return IntentType::SEARCH_SYMBOL;
    if (lower.find("refactor") != std::string::npos) return IntentType::REFACTOR_RENAME;
    if (lower.find("debug") != std::string::npos) return IntentType::DEBUG_START;
    if (lower.find("agent") != std::string::npos) return IntentType::AGENT_SPAWN;
    
    return IntentType::CHAT_MESSAGE;
}

std::vector<IntentType> IntentCompression::ClassifyMulti(const std::string& prompt) {
    std::vector<IntentType> types;
    types.push_back(Classify(prompt));
    return types;
}

std::vector<EvidenceItem> IntentCompression::ExtractEvidence(const std::string& context) {
    std::vector<EvidenceItem> evidence;
    // Simplified extraction
    return evidence;
}

std::vector<Blocker> IntentCompression::ExtractBlockers(const std::string& context) {
    std::vector<Blocker> blockers;
    // Simplified extraction
    return blockers;
}

float IntentCompression::CalculateSimilarity(const CompressedIntent& a, const CompressedIntent& b) {
    // Simple similarity based on type and hash
    if (a.intent_type != b.intent_type) return 0.0f;
    if (a.context_hash == b.context_hash) return 1.0f;
    return 0.5f;
}

std::vector<FullIntent> IntentCompression::FindSimilar(const CompressedIntent& query, size_t limit) {
    std::vector<FullIntent> results;
    (void)query;
    (void)limit;
    return results;
}

std::string IntentCompression::StoreIntent(const FullIntent& intent) {
    std::string id = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    intent_store_[id] = intent;
    return id;
}

std::optional<FullIntent> IntentCompression::RetrieveIntent(const std::string& intent_id) {
    auto it = intent_store_.find(intent_id);
    if (it != intent_store_.end()) {
        return it->second;
    }
    return std::nullopt;
}

IntentCompression::CompressionStats IntentCompression::GetStats() const {
    return stats_;
}

// Global instance
IntentCompression& IntentCompression::Instance() {
    static IntentCompression instance;
    return instance;
}

// IntentRouter implementation
IntentRouter& IntentRouter::Instance() {
    static IntentRouter instance;
    return instance;
}

void IntentRouter::RegisterHandler(IntentType type, IntentHandler handler) {
    handlers_[type] = handler;
}

void IntentRouter::RegisterDefaultHandler(IntentHandler handler) {
    default_handler_ = handler;
}

void IntentRouter::Route(const CompressedIntent& compressed) {
    auto it = handlers_.find(static_cast<IntentType>(compressed.intent_type));
    if (it != handlers_.end()) {
        FullIntent intent = IntentCompression::Instance().Decompress(compressed);
        it->second(compressed, intent);
    } else if (default_handler_) {
        FullIntent intent = IntentCompression::Instance().Decompress(compressed);
        default_handler_(compressed, intent);
    }
}

void IntentRouter::Route(const FullIntent& intent) {
    auto it = handlers_.find(intent.type);
    if (it != handlers_.end()) {
        CompressedIntent compressed = IntentCompression::Instance().Compress(intent);
        it->second(compressed, intent);
    } else if (default_handler_) {
        CompressedIntent compressed = IntentCompression::Instance().Compress(intent);
        default_handler_(compressed, intent);
    }
}

void IntentRouter::RouteBatch(const std::vector<CompressedIntent>& intents) {
    for (const auto& intent : intents) {
        Route(intent);
    }
}

bool IntentRouter::HasHandler(IntentType type) const {
    return handlers_.find(type) != handlers_.end();
}

std::vector<IntentType> IntentRouter::GetHandledTypes() const {
    std::vector<IntentType> types;
    for (const auto& [type, _] : handlers_) {
        types.push_back(type);
    }
    return types;
}

// Helper functions
const char* IntentTypeToString(IntentType type) {
    switch (type) {
        case IntentType::UNKNOWN: return "UNKNOWN";
        case IntentType::FILE_EDIT: return "FILE_EDIT";
        case IntentType::FILE_CREATE: return "FILE_CREATE";
        case IntentType::FILE_DELETE: return "FILE_DELETE";
        case IntentType::FILE_READ: return "FILE_READ";
        case IntentType::BUILD_REQUEST: return "BUILD_REQUEST";
        case IntentType::BUILD_CANCEL: return "BUILD_CANCEL";
        case IntentType::TERMINAL_COMMAND: return "TERMINAL_COMMAND";
        case IntentType::TERMINAL_KILL: return "TERMINAL_KILL";
        case IntentType::SEARCH_SYMBOL: return "SEARCH_SYMBOL";
        case IntentType::SEARCH_REFERENCES: return "SEARCH_REFERENCES";
        case IntentType::REFACTOR_RENAME: return "REFACTOR_RENAME";
        case IntentType::REFACTOR_EXTRACT: return "REFACTOR_EXTRACT";
        case IntentType::DEBUG_START: return "DEBUG_START";
        case IntentType::DEBUG_BREAKPOINT: return "DEBUG_BREAKPOINT";
        case IntentType::DEBUG_STEP: return "DEBUG_STEP";
        case IntentType::AGENT_SPAWN: return "AGENT_SPAWN";
        case IntentType::AGENT_KILL: return "AGENT_KILL";
        case IntentType::SYSTEM_CONFIG: return "SYSTEM_CONFIG";
        case IntentType::CHAT_MESSAGE: return "CHAT_MESSAGE";
        case IntentType::CUSTOM: return "CUSTOM";
        default: return "UNKNOWN";
    }
}

IntentType IntentTypeFromString(const std::string& str) {
    if (str == "FILE_EDIT") return IntentType::FILE_EDIT;
    if (str == "FILE_CREATE") return IntentType::FILE_CREATE;
    if (str == "FILE_DELETE") return IntentType::FILE_DELETE;
    if (str == "FILE_READ") return IntentType::FILE_READ;
    if (str == "BUILD_REQUEST") return IntentType::BUILD_REQUEST;
    if (str == "BUILD_CANCEL") return IntentType::BUILD_CANCEL;
    if (str == "TERMINAL_COMMAND") return IntentType::TERMINAL_COMMAND;
    if (str == "TERMINAL_KILL") return IntentType::TERMINAL_KILL;
    if (str == "SEARCH_SYMBOL") return IntentType::SEARCH_SYMBOL;
    if (str == "SEARCH_REFERENCES") return IntentType::SEARCH_REFERENCES;
    if (str == "REFACTOR_RENAME") return IntentType::REFACTOR_RENAME;
    if (str == "REFACTOR_EXTRACT") return IntentType::REFACTOR_EXTRACT;
    if (str == "DEBUG_START") return IntentType::DEBUG_START;
    if (str == "DEBUG_BREAKPOINT") return IntentType::DEBUG_BREAKPOINT;
    if (str == "DEBUG_STEP") return IntentType::DEBUG_STEP;
    if (str == "AGENT_SPAWN") return IntentType::AGENT_SPAWN;
    if (str == "AGENT_KILL") return IntentType::AGENT_KILL;
    if (str == "SYSTEM_CONFIG") return IntentType::SYSTEM_CONFIG;
    if (str == "CHAT_MESSAGE") return IntentType::CHAT_MESSAGE;
    if (str == "CUSTOM") return IntentType::CUSTOM;
    return IntentType::UNKNOWN;
}

} // namespace Sovereign
