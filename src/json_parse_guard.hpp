#pragma once

#include "json_sanitizer.hpp"
#include "json_schema_validator.hpp"
#include <nlohmann/json.hpp>
#include <string>
#include <functional>
#include <memory>

namespace RawrXD {
namespace JSON {

using json = nlohmann::json;

// Callback signatures for logging
using ParseErrorCallback = std::function<void(const std::string&)>;
using ParseSuccessCallback = std::function<void(const json&)>;

/**
 * @brief Safe JSON parsing guard with multi-layer defense
 * 
 * Pipeline:
 * 1. Sanitization (strip fences, trim whitespace)
 * 2. Format verification (looks like JSON)
 * 3. Safe parsing with detailed error capture
 * 4. Schema validation
 * 5. Self-healing trigger on failure
 * 
 * This is the CRITICAL interface between LLM output and tool dispatch.
 */
class JSONParseGuard {
public:
    /**
     * @brief Parse JSON with full hardening
     * 
     * @param raw_input Raw input from LLM (may contain markdown, etc.)
     * @param on_parse_error Callback if parsing fails (for logging/recovery)
     * @param on_parse_success Callback on successful parse
     * @param require_schema If true, will validate against schema
     * @param schema_validator Schema validation function (e.g., ToolCallSchema::Validate)
     * 
     * @return Parsed JSON object, or empty object on failure
     */
    template<typename SchemaValidator>
    static json SafeParse(
        const std::string& raw_input,
        ParseErrorCallback on_parse_error = nullptr,
        ParseSuccessCallback on_parse_success = nullptr,
        bool require_schema = true,
        SchemaValidator schema_validator = nullptr)
    {
        try {
            // ========== LAYER 1: SANITIZATION ==========
            std::string sanitized = JSONSanitizer::Sanitize(raw_input);
            
            if (sanitized.empty()) {
                std::string error = "Input sanitized to empty after cleanup";
                if (on_parse_error) on_parse_error(error);
                return json::object();
            }
            
            // ========== LAYER 2: FORMAT CHECK ==========
            if (!JSONSanitizer::LooksLikeJSON(sanitized)) {
                std::string error = "Sanitized input does not look like JSON. First 100 chars: " + 
                                   sanitized.substr(0, 100);
                if (on_parse_error) on_parse_error(error);
                return json::object();
            }
            
            // ========== LAYER 3: SAFE PARSE ==========
            json parsed;
            try {
                parsed = json::parse(sanitized);
            } catch (const json::parse_error& e) {
                std::string error = std::string("JSON parse error at byte offset ") + 
                                   std::to_string(e.byte) + ": " + e.what();
                if (on_parse_error) on_parse_error(error);
                return json::object();
            } catch (const std::exception& e) {
                std::string error = std::string("Unexpected parse exception: ") + e.what();
                if (on_parse_error) on_parse_error(error);
                return json::object();
            }
            
            // ========== LAYER 4: SCHEMA VALIDATION ==========
            if (require_schema && schema_validator) {
                std::string validation_error;
                if (!schema_validator(parsed, validation_error)) {
                    std::string error = std::string("Schema validation failed: ") + validation_error;
                    if (on_parse_error) on_parse_error(error);
                    return json::object();
                }
            }
            
            // ========== SUCCESS ==========
            if (on_parse_success) on_parse_success(parsed);
            return parsed;
            
        } catch (const std::exception& e) {
            std::string error = std::string("Unhandled exception in SafeParse: ") + e.what();
            if (on_parse_error) on_parse_error(error);
            return json::object();
        }
    }
    
    /**
     * @brief Overload for when you don't need schema validation
     */
    static json SafeParse(
        const std::string& raw_input,
        ParseErrorCallback on_parse_error = nullptr,
        ParseSuccessCallback on_parse_success = nullptr)
    {
        return SafeParse(raw_input, on_parse_error, on_parse_success, false, nullptr);
    }
    
    /**
     * @brief Extract and parse JSON from streaming response
     * 
     * Handles line-delimited JSON (NDJSON) or single-object responses
     * 
     * @param streaming_chunk One chunk of streaming data
     * @return Parsed JSON, or empty on failure
     */
    static json SafeParseStreamChunk(
        const std::string& streaming_chunk,
        ParseErrorCallback on_error = nullptr)
    {
        std::string sanitized = JSONSanitizer::Sanitize(streaming_chunk);
        
        if (sanitized.empty()) {
            if (on_error) on_error("Streaming chunk sanitized to empty");
            return json::object();
        }
        
        try {
            return json::parse(sanitized);
        } catch (const std::exception& e) {
            if (on_error) on_error(std::string("Stream chunk parse failed: ") + e.what());
            return json::object();
        }
    }
};

/**
 * @brief Self-healing inference recovery
 * 
 * When JSON parsing fails, this generates a repair prompt that can be 
 * submitted back to the LLM to request corrected output.
 * 
 * This transforms a crash into an autonomous retry loop.
 */
class JSONParseRecovery {
public:
    /**
     * @brief Generate a repair prompt for failed output
     * 
     * @param bad_output The output that failed to parse
     * @param parse_error The error description
     * @return A prompt that can be submitted to SubmitInference to retry
     */
    static std::string GenerateRepairPrompt(
        const std::string& bad_output,
        const std::string& parse_error)
    {
        return 
            "Your previous response was invalid JSON. Please fix it and try again.\n"
            "\n"
            "Error: " + parse_error + "\n"
            "\n"
            "Requirements:\n"
            "- Return ONLY valid JSON\n"
            "- No markdown code fences\n"
            "- No comments or explanations outside the JSON\n"
            "- Ensure 'tool' and 'arguments' fields are present\n"
            "- Use proper JSON syntax (quotes, commas, etc.)\n"
            "\n"
            "Previous output:\n" +
            bad_output + "\n"
            "\n"
            "Please return valid JSON now:";
    }
    
    /**
     * @brief Check if we should attempt recovery
     * 
     * Some parse failures are unrecoverable (e.g., completely empty output).
     * This method determines if it's worth submitting a retry.
     * 
     * @param output The output that failed
     * @param error The parse error
     * @return true if recovery attempt is worthwhile
     */
    static bool ShouldAttemptRecovery(
        const std::string& output,
        const std::string& error)
    {
        // Don't retry on empty output
        if (output.empty() || output.find_first_not_of(" \n\r\t") == std::string::npos) {
            return false;
        }
        
        // Don't retry if output is way too large (likely corrupt)
        if (output.length() > 10 * 1024 * 1024) {  // 10MB
            return false;
        }
        
        // Don't retry if error suggests fundamental type mismatch
        if (error.find("Expected") != std::string::npos && 
            error.find("but got") != std::string::npos) {
            // Some type errors might be recoverable
            return true;
        }
        
        // Recovery is reasonable for most parse errors
        return true;
    }
    
    /**
     * @brief Log recovery attempt for observability
     */
    static void LogRecoveryAttempt(
        int attempt_number,
        const std::string& error,
        std::function<void(const std::string&)> logger = nullptr)
    {
        if (!logger) return;
        
        std::string msg = "JSON parse recovery attempt #" + std::to_string(attempt_number) + 
                         ": " + error;
        logger(msg);
    }
};

} // namespace JSON
} // namespace RawrXD
