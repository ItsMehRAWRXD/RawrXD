#pragma once
#include <vector>
#include <string>
#include <unordered_map>
#include <set>
#include <optional>
#include <functional>
#include <random>
#include <array>
#include <cstdint>
#include <chrono>

namespace RawrXD::Reverse {

    // === All Pattern Types ===
    
    enum class PatternType {
        ORIGINAL,
        INVERSE,
        COMPLEMENT,
        REVERSED,
        XOR_VARIANT,
        ANTI_PATTERN,
        DISCOVERED,
        CONTEXT_INVERSE,
        SLIDING_WINDOW,
        FREQUENCY_BASED,
        TRANSITION_BASED,
        ENTROPY_BASED,
        HYBRID
    };

    // === Pattern with Full Metadata ===
    
    struct ComprehensivePattern {
        std::string id;
        std::string name;
        std::string description;
        std::vector<uint8_t> bytes;
        std::vector<uint8_t> mask;
        PatternType type;
        double confidence = 0.0;
        
        std::string source_id;
        std::string transform_chain;
        
        double entropy = 0.0;
        double byte_diversity = 0.0;
        double uniformity = 0.0;
        double repetition_score = 0.0;
        double complexity = 0.0;
        double predictability = 0.0;
        
        size_t frequency = 0;
        std::vector<size_t> offsets;
        std::unordered_map<uint8_t, double> byte_probability;
        
        std::vector<uint8_t> left_context;
        std::vector<uint8_t> right_context;
        std::vector<std::string> contexts;
        
        bool validated = false;
        double validation_score = 0.0;
        std::vector<std::string> validation_errors;
        std::vector<std::string> warnings;
        
        std::set<std::string> tags;
        std::string category;
        
        uint64_t created_timestamp = 0;
        uint64_t last_modified = 0;
    };

    // === Pattern Generation Request ===
    
    struct GenerationRequest {
        std::vector<uint8_t> source_bytes;
        std::vector<PatternType> desired_types;
        bool generate_inverses = true;
        bool generate_complements = true;
        bool generate_reversed = true;
        bool generate_xor_variants = true;
        bool generate_anti_patterns = true;
        bool discover_from_binary = false;
        
        std::vector<uint8_t> xor_keys = {0x01, 0x0F, 0x55, 0xAA, 0xFF};
        size_t anti_pattern_count = 10;
        size_t min_pattern_length = 2;
        size_t max_pattern_length = 64;
        
        double confidence_threshold = 0.5;
        bool preserve_original = true;
        bool validate_generated = true;
    };

    // === Pattern Metrics ===
    
    struct PatternMetrics {
        double shannon_entropy = 0.0;
        double conditional_entropy = 0.0;
        double mutual_information = 0.0;
        double byte_diversity = 0.0;
        double unique_byte_ratio = 0.0;
        double uniformity_index = 0.0;
        double repetition_index = 0.0;
        double periodicity_score = 0.0;
        double complexity_measure = 0.0;
        double mean = 0.0;
        double variance = 0.0;
        double std_dev = 0.0;
        double skewness = 0.0;
        double kurtosis = 0.0;
        double information_content = 0.0;
        double redundancy = 0.0;
        double predictability = 0.0;
        double generation_time_ms = 0.0;
        double validation_time_ms = 0.0;
        size_t memory_usage_bytes = 0.0;
    };

    // === Pattern Comparison ===
    
    struct PatternComparison {
        double similarity = 0.0;
        double inverse_similarity = 0.0;
        size_t hamming_distance = 0;
        double normalized_hamming = 0.0;
        double xor_similarity = 0.0;
        double cosine_similarity = 0.0;
        double correlation_coefficient = 0.0;
        std::vector<size_t> matching_positions;
        std::vector<size_t> differing_positions;
        std::vector<std::pair<size_t, uint8_t>> source_bytes;
        std::vector<std::pair<size_t, uint8_t>> target_bytes;
    };

    // === Validation Result ===
    
    struct ValidationResult {
        bool valid = false;
        double confidence = 0.0;
        std::vector<std::string> passed_checks;
        std::vector<std::string> failed_checks;
        std::vector<std::string> warnings;
        std::vector<std::pair<std::string, double>> check_scores;
    };

    // === Sliding Window Result ===
    
    struct SlidingWindowResult {
        size_t window_id = 0;
        size_t offset = 0;
        std::vector<ComprehensivePattern> patterns;
        double window_entropy = 0.0;
        std::unordered_map<uint8_t, size_t> frequency;
        bool is_anomalous = false;
    };

    // === Generator Statistics ===
    
    struct GeneratorStats {
        size_t total_patterns_generated = 0;
        size_t total_inverses = 0;
        size_t total_complements = 0;
        size_t total_reversed = 0;
        size_t total_xor_variants = 0;
        size_t total_anti_patterns = 0;
        size_t total_discovered = 0;
        size_t total_validated = 0;
        size_t total_failed_validation = 0;
        double average_generation_time_ms = 0.0;
        double average_validation_time_ms = 0.0;
        size_t memory_used_bytes = 0;
        std::unordered_map<PatternType, size_t> type_counts;
    };

    // === Comprehensive Generator Class ===
    
    class ComprehensivePatternGenerator {
    public:
        ComprehensivePatternGenerator();
        ~ComprehensivePatternGenerator();

        std::vector<ComprehensivePattern> generateAllPatterns(
            const std::vector<uint8_t>& source,
            const GenerationRequest& request = GenerationRequest()
        );

        ComprehensivePattern generateInverse(const std::vector<uint8_t>& source, const std::string& source_id = "");
        ComprehensivePattern generateComplement(const std::vector<uint8_t>& source, const std::string& source_id = "");
        ComprehensivePattern generateReversed(const std::vector<uint8_t>& source, const std::string& source_id = "");
        ComprehensivePattern generateXORVariant(const std::vector<uint8_t>& source, uint8_t key, const std::string& source_id = "");
        std::vector<ComprehensivePattern> generateAntiPatterns(const std::vector<uint8_t>& source, size_t count = 10);
        
        std::vector<ComprehensivePattern> discoverPatterns(
            const uint8_t* data, 
            size_t length,
            size_t min_len = 4,
            size_t max_len = 64,
            size_t min_frequency = 2
        );
        
        std::vector<ComprehensivePattern> discoverByFrequency(
            const uint8_t* data,
            size_t length,
            size_t min_frequency = 3
        );
        
        std::vector<ComprehensivePattern> discoverByEntropy(
            const uint8_t* data,
            size_t length,
            double min_entropy = 0.5,
            double max_entropy = 7.0
        );

        PatternMetrics calculateMetrics(const ComprehensivePattern& pattern);
        PatternMetrics calculateMetrics(const std::vector<uint8_t>& bytes);
        
        PatternComparison comparePatterns(const ComprehensivePattern& a, const ComprehensivePattern& b);
        ValidationResult validatePattern(const ComprehensivePattern& pattern);
        
        std::string exportToJSON(const std::vector<ComprehensivePattern>& patterns);
        std::string exportToCSV(const std::vector<ComprehensivePattern>& patterns);
        std::string generateReport(const std::vector<ComprehensivePattern>& patterns);
        
        bool exportToBigDaddyGModel(
            const std::vector<ComprehensivePattern>& patterns,
            const std::string& model_path
        );
        
        std::vector<SlidingWindowResult> analyzeWithSlidingWindow(
            const uint8_t* data,
            size_t length,
            size_t window_size = 4096,
            size_t stride = 512
        );

        GeneratorStats getStats() const;
        void resetStats();

        static std::string getTypeString(PatternType type);

    private:
        std::vector<uint8_t> computeInverse(const std::vector<uint8_t>& bytes);
        std::vector<uint8_t> computeComplement(const std::vector<uint8_t>& bytes);
        std::vector<uint8_t> computeReverse(const std::vector<uint8_t>& bytes);
        std::vector<uint8_t> computeXOR(const std::vector<uint8_t>& bytes, uint8_t key);
        
        double calculateEntropy(const std::vector<uint8_t>& bytes);
        double calculateDiversity(const std::vector<uint8_t>& bytes);
        double calculateUniformity(const std::vector<uint8_t>& bytes);
        double calculateRepetition(const std::vector<uint8_t>& bytes);
        double calculateComplexity(const std::vector<uint8_t>& bytes);
        double calculatePredictability(const std::vector<uint8_t>& bytes);
        
        std::string generateId(PatternType type);

        std::mt19937 rng_;
        std::uniform_int_distribution<uint8_t> byte_dist_;
        
        GeneratorStats stats_;
        std::unordered_map<std::string, std::vector<ComprehensivePattern>> pattern_cache_;
        
        struct Config {
            bool enable_caching = true;
            bool enable_validation = true;
            bool enable_stats = true;
            size_t max_cache_size = 10000;
        } config_;
    };

} // namespace RawrXD::Reverse
