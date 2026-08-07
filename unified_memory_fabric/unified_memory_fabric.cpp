// ============================================================================
// UNIFIED MEMORY FABRIC
// Sliding Doors + Reverse Decode + Predictive Routing + Hierarchical Memory
// + Resizeable Learning + Chatter Boxes + Sizeless Model + Never Ending Engine
// ============================================================================
//
// One idea. One code. Every concept reverse engineered into a single fabric.
//
// - Sliding Doors:    modules open/close based on demand
// - Reverse Decode:   weights reconstructed from latent on demand
// - Predictive Route: router opens doors before they're needed
// - Hierarchical Memory: hot/warm/latent/archived tiers
// - Resizeable:       unused gets unweighted, structure preserved
// - Chatter Boxes:    context organized into specialized boxes
// - Sizeless:         model has no fixed size, becomes what you need
// - Never Ending:     new chapters added dynamically forever
//
// Signed: ~g87 | RawrXD | uwu kawaii
// ============================================================================

#include <algorithm>
#include <array>
#include <atomic>
#include <bit>
#include <chrono>
#include <cmath>
#include <concepts>
#include <coroutine>
#include <cstdint>
#include <cstring>
#include <execution>
#include <expected>
#include <format>
#include <functional>
#include <future>
#include <latch>
#include <memory>
#include <memory_resource>
#include <mutex>
#include <numeric>
#include <optional>
#include <queue>
#include <random>
#include <ranges>
#include <semaphore>
#include <source_location>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <type_traits>
#include <unordered_map>
#include <variant>
#include <vector>

// ============================================================================
// CONSTANTS
// ============================================================================

inline constexpr size_t kCacheLine     = 64;
inline constexpr size_t kPageSize      = 4096;
inline constexpr size_t kHugePageSize  = 2 * 1024 * 1024;
inline constexpr float  kPi            = 3.14159265358979323846f;
inline constexpr size_t kMaxBoxes      = 8;
inline constexpr size_t kDefaultBoxTokens = 4096;
inline constexpr size_t kLatentDim     = 64;
inline constexpr size_t kSeedSize      = 256;
inline constexpr float  kDoorOpenThreshold  = 0.80f;
inline constexpr float  kDoorCloseThreshold = 0.20f;
inline constexpr float  kDecayRate     = 0.10f;
inline constexpr float  kGrowRate      = 1.00f;
inline constexpr size_t kMaxChapters   = 1024;
inline constexpr size_t kPreloadAhead  = 2;

// ============================================================================
// RESIDENCY — Where a module lives in the memory hierarchy
// ============================================================================

enum class Residency : uint8_t {
    ACTIVE,          // Full weights resident in fast memory
    WARM,            // Compressed in VRAM, quick to expand
    LATENT,          // Decoder representation only (very compact)
    ARCHIVED,        // Seed only (minimal metadata)
    PREDICTED,       // Door is opening, reconstruction in flight
    UNWEIGHTED,      // Structure preserved, weights ~zero
    TRANSITIONING,   // Gaining or losing weight
    FROZEN           // Locked at current value (important knowledge)
};

constexpr const char* residency_name(Residency r) noexcept {
    switch (r) {
        case Residency::ACTIVE:        return "ACTIVE";
        case Residency::WARM:          return "WARM";
        case Residency::LATENT:        return "LATENT";
        case Residency::ARCHIVED:      return "ARCHIVED";
        case Residency::PREDICTED:     return "PREDICTED";
        case Residency::UNWEIGHTED:    return "UNWEIGHTED";
        case Residency::TRANSITIONING: return "TRANSITIONING";
        case Residency::FROZEN:        return "FROZEN";
    }
    return "UNKNOWN";
}

// ============================================================================
// DOOR STATE — Sliding doors between memory regions
// ============================================================================

enum class DoorState : uint8_t {
    OPEN,
    OPENING,
    HALF_OPEN,
    CLOSING,
    CLOSED,
    SEALED
};

constexpr const char* door_name(DoorState d) noexcept {
    switch (d) {
        case DoorState::OPEN:    return "OPEN";
        case DoorState::OPENING: return "OPENING";
        case DoorState::HALF_OPEN: return "HALF_OPEN";
        case DoorState::CLOSING: return "CLOSING";
        case DoorState::CLOSED:  return "CLOSED";
        case DoorState::SEALED:  return "SEALED";
    }
    return "UNKNOWN";
}

// ============================================================================
// BOX TYPE — Chatter box specializations
// ============================================================================

enum class BoxType : uint8_t {
    SYSTEM,
    USER,
    ASSISTANT,
    KNOWLEDGE,
    WORKING_MEMORY,
    REASONING,
    PLAN,
    ATTENTION,
    CUSTOM
};

constexpr const char* box_name(BoxType b) noexcept {
    switch (b) {
        case BoxType::SYSTEM:        return "system";
        case BoxType::USER:          return "user";
        case BoxType::ASSISTANT:     return "assistant";
        case BoxType::KNOWLEDGE:     return "knowledge";
        case BoxType::WORKING_MEMORY: return "working";
        case BoxType::REASONING:     return "reasoning";
        case BoxType::PLAN:          return "plan";
        case BoxType::ATTENTION:     return "attention";
        case BoxType::CUSTOM:        return "custom";
    }
    return "unknown";
}

// ============================================================================
// TASK TYPE — What the router detects
// ============================================================================

enum class TaskType : uint8_t {
    MATH,
    CODE,
    CREATIVE,
    REASONING,
    CONVERSATION,
    KNOWLEDGE,
    PLANNING,
    ANALYSIS,
    UNKNOWN
};

constexpr const char* task_name(TaskType t) noexcept {
    switch (t) {
        case TaskType::MATH:         return "math";
        case TaskType::CODE:         return "code";
        case TaskType::CREATIVE:     return "creative";
        case TaskType::REASONING:    return "reasoning";
        case TaskType::CONVERSATION: return "conversation";
        case TaskType::KNOWLEDGE:    return "knowledge";
        case TaskType::PLANNING:     return "planning";
        case TaskType::ANALYSIS:     return "analysis";
        case TaskType::UNKNOWN:      return "unknown";
    }
    return "unknown";
}

// ============================================================================
// CHAPTER — A chapter in the Never Ending Intelligence Engine
// ============================================================================

struct Chapter {
    uint32_t id;
    std::string title;
    std::vector<TaskType> knowledge_types;
    std::string description;
    std::vector<std::string> tags;
    Residency state = Residency::ARCHIVED;
    uint64_t last_used = 0;
    uint32_t use_count = 0;
    float quality_score = 1.0f;
    uint64_t param_count = 1'000'000'000;  // 1B per chapter
    uint64_t file_size_bytes = 2'000'000'000;  // ~2GB Q4
    std::array<uint8_t, kSeedSize> seed{};
    std::array<uint8_t, kLatentDim> latent{};
};

// ============================================================================
// MEMORY NODE — The fundamental unit of the fabric
// ============================================================================

struct MemoryNode {
    uint64_t id;
    std::string name;
    std::string layer;
    std::string weight_type;  // "attention", "ffn", "embedding", "norm", "output"

    // State
    Residency state = Residency::ARCHIVED;
    DoorState door = DoorState::CLOSED;

    // Sizing
    uint64_t bytes = 0;
    uint64_t num_params = 0;

    // Scoring
    float probability = 0.0f;
    float importance = 0.5f;
    float entropy = 0.0f;
    float reuse_score = 0.0f;
    float temperature = 1.0f;

    // Timing
    uint64_t last_used = 0;
    uint64_t predicted_next = 0;
    uint64_t created_at = 0;
    uint32_t use_count = 0;

    // Memory pointers (tiered)
    void* resident_weights = nullptr;   // Tier 0: full weights
    void* compressed_data = nullptr;    // Tier 1: compressed in VRAM
    void* latent = nullptr;             // Tier 2: decoder representation
    std::array<uint8_t, kSeedSize> seed{};  // Tier 3: seed only

    // Reconstruction
    std::function<void*(void*, void*)> reconstructor;
    std::function<void(void*)> destructor;

    // Neighbors for temporal locality
    std::vector<uint64_t> neighbors;

    // Box association
    BoxType box_type = BoxType::CUSTOM;
    std::string box_name;

    // Chapter association
    uint32_t chapter_id = 0;

    // Full weights (for resizeable learning)
    std::vector<float> full_weights_sample;   // Representative sample
    std::vector<float> current_weights_sample;
    float decay_rate = kDecayRate;
    float grow_rate = kGrowRate;

    uint64_t memory_estimate() const noexcept {
        switch (state) {
            case Residency::ACTIVE:        return bytes;
            case Residency::WARM:          return bytes / 4;
            case Residency::LATENT:        return kLatentDim * sizeof(float);
            case Residency::ARCHIVED:      return kSeedSize;
            case Residency::PREDICTED:     return bytes / 2;
            case Residency::UNWEIGHTED:    return kSeedSize + 64;
            case Residency::TRANSITIONING: return bytes / 2;
            case Residency::FROZEN:        return bytes;
        }
        return 0;
    }

    float weight_magnitude() const noexcept {
        if (current_weights_sample.empty()) return 0.0f;
        float sum = 0.0f;
        for (auto w : current_weights_sample) sum += std::abs(w);
        return sum / static_cast<float>(current_weights_sample.size());
    }

    float full_magnitude() const noexcept {
        if (full_weights_sample.empty()) return 0.0f;
        float sum = 0.0f;
        for (auto w : full_weights_sample) sum += std::abs(w);
        return sum / static_cast<float>(full_weights_sample.size());
    }
};

// ============================================================================
// MESSAGE — Chatter box message passing
// ============================================================================

struct Message {
    std::string sender;
    std::string recipient;  // or "broadcast"
    std::string content;
    std::string msg_type;   // "request", "response", "broadcast", "update", "transfer"
    uint32_t priority = 0;
    uint64_t timestamp = 0;
    std::array<uint8_t, 12> msg_id{};
};

// ============================================================================
// ROUTING DECISION — What the router decides
// ============================================================================

struct RoutingDecision {
    std::vector<uint64_t> primary_nodes;
    std::vector<uint64_t> secondary_nodes;
    std::vector<uint64_t> unweighted_nodes;
    float confidence = 0.0f;
    TaskType task_type = TaskType::UNKNOWN;
    std::string input_summary;
};

// ============================================================================
// CHATTER CONTEXT — The sum of all chatter boxes
// ============================================================================

struct ChatterContext {
    std::unordered_map<std::string, std::vector<std::string>> boxes;
    uint64_t total_tokens = 0;
    uint64_t max_total_tokens = 0;
    uint32_t box_count = 0;
    uint32_t active_box_count = 0;

    std::string to_prompt(const std::string& format = "tagged") const {
        std::ostringstream oss;
        if (format == "tagged") {
            for (auto& [name, tokens] : boxes) {
                if (tokens.empty()) continue;
                oss << "<box name=\"" << name << "\">\n";
                for (auto& t : tokens) oss << t << " ";
                oss << "\n</box>\n";
            }
        } else if (format == "linear") {
            for (auto& [name, tokens] : boxes) {
                if (tokens.empty()) continue;
                oss << "[" << name << "]\n";
                for (auto& t : tokens) oss << t << " ";
                oss << "\n";
            }
        }
        return oss.str();
    }
};

// ============================================================================
// SYSTEM SPECS — Auto-detected hardware
// ============================================================================

struct SystemSpecs {
    std::string cpu_name;
    uint32_t cpu_cores = 0;
    uint32_t cpu_threads = 0;
    float cpu_freq_ghz = 0.0f;
    float total_ram_gb = 0.0f;
    float available_ram_gb = 0.0f;
    float usable_ram_gb = 0.0f;
    std::string gpu_name;
    float gpu_vram_gb = 0.0f;
    bool gpu_available = false;
    std::string gpu_type;
    std::string os_name;
    std::string arch;
    std::string max_model_size = "1B";
    uint64_t max_model_params = 1'000'000'000;
    float max_model_memory_mb = 2000.0f;
    std::string recommended_quant = "Q4_K_M";
};

// ============================================================================
// GENERATION REPORT — Output from model generation
// ============================================================================

struct GenerationReport {
    std::string seed_id;
    std::string seed_size;
    std::string target_size;
    uint64_t actual_params = 0;
    float generation_time_ms = 0.0f;
    float memory_footprint_mb = 0.0f;
    std::string seed_to_model_ratio;
    uint32_t layers_generated = 0;
    bool lazy = true;
    uint64_t cached_weights = 0;
    float storage_saved_pct = 0.0f;
    std::string signature = "~g87";
};

// ============================================================================
// STATISTICS — Unified stats
// ============================================================================

struct FabricStats {
    uint64_t total_nodes = 0;
    uint64_t active_nodes = 0;
    uint64_t warm_nodes = 0;
    uint64_t latent_nodes = 0;
    uint64_t archived_nodes = 0;
    uint64_t predicted_nodes = 0;
    uint64_t total_bytes = 0;
    uint64_t active_bytes = 0;
    uint64_t compressed_bytes = 0;
    uint64_t latent_bytes = 0;
    uint64_t archived_bytes = 0;
    float memory_savings_pct = 0.0f;
    uint64_t total_inferences = 0;
    uint64_t total_page_turns = 0;
    uint64_t preload_hits = 0;
    uint64_t preload_misses = 0;
    float preload_hit_rate = 0.0f;
    uint64_t messages_passed = 0;
    uint32_t chapter_count = 0;
    uint32_t box_count = 0;
    float avg_confidence = 0.0f;
    float avg_latency_ms = 0.0f;
    std::string version = "umf-1.0";
    std::string signature = "~g87";
};

// ============================================================================
// RANDOM — Deterministic hash-based RNG (no std::rand)
// ============================================================================

class HashRNG {
    std::array<uint64_t, 4> state_;
public:
    explicit HashRNG(uint64_t seed) noexcept {
        state_ = {seed, seed ^ 0x9e3779b97f4a7c15ULL,
                  seed ^ 0xbf58476d1ce4e5b9ULL, seed ^ 0x9e3779b97f4a7c15ULL};
    }

    uint64_t next() noexcept {
        uint64_t x = state_[0];
        uint64_t y = state_[1];
        state_[0] = y;
        x ^= x << 23;
        state_[1] = x ^ y ^ (x >> 17) ^ (y >> 26);
        state_[2] = state_[2] + 0x9e3779b97f4a7c15ULL;
        state_[3] = state_[3] + 1;
        return state_[1] + state_[3];
    }

    float uniform() noexcept {
        return static_cast<float>(next() & 0xFFFFFF) / 16777216.0f;
    }

    float normal(float mean = 0.0f, float stddev = 1.0f) noexcept {
        float u1 = uniform();
        float u2 = uniform();
        float r = std::sqrt(-2.0f * std::log(u1 + 1e-10f));
        float theta = 2.0f * kPi * u2;
        return mean + stddev * r * std::cos(theta);
    }
};

// ============================================================================
// TIMING
// ============================================================================

inline uint64_t now() noexcept {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()
    ).count();
}

// ============================================================================
// UNIFIED MEMORY FABRIC — The single class that does everything
// ============================================================================

class UnifiedMemoryFabric {
public:
    UnifiedMemoryFabric() {
        created_at_ = now();
        rng_ = std::make_unique<HashRNG>(created_at_);
        create_default_boxes();
        create_default_chapters();
    }

    ~UnifiedMemoryFabric() {
        for (auto& [id, node] : nodes_) {
            if (node.destructor && node.resident_weights) {
                node.destructor(node.resident_weights);
            }
        }
    }

    // ========================================================================
    // MAIN TICK — Called every inference step
    // ========================================================================

    void tick(const std::string& input) {
        auto tick_start = now();

        // 1. Detect system specs (first time)
        if (first_tick_) {
            detect_system_specs();
            first_tick_ = false;
        }

        // 2. Route the input
        auto decision = route(input);

        // 3. Predict which nodes will be needed
        predict(decision);

        // 4. Open sliding doors for predicted nodes
        open_sliding_doors();

        // 5. Reverse decode latent → weights
        reverse_decode();

        // 6. Weight up primary, unweight rest
        apply_resizeable_learning(decision);

        // 7. Write to chatter boxes
        write_to_boxes(input, decision);

        // 8. Process messages between boxes
        process_messages();

        // 9. Compress cold nodes
        compress_cold_nodes();

        // 10. Archive dormant nodes
        archive_dormant();

        // 11. Defragment if needed
        if (++ticks_since_defrag_ > 100) {
            defragment();
            ticks_since_defrag_ = 0;
        }

        // 12. Preload next chapters
        preload_next_chapters(decision);

        total_inferences_++;
        total_latency_ms_ += static_cast<float>(now() - tick_start);
    }

    // ========================================================================
    // INFERENCE — Full pipeline
    // ========================================================================

    std::string infer(const std::string& input) {
        tick(input);

        // Simulated inference
        std::ostringstream oss;
        oss << "[Unified Memory Fabric]\n";
        oss << "  Input: " << input.substr(0, 60) << "...\n";
        oss << "  Task: " << task_name(last_task_) << "\n";
        oss << "  Active nodes: " << count_residency(Residency::ACTIVE) << "/" << nodes_.size() << "\n";
        oss << "  Memory: " << (active_bytes_ / (1024*1024)) << "MB active / "
            << (total_bytes_ / (1024*1024)) << "MB total\n";
        oss << "  Savings: " << memory_savings_pct() << "%\n";
        oss << "  Boxes: " << boxes_.size() << " chatter boxes\n";
        oss << "  Chapters: " << chapters_.size() << " available\n";
        oss << "  Signed: ~g87\n";

        return oss.str();
    }

    // ========================================================================
    // ADD NODE — Add a memory node to the fabric
    // ========================================================================

    uint64_t add_node(const std::string& name, const std::string& layer,
                      const std::string& weight_type, uint64_t num_params,
                      float importance = 0.5f,
                      BoxType box_type = BoxType::CUSTOM,
                      const std::string& box_name = "",
                      uint32_t chapter_id = 0) {
        uint64_t id = next_id_++;
        uint64_t bytes = num_params * 4;  // FP32

        auto& node = nodes_[id];
        node.id = id;
        node.name = name;
        node.layer = layer;
        node.weight_type = weight_type;
        node.state = Residency::ARCHIVED;
        node.door = DoorState::CLOSED;
        node.bytes = bytes;
        node.num_params = num_params;
        node.importance = importance;
        node.created_at = now();
        node.last_used = now();
        node.box_type = box_type;
        node.box_name = box_name;
        node.chapter_id = chapter_id;

        // Generate seed (deterministic from name)
        HashRNG seed_rng(std::hash<std::string>{}(name));
        for (auto& b : node.seed) b = static_cast<uint8_t>(seed_rng.next() & 0xFF);

        // Generate full weights sample (lazy — small representative sample)
        size_t sample_size = std::min<size_t>(num_params, 10000);
        HashRNG weight_rng(seed_rng.next());
        node.full_weights_sample.resize(sample_size);
        node.current_weights_sample.resize(sample_size, 0.0f);
        for (size_t i = 0; i < sample_size; i++) {
            node.full_weights_sample[i] = weight_rng.normal(0.0f, 0.02f);
        }

        // Set reconstructor (simulated)
        node.reconstructor = [](void* seed, void* latent) -> void* {
            // In production: decode latent → full weights
            auto* mem = std::aligned_alloc(kCacheLine, 1024);
            std::memset(mem, 0, 1024);
            return mem;
        };

        node.destructor = [](void* mem) {
            std::free(mem);
        };

        total_bytes_ += bytes;
        archived_bytes_ += bytes;

        return id;
    }

    // ========================================================================
    // ADD CHAPTER — Add a chapter to the Never Ending Engine
    // ========================================================================

    uint32_t add_chapter(const std::string& title,
                         const std::vector<TaskType>& knowledge_types,
                         const std::string& description,
                         const std::vector<std::string>& tags = {}) {
        uint32_t id = static_cast<uint32_t>(chapters_.size() + 1);
        auto& ch = chapters_[id];
        ch.id = id;
        ch.title = title;
        ch.knowledge_types = knowledge_types;
        ch.description = description;
        ch.tags = tags;
        ch.state = Residency::ARCHIVED;

        // Generate seed
        HashRNG seed_rng(std::hash<std::string>{}(title));
        for (auto& b : ch.seed) b = static_cast<uint8_t>(seed_rng.next() & 0xFF);

        return id;
    }

    // ========================================================================
    // ADD BOX — Add a chatter box
    // ========================================================================

    void add_box(const std::string& name, BoxType type, size_t max_tokens = kDefaultBoxTokens) {
        boxes_[name] = {};
        box_types_[name] = type;
        box_max_tokens_[name] = max_tokens;
    }

    // ========================================================================
    // WRITE TO BOX
    // ========================================================================

    void write_to_box(const std::string& box_name, const std::string& content) {
        auto& tokens = boxes_[box_name];
        std::istringstream iss(content);
        std::string token;
        while (iss >> token) {
            if (tokens.size() >= box_max_tokens_[box_name]) break;
            tokens.push_back(token);
        }
    }

    // ========================================================================
    // SEND MESSAGE
    // ========================================================================

    void send_message(const std::string& sender, const std::string& recipient,
                      const std::string& content, const std::string& type = "update",
                      uint32_t priority = 0) {
        Message msg;
        msg.sender = sender;
        msg.recipient = recipient;
        msg.content = content;
        msg.msg_type = type;
        msg.priority = priority;
        msg.timestamp = now();
        message_queue_.push(msg);
        messages_passed_++;
    }

    // ========================================================================
    // GENERATE MODEL — Sizeless model generation
    // ========================================================================

    GenerationReport generate_model(const std::string& seed_id,
                                     const std::string& target_size = "1B",
                                     bool lazy = true) {
        GenerationReport report;
        report.seed_id = seed_id;
        report.target_size = target_size;
        report.lazy = lazy;
        report.signature = "~g87";

        auto gen_start = now();

        // Size presets
        struct SizePreset { const char* name; uint64_t params; uint32_t hidden; uint32_t layers; uint32_t heads; };
        static constexpr SizePreset presets[] = {
            {"100M",  100'000'000,   768, 12, 12},
            {"250M",  250'000'000,  1024, 16, 16},
            {"500M",  500'000'000,  1280, 20, 20},
            {"1B",  1'000'000'000, 2048, 24, 16},
            {"3B",  3'000'000'000, 3200, 32, 32},
            {"7B",  7'000'000'000, 4096, 32, 32},
            {"13B",13'000'000'000, 5120, 40, 40},
            {"70B",70'000'000'000, 8192, 80, 64},
        };

        const SizePreset* preset = &presets[0];
        for (auto& p : presets) {
            if (target_size == p.name) { preset = &p; break; }
        }

        report.actual_params = preset->params;
        report.memory_footprint_mb = static_cast<float>(preset->params * 4) / (1024.0f * 1024.0f);
        report.generation_time_ms = static_cast<float>(now() - gen_start);
        report.layers_generated = preset->layers;

        // Add nodes for each layer
        uint32_t hidden = preset->hidden;
        uint32_t ffn = hidden * 4;
        uint32_t vocab = 32000;

        add_node("embedding", "input", "embedding", vocab * hidden, 0.9f, BoxType::KNOWLEDGE, "knowledge");

        uint32_t layers_per_group = 4;
        for (uint32_t g = 0; g < preset->layers / layers_per_group; g++) {
            float imp = 0.9f - static_cast<float>(g) * 0.1f;
            std::string group = std::to_string(g);
            add_node("attention_g" + group, "layers", "attention", 4 * hidden * hidden, imp);
            add_node("ffn_g" + group, "layers", "ffn", 4 * hidden * ffn, imp);
            add_node("norm_g" + group, "layers", "norm", 4 * hidden, imp * 0.5f);
        }

        add_node("output", "output", "output", hidden * vocab, 0.9f, BoxType::ASSISTANT, "assistant");

        report.seed_to_model_ratio = std::format("{}KB -> {:.0f}MB = 1:{:.0f}",
            kSeedSize / 1024, report.memory_footprint_mb,
            report.memory_footprint_mb * 1024.0f * 1024.0f / static_cast<float>(kSeedSize));

        return report;
    }

    // ========================================================================
    // GET STATS
    // ========================================================================

    FabricStats get_stats() const {
        FabricStats stats;
        stats.total_nodes = nodes_.size();
        stats.total_bytes = total_bytes_;
        stats.total_inferences = total_inferences_;
        stats.total_page_turns = page_turns_;
        stats.preload_hits = preload_hits_;
        stats.preload_misses = preload_misses_;
        stats.preload_hit_rate = page_turns_ > 0
            ? (static_cast<float>(preload_hits_) / static_cast<float>(page_turns_)) * 100.0f
            : 0.0f;
        stats.messages_passed = messages_passed_;
        stats.chapter_count = static_cast<uint32_t>(chapters_.size());
        stats.box_count = static_cast<uint32_t>(boxes_.size());
        stats.avg_latency_ms = total_inferences_ > 0
            ? total_latency_ms_ / static_cast<float>(total_inferences_)
            : 0.0f;

        for (auto& [id, node] : nodes_) {
            switch (node.state) {
                case Residency::ACTIVE:        stats.active_nodes++;    stats.active_bytes += node.bytes; break;
                case Residency::WARM:          stats.warm_nodes++;     stats.compressed_bytes += node.bytes / 4; break;
                case Residency::LATENT:        stats.latent_nodes++;   stats.latent_bytes += kLatentDim * sizeof(float); break;
                case Residency::ARCHIVED:      stats.archived_nodes++;  stats.archived_bytes += kSeedSize; break;
                case Residency::PREDICTED:     stats.predicted_nodes++; break;
                default: break;
            }
        }

        stats.memory_savings_pct = total_bytes_ > 0
            ? (1.0f - static_cast<float>(stats.active_bytes + stats.compressed_bytes + stats.latent_bytes + stats.archived_bytes)
                     / static_cast<float>(total_bytes_)) * 100.0f
            : 0.0f;

        return stats;
    }

    // ========================================================================
    // PRINT SUMMARY
    // ========================================================================

    void print_summary() const {
        auto stats = get_stats();

        printf("\n");
        printf("╔══════════════════════════════════════════════════════════════════════╗\n");
        printf("║              UNIFIED MEMORY FABRIC — %s              ║\n", stats.version.c_str());
        printf("║              Signed: %s                                      ║\n", stats.signature.c_str());
        printf("╠══════════════════════════════════════════════════════════════════════╣\n");
        printf("║  Nodes:     %5llu total  │  Active: %5llu  │  Warm: %5llu  │  Latent: %5llu  │  Archived: %5llu  ║\n",
               (unsigned long long)stats.total_nodes,
               (unsigned long long)stats.active_nodes,
               (unsigned long long)stats.warm_nodes,
               (unsigned long long)stats.latent_nodes,
               (unsigned long long)stats.archived_nodes);
        printf("║  Memory:    %5llu MB total │  Active: %5llu MB │  Saved: %5.0f%%              ║\n",
               (unsigned long long)(stats.total_bytes / (1024*1024)),
               (unsigned long long)(stats.active_bytes / (1024*1024)),
               stats.memory_savings_pct);
        printf("║  Inferences: %5llu      │  Page turns: %5llu  │  Preload hit: %5.0f%%        ║\n",
               (unsigned long long)stats.total_inferences,
               (unsigned long long)stats.total_page_turns,
               stats.preload_hit_rate);
        printf("║  Chapters:  %5u       │  Boxes: %5u       │  Messages: %5llu              ║\n",
               stats.chapter_count, stats.box_count,
               (unsigned long long)stats.messages_passed);
        printf("╠══════════════════════════════════════════════════════════════════════╣\n");
        printf("║  Residency:                                                         ║\n");
        printf("║    ACTIVE=%s  WARM=%s  LATENT=%s  ARCHIVED=%s  PREDICTED=%s  ║\n",
               residency_name(Residency::ACTIVE),
               residency_name(Residency::WARM),
               residency_name(Residency::LATENT),
               residency_name(Residency::ARCHIVED),
               residency_name(Residency::PREDICTED));
        printf("║  Doors:     OPEN | OPENING | HALF_OPEN | CLOSING | CLOSED | SEALED  ║\n");
        printf("║  Boxes:     system | user | assistant | knowledge | working         ║\n");
        printf("║  Chapters:  Never Ending — add more anytime                         ║\n");
        printf("║  Sizeless:  Same seed → 100M | 1B | 7B | 70B | 1T                   ║\n");
        printf("╚══════════════════════════════════════════════════════════════════════╝\n");
    }

private:
    // ========================================================================
    // MEMBERS
    // ========================================================================

    std::unordered_map<uint64_t, MemoryNode> nodes_;
    std::unordered_map<uint32_t, Chapter> chapters_;
    std::unordered_map<std::string, std::vector<std::string>> boxes_;
    std::unordered_map<std::string, BoxType> box_types_;
    std::unordered_map<std::string, size_t> box_max_tokens_;
    std::queue<Message> message_queue_;
    std::unique_ptr<HashRNG> rng_;
    uint64_t next_id_ = 1;
    uint64_t total_bytes_ = 0;
    uint64_t active_bytes_ = 0;
    uint64_t archived_bytes_ = 0;
    uint64_t total_inferences_ = 0;
    uint64_t total_latency_ms_ = 0;
    uint64_t page_turns_ = 0;
    uint64_t preload_hits_ = 0;
    uint64_t preload_misses_ = 0;
    uint64_t messages_passed_ = 0;
    uint64_t ticks_since_defrag_ = 0;
    uint64_t created_at_ = 0;
    bool first_tick_ = true;
    TaskType last_task_ = TaskType::UNKNOWN;
    SystemSpecs system_specs_;
    std::vector<uint32_t> chapter_load_order_;
    std::vector<uint32_t> active_chapters_;

    // ========================================================================
    // DETECT SYSTEM SPECS
    // ========================================================================

    void detect_system_specs() {
        system_specs_.cpu_cores = std::thread::hardware_concurrency();
        system_specs_.cpu_threads = system_specs_.cpu_cores * 2;

        // Estimate RAM (platform-specific would use OS APIs)
        system_specs_.total_ram_gb = 32.0f;  // Default estimate
        system_specs_.available_ram_gb = system_specs_.total_ram_gb * 0.6f;
        system_specs_.usable_ram_gb = system_specs_.available_ram_gb * 0.75f;

        // Determine max model size
        if (system_specs_.usable_ram_gb >= 100.0f) {
            system_specs_.max_model_size = "70B";
            system_specs_.max_model_params = 70'000'000'000;
        } else if (system_specs_.usable_ram_gb >= 24.0f) {
            system_specs_.max_model_size = "7B";
            system_specs_.max_model_params = 7'000'000'000;
        } else if (system_specs_.usable_ram_gb >= 6.0f) {
            system_specs_.max_model_size = "1B";
            system_specs_.max_model_params = 1'000'000'000;
        } else {
            system_specs_.max_model_size = "100M";
            system_specs_.max_model_params = 100'000'000;
        }
    }

    // ========================================================================
    // CREATE DEFAULT BOXES
    // ========================================================================

    void create_default_boxes() {
        add_box("system", BoxType::SYSTEM, 2048);
        add_box("user", BoxType::USER, 4096);
        add_box("assistant", BoxType::ASSISTANT, 4096);
        add_box("knowledge", BoxType::KNOWLEDGE, 2048);
        add_box("working", BoxType::WORKING_MEMORY, 1024);
    }

    // ========================================================================
    // CREATE DEFAULT CHAPTERS
    // ========================================================================

    void create_default_chapters() {
        add_chapter("Math & Logic", {TaskType::MATH, TaskType::REASONING},
                     "Algebra, calculus, proofs, numerical computation");
        add_chapter("Code Generation", {TaskType::CODE},
                     "Programming in 40+ languages, debugging, architecture");
        add_chapter("Creative Writing", {TaskType::CREATIVE},
                     "Stories, poetry, scripts, creative content");
        add_chapter("Science & Physics", {TaskType::KNOWLEDGE, TaskType::REASONING},
                     "Physics, chemistry, astronomy, scientific reasoning");
        add_chapter("History & Events", {TaskType::KNOWLEDGE},
                     "World history, dates, events, historical context");
        add_chapter("Conversation", {TaskType::CONVERSATION},
                     "Chat, dialogue, social interaction, empathy");
        add_chapter("Planning & Strategy", {TaskType::PLANNING, TaskType::REASONING},
                     "Task planning, multi-step reasoning, strategy");
        add_chapter("Analysis", {TaskType::ANALYSIS, TaskType::REASONING},
                     "Critical analysis, evaluation, comparison");
    }

    // ========================================================================
    // ROUTE — Determine the main attraction
    // ========================================================================

    RoutingDecision route(const std::string& input) {
        RoutingDecision decision;
        decision.input_summary = input.substr(0, 100);

        // Detect task type
        auto input_lower = input;
        std::transform(input_lower.begin(), input_lower.end(), input_lower.begin(), ::tolower);

        struct Keyword { const char* word; TaskType task; };
        static constexpr Keyword keywords[] = {
            {"math", TaskType::MATH}, {"calculate", TaskType::MATH},
            {"equation", TaskType::MATH}, {"integral", TaskType::MATH},
            {"code", TaskType::CODE}, {"program", TaskType::CODE},
            {"python", TaskType::CODE}, {"function", TaskType::CODE},
            {"write", TaskType::CREATIVE}, {"story", TaskType::CREATIVE},
            {"poem", TaskType::CREATIVE}, {"creative", TaskType::CREATIVE},
            {"why", TaskType::REASONING}, {"how", TaskType::REASONING},
            {"explain", TaskType::REASONING}, {"reason", TaskType::REASONING},
            {"plan", TaskType::PLANNING}, {"strategy", TaskType::PLANNING},
            {"step", TaskType::PLANNING}, {"approach", TaskType::PLANNING},
            {"analyze", TaskType::ANALYSIS}, {"compare", TaskType::ANALYSIS},
            {"evaluate", TaskType::ANALYSIS}, {"examine", TaskType::ANALYSIS},
            {"what is", TaskType::KNOWLEDGE}, {"tell me", TaskType::KNOWLEDGE},
            {"define", TaskType::KNOWLEDGE}, {"describe", TaskType::KNOWLEDGE},
        };

        std::unordered_map<TaskType, int> scores;
        for (auto& kw : keywords) {
            if (input_lower.find(kw.word) != std::string::npos) {
                scores[kw.task]++;
            }
        }

        TaskType best = TaskType::CONVERSATION;
        int best_score = 0;
        for (auto& [task, score] : scores) {
            if (score > best_score) { best = task; best_score = score; }
        }
        last_task_ = best;
        decision.task_type = best;

        // Score each node
        struct Scored { uint64_t id; float score; };
        std::vector<Scored> scored_nodes;

        for (auto& [id, node] : nodes_) {
            float score = 0.0f;

            // Task-based preference
            switch (best) {
                case TaskType::MATH:
                    if (node.weight_type == "attention" && node.name.find("early") != std::string::npos) score += 10;
                    if (node.weight_type == "ffn" && node.name.find("mid") != std::string::npos) score += 8;
                    break;
                case TaskType::CODE:
                    if (node.weight_type == "attention" && node.name.find("mid") != std::string::npos) score += 10;
                    if (node.weight_type == "ffn" && node.name.find("mid") != std::string::npos) score += 8;
                    break;
                case TaskType::CREATIVE:
                    if (node.weight_type == "attention" && node.name.find("late") != std::string::npos) score += 10;
                    if (node.weight_type == "ffn" && node.name.find("early") != std::string::npos) score += 8;
                    break;
                case TaskType::REASONING:
                    if (node.weight_type == "attention") score += 8;
                    if (node.weight_type == "ffn" && node.name.find("mid") != std::string::npos) score += 6;
                    break;
                case TaskType::KNOWLEDGE:
                    if (node.box_type == BoxType::KNOWLEDGE) score += 10;
                    if (node.weight_type == "ffn") score += 6;
                    break;
                case TaskType::PLANNING:
                    if (node.weight_type == "attention" && node.name.find("early") != std::string::npos) score += 10;
                    if (node.weight_type == "ffn" && node.name.find("early") != std::string::npos) score += 8;
                    break;
                case TaskType::ANALYSIS:
                    if (node.weight_type == "ffn" && node.name.find("early") != std::string::npos) score += 10;
                    if (node.weight_type == "ffn" && node.name.find("mid") != std::string::npos) score += 8;
                    break;
                default:
                    if (node.weight_type == "attention") score += 5;
                    if (node.weight_type == "ffn") score += 3;
                    break;
            }

            // Importance bonus
            score += node.importance * 5.0f;

            // Recency bonus
            if (now() - node.last_used < 5000) score += 2.0f;

            // Usage bonus
            score += std::min(static_cast<float>(node.use_count) * 0.1f, 3.0f);

            scored_nodes.push_back({id, score});
        }

        // Sort by score
        std::sort(scored_nodes.begin(), scored_nodes.end(),
                  [](auto& a, auto& b) { return a.score > b.score; });

        // Top 30% primary, next 30% secondary, rest unweighted
        size_t total = scored_nodes.size();
        size_t primary_count = std::max<size_t>(1, total * 30 / 100);
        size_t secondary_count = std::max<size_t>(1, total * 30 / 100);

        for (size_t i = 0; i < total; i++) {
            if (i < primary_count)
                decision.primary_nodes.push_back(scored_nodes[i].id);
            else if (i < primary_count + secondary_count)
                decision.secondary_nodes.push_back(scored_nodes[i].id);
            else
                decision.unweighted_nodes.push_back(scored_nodes[i].id);
        }

        decision.confidence = scored_nodes.empty() ? 0.5f
            : scored_nodes[0].score / 20.0f;

        return decision;
    }

    // ========================================================================
    // PREDICT — Predict which nodes will be needed
    // ========================================================================

    void predict(const RoutingDecision& decision) {
        for (auto& [id, node] : nodes_) {
            // Temporal locality: nodes used together tend to be used together again
            float temporal = 0.0f;
            for (auto& nid : node.neighbors) {
                auto it = nodes_.find(nid);
                if (it != nodes_.end() && now() - it->second.last_used < 10000) {
                    temporal += 0.1f;
                }
            }

            // Semantic similarity: nodes with similar names tend to activate together
            float semantic = 0.0f;
            for (auto& pid : decision.primary_nodes) {
                auto it = nodes_.find(pid);
                if (it != nodes_.end() && it->second.weight_type == node.weight_type) {
                    semantic += 0.15f;
                }
            }

            // Routing prediction: if this node was primary before, likely again
            float routing = node.importance * 0.2f;

            // Attention history: recently used nodes more likely
            float attention = (now() - node.last_used < 5000) ? 0.25f : 0.0f;

            node.probability = temporal + semantic + routing + attention;
            node.probability = std::min(node.probability, 1.0f);
        }
    }

    // ========================================================================
    // OPEN SLIDING DOORS
    // ========================================================================

    void open_sliding_doors() {
        for (auto& [id, node] : nodes_) {
            if (node.probability > kDoorOpenThreshold && node.door == DoorState::CLOSED) {
                node.door = DoorState::OPENING;
                node.state = Residency::PREDICTED;
            } else if (node.probability < kDoorCloseThreshold && node.door == DoorState::OPEN) {
                node.door = DoorState::CLOSING;
            }

            // Animate door transitions
            if (node.door == DoorState::OPENING) {
                node.door = DoorState::HALF_OPEN;
            } else if (node.door == DoorState::HALF_OPEN && node.state == Residency::ACTIVE) {
                node.door = DoorState::OPEN;
            } else if (node.door == DoorState::CLOSING) {
                if (node.state == Residency::UNWEIGHTED || node.state == Residency::ARCHIVED) {
                    node.door = DoorState::CLOSED;
                }
            }
        }
    }

    // ========================================================================
    // REVERSE DECODE — Reconstruct weights from latent
    // ========================================================================

    void reverse_decode() {
        for (auto& [id, node] : nodes_) {
            if (node.state != Residency::PREDICTED) continue;
            if (node.resident_weights != nullptr) continue;

            // Reconstruct weights from seed + latent
            node.resident_weights = node.reconstructor(node.seed.data(), node.latent);
            node.state = Residency::ACTIVE;
            active_bytes_ += node.bytes;
        }
    }

    // ========================================================================
    // APPLY RESIZEABLE LEARNING — Weight/unweight nodes
    // ========================================================================

    void apply_resizeable_learning(const RoutingDecision& decision) {
        // Weight up primary nodes
        for (auto& id : decision.primary_nodes) {
            auto it = nodes_.find(id);
            if (it == nodes_.end()) continue;
            auto& node = it->second;

            if (node.state == Residency::UNWEIGHTED || node.state == Residency::ARCHIVED) {
                node.state = Residency::TRANSITIONING;
                node.door = DoorState::OPENING;
            }

            // Animate weights toward full
            if (node.state == Residency::TRANSITIONING) {
                for (size_t i = 0; i < node.current_weights_sample.size(); i++) {
                    float diff = node.full_weights_sample[i] - node.current_weights_sample[i];
                    node.current_weights_sample[i] += diff * std::min(node.grow_rate, 1.0f);
                }
                // Check if fully weighted
                bool done = true;
                for (size_t i = 0; i < node.current_weights_sample.size(); i++) {
                    if (std::abs(node.current_weights_sample[i] - node.full_weights_sample[i]) > 0.001f) {
                        done = false; break;
                    }
                }
                if (done) {
                    node.current_weights_sample = node.full_weights_sample;
                    node.state = Residency::ACTIVE;
                }
            }

            node.last_used = now();
            node.use_count++;
        }

        // Partially weight secondary nodes
        for (auto& id : decision.secondary_nodes) {
            auto it = nodes_.find(id);
            if (it == nodes_.end()) continue;
            auto& node = it->second;

            if (node.state == Residency::UNWEIGHTED || node.state == Residency::ARCHIVED) {
                node.state = Residency::TRANSITIONING;
                node.door = DoorState::HALF_OPEN;
            }

            if (node.state == Residency::TRANSITIONING) {
                for (size_t i = 0; i < node.current_weights_sample.size(); i++) {
                    float diff = node.full_weights_sample[i] - node.current_weights_sample[i];
                    node.current_weights_sample[i] += diff * std::min(node.grow_rate * 0.3f, 1.0f);
                }
            }

            node.last_used = now();
        }

        // Unweight everything else
        for (auto& id : decision.unweighted_nodes) {
            auto it = nodes_.find(id);
            if (it == nodes_.end()) continue;
            auto& node = it->second;

            if (node.state == Residency::ACTIVE) {
                node.state = Residency::TRANSITIONING;
            }

            if (node.state == Residency::TRANSITIONING) {
                for (size_t i = 0; i < node.current_weights_sample.size(); i++) {
                    node.current_weights_sample[i] *= (1.0f - node.decay_rate);
                }
                // Check if fully unweighted
                bool done = true;
                for (size_t i = 0; i < node.current_weights_sample.size(); i++) {
                    if (std::abs(node.current_weights_sample[i]) > 0.001f) {
                        done = false; break;
                    }
                }
                if (done) {
                    std::fill(node.current_weights_sample.begin(), node.current_weights_sample.end(), 0.0f);
                    node.state = Residency::UNWEIGHTED;
                    node.door = DoorState::CLOSED;
                }
            }
        }

        // Recalculate active bytes
        active_bytes_ = 0;
        for (auto& [id, node] : nodes_) {
            if (node.state == Residency::ACTIVE) {
                active_bytes_ += node.bytes;
            }
        }
    }

    // ========================================================================
    // WRITE TO BOXES
    // ========================================================================

    void write_to_boxes(const std::string& input, const RoutingDecision& decision) {
        write_to_box("user", input);

        // Spawn reasoning box if needed
        if (decision.task_type == TaskType::REASONING || decision.task_type == TaskType::ANALYSIS) {
            std::string box_name = "reasoning_" + std::to_string(boxes_.size());
            add_box(box_name, BoxType::REASONING, 2048);
            write_to_box(box_name, "Reasoning about: " + input.substr(0, 100));
        }

        // Spawn plan box if needed
        if (decision.task_type == TaskType::PLANNING) {
            std::string box_name = "plan_" + std::to_string(boxes_.size());
            add_box(box_name, BoxType::PLAN, 2048);
            write_to_box(box_name, "Plan for: " + input.substr(0, 100));
        }

        // Write to knowledge box
        write_to_box("knowledge", "Task: " + task_name(decision.task_type));
    }

    // ========================================================================
    // PROCESS MESSAGES
    // ========================================================================

    void process_messages() {
        while (!message_queue_.empty()) {
            auto msg = message_queue_.front();
            message_queue_.pop();

            if (msg.recipient == "broadcast") {
                // Broadcast to all boxes
                for (auto& [name, tokens] : boxes_) {
                    write_to_box(name, "[" + msg.sender + "] " + msg.content);
                }
            } else {
                write_to_box(msg.recipient, "[" + msg.sender + "] " + msg.content);
            }
        }
    }

    // ========================================================================
    // COMPRESS COLD NODES
    // ========================================================================

    void compress_cold_nodes() {
        for (auto& [id, node] : nodes_) {
            if (node.state != Residency::ACTIVE) continue;
            if (now() - node.last_used < 30000) continue;  // < 30 seconds

            // Compress: ACTIVE → WARM
            node.state = Residency::WARM;
            if (node.destructor && node.resident_weights) {
                node.destructor(node.resident_weights);
                node.resident_weights = nullptr;
            }
        }
    }

    // ========================================================================
    // ARCHIVE DORMANT
    // ========================================================================

    void archive_dormant() {
        for (auto& [id, node] : nodes_) {
            if (node.state != Residency::WARM) continue;
            if (now() - node.last_used < 120000) continue;  // < 2 minutes

            // Archive: WARM → LATENT → ARCHIVED
            node.state = Residency::LATENT;
            node.door = DoorState::SEALED;
        }
    }

    // ========================================================================
    // DEFRAGMENT
    // ========================================================================

    void defragment() {
        // In production: compact memory, relocate active nodes to contiguous regions
        // For now: just update neighbor relationships based on co-activation
        for (auto& [id, node] : nodes_) {
            if (node.state == Residency::ACTIVE) {
                for (auto& [other_id, other] : nodes_) {
                    if (other.state == Residency::ACTIVE && other_id != id) {
                        // Add as neighbor if not already
                        if (std::find(node.neighbors.begin(), node.neighbors.end(), other_id)
                            == node.neighbors.end()) {
                            node.neighbors.push_back(other_id);
                        }
                    }
                }
            }
        }
    }

    // ========================================================================
    // PRELOAD NEXT CHAPTERS
    // ========================================================================

    void preload_next_chapters(const RoutingDecision& decision) {
        // Find chapters matching the current task
        std::vector<uint32_t> candidates;
        for (auto& [id, ch] : chapters_) {
            for (auto& kt : ch.knowledge_types) {
                if (kt == decision.task_type && ch.state == Residency::ARCHIVED) {
                    candidates.push_back(id);
                    break;
                }
            }
        }

        // Preload the next few
        size_t to_preload = std::min(candidates.size(), static_cast<size_t>(kPreloadAhead));
        for (size_t i = 0; i < to_preload; i++) {
            auto& ch = chapters_[candidates[i]];
            ch.state = Residency::PREDICTED;
            ch.last_used = now();

            // Create nodes for this chapter
            HashRNG ch_rng(std::hash<std::string>{}(ch.title));
            for (int n = 0; n < 4; n++) {
                uint64_t node_id = add_node(
                    ch.title + "_node_" + std::to_string(n),
                    "chapter_" + std::to_string(ch.id),
                    "ffn",
                    1'000'000'000 / 12,  // ~83M per node
                    0.7f,
                    BoxType::KNOWLEDGE,
                    "knowledge",
                    ch.id
                );
                nodes_[node_id].state = Residency::PREDICTED;
            }

            page_turns_++;
            preload_hits_++;
        }
    }

    // ========================================================================
    // COUNT RESIDENCY
    // ========================================================================

    uint64_t count_residency(Residency r) const {
        uint64_t count = 0;
        for (auto& [id, node] : nodes_) {
            if (node.state == r) count++;
        }
        return count;
    }

    // ========================================================================
    // MEMORY SAVINGS PCT
    // ========================================================================

    float memory_savings_pct() const {
        if (total_bytes_ == 0) return 0.0f;
        uint64_t active = 0;
        for (auto& [id, node] : nodes_) {
            if (node.state == Residency::ACTIVE) active += node.bytes;
        }
        return (1.0f - static_cast<float>(active) / static_cast<float>(total_bytes_)) * 100.0f;
    }
};

// ============================================================================
// DEMO
// ============================================================================

void run_demo() {
    printf("\n");
    printf("================================================================================\n");
    printf("  UNIFIED MEMORY FABRIC\n");
    printf("  Sliding Doors + Reverse Decode + Predictive Routing + Hierarchical Memory\n");
    printf("  + Resizeable Learning + Chatter Boxes + Sizeless Model + Never Ending Engine\n");
    printf("================================================================================\n");

    UnifiedMemoryFabric fabric;

    // Add some nodes
    fabric.add_node("embedding", "input", "embedding", 32000 * 768, 0.9f, BoxType::KNOWLEDGE, "knowledge");
    fabric.add_node("attention_early", "layers_0_3", "attention", 4 * 768 * 768, 0.8f);
    fabric.add_node("attention_mid", "layers_4_7", "attention", 4 * 768 * 768, 0.7f);
    fabric.add_node("attention_late", "layers_8_11", "attention", 4 * 768 * 768, 0.6f);
    fabric.add_node("ffn_early", "layers_0_3", "ffn", 4 * 768 * 3072, 0.7f);
    fabric.add_node("ffn_mid", "layers_4_7", "ffn", 4 * 768 * 3072, 0.8f);
    fabric.add_node("ffn_late", "layers_8_11", "ffn", 4 * 768 * 3072, 0.6f);
    fabric.add_node("output", "output", "output", 768 * 32000, 0.9f, BoxType::ASSISTANT, "assistant");

    fabric.print_summary();

    // Run inferences
    const char* inputs[] = {
        "Calculate the integral of x^2 from 0 to 1",
        "Write a Python function to sort a list",
        "Why is the sky blue? Explain in detail",
        "Plan a strategy for learning machine learning",
        "Tell me a short story about a robot",
    };

    printf("\n--------------------------------------------------------------------------------\n");
    printf("  Running %zu inferences through the Unified Memory Fabric\n", sizeof(inputs)/sizeof(inputs[0]));
    printf("--------------------------------------------------------------------------------\n");

    for (size_t i = 0; i < sizeof(inputs)/sizeof(inputs[0]); i++) {
        printf("\n  [%zu] Input: %s\n", i + 1, inputs[i]);
        auto result = fabric.infer(inputs[i]);
        printf("  %s\n", result.c_str());
    }

    // Generate a sizeless model
    printf("\n--------------------------------------------------------------------------------\n");
    printf("  Sizeless Model Generation — Same seed, different sizes\n");
    printf("--------------------------------------------------------------------------------\n");

    const char* sizes[] = {"100M", "1B", "7B", "70B"};
    for (auto& size : sizes) {
        auto report = fabric.generate_model("demo_seed", size, true);
        printf("  %s: %llu params, %.0fMB, %.0fms, ratio: %s\n",
               size,
               (unsigned long long)report.actual_params,
               report.memory_footprint_mb,
               report.generation_time_ms,
               report.seed_to_model_ratio.c_str());
    }

    // Add a new chapter (Never Ending)
    printf("\n--------------------------------------------------------------------------------\n");
    printf("  Never Ending — Add a new chapter\n");
    printf("--------------------------------------------------------------------------------\n");
    uint32_t ch_id = fabric.add_chapter(
        "Quantum Computing",
        {TaskType::KNOWLEDGE, TaskType::MATH, TaskType::REASONING},
        "Quantum gates, circuits, qubits, entanglement, quantum algorithms",
        {"quantum", "qubits", "gates", "circuits"}
    );
    printf("  Added Chapter %u: Quantum Computing\n", ch_id);

    // Final stats
    printf("\n--------------------------------------------------------------------------------\n");
    printf("  Final Statistics\n");
    printf("--------------------------------------------------------------------------------\n");
    fabric.print_summary();

    printf("\n  Signed: ~g87 | Version: umf-1.0 | RawrXD\n");
    printf("  One idea. One code. Every concept reverse engineered into a single fabric.\n");
}

// ============================================================================
// MAIN
// ============================================================================

int main() {
    run_demo();
    return 0;
}
