// =============================================================================
// CinematicVibeEngine.hpp — Kimi K2.6 Cinematic Vibe Engine
// =============================================================================
// Generates modern, high-conversion interfaces with automated selection of:
//   - Color palettes (based on project mood)
//   - Typography (font pairing)
//   - UX patterns (based on project type)
//   - Animation choreography
//   - Micro-interactions
//
// The engine analyzes the user's project description to determine a "vibe"
// and produces a complete design system specification that the Frontend
// Squad agents use to generate consistent UI components.
//
// Rule: NO SOURCE FILE IS TO BE SIMPLIFIED
// =============================================================================

#pragma once

#include "KimiSwarmRoles.hpp"
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>

namespace KimiSwarm {

// =============================================================================
// VIBE MOOD CLASSIFICATION
// =============================================================================

enum class VibeMood : uint8_t {
    Unknown        = 0,
    Professional   = 1,   // Corporate, B2B, SaaS dashboards
    Playful        = 2,   // Consumer apps, games, social
    Minimalist     = 3,   // Clean, focused, productivity tools
    Bold           = 4,   // Marketing, landing pages, startups
    Elegant        = 5,   // Luxury, fashion, premium services
    Technical      = 6,   // Developer tools, dashboards, data viz
    Warm           = 7,   // Community, education, healthcare
    Futuristic     = 8,   // AI, crypto, Web3, sci-fi
    Organic        = 9,   // Eco, wellness, natural products
    Dark           = 10   // Cybersecurity, gaming, dev tools
};

// =============================================================================
// DESIGN SYSTEM SPECIFICATION
// =============================================================================

struct ColorPalette {
    std::string name;
    std::string primary;        // Hex color
    std::string secondary;
    std::string accent;
    std::string background;
    std::string surface;
    std::string textPrimary;
    std::string textSecondary;
    std::string success;
    std::string warning;
    std::string error;
    std::string info;
    std::vector<std::string> gradientStops;  // For hero sections
};

struct TypographySpec {
    std::string headingFont;    // e.g. "Inter"
    std::string bodyFont;       // e.g. "Inter"
    std::string monoFont;       // e.g. "JetBrains Mono"
    std::string headingWeight;  // e.g. "700"
    std::string bodyWeight;     // e.g. "400"
    double      headingScale;   // 1.250 (major third) etc.
    double      bodyLineHeight; // 1.6
    std::string googleFontsUrl; // Pre-built URL for import
};

struct UXPattern {
    std::string name;           // e.g. "Bento Grid"
    std::string description;
    std::string component;      // Component name to generate
    std::string usage;          // When to use this pattern
    bool        responsive;     // Adapts to mobile
};

struct AnimationSpec {
    std::string name;           // e.g. "FadeInUp"
    std::string property;       // "opacity, transform"
    std::string from;           // "0, translateY(20px)"
    std::string to;             // "1, translateY(0)"
    std::string duration;       // "0.5s"
    std::string easing;         // "cubic-bezier(0.4, 0, 0.2, 1)"
    std::string trigger;        // "onMount", "onScroll", "onHover"
};

struct MicroInteraction {
    std::string element;        // "button", "input", "card"
    std::string interaction;    // "hover", "focus", "click"
    std::string effect;         // "scale(1.05)", "glow"
    std::string duration;       // "0.2s"
};

struct DesignSystem {
    VibeMood                       mood;
    std::string                    moodName;
    ColorPalette                   palette;
    TypographySpec                 typography;
    std::vector<UXPattern>         patterns;
    std::vector<AnimationSpec>     animations;
    std::vector<MicroInteraction>  microInteractions;
    std::string                    tailwindConfig;  // Generated Tailwind config
    std::string                    cssVariables;    // CSS custom properties
    std::string                    designTokens;    // JSON design tokens
    std::string                    rationale;       // Why these choices
};

// =============================================================================
// PROJECT MOOD ANALYZER
// =============================================================================

struct ProjectMoodAnalysis {
    VibeMood            detectedMood;
    double              confidence;          // 0.0-1.0
    std::vector<std::string> moodKeywords;  // Matched keywords
    std::string         projectType;         // "SaaS", "E-commerce", etc.
    std::string         targetAudience;
    std::string         brandPersonality;
    bool                isDarkModePreferred;
    bool                isMobileFirst;
};

// =============================================================================
// CINEMATIC VIBE ENGINE
// =============================================================================

class CinematicVibeEngine {
public:
    static CinematicVibeEngine& instance();

    // Analyze project description to determine mood
    ProjectMoodAnalysis analyzeMood(const std::string& projectDescription);

    // Generate complete design system from mood analysis
    DesignSystem generateDesignSystem(const ProjectMoodAnalysis& analysis);

    // One-shot: description → design system
    DesignSystem createVibe(const std::string& projectDescription);

    // Generate Tailwind config from design system
    std::string generateTailwindConfig(const DesignSystem& ds);

    // Generate CSS variables from design system
    std::string generateCSSVariables(const DesignSystem& ds);

    // Generate design tokens JSON
    std::string generateDesignTokens(const DesignSystem& ds);

    // Get palette for a specific mood
    ColorPalette getPaletteForMood(VibeMood mood);

    // Get typography for a specific mood
    TypographySpec getTypographyForMood(VibeMood mood);

    // Get UX patterns for project type
    std::vector<UXPattern> getPatternsForProjectType(const std::string& projectType);

    // Get animation choreography for mood
    std::vector<AnimationSpec> getAnimationsForMood(VibeMood mood);

    // Get micro-interactions for mood
    std::vector<MicroInteraction> getMicroInteractionsForMood(VibeMood mood);

    // Export design system as a prompt for Frontend Squad agents
    std::string exportAsPrompt(const DesignSystem& ds);

    // Export design system as a JSON spec
    std::string exportAsJson(const DesignSystem& ds);

private:
    CinematicVibeEngine();

    mutable std::mutex mutex_;

    // Mood keyword maps
    std::unordered_map<VibeMood, std::vector<std::string>> moodKeywords_;

    // Pre-built palettes per mood
    std::unordered_map<VibeMood, ColorPalette> palettes_;

    // Pre-built typography per mood
    std::unordered_map<VibeMood, TypographySpec> typography_;

    void initializeMoodKeywords();
    void initializePalettes();
    void initializeTypography();

    VibeMood classifyMood(const std::string& text, std::vector<std::string>& matched);
    std::string detectProjectType(const std::string& text);
    std::string detectAudience(const std::string& text);
    bool detectDarkModePreference(const std::string& text);
    bool detectMobileFirst(const std::string& text);
};

} // namespace KimiSwarm