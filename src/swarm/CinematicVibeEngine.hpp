#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>

namespace rawrxd {
namespace swarm {

// Color palette definition
struct ColorPalette {
    std::string name;
    std::string primary;
    std::string secondary;
    std::string accent;
    std::string background;
    std::string surface;
    std::string text;
    std::string textMuted;
    std::string success;
    std::string warning;
    std::string error;
    std::string info;
};

// Typography system
struct TypographySystem {
    std::string headingFont;
    std::string bodyFont;
    std::string monoFont;
    std::map<std::string, std::string> sizes; // h1, h2, h3, body, small, etc.
    std::map<std::string, std::string> weights;
    std::map<std::string, std::string> lineHeights;
};

// Spacing system
struct SpacingSystem {
    std::map<std::string, std::string> scale; // xs, sm, md, lg, xl, 2xl, etc.
    std::string baseUnit;
};

// Animation preset
struct AnimationPreset {
    std::string name;
    std::string duration;
    std::string easing;
    std::string properties;
    std::string keyframes;
};

// Design system container
struct DesignSystem {
    ColorPalette palette;
    TypographySystem typography;
    SpacingSystem spacing;
    std::vector<AnimationPreset> animations;
    std::map<std::string, std::string> shadows;
    std::map<std::string, std::string> borders;
    std::map<std::string, std::string> breakpoints;
    std::string theme; // "light", "dark", "auto"
};

// Vibe specification
struct VibeSpec {
    std::string name;
    std::string description;
    std::string mood; // "professional", "playful", "minimal", "bold", "elegant"
    std::string targetAudience;
    std::vector<std::string> keywords;
    std::vector<std::string> referenceSites;
    bool darkMode{false};
    bool animations{true};
    bool glassmorphism{false};
    bool neumorphism{false};
};

// Component style
struct ComponentStyle {
    std::string componentType;
    std::map<std::string, std::string> styles;
    std::map<std::string, std::string> states; // hover, active, disabled, etc.
    std::vector<std::string> animations;
};

// Cinematic Vibe Engine - Generates cohesive UI/UX design systems
class CinematicVibeEngine {
public:
    // Design system generation
    DesignSystem generateDesignSystem(const VibeSpec& spec);
    
    // Palette generators
    ColorPalette generatePalette(const std::string& mood, bool darkMode);
    ColorPalette generateMonochromePalette(const std::string& baseColor);
    ColorPalette generateComplementaryPalette(const std::string& primary);
    ColorPalette generateAnalogousPalette(const std::string& primary);
    
    // Typography
    TypographySystem generateTypography(const VibeSpec& spec);
    std::string selectHeadingFont(const std::string& mood);
    std::string selectBodyFont(const std::string& mood);
    
    // Spacing
    SpacingSystem generateSpacing(int density = 4); // 4, 8, 16px base
    
    // Animations
    std::vector<AnimationPreset> generateAnimations(const VibeSpec& spec);
    AnimationPreset generateFadeAnimation(const std::string& direction);
    AnimationPreset generateSlideAnimation(const std::string& direction);
    AnimationPreset generateScaleAnimation();
    AnimationPreset generatePulseAnimation();
    AnimationPreset generateShakeAnimation();
    
    // Component styles
    std::map<std::string, ComponentStyle> generateComponentStyles(const DesignSystem& system);
    ComponentStyle generateButtonStyle(const DesignSystem& system);
    ComponentStyle generateInputStyle(const DesignSystem& system);
    ComponentStyle generateCardStyle(const DesignSystem& system);
    ComponentStyle generateModalStyle(const DesignSystem& system);
    ComponentStyle generateNavigationStyle(const DesignSystem& system);
    
    // CSS generation
    std::string generateCSSVariables(const DesignSystem& system);
    std::string generateTailwindConfig(const DesignSystem& system);
    std::string generateStyledComponentsTheme(const DesignSystem& system);
    
    // Theme variants
    DesignSystem generateDarkVariant(const DesignSystem& light);
    DesignSystem generateHighContrastVariant(const DesignSystem& base);
    DesignSystem generateCompactVariant(const DesignSystem& base);
    
    // Vibe presets
    static VibeSpec ProfessionalVibe();
    static VibeSpec PlayfulVibe();
    static VibeSpec MinimalVibe();
    static VibeSpec BoldVibe();
    static VibeSpec ElegantVibe();
    static VibeSpec CyberpunkVibe();
    static VibeSpec NatureVibe();
    static VibeSpec LuxuryVibe();
};

} // namespace swarm
} // namespace rawrxd
