#include "CinematicVibeEngine.hpp"
#include <sstream>
#include <algorithm>
#include <cctype>

namespace rawrxd {
namespace swarm {

DesignSystem CinematicVibeEngine::generateDesignSystem(const VibeSpec& spec) {
    DesignSystem system;
    system.palette = generatePalette(spec.mood, spec.darkMode);
    system.typography = generateTypography(spec);
    system.spacing = generateSpacing(4);
    system.animations = generateAnimations(spec);
    system.theme = spec.darkMode ? "dark" : "light";
    
    // Shadows
    system.shadows["sm"] = "0 1px 2px 0 rgba(0, 0, 0, 0.05)";
    system.shadows["md"] = "0 4px 6px -1px rgba(0, 0, 0, 0.1)";
    system.shadows["lg"] = "0 10px 15px -3px rgba(0, 0, 0, 0.1)";
    system.shadows["xl"] = "0 20px 25px -5px rgba(0, 0, 0, 0.1)";
    
    // Borders
    system.borders["none"] = "0";
    system.borders["thin"] = "1px";
    system.borders["medium"] = "2px";
    system.borders["thick"] = "4px";
    
    // Breakpoints
    system.breakpoints["sm"] = "640px";
    system.breakpoints["md"] = "768px";
    system.breakpoints["lg"] = "1024px";
    system.breakpoints["xl"] = "1280px";
    system.breakpoints["2xl"] = "1536px";
    
    return system;
}

ColorPalette CinematicVibeEngine::generatePalette(const std::string& mood, bool darkMode) {
    ColorPalette palette;
    
    if (mood == "professional") {
        palette.primary = darkMode ? "#3b82f6" : "#2563eb";
        palette.secondary = darkMode ? "#64748b" : "#475569";
        palette.accent = "#8b5cf6";
        palette.background = darkMode ? "#0f172a" : "#ffffff";
        palette.surface = darkMode ? "#1e293b" : "#f8fafc";
        palette.text = darkMode ? "#f1f5f9" : "#0f172a";
        palette.textMuted = darkMode ? "#94a3b8" : "#64748b";
    } else if (mood == "playful") {
        palette.primary = "#f59e0b";
        palette.secondary = "#ec4899";
        palette.accent = "#8b5cf6";
        palette.background = darkMode ? "#1a1a2e" : "#fffbeb";
        palette.surface = darkMode ? "#16213e" : "#ffffff";
        palette.text = darkMode ? "#fef3c7" : "#1f2937";
        palette.textMuted = darkMode ? "#fde68a" : "#6b7280";
    } else if (mood == "minimal") {
        palette.primary = darkMode ? "#e5e5e5" : "#171717";
        palette.secondary = darkMode ? "#a3a3a3" : "#525252";
        palette.accent = darkMode ? "#ffffff" : "#000000";
        palette.background = darkMode ? "#0a0a0a" : "#ffffff";
        palette.surface = darkMode ? "#171717" : "#f5f5f5";
        palette.text = darkMode ? "#fafafa" : "#0a0a0a";
        palette.textMuted = darkMode ? "#737373" : "#737373";
    } else if (mood == "bold") {
        palette.primary = "#dc2626";
        palette.secondary = "#1f2937";
        palette.accent = "#fbbf24";
        palette.background = darkMode ? "#000000" : "#ffffff";
        palette.surface = darkMode ? "#1a1a1a" : "#f3f4f6";
        palette.text = darkMode ? "#ffffff" : "#111827";
        palette.textMuted = darkMode ? "#9ca3af" : "#6b7280";
    } else if (mood == "elegant") {
        palette.primary = darkMode ? "#d4af37" : "#b8860b";
        palette.secondary = darkMode ? "#4a4a4a" : "#2d2d2d";
        palette.accent = "#8b0000";
        palette.background = darkMode ? "#0a0a0a" : "#faf9f6";
        palette.surface = darkMode ? "#1a1a1a" : "#ffffff";
        palette.text = darkMode ? "#f5f5dc" : "#1a1a1a";
        palette.textMuted = darkMode ? "#a0a0a0" : "#666666";
    } else {
        // Default
        palette.primary = "#3b82f6";
        palette.secondary = "#64748b";
        palette.accent = "#8b5cf6";
        palette.background = darkMode ? "#0f172a" : "#ffffff";
        palette.surface = darkMode ? "#1e293b" : "#f8fafc";
        palette.text = darkMode ? "#f1f5f9" : "#0f172a";
        palette.textMuted = darkMode ? "#94a3b8" : "#64748b";
    }
    
    palette.success = "#22c55e";
    palette.warning = "#f59e0b";
    palette.error = "#ef4444";
    palette.info = "#3b82f6";
    
    return palette;
}

TypographySystem CinematicVibeEngine::generateTypography(const VibeSpec& spec) {
    TypographySystem typography;
    
    typography.headingFont = selectHeadingFont(spec.mood);
    typography.bodyFont = selectBodyFont(spec.mood);
    typography.monoFont = "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace";
    
    typography.sizes["h1"] = "2.25rem";
    typography.sizes["h2"] = "1.875rem";
    typography.sizes["h3"] = "1.5rem";
    typography.sizes["h4"] = "1.25rem";
    typography.sizes["body"] = "1rem";
    typography.sizes["small"] = "0.875rem";
    typography.sizes["xs"] = "0.75rem";
    
    typography.weights["light"] = "300";
    typography.weights["normal"] = "400";
    typography.weights["medium"] = "500";
    typography.weights["semibold"] = "600";
    typography.weights["bold"] = "700";
    
    typography.lineHeights["tight"] = "1.25";
    typography.lineHeights["normal"] = "1.5";
    typography.lineHeights["relaxed"] = "1.75";
    
    return typography;
}

std::string CinematicVibeEngine::selectHeadingFont(const std::string& mood) {
    if (mood == "professional") return "Inter, system-ui, sans-serif";
    if (mood == "playful") return "Poppins, system-ui, sans-serif";
    if (mood == "minimal") return "Inter, system-ui, sans-serif";
    if (mood == "bold") return "Montserrat, system-ui, sans-serif";
    if (mood == "elegant") return "Playfair Display, Georgia, serif";
    return "Inter, system-ui, sans-serif";
}

std::string CinematicVibeEngine::selectBodyFont(const std::string& mood) {
    if (mood == "professional") return "Inter, system-ui, sans-serif";
    if (mood == "playful") return "Nunito, system-ui, sans-serif";
    if (mood == "minimal") return "Inter, system-ui, sans-serif";
    if (mood == "bold") return "Roboto, system-ui, sans-serif";
    if (mood == "elegant") return "Lora, Georgia, serif";
    return "Inter, system-ui, sans-serif";
}

SpacingSystem CinematicVibeEngine::generateSpacing(int density) {
    SpacingSystem spacing;
    spacing.baseUnit = std::to_string(density) + "px";
    
    spacing.scale["0"] = "0";
    spacing.scale["xs"] = std::to_string(density) + "px";
    spacing.scale["sm"] = std::to_string(density * 2) + "px";
    spacing.scale["md"] = std::to_string(density * 4) + "px";
    spacing.scale["lg"] = std::to_string(density * 6) + "px";
    spacing.scale["xl"] = std::to_string(density * 8) + "px";
    spacing.scale["2xl"] = std::to_string(density * 12) + "px";
    spacing.scale["3xl"] = std::to_string(density * 16) + "px";
    spacing.scale["4xl"] = std::to_string(density * 24) + "px";
    
    return spacing;
}

std::vector<AnimationPreset> CinematicVibeEngine::generateAnimations(const VibeSpec& spec) {
    std::vector<AnimationPreset> animations;
    
    if (spec.animations) {
        animations.push_back(generateFadeAnimation("in"));
        animations.push_back(generateFadeAnimation("out"));
        animations.push_back(generateSlideAnimation("up"));
        animations.push_back(generateSlideAnimation("down"));
        animations.push_back(generateScaleAnimation());
        
        if (spec.mood == "playful") {
            animations.push_back(generatePulseAnimation());
            animations.push_back(generateShakeAnimation());
        }
    }
    
    return animations;
}

AnimationPreset CinematicVibeEngine::generateFadeAnimation(const std::string& direction) {
    AnimationPreset anim;
    anim.name = "fade-" + direction;
    anim.duration = "300ms";
    anim.easing = "ease-in-out";
    anim.properties = "opacity";
    anim.keyframes = direction == "in" 
        ? "from { opacity: 0; } to { opacity: 1; }"
        : "from { opacity: 1; } to { opacity: 0; }";
    return anim;
}

AnimationPreset CinematicVibeEngine::generateSlideAnimation(const std::string& direction) {
    AnimationPreset anim;
    anim.name = "slide-" + direction;
    anim.duration = "300ms";
    anim.easing = "cubic-bezier(0.4, 0, 0.2, 1)";
    anim.properties = "transform, opacity";
    
    std::string transform;
    if (direction == "up") transform = "translateY(20px)";
    else if (direction == "down") transform = "translateY(-20px)";
    else if (direction == "left") transform = "translateX(20px)";
    else if (direction == "right") transform = "translateX(-20px)";
    
    anim.keyframes = "from { transform: " + transform + "; opacity: 0; } to { transform: none; opacity: 1; }";
    return anim;
}

AnimationPreset CinematicVibeEngine::generateScaleAnimation() {
    AnimationPreset anim;
    anim.name = "scale";
    anim.duration = "200ms";
    anim.easing = "ease-out";
    anim.properties = "transform";
    anim.keyframes = "from { transform: scale(0.95); } to { transform: scale(1); }";
    return anim;
}

AnimationPreset CinematicVibeEngine::generatePulseAnimation() {
    AnimationPreset anim;
    anim.name = "pulse";
    anim.duration = "2s";
    anim.easing = "ease-in-out";
    anim.properties = "opacity";
    anim.keyframes = "0%, 100% { opacity: 1; } 50% { opacity: 0.5; }";
    return anim;
}

AnimationPreset CinematicVibeEngine::generateShakeAnimation() {
    AnimationPreset anim;
    anim.name = "shake";
    anim.duration = "500ms";
    anim.easing = "ease-in-out";
    anim.properties = "transform";
    anim.keyframes = "0%, 100% { transform: translateX(0); } 25% { transform: translateX(-5px); } 75% { transform: translateX(5px); }";
    return anim;
}

std::string CinematicVibeEngine::generateCSSVariables(const DesignSystem& system) {
    std::stringstream css;
    css << ":root {\n";
    
    // Colors
    css << "  --color-primary: " << system.palette.primary << ";\n";
    css << "  --color-secondary: " << system.palette.secondary << ";\n";
    css << "  --color-accent: " << system.palette.accent << ";\n";
    css << "  --color-background: " << system.palette.background << ";\n";
    css << "  --color-surface: " << system.palette.surface << ";\n";
    css << "  --color-text: " << system.palette.text << ";\n";
    css << "  --color-text-muted: " << system.palette.textMuted << ";\n";
    css << "  --color-success: " << system.palette.success << ";\n";
    css << "  --color-warning: " << system.palette.warning << ";\n";
    css << "  --color-error: " << system.palette.error << ";\n";
    css << "  --color-info: " << system.palette.info << ";\n";
    
    css << "}\n";
    return css.str();
}

std::string CinematicVibeEngine::generateTailwindConfig(const DesignSystem& system) {
    std::stringstream config;
    config << "module.exports = {\n";
    config << "  theme: {\n";
    config << "    extend: {\n";
    config << "      colors: {\n";
    config << "        primary: '" << system.palette.primary << "',\n";
    config << "        secondary: '" << system.palette.secondary << "',\n";
    config << "        accent: '" << system.palette.accent << "',\n";
    config << "      },\n";
    config << "      fontFamily: {\n";
    config << "        heading: ['" << system.typography.headingFont << "'],\n";
    config << "        body: ['" << system.typography.bodyFont << "'],\n";
    config << "      },\n";
    config << "    },\n";
    config << "  },\n";
    config << "};\n";
    return config.str();
}

VibeSpec CinematicVibeEngine::ProfessionalVibe() {
    VibeSpec spec;
    spec.name = "Professional";
    spec.mood = "professional";
    spec.description = "Clean, trustworthy, business-focused";
    spec.darkMode = false;
    spec.animations = true;
    return spec;
}

VibeSpec CinematicVibeEngine::MinimalVibe() {
    VibeSpec spec;
    spec.name = "Minimal";
    spec.mood = "minimal";
    spec.description = "Stripped down, focused, essential";
    spec.darkMode = false;
    spec.animations = false;
    return spec;
}

VibeSpec CinematicVibeEngine::PlayfulVibe() {
    VibeSpec spec;
    spec.name = "Playful";
    spec.mood = "playful";
    spec.description = "Fun, energetic, approachable";
    spec.darkMode = false;
    spec.animations = true;
    return spec;
}

VibeSpec CinematicVibeEngine::BoldVibe() {
    VibeSpec spec;
    spec.name = "Bold";
    spec.mood = "bold";
    spec.description = "Strong, confident, impactful";
    spec.darkMode = false;
    spec.animations = true;
    return spec;
}

VibeSpec CinematicVibeEngine::ElegantVibe() {
    VibeSpec spec;
    spec.name = "Elegant";
    spec.mood = "elegant";
    spec.description = "Sophisticated, refined, luxurious";
    spec.darkMode = true;
    spec.animations = true;
    return spec;
}

VibeSpec CinematicVibeEngine::CyberpunkVibe() {
    VibeSpec spec;
    spec.name = "Cyberpunk";
    spec.mood = "bold";
    spec.description = "Neon, futuristic, edgy";
    spec.darkMode = true;
    spec.animations = true;
    spec.glassmorphism = true;
    return spec;
}

VibeSpec CinematicVibeEngine::NatureVibe() {
    VibeSpec spec;
    spec.name = "Nature";
    spec.mood = "playful";
    spec.description = "Organic, calming, earthy";
    spec.darkMode = false;
    spec.animations = true;
    return spec;
}

VibeSpec CinematicVibeEngine::LuxuryVibe() {
    VibeSpec spec;
    spec.name = "Luxury";
    spec.mood = "elegant";
    spec.description = "Premium, exclusive, high-end";
    spec.darkMode = true;
    spec.animations = true;
    return spec;
}

} // namespace swarm
} // namespace rawrxd
