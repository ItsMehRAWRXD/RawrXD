// =============================================================================
// CinematicVibeEngine.cpp — Kimi K2.6 Cinematic Vibe Engine Implementation
// =============================================================================
// Rule: NO SOURCE FILE IS TO BE SIMPLIFIED
// =============================================================================

#include "CinematicVibeEngine.hpp"
#include <algorithm>
#include <cctype>
#include <sstream>
#include <chrono>
#include <random>

namespace KimiSwarm {

// =============================================================================
// SINGLETON
// =============================================================================

CinematicVibeEngine& CinematicVibeEngine::instance() {
    static CinematicVibeEngine inst;
    return inst;
}

CinematicVibeEngine::CinematicVibeEngine() {
    initializeMoodKeywords();
    initializePalettes();
    initializeTypography();
}

// =============================================================================
// MOOD KEYWORD INITIALIZATION
// =============================================================================

void CinematicVibeEngine::initializeMoodKeywords() {
    moodKeywords_[VibeMood::Professional] = {
        "enterprise", "corporate", "business", "b2b", "saas", "dashboard",
        "analytics", "report", "management", "crm", "erp", "workflow",
        "office", "professional", "formal", "trust", "reliable"
    };
    moodKeywords_[VibeMood::Playful] = {
        "fun", "game", "play", "social", "casual", "colorful", "emoji",
        "entertainment", "kids", "party", "creative", "quirky", "joyful"
    };
    moodKeywords_[VibeMood::Minimalist] = {
        "minimal", "clean", "simple", "focus", "productivity", "todo",
        "notes", "zen", "sparse", "essential", "clutter-free", "distraction"
    };
    moodKeywords_[VibeMood::Bold] = {
        "startup", "launch", "marketing", "landing", "hero", "bold",
        "vibrant", "conversion", "growth", "disruptive", "innovative",
        "standout", "impactful", "striking"
    };
    moodKeywords_[VibeMood::Elegant] = {
        "luxury", "premium", "fashion", "elegant", "sophisticated",
        "boutique", "high-end", "refined", "exclusive", "designer",
        "couture", "beauty", "spa"
    };
    moodKeywords_[VibeMood::Technical] = {
        "developer", "api", "code", "technical", "documentation", "ide",
        "compiler", "debugger", "terminal", "devops", "ci/cd", "monitoring",
        "infrastructure", "kubernetes", "docker"
    };
    moodKeywords_[VibeMood::Warm] = {
        "community", "education", "learning", "course", "healthcare",
        "wellness", "care", "support", "friendly", "warm", "welcome",
        "nonprofit", "charity", "family"
    };
    moodKeywords_[VibeMood::Futuristic] = {
        "ai", "artificial intelligence", "machine learning", "crypto",
        "blockchain", "web3", "future", "futuristic", "metaverse",
        "robotics", "autonomous", "neural", "quantum", "space"
    };
    moodKeywords_[VibeMood::Organic] = {
        "eco", "organic", "natural", "green", "sustainable", "environment",
        "plant", "garden", "farm", "bio", "recycle", "climate", "earth"
    };
    moodKeywords_[VibeMood::Dark] = {
        "security", "cyber", "hacker", "dark", "gaming", "nocturnal",
        "stealth", "encrypted", "pentest", "forensics", "malware",
        "reverse engineering", "underground"
    };
}

// =============================================================================
// PALETTE INITIALIZATION
// =============================================================================

void CinematicVibeEngine::initializePalettes() {
    palettes_[VibeMood::Professional] = {
        "Corporate Blue", "#2563EB", "#1E40AF", "#3B82F6",
        "#F8FAFC", "#FFFFFF", "#0F172A", "#64748B",
        "#10B981", "#F59E0B", "#EF4444", "#3B82F6",
        {"#1E40AF", "#2563EB", "#3B82F6", "#60A5FA"}
    };
    palettes_[VibeMood::Playful] = {
        "Rainbow Pop", "#EC4899", "#8B5CF6", "#F59E0B",
        "#FFF9F0", "#FFFFFF", "#1F2937", "#6B7280",
        "#10B981", "#F59E0B", "#EF4444", "#3B82F6",
        {"#EC4899", "#8B5CF6", "#6366F1", "#3B82F6"}
    };
    palettes_[VibeMood::Minimalist] = {
        "Monochrome Zen", "#000000", "#374151", "#6B7280",
        "#FFFFFF", "#FAFAFA", "#111827", "#9CA3AF",
        "#059669", "#D97706", "#DC2626", "#2563EB",
        {"#F3F4F6", "#E5E7EB", "#D1D5DB", "#9CA3AF"}
    };
    palettes_[VibeMood::Bold] = {
        "Electric Startup", "#7C3AED", "#DC2626", "#F59E0B",
        "#0F0F0F", "#1A1A1A", "#FFFFFF", "#A1A1AA",
        "#10B981", "#F59E0B", "#EF4444", "#3B82F6",
        {"#7C3AED", "#DC2626", "#F59E0B", "#10B981"}
    };
    palettes_[VibeMood::Elegant] = {
        "Golden Luxury", "#B8860B", "#1A1A1A", "#D4AF37",
        "#FAFAFA", "#F5F5F0", "#1A1A1A", "#6B6B6B",
        "#556B2F", "#CD853F", "#8B0000", "#4682B4",
        {"#1A1A1A", "#B8860B", "#D4AF37", "#F5F5F0"}
    };
    palettes_[VibeMood::Technical] = {
        "Terminal Green", "#10B981", "#059669", "#34D399",
        "#0F172A", "#1E293B", "#E2E8F0", "#94A3B8",
        "#22C55E", "#EAB308", "#EF4444", "#3B82F6",
        {"#0F172A", "#1E293B", "#10B981", "#34D399"}
    };
    palettes_[VibeMood::Warm] = {
        "Sunset Warmth", "#EA580C", "#C2410C", "#FB923C",
        "#FFFBEB", "#FFF7ED", "#431407", "#9A3412",
        "#16A34A", "#EAB308", "#DC2626", "#0284C7",
        {"#EA580C", "#FB923C", "#FCD34D", "#FEF3C7"}
    };
    palettes_[VibeMood::Futuristic] = {
        "Neon Cyber", "#00FFFF", "#FF00FF", "#00FF88",
        "#0A0A0F", "#12121F", "#E0E0FF", "#8888BB",
        "#00FF88", "#FFAA00", "#FF0044", "#00CCFF",
        {"#0A0A0F", "#00FFFF", "#FF00FF", "#00FF88"}
    };
    palettes_[VibeMood::Organic] = {
        "Forest Green", "#16A34A", "#15803D", "#22C55E",
        "#F0FDF4", "#F7Fee7", "#14532D", "#4D7C0F",
        "#16A34A", "#CA8A04", "#DC2626", "#2563EB",
        {"#14532D", "#16A34A", "#22C55E", "#86EFAC"}
    };
    palettes_[VibeMood::Dark] = {
        "Midnight Ops", "#DC2626", "#991B1B", "#EF4444",
        "#09090B", "#18181B", "#FAFAFA", "#A1A1AA",
        "#22C55E", "#EAB308", "#EF4444", "#3B82F6",
        {"#09090B", "#18181B", "#DC2626", "#EF4444"}
    };
}

// =============================================================================
// TYPOGRAPHY INITIALIZATION
// =============================================================================

void CinematicVibeEngine::initializeTypography() {
    typography_[VibeMood::Professional] = {
        "Inter", "Inter", "JetBrains Mono", "700", "400",
        1.250, 1.6,
        "https://fonts.googleapis.com/css2?family=Inter:wght@400;700&family=JetBrains+Mono&display=swap"
    };
    typography_[VibeMood::Playful] = {
        "Poppins", "Nunito", "Fira Code", "800", "400",
        1.333, 1.7,
        "https://fonts.googleapis.com/css2?family=Poppins:wght@400;800&family=Nunito:wght@400;700&family=Fira+Code&display=swap"
    };
    typography_[VibeMood::Minimalist] = {
        "Inter", "Inter", "JetBrains Mono", "600", "300",
        1.200, 1.8,
        "https://fonts.googleapis.com/css2?family=Inter:wght@300;600&family=JetBrains+Mono&display=swap"
    };
    typography_[VibeMood::Bold] = {
        "Space Grotesk", "Inter", "JetBrains Mono", "700", "400",
        1.414, 1.6,
        "https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;700&family=Inter:wght@400;700&family=JetBrains+Mono&display=swap"
    };
    typography_[VibeMood::Elegant] = {
        "Playfair Display", "Lora", "Cormorant Garamond", "600", "400",
        1.333, 1.8,
        "https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;600&family=Lora:wght@400;500&family=Cormorant+Garamond:wght@400;600&display=swap"
    };
    typography_[VibeMood::Technical] = {
        "JetBrains Mono", "Inter", "JetBrains Mono", "600", "400",
        1.250, 1.5,
        "https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Inter:wght@400;600&display=swap"
    };
    typography_[VibeMood::Warm] = {
        "Nunito", "Nunito", "Fira Code", "700", "400",
        1.250, 1.7,
        "https://fonts.googleapis.com/css2?family=Nunito:wght@400;700&family=Fira+Code&display=swap"
    };
    typography_[VibeMood::Futuristic] = {
        "Orbitron", "Rajdhani", "Share Tech Mono", "700", "400",
        1.333, 1.5,
        "https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&family=Rajdhani:wght@400;600&family=Share+Tech+Mono&display=swap"
    };
    typography_[VibeMood::Organic] = {
        "DM Serif Display", "DM Sans", "Fira Code", "400", "400",
        1.250, 1.7,
        "https://fonts.googleapis.com/css2?family=DM+Serif+Display&family=DM+Sans:wght@400;500&family=Fira+Code&display=swap"
    };
    typography_[VibeMood::Dark] = {
        "IBM Plex Mono", "IBM Plex Sans", "IBM Plex Mono", "600", "400",
        1.250, 1.5,
        "https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@400;600&display=swap"
    };
}

// =============================================================================
// MOOD ANALYSIS
// =============================================================================

static std::string toLower(const std::string& s) {
    std::string result = s;
    std::transform(result.begin(), result.end(), result.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return result;
}

VibeMood CinematicVibeEngine::classifyMood(const std::string& text,
                                            std::vector<std::string>& matched) {
    std::string lower = toLower(text);
    VibeMood bestMood = VibeMood::Professional;
    uint32_t bestScore = 0;

    for (const auto& [mood, keywords] : moodKeywords_) {
        uint32_t score = 0;
        for (const auto& kw : keywords) {
            if (lower.find(kw) != std::string::npos) {
                score++;
                matched.push_back(kw);
            }
        }
        if (score > bestScore) {
            bestScore = score;
            bestMood = mood;
        }
    }

    // Remove duplicates from matched
    std::sort(matched.begin(), matched.end());
    matched.erase(std::unique(matched.begin(), matched.end()), matched.end());

    return bestMood;
}

std::string CinematicVibeEngine::detectProjectType(const std::string& text) {
    std::string lower = toLower(text);
    if (lower.find("dashboard") != std::string::npos || lower.find("analytics") != std::string::npos)
        return "Dashboard";
    if (lower.find("e-commerce") != std::string::npos || lower.find("shop") != std::string::npos || lower.find("store") != std::string::npos)
        return "E-commerce";
    if (lower.find("social") != std::string::npos)
        return "Social Platform";
    if (lower.find("blog") != std::string::npos || lower.find("cms") != std::string::npos)
        return "Content Platform";
    if (lower.find("api") != std::string::npos)
        return "API Service";
    if (lower.find("game") != std::string::npos)
        return "Game";
    if (lower.find("education") != std::string::npos || lower.find("course") != std::string::npos || lower.find("learning") != std::string::npos)
        return "Education Platform";
    if (lower.find("saas") != std::string::npos)
        return "SaaS Application";
    return "Web Application";
}

std::string CinematicVibeEngine::detectAudience(const std::string& text) {
    std::string lower = toLower(text);
    if (lower.find("enterprise") != std::string::npos || lower.find("b2b") != std::string::npos)
        return "Enterprise/Business";
    if (lower.find("consumer") != std::string::npos || lower.find("b2c") != std::string::npos)
        return "Consumer";
    if (lower.find("developer") != std::string::npos)
        return "Developers";
    if (lower.find("kids") != std::string::npos || lower.find("children") != std::string::npos)
        return "Children";
    return "General Audience";
}

bool CinematicVibeEngine::detectDarkModePreference(const std::string& text) {
    std::string lower = toLower(text);
    return lower.find("dark") != std::string::npos ||
           lower.find("dark mode") != std::string::npos ||
           lower.find("night") != std::string::npos ||
           lower.find("cyber") != std::string::npos ||
           lower.find("security") != std::string::npos;
}

bool CinematicVibeEngine::detectMobileFirst(const std::string& text) {
    std::string lower = toLower(text);
    return lower.find("mobile") != std::string::npos ||
           lower.find("responsive") != std::string::npos ||
           lower.find("app") != std::string::npos;
}

ProjectMoodAnalysis CinematicVibeEngine::analyzeMood(const std::string& projectDescription) {
    std::lock_guard<std::mutex> lock(mutex_);

    ProjectMoodAnalysis analysis;
    std::vector<std::string> matched;
    analysis.detectedMood = classifyMood(projectDescription, matched);
    analysis.moodKeywords = matched;
    analysis.confidence = std::min(1.0, 0.3 + (matched.size() * 0.15));
    analysis.projectType = detectProjectType(projectDescription);
    analysis.targetAudience = detectAudience(projectDescription);
    analysis.isDarkModePreferred = detectDarkModePreference(projectDescription);
    analysis.isMobileFirst = detectMobileFirst(projectDescription);

    static const char* moodNames[] = {
        "Unknown", "Professional", "Playful", "Minimalist", "Bold",
        "Elegant", "Technical", "Warm", "Futuristic", "Organic", "Dark"
    };
    analysis.brandPersonality = moodNames[static_cast<int>(analysis.detectedMood)];

    return analysis;
}

// =============================================================================
// DESIGN SYSTEM GENERATION
// =============================================================================

ColorPalette CinematicVibeEngine::getPaletteForMood(VibeMood mood) {
    auto it = palettes_.find(mood);
    if (it != palettes_.end()) return it->second;
    return palettes_[VibeMood::Professional];
}

TypographySpec CinematicVibeEngine::getTypographyForMood(VibeMood mood) {
    auto it = typography_.find(mood);
    if (it != typography_.end()) return it->second;
    return typography_[VibeMood::Professional];
}

std::vector<UXPattern> CinematicVibeEngine::getPatternsForProjectType(const std::string& projectType) {
    std::vector<UXPattern> patterns;

    if (projectType == "Dashboard" || projectType == "SaaS Application") {
        patterns.push_back({"Bento Grid", "Grid-based dashboard layout", "DashboardGrid", "Main dashboard view", true});
        patterns.push_back({"Data Table", "Sortable, filterable table", "DataTable", "List views", true});
        patterns.push_back({"Sidebar Navigation", "Collapsible sidebar", "Sidebar", "App navigation", true});
        patterns.push_back({"Card Stack", "Stacked info cards", "CardStack", "Metrics display", true});
    } else if (projectType == "E-commerce") {
        patterns.push_back({"Product Grid", "Responsive product cards", "ProductGrid", "Product listing", true});
        patterns.push_back({"Shopping Cart Drawer", "Slide-out cart", "CartDrawer", "Cart access", true});
        patterns.push_back({"Product Detail", "Image gallery + specs", "ProductDetail", "Product page", true});
        patterns.push_back({"Checkout Wizard", "Multi-step checkout", "CheckoutWizard", "Purchase flow", true});
    } else if (projectType == "Landing Page" || projectType == "Web Application") {
        patterns.push_back({"Hero Section", "Full-width hero with CTA", "HeroSection", "Above the fold", true});
        patterns.push_back({"Feature Grid", "3-column feature cards", "FeatureGrid", "Value props", true});
        patterns.push_back({"Testimonial Carousel", "Auto-rotating testimonials", "TestimonialCarousel", "Social proof", true});
        patterns.push_back({"Pricing Table", "Tiered pricing cards", "PricingTable", "Conversion", true});
    } else {
        patterns.push_back({"Hero Section", "Full-width hero", "HeroSection", "Landing", true});
        patterns.push_back({"Content Grid", "Responsive grid", "ContentGrid", "Main content", true});
        patterns.push_back({"Footer", "Multi-column footer", "Footer", "Page bottom", true});
    }

    patterns.push_back({"Navigation Bar", "Sticky top navigation", "NavBar", "Primary nav", true});
    patterns.push_back({"Modal Dialog", "Overlay dialog", "Modal", "Confirmations", true});
    patterns.push_back({"Toast Notifications", "Stacked toasts", "ToastContainer", "Feedback", true});

    return patterns;
}

std::vector<AnimationSpec> CinematicVibeEngine::getAnimationsForMood(VibeMood mood) {
    std::vector<AnimationSpec> anims;

    // Common animations for all moods
    anims.push_back({"FadeIn", "opacity", "0", "1", "0.3s", "ease-out", "onMount"});
    anims.push_back({"SlideInRight", "transform", "translateX(100%)", "translateX(0)", "0.4s", "cubic-bezier(0.4, 0, 0.2, 1)", "onMount"});

    switch (mood) {
        case VibeMood::Bold:
        case VibeMood::Futuristic:
            anims.push_back({"ScaleIn", "transform", "scale(0.8)", "scale(1)", "0.5s", "cubic-bezier(0.34, 1.56, 0.64, 1)", "onMount"});
            anims.push_back({"Glow", "boxShadow", "0 0 0px rgba(0,255,255,0)", "0 0 20px rgba(0,255,255,0.5)", "2s", "ease-in-out", "onHover"});
            anims.push_back({"GradientShift", "backgroundPosition", "0% 50%", "100% 50%", "3s", "linear", "onMount"});
            break;
        case VibeMood::Elegant:
            anims.push_back({"FadeInUp", "opacity, transform", "0, translateY(30px)", "1, translateY(0)", "0.8s", "cubic-bezier(0.16, 1, 0.3, 1)", "onScroll"});
            anims.push_back({"LetterSpacing", "letterSpacing", "0.5em", "0.1em", "1.5s", "ease-out", "onMount"});
            break;
        case VibeMood::Playful:
            anims.push_back({"BounceIn", "transform", "scale(0) rotate(-180deg)", "scale(1) rotate(0)", "0.6s", "cubic-bezier(0.68, -0.55, 0.265, 1.55)", "onMount"});
            anims.push_back({"Wiggle", "transform", "rotate(0deg)", "rotate(3deg)", "0.3s", "ease-in-out", "onHover"});
            break;
        case VibeMood::Minimalist:
            anims.push_back({"SubtleFade", "opacity", "0", "1", "0.5s", "ease", "onScroll"});
            anims.push_back({"Underline", "width", "0%", "100%", "0.3s", "ease-out", "onHover"});
            break;
        default:
            anims.push_back({"FadeInUp", "opacity, transform", "0, translateY(20px)", "1, translateY(0)", "0.5s", "cubic-bezier(0.4, 0, 0.2, 1)", "onMount"});
            break;
    }

    return anims;
}

std::vector<MicroInteraction> CinematicVibeEngine::getMicroInteractionsForMood(VibeMood mood) {
    std::vector<MicroInteraction> interactions;

    interactions.push_back({"button", "hover", "scale(1.05)", "0.2s"});
    interactions.push_back({"button", "click", "scale(0.95)", "0.1s"});
    interactions.push_back({"input", "focus", "borderColor: primary", "0.2s"});
    interactions.push_back({"card", "hover", "translateY(-4px) + shadow", "0.3s"});

    switch (mood) {
        case VibeMood::Futuristic:
            interactions.push_back({"button", "hover", "glow + scale(1.05)", "0.3s"});
            interactions.push_back({"card", "hover", "borderGlow + scale(1.02)", "0.3s"});
            break;
        case VibeMood::Playful:
            interactions.push_back({"button", "hover", "wiggle + scale(1.1)", "0.3s"});
            interactions.push_back({"icon", "hover", "rotate(15deg)", "0.2s"});
            break;
        case VibeMood::Elegant:
            interactions.push_back({"link", "hover", "underline expand", "0.4s"});
            interactions.push_back({"card", "hover", "lift + golden border", "0.5s"});
            break;
        default:
            break;
    }

    return interactions;
}

DesignSystem CinematicVibeEngine::generateDesignSystem(const ProjectMoodAnalysis& analysis) {
    std::lock_guard<std::mutex> lock(mutex_);

    DesignSystem ds;
    ds.mood = analysis.detectedMood;

    static const char* moodNames[] = {
        "Unknown", "Professional", "Playful", "Minimalist", "Bold",
        "Elegant", "Technical", "Warm", "Futuristic", "Organic", "Dark"
    };
    ds.moodName = moodNames[static_cast<int>(analysis.detectedMood)];

    ds.palette = getPaletteForMood(analysis.detectedMood);
    ds.typography = getTypographyForMood(analysis.detectedMood);
    ds.patterns = getPatternsForProjectType(analysis.projectType);
    ds.animations = getAnimationsForMood(analysis.detectedMood);
    ds.microInteractions = getMicroInteractionsForMood(analysis.detectedMood);

    ds.tailwindConfig = generateTailwindConfig(ds);
    ds.cssVariables = generateCSSVariables(ds);
    ds.designTokens = generateDesignTokens(ds);

    std::ostringstream rationale;
    rationale << "Mood: " << ds.moodName << " (confidence: " << analysis.confidence << ")\n"
              << "Project type: " << analysis.projectType << "\n"
              << "Target audience: " << analysis.targetAudience << "\n"
              << "Dark mode: " << (analysis.isDarkModePreferred ? "preferred" : "not required") << "\n"
              << "Mobile-first: " << (analysis.isMobileFirst ? "yes" : "no") << "\n"
              << "Palette: " << ds.palette.name << "\n"
              << "Typography: " << ds.typography.headingFont << " / " << ds.typography.bodyFont << "\n"
              << "Patterns: " << ds.patterns.size() << " UX patterns selected\n"
              << "Animations: " << ds.animations.size() << " choreographed\n"
              << "Micro-interactions: " << ds.microInteractions.size() << " defined";
    ds.rationale = rationale.str();

    return ds;
}

DesignSystem CinematicVibeEngine::createVibe(const std::string& projectDescription) {
    auto analysis = analyzeMood(projectDescription);
    return generateDesignSystem(analysis);
}

// =============================================================================
// EXPORT FORMATS
// =============================================================================

std::string CinematicVibeEngine::generateTailwindConfig(const DesignSystem& ds) {
    std::ostringstream cfg;
    cfg << "/** Tailwind Config — Auto-generated by Cinematic Vibe Engine **/\n"
        << "/** Mood: " << ds.moodName << " **/\n\n"
        << "module.exports = {\n"
        << "  theme: {\n"
        << "    extend: {\n"
        << "      colors: {\n"
        << "        primary: '" << ds.palette.primary << "',\n"
        << "        secondary: '" << ds.palette.secondary << "',\n"
        << "        accent: '" << ds.palette.accent << "',\n"
        << "        background: '" << ds.palette.background << "',\n"
        << "        surface: '" << ds.palette.surface << "',\n"
        << "        'text-primary': '" << ds.palette.textPrimary << "',\n"
        << "        'text-secondary': '" << ds.palette.textSecondary << "',\n"
        << "        success: '" << ds.palette.success << "',\n"
        << "        warning: '" << ds.palette.warning << "',\n"
        << "        error: '" << ds.palette.error << "',\n"
        << "        info: '" << ds.palette.info << "',\n"
        << "      },\n"
        << "      fontFamily: {\n"
        << "        heading: ['" << ds.typography.headingFont << "', 'sans-serif'],\n"
        << "        body: ['" << ds.typography.bodyFont << "', 'sans-serif'],\n"
        << "        mono: ['" << ds.typography.monoFont << "', 'monospace'],\n"
        << "      },\n"
        << "      animation: {\n";
    for (size_t i = 0; i < ds.animations.size(); ++i) {
        const auto& a = ds.animations[i];
        cfg << "        '" << a.name << "': '" << a.duration << " " << a.easing << "',\n";
    }
    cfg << "      },\n"
        << "    },\n"
        << "  },\n"
        << "  plugins: [],\n"
        << "}\n";
    return cfg.str();
}

std::string CinematicVibeEngine::generateCSSVariables(const DesignSystem& ds) {
    std::ostringstream css;
    css << "/* CSS Variables — Auto-generated by Cinematic Vibe Engine */\n"
        << "/* Mood: " << ds.moodName << " */\n\n"
        << ":root {\n"
        << "  --color-primary: " << ds.palette.primary << ";\n"
        << "  --color-secondary: " << ds.palette.secondary << ";\n"
        << "  --color-accent: " << ds.palette.accent << ";\n"
        << "  --color-background: " << ds.palette.background << ";\n"
        << "  --color-surface: " << ds.palette.surface << ";\n"
        << "  --color-text-primary: " << ds.palette.textPrimary << ";\n"
        << "  --color-text-secondary: " << ds.palette.textSecondary << ";\n"
        << "  --color-success: " << ds.palette.success << ";\n"
        << "  --color-warning: " << ds.palette.warning << ";\n"
        << "  --color-error: " << ds.palette.error << ";\n"
        << "  --color-info: " << ds.palette.info << ";\n"
        << "  --font-heading: '" << ds.typography.headingFont << "', sans-serif;\n"
        << "  --font-body: '" << ds.typography.bodyFont << "', sans-serif;\n"
        << "  --font-mono: '" << ds.typography.monoFont << "', monospace;\n"
        << "  --font-heading-weight: " << ds.typography.headingWeight << ";\n"
        << "  --font-body-weight: " << ds.typography.bodyWeight << ";\n"
        << "  --heading-scale: " << ds.typography.headingScale << ";\n"
        << "  --body-line-height: " << ds.typography.bodyLineHeight << ";\n"
        << "}\n";
    return css.str();
}

std::string CinematicVibeEngine::generateDesignTokens(const DesignSystem& ds) {
    std::ostringstream json;
    json << "{\n"
         << "  \"mood\": \"" << ds.moodName << "\",\n"
         << "  \"color\": {\n"
         << "    \"primary\": \"" << ds.palette.primary << "\",\n"
         << "    \"secondary\": \"" << ds.palette.secondary << "\",\n"
         << "    \"accent\": \"" << ds.palette.accent << "\",\n"
         << "    \"background\": \"" << ds.palette.background << "\",\n"
         << "    \"surface\": \"" << ds.palette.surface << "\",\n"
         << "    \"textPrimary\": \"" << ds.palette.textPrimary << "\",\n"
         << "    \"textSecondary\": \"" << ds.palette.textSecondary << "\",\n"
         << "    \"success\": \"" << ds.palette.success << "\",\n"
         << "    \"warning\": \"" << ds.palette.warning << "\",\n"
         << "    \"error\": \"" << ds.palette.error << "\",\n"
         << "    \"info\": \"" << ds.palette.info << "\"\n"
         << "  },\n"
         << "  \"typography\": {\n"
         << "    \"headingFont\": \"" << ds.typography.headingFont << "\",\n"
         << "    \"bodyFont\": \"" << ds.typography.bodyFont << "\",\n"
         << "    \"monoFont\": \"" << ds.typography.monoFont << "\",\n"
         << "    \"headingWeight\": \"" << ds.typography.headingWeight << "\",\n"
         << "    \"bodyWeight\": \"" << ds.typography.bodyWeight << "\",\n"
         << "    \"headingScale\": " << ds.typography.headingScale << ",\n"
         << "    \"bodyLineHeight\": " << ds.typography.bodyLineHeight << "\n"
         << "  },\n"
         << "  \"patterns\": " << ds.patterns.size() << ",\n"
         << "  \"animations\": " << ds.animations.size() << ",\n"
         << "  \"microInteractions\": " << ds.microInteractions.size() << "\n"
         << "}\n";
    return json.str();
}

std::string CinematicVibeEngine::exportAsPrompt(const DesignSystem& ds) {
    std::ostringstream prompt;
    prompt << "=== CINEMATIC VIBE ENGINE — DESIGN SYSTEM SPECIFICATION ===\n\n"
           << "MOOD: " << ds.moodName << "\n\n"
           << "COLOR PALETTE (" << ds.palette.name << "):\n"
           << "  Primary:   " << ds.palette.primary << "\n"
           << "  Secondary: " << ds.palette.secondary << "\n"
           << "  Accent:    " << ds.palette.accent << "\n"
           << "  Background:" << ds.palette.background << "\n"
           << "  Surface:   " << ds.palette.surface << "\n"
           << "  Text:      " << ds.palette.textPrimary << " / " << ds.palette.textSecondary << "\n"
           << "  Success:   " << ds.palette.success << "\n"
           << "  Warning:   " << ds.palette.warning << "\n"
           << "  Error:     " << ds.palette.error << "\n"
           << "  Info:      " << ds.palette.info << "\n\n"
           << "TYPOGRAPHY:\n"
           << "  Heading: " << ds.typography.headingFont << " (weight " << ds.typography.headingWeight << ")\n"
           << "  Body:    " << ds.typography.bodyFont << " (weight " << ds.typography.bodyWeight << ")\n"
           << "  Mono:    " << ds.typography.monoFont << "\n"
           << "  Scale:   " << ds.typography.headingScale << " (modular)\n"
           << "  Line Height: " << ds.typography.bodyLineHeight << "\n\n"
           << "UX PATTERNS:\n";
    for (const auto& p : ds.patterns) {
        prompt << "  - " << p.name << ": " << p.description << " (component: " << p.component << ")\n";
    }
    prompt << "\nANIMATIONS:\n";
    for (const auto& a : ds.animations) {
        prompt << "  - " << a.name << ": " << a.property << " from " << a.from
               << " to " << a.to << " over " << a.duration << " (" << a.easing << ") on " << a.trigger << "\n";
    }
    prompt << "\nMICRO-INTERACTIONS:\n";
    for (const auto& m : ds.microInteractions) {
        prompt << "  - " << m.element << " " << m.interaction << ": " << m.effect << " (" << m.duration << ")\n";
    }
    prompt << "\nRATIONALE:\n" << ds.rationale << "\n\n"
           << "=== END DESIGN SYSTEM ===\n";
    return prompt.str();
}

std::string CinematicVibeEngine::exportAsJson(const DesignSystem& ds) {
    return generateDesignTokens(ds);
}

} // namespace KimiSwarm