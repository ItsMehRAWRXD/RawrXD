#pragma once

#include "SwarmOrchestrator.hpp"
#include "CinematicVibeEngine.hpp"
#include <vector>
#include <string>
#include <functional>

namespace rawrxd {
namespace swarm {

// UI Component specification
struct ComponentSpec {
    std::string name;
    std::string type;           // "page", "component", "layout", "form"
    std::vector<std::string> props;
    std::vector<std::string> events;
    std::string accessibilityLevel; // "wcag-aa", "wcag-aaa"
    bool responsive{true};
    bool animated{false};
    std::string animationType;   // "fade", "slide", "scale", "custom"
};

// Form field specification
struct FormField {
    std::string name;
    std::string label;
    std::string type;           // "text", "email", "password", "select", "checkbox"
    bool required{false};
    std::string validation;     // regex pattern or "email", "url", etc.
    std::string placeholder;
    std::vector<std::pair<std::string, std::string>> options; // for select
};

// Frontend Squad - 120 parallel UI/UX agents
class FrontendSquad {
public:
    struct PageRequest {
        std::string route;
        std::string title;
        std::string purpose;
        std::vector<ComponentSpec> components;
        std::vector<FormField> forms;
        std::string layout;     // "sidebar", "topnav", "dashboard", "landing"
    };
    
    struct GeneratedPage {
        std::string route;
        std::string tsxContent;
        std::string scssContent;
        std::string testContent;
        std::vector<std::string> dependencies;
        std::vector<std::string> componentImports;
    };
    
    struct ComponentLibrary {
        std::vector<GeneratedPage> pages;
        std::map<std::string, std::string> sharedComponents;
        std::string themeFile;
        std::string globalStyles;
    };
    
    // Main generation function - parallel execution
    ComponentLibrary generateApplication(
        const std::vector<PageRequest>& requests,
        const DesignSystem& designSystem
    );
    
    // Individual component generators (can run in parallel)
    GeneratedPage generatePage(
        const PageRequest& request,
        const DesignSystem& designSystem
    );
    
    // Page generation helpers
    std::string generateImports(
        const PageRequest& request,
        const DesignSystem& designSystem
    );
    std::string generatePageComponent(
        const PageRequest& request,
        const DesignSystem& designSystem
    );
    std::string generatePageStyles(
        const PageRequest& request,
        const DesignSystem& designSystem
    );
    std::string generatePageTest(
        const PageRequest& request,
        const DesignSystem& designSystem
    );
    std::map<std::string, std::string> generateSharedComponents(
        const DesignSystem& designSystem
    );
    std::string generateThemeFile(
        const DesignSystem& designSystem
    );
    std::string generateGlobalStyles(
        const DesignSystem& designSystem
    );
    
    std::string generateComponent(
        const ComponentSpec& spec,
        const DesignSystem& designSystem
    );
    
    std::string generateForm(
        const std::vector<FormField>& fields,
        const DesignSystem& designSystem
    );
    
    std::string generateStyles(
        const ComponentSpec& spec,
        const DesignSystem& designSystem
    );
    
    std::string generateAnimation(
        const ComponentSpec& spec,
        const DesignSystem& designSystem
    );
    
    // React-specific generators
    std::string generateReactComponent(const ComponentSpec& spec);
    std::string generateReactHook(const std::string& name, const std::vector<std::string>& deps);
    std::string generateReactContext(const std::string& name);
    std::string generateReactReducer(const std::string& featureName);
    
    // Vue-specific generators
    std::string generateVueComponent(const ComponentSpec& spec);
    std::string generateVueComposable(const std::string& name);
    std::string generateVueStore(const std::string& featureName);
    
    // Test generation
    std::string generateUnitTest(const ComponentSpec& spec);
    std::string generateE2ETest(const PageRequest& request);
    std::string generateStorybookStory(const ComponentSpec& spec);
    
    // Accessibility
    std::string addAccessibilityAttributes(const std::string& component);
    std::string generateAccessibilityTest(const ComponentSpec& spec);
    
    // Responsive design
    std::string generateResponsiveStyles(const ComponentSpec& spec);
    std::string generateMobileFirstCSS(const std::string& baseStyles);
    
    // Asset generation
    std::string generateSVGIcon(const std::string& name, const std::string& style);
    std::string generateImagePlaceholder(const std::string& dimensions);
    
    // Performance optimization
    std::string addLazyLoading(const std::string& component);
    std::string addMemoization(const std::string& component);
    std::string generateCodeSplitting(const std::vector<std::string>& routes);
};

} // namespace swarm
} // namespace rawrxd
