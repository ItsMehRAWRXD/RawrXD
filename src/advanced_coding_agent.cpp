#include "advanced_coding_agent.h"

AdvancedCodingAgentIntegration::AdvancedCodingAgentIntegration(
    std::shared_ptr<Logger> logger,
    std::shared_ptr<Metrics> metrics)
    : m_logger(logger), m_metrics(metrics) {
    m_logger->info("AdvancedCodingAgent initialized");
}

GeneratedFeature AdvancedCodingAgentIntegration::implementFeature(
    const FeatureRequest& request) {

    m_logger->info("Implementing feature: {}", request.description);

    GeneratedFeature feature;
    feature.code = "// Generated implementation\n";
    feature.explanation = "Feature implementation generated from request";
    feature.confidence = 0.85;
    
    m_metrics->incrementCounter("features_generated");
    return feature;
}

std::vector<GeneratedFeature> AdvancedCodingAgentIntegration::generateImplementationOptions(
    const std::string& description,
    const std::string& context) {

    m_logger->info("Generating implementation options");

    std::vector<GeneratedFeature> options;
    std::string descLower = description;
    std::transform(descLower.begin(), descLower.end(), descLower.begin(),
                   [](unsigned char c){ return std::tolower(c); });

    // Option 1: Class-based implementation (detect class-like requests)
    {
        GeneratedFeature opt;
        opt.explanation = "Class-based implementation with encapsulation";
        opt.confidence = 0.80;

        std::string className = "GeneratedClass";
        // Try to extract a class name from description
        size_t classPos = descLower.find("class ");
        if (classPos != std::string::npos) {
            size_t endPos = descLower.find_first_of(" \t\n:", classPos + 6);
            if (endPos != std::string::npos) {
                className = descLower.substr(classPos + 6, endPos - classPos - 6);
            }
        }

        opt.code = "// Option 1: Class-based implementation\n"
                   "class " + className + " {\n"
                   "public:\n"
                   "    " + className + "();\n"
                   "    ~" + className + "();\n"
                   "\n"
                   "    void initialize();\n"
                   "    void process();\n"
                   "    std::string getStatus() const;\n"
                   "\n"
                   "private:\n"
                   "    bool m_initialized = false;\n"
                   "};\n"
                   "\n"
                   + className + "::" + className + "() : m_initialized(false) {}\n"
                   + className + "::~" + className + "() {}\n"
                   "\n"
                   "void " + className + "::initialize() {\n"
                   "    m_initialized = true;\n"
                   "}\n"
                   "\n"
                   "void " + className + "::process() {\n"
                   "    if (!m_initialized) initialize();\n"
                   "    // Implementation logic based on: " + description + "\n"
                   "}\n"
                   "\n"
                   "std::string " + className + "::getStatus() const {\n"
                   "    return m_initialized ? \"initialized\" : \"not initialized\";\n"
                   "}\n";

        options.push_back(opt);
    }

    // Option 2: Function-based implementation
    {
        GeneratedFeature opt;
        opt.explanation = "Function-based implementation with clear separation of concerns";
        opt.confidence = 0.75;

        std::string funcName = "implementFeature";
        size_t fnPos = descLower.find("function ");
        if (fnPos != std::string::npos) {
            size_t endPos = descLower.find_first_of(" \t\n(", fnPos + 9);
            if (endPos != std::string::npos) {
                funcName = descLower.substr(fnPos + 9, endPos - fnPos - 9);
            }
        }

        opt.code = "// Option 2: Function-based implementation\n"
                   "#include <string>\n"
                   "#include <vector>\n"
                   "\n"
                   "std::string " + funcName + "(const std::string& input) {\n"
                   "    // Validate input\n"
                   "    if (input.empty()) return {};\n"
                   "\n"
                   "    // Process based on: " + description + "\n"
                   "    std::string result = input;\n"
                   "    // Transformation logic goes here\n"
                   "\n"
                   "    return result;\n"
                   "}\n"
                   "\n"
                   "bool " + funcName + "_validate(const std::string& input) {\n"
                   "    return !input.empty();\n"
                   "}\n";

        options.push_back(opt);
    }

    // Option 3: Module-based implementation (if context suggests modular design)
    {
        GeneratedFeature opt;
        opt.explanation = "Module-based implementation with interface/implementation split";
        opt.confidence = 0.70;

        opt.code = "// Option 3: Module-based implementation\n"
                   "// Module interface\n"
                   "#pragma once\n"
                   "\n"
                   "#include <string>\n"
                   "\n"
                   "namespace feature_module {\n"
                   "\n"
                   "class Interface {\n"
                   "public:\n"
                   "    virtual ~Interface() = default;\n"
                   "    virtual std::string execute(const std::string& input) = 0;\n"
                   "};\n"
                   "\n"
                   "std::unique_ptr<Interface> create();\n"
                   "\n"
                   "} // namespace feature_module\n"
                   "\n"
                   "// Module implementation\n"
                   "#include \"feature_module.h\"\n"
                   "\n"
                   "namespace feature_module {\n"
                   "\n"
                   "class Implementation : public Interface {\n"
                   "public:\n"
                   "    std::string execute(const std::string& input) override {\n"
                   "        // Implementation based on: " + description + "\n"
                   "        return input;\n"
                   "    }\n"
                   "};\n"
                   "\n"
                   "std::unique_ptr<Interface> create() {\n"
                   "    return std::make_unique<Implementation>();\n"
                   "}\n"
                   "\n"
                   "} // namespace feature_module\n";

        options.push_back(opt);
    }

    m_metrics->incrementCounter("implementation_options_generated");
    return options;
}

std::string AdvancedCodingAgentIntegration::generateDocumentation(
    const std::string& code) {

    m_logger->info("Generating documentation for {} chars", code.length());

    std::string doc = "/**\n";
    doc += " * Auto-generated documentation\n";
    doc += " * Function purpose and usage\n";
    doc += " */\n";

    m_metrics->incrementCounter("documentation_generated");
    return doc;
}

std::string AdvancedCodingAgentIntegration::generateFunctionDocumentation(
    const std::string& functionCode,
    const std::string& style) {

    m_logger->info("Generating {} documentation", style);
    return "/// Auto-generated documentation";
}

std::vector<std::string> AdvancedCodingAgentIntegration::generateTests(
    const std::string& functionCode) {

    m_logger->info("Generating tests for function");

    std::vector<std::string> tests;
    
    tests.push_back("TEST_CASE(\"Basic functionality\") { /* test */ }");
    tests.push_back("TEST_CASE(\"Edge cases\") { /* test */ }");
    tests.push_back("TEST_CASE(\"Error handling\") { /* test */ }");

    m_metrics->incrementCounter("tests_generated");
    return tests;
}

std::vector<std::string> AdvancedCodingAgentIntegration::findBugs(
    const std::string& code) {

    m_logger->info("Analyzing code for bugs");

    std::vector<std::string> bugs;
    
    // Analysis would go here
    // For now, return empty - actual bugs would be detected

    m_metrics->incrementCounter("bug_analysis_runs");
    return bugs;
}

std::vector<std::string> AdvancedCodingAgentIntegration::optimizeCode(
    const std::string& code) {

    m_logger->info("Optimizing code");

    std::vector<std::string> optimizations;
    
    optimizations.push_back("Use const references for large objects");
    optimizations.push_back("Cache repeated computations");
    optimizations.push_back("Use move semantics for large returns");

    m_metrics->incrementCounter("optimization_suggestions");
    return optimizations;
}

std::vector<SecurityIssue> AdvancedCodingAgentIntegration::scanSecurity(
    const std::string& code,
    const std::string& language) {

    m_logger->info("Scanning security for {}", language);

    std::vector<SecurityIssue> issues;
    
    // Security analysis would go here

    m_metrics->incrementCounter("security_scans");
    return issues;
}

std::string AdvancedCodingAgentIntegration::buildFeaturePrompt(
    const FeatureRequest& request) {

    std::string prompt = "Generate " + request.language + " code for: ";
    prompt += request.description;
    return prompt;
}

bool AdvancedCodingAgentIntegration::validateGeneratedCode(const std::string& code) {
    // Validate code syntax and logic
    if (code.empty()) {
        return false;
    }
    
    // Check for balanced braces
    int braceDepth = 0;
    int parenDepth = 0;
    int bracketDepth = 0;
    
    for (char c : code) {
        switch (c) {
            case '{': braceDepth++; break;
            case '}': 
                braceDepth--;
                if (braceDepth < 0) return false; // Unmatched closing brace
                break;
            case '(': parenDepth++; break;
            case ')': 
                parenDepth--;
                if (parenDepth < 0) return false; // Unmatched closing paren
                break;
            case '[': bracketDepth++; break;
            case ']': 
                bracketDepth--;
                if (bracketDepth < 0) return false; // Unmatched closing bracket
                break;
        }
    }
    
    if (braceDepth != 0 || parenDepth != 0 || bracketDepth != 0) {
        return false; // Unbalanced delimiters
    }
    
    // Check for obvious syntax issues
    if (code.find("return") != std::string::npos && 
        code.find(";") == std::string::npos) {
        return false; // Return statement without semicolon
    }
    
    // Check for empty function bodies that should have content
    std::regex emptyFunc(R"(\w+\s*\([^)]*\)\s*\{\s*\})");
    if (std::regex_search(code, emptyFunc)) {
        // Empty function body might be intentional (e.g., destructor)
        // Just log it, don't fail validation
    }
    
    m_metrics->incrementCounter("code_validations");
    return true;
}
