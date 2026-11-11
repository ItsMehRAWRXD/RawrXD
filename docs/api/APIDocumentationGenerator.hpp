// RawrXD API Documentation Generator
// Phase S.1: Automated API documentation from source code
// OpenAPI/Swagger generation with code examples

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>

namespace RawrXD {
namespace Documentation {

// API endpoint information
struct APIEndpoint {
    std::string path;
    std::string method;  // GET, POST, PUT, DELETE, etc.
    std::string summary;
    std::string description;
    std::vector<std::string> tags;
    
    // Parameters
    struct Parameter {
        std::string name;
        std::string in_;     // query, path, header, body
        std::string type;
        bool required;
        std::string description;
        std::string defaultValue;
    };
    std::vector<Parameter> parameters;
    
    // Request body
    struct RequestBody {
        std::string contentType;
        std::string schema;
        std::string example;
    };
    std::optional<RequestBody> requestBody;
    
    // Responses
    struct Response {
        int statusCode;
        std::string description;
        std::string contentType;
        std::string schema;
        std::string example;
    };
    std::map<int, Response> responses;
    
    // Security
    std::vector<std::string> security;
    
    // Code examples
    std::map<std::string, std::string> codeExamples;  // language -> code
};

// API schema/model
struct APISchema {
    std::string name;
    std::string description;
    std::string type;  // object, array, string, etc.
    
    struct Property {
        std::string name;
        std::string type;
        std::string format;
        bool required;
        std::string description;
        std::optional<std::string> ref;  // Reference to another schema
    };
    std::vector<Property> properties;
};

// OpenAPI specification
struct OpenAPISpec {
    std::string openapi = "3.0.0";
    struct Info {
        std::string title;
        std::string version;
        std::string description;
        std::string termsOfService;
        struct Contact {
            std::string name;
            std::string email;
            std::string url;
        } contact;
        struct License {
            std::string name;
            std::string url;
        } license;
    } info;
    
    std::vector<std::string> servers;
    std::map<std::string, APIEndpoint> paths;
    std::map<std::string, APISchema> schemas;
    std::map<std::string, std::map<std::string, std::vector<std::string>>> securitySchemes;
};

// Documentation generator
class APIDocumentationGenerator {
public:
    APIDocumentationGenerator();
    ~APIDocumentationGenerator();
    
    // Source parsing
    bool parseSourceDirectory(const std::string& path);
    bool parseSourceFile(const std::string& path);
    
    // Endpoint registration (manual)
    void registerEndpoint(const APIEndpoint& endpoint);
    void registerSchema(const APISchema& schema);
    
    // Code annotation parsing
    void parseAnnotations(const std::string& sourceCode);
    
    // Generation
    std::string generateOpenAPI() const;
    std::string generateSwaggerUI() const;
    std::string generateMarkdown() const;
    std::string generateHTML() const;
    
    // Export
    bool exportToFile(const std::string& path, const std::string& format) const;
    bool exportOpenAPI(const std::string& path) const;
    bool exportPostmanCollection(const std::string& path) const;
    
    // Code examples
    void addCodeExample(const std::string& endpoint, const std::string& language, 
                        const std::string& code);
    std::string generateSDKExample(const std::string& endpoint, const std::string& language) const;
    
    // Validation
    bool validateSpec() const;
    std::vector<std::string> getValidationErrors() const;
    
    // Statistics
    struct DocStats {
        uint32_t endpointCount;
        uint32_t schemaCount;
        uint32_t exampleCount;
        uint32_t coveragePercent;
        std::map<std::string, uint32_t> endpointsByTag;
    };
    DocStats getStats() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// Interactive API explorer
class APIExplorer {
public:
    APIExplorer(APIDocumentationGenerator* generator);
    
    // Server
    bool start(uint16_t port = 8080);
    bool stop();
    
    // Interactive features
    std::string executeRequest(const std::string& endpoint, const std::string& method,
                               const std::map<std::string, std::string>& params);
    std::string generateCurlCommand(const std::string& endpoint, const std::string& method) const;
    
private:
    APIDocumentationGenerator* generator_;
};

} // namespace Documentation
} // namespace RawrXD
