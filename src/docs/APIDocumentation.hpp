/**
 * APIDocumentation.hpp
 *
 * Phase J Batch 1/5: API Documentation Generator
 *
 * Automatic API documentation generation from source code with
 * OpenAPI/Swagger support, code examples, and interactive playgrounds.
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <optional>

namespace Docs {

// ============================================================================
// Forward Declarations
// ============================================================================

class APIEndpoint;
class APIModel;
class APIDocumentation;
class DocumentationGenerator;

// ============================================================================
// HTTP Method
// ============================================================================

enum class HttpMethod {
    GET,
    POST,
    PUT,
    PATCH,
    DELETE,
    HEAD,
    OPTIONS,
    TRACE
};

std::string HttpMethodToString(HttpMethod method);
HttpMethod HttpMethodFromString(const std::string& str);

// ============================================================================
// Parameter Location
// ============================================================================

enum class ParameterLocation {
    PATH,       // /users/{id}
    QUERY,      // ?name=value
    HEADER,     // X-Api-Key: value
    COOKIE,     // Cookie: name=value
    BODY        // Request body
};

// ============================================================================
// Data Type
// ============================================================================

enum class DataType {
    STRING,
    INTEGER,
    NUMBER,
    BOOLEAN,
    ARRAY,
    OBJECT,
    FILE,
    NULL_TYPE
};

// ============================================================================
// API Parameter
// ============================================================================

/**
 * API endpoint parameter.
 */
struct APIParameter {
    std::string name;
    std::string description;
    ParameterLocation location;
    DataType type;
    std::string format;         // int32, int64, float, double, date, datetime, uuid, etc.
    bool required;
    bool deprecated;
    std::optional<std::string> defaultValue;
    std::optional<std::string> example;
    std::vector<std::string> enumValues;
    std::map<std::string, std::string> metadata;
    
    // Validation
    std::optional<double> minimum;
    std::optional<double> maximum;
    std::optional<uint32_t> minLength;
    std::optional<uint32_t> maxLength;
    std::optional<std::string> pattern;
    
    APIParameter();
    
    std::string ToOpenAPI() const;
    std::string ToMarkdown() const;
};

// ============================================================================
// API Response
// ============================================================================

/**
 * API response definition.
 */
struct APIResponse {
    int statusCode;
    std::string description;
    std::string contentType;
    std::string schema;         // JSON Schema or type reference
    std::optional<std::string> example;
    std::map<std::string, std::string> headers;
    
    APIResponse();
    explicit APIResponse(int code);
    
    std::string ToOpenAPI() const;
    std::string ToMarkdown() const;
};

// ============================================================================
// API Endpoint
// ============================================================================

/**
 * API endpoint definition.
 */
class APIEndpoint {
public:
    struct Config {
        std::string path;
        HttpMethod method;
        std::string summary;
        std::string description;
        std::vector<std::string> tags;
        std::string operationId;
        bool deprecated;
        std::vector<std::string> servers;
    };
    
    explicit APIEndpoint(const Config& config);
    
    // Parameters
    void AddParameter(const APIParameter& param);
    void AddParameters(const std::vector<APIParameter>& params);
    std::vector<APIParameter> GetParameters() const;
    std::vector<APIParameter> GetParameters(ParameterLocation location) const;
    
    // Request body
    void SetRequestBody(const std::string& contentType, const std::string& schema,
                        bool required = true);
    void SetRequestBodyExample(const std::string& example);
    bool HasRequestBody() const;
    
    // Responses
    void AddResponse(const APIResponse& response);
    void AddResponses(const std::vector<APIResponse>& responses);
    std::vector<APIResponse> GetResponses() const;
    std::optional<APIResponse> GetResponse(int statusCode) const;
    
    // Security
    void AddSecurityRequirement(const std::string& scheme,
                                 const std::vector<std::string>& scopes = {});
    
    // Code examples
    void AddCodeExample(const std::string& language, const std::string& code);
    std::map<std::string, std::string> GetCodeExamples() const;
    
    // Accessors
    const Config& GetConfig() const { return config_; }
    std::string GetFullPath() const;
    
    // Export
    std::string ToOpenAPI() const;
    std::string ToMarkdown() const;
    std::string ToHtml() const;
    
private:
    Config config_;
    std::vector<APIParameter> parameters_;
    
    struct RequestBody {
        std::string contentType;
        std::string schema;
        std::optional<std::string> example;
        bool required;
    };
    std::optional<RequestBody> requestBody_;
    
    std::vector<APIResponse> responses_;
    std::map<std::string, std::vector<std::string>> securityRequirements_;
    std::map<std::string, std::string> codeExamples_;
};

// ============================================================================
// API Model
// ============================================================================

/**
 * API data model (schema).
 */
class APIModel {
public:
    struct Property {
        std::string name;
        std::string description;
        DataType type;
        std::string format;
        bool required;
        bool readOnly;
        bool writeOnly;
        std::optional<std::string> defaultValue;
        std::optional<std::string> example;
        std::string reference;  // $ref to another model
    };
    
    APIModel(const std::string& name, const std::string& description);
    
    // Properties
    void AddProperty(const Property& prop);
    void AddProperties(const std::vector<Property>& props);
    std::vector<Property> GetProperties() const;
    std::optional<Property> GetProperty(const std::string& name) const;
    
    // Inheritance
    void SetParent(const std::string& parentModel);
    std::optional<std::string> GetParent() const;
    
    // Validation
    void AddRequired(const std::string& property);
    std::vector<std::string> GetRequired() const;
    
    // Example
    void SetExample(const std::string& example);
    std::optional<std::string> GetExample() const;
    
    // Accessors
    std::string GetName() const { return name_; }
    std::string GetDescription() const { return description_; }
    
    // Export
    std::string ToJsonSchema() const;
    std::string ToOpenAPI() const;
    std::string ToMarkdown() const;
    std::string ToTypeScript() const;
    std::string ToCSharp() const;
    std::string ToJava() const;
    std::string ToPython() const;
    std::string ToGo() const;
    std::string ToRust() const;
    
private:
    std::string name_;
    std::string description_;
    std::vector<Property> properties_;
    std::optional<std::string> parent_;
    std::vector<std::string> required_;
    std::optional<std::string> example_;
};

// ============================================================================
// API Tag
// ============================================================================

/**
 * API tag/group.
 */
struct APITag {
    std::string name;
    std::string description;
    std::optional<std::string> externalDocsUrl;
    std::optional<std::string> externalDocsDescription;
};

// ============================================================================
// API Server
// ============================================================================

/**
 * API server definition.
 */
struct APIServer {
    std::string url;
    std::string description;
    std::map<std::string, std::string> variables;
};

// ============================================================================
// Security Scheme
// ============================================================================

/**
 * API security scheme.
 */
struct SecurityScheme {
    enum class Type {
        HTTP,
        API_KEY,
        OAUTH2,
        OPEN_ID_CONNECT
    };
    
    enum class HttpScheme {
        BASIC,
        BEARER
    };
    
    std::string name;
    Type type;
    std::string description;
    
    // HTTP
    HttpScheme httpScheme;
    std::string bearerFormat;
    
    // API Key
    std::string apiKeyName;
    ParameterLocation apiKeyLocation;
    
    // OAuth2
    struct OAuthFlow {
        std::string authorizationUrl;
        std::string tokenUrl;
        std::string refreshUrl;
        std::map<std::string, std::string> scopes;
    };
    std::map<std::string, OAuthFlow> oauthFlows;
    
    // OpenID Connect
    std::string openIdConnectUrl;
};

// ============================================================================
// API Documentation
// ============================================================================

/**
 * Complete API documentation.
 */
class APIDocumentation {
public:
    struct Info {
        std::string title;
        std::string description;
        std::string version;
        std::optional<std::string> termsOfService;
        
        struct Contact {
            std::string name;
            std::optional<std::string> url;
            std::optional<std::string> email;
        };
        std::optional<Contact> contact;
        
        struct License {
            std::string name;
            std::optional<std::string> url;
        };
        std::optional<License> license;
    };
    
    explicit APIDocumentation(const Info& info);
    
    // Servers
    void AddServer(const APIServer& server);
    std::vector<APIServer> GetServers() const;
    
    // Tags
    void AddTag(const APITag& tag);
    std::vector<APITag> GetTags() const;
    
    // Endpoints
    void AddEndpoint(std::shared_ptr<APIEndpoint> endpoint);
    void AddEndpoints(const std::vector<std::shared_ptr<APIEndpoint>>& endpoints);
    std::vector<std::shared_ptr<APIEndpoint>> GetEndpoints() const;
    std::vector<std::shared_ptr<APIEndpoint>> GetEndpointsByTag(const std::string& tag) const;
    std::optional<std::shared_ptr<APIEndpoint>> GetEndpoint(HttpMethod method,
                                                                  const std::string& path) const;
    
    // Models
    void AddModel(std::shared_ptr<APIModel> model);
    std::vector<std::shared_ptr<APIModel>> GetModels() const;
    std::optional<std::shared_ptr<APIModel>> GetModel(const std::string& name) const;
    
    // Security
    void AddSecurityScheme(const SecurityScheme& scheme);
    std::vector<SecurityScheme> GetSecuritySchemes() const;
    void SetGlobalSecurity(const std::vector<std::string>& schemeNames);
    
    // External docs
    void SetExternalDocs(const std::string& url, const std::string& description);
    
    // Export
    std::string ToOpenAPI() const;
    std::string ToAsyncAPI() const;
    std::string ToMarkdown() const;
    std::string ToHtml() const;
    std::string ToPostmanCollection() const;
    std::string ToInsomniaCollection() const;
    
    // Validation
    bool Validate() const;
    std::vector<std::string> GetValidationErrors() const;
    
private:
    Info info_;
    std::vector<APIServer> servers_;
    std::vector<APITag> tags_;
    std::vector<std::shared_ptr<APIEndpoint>> endpoints_;
    std::vector<std::shared_ptr<APIModel>> models_;
    std::vector<SecurityScheme> securitySchemes_;
    std::optional<std::vector<std::string>> globalSecurity_;
    std::optional<std::pair<std::string, std::string>> externalDocs_;
};

// ============================================================================
// Documentation Generator
// ============================================================================

/**
 * Generates API documentation from source code.
 */
class DocumentationGenerator {
public:
    struct Config {
        std::string sourceDirectory;
        std::string outputDirectory;
        std::vector<std::string> includePatterns;
        std::vector<std::string> excludePatterns;
        std::string baseUrl;
        bool generateExamples = true;
        bool generateClientSDKs = false;
        std::vector<std::string> sdkLanguages;
    };
    
    explicit DocumentationGenerator(const Config& config);
    
    // Parsing
    bool ParseSource();
    bool ParseFile(const std::string& filepath);
    
    // Generation
    bool GenerateOpenAPI(const std::string& outputPath);
    bool GenerateMarkdown(const std::string& outputPath);
    bool GenerateHtml(const std::string& outputPath);
    bool GeneratePostman(const std::string& outputPath);
    
    // SDK generation
    bool GenerateClientSDK(const std::string& language, const std::string& outputPath);
    bool GenerateAllSDKs(const std::string& outputDirectory);
    
    // Interactive docs
    bool GenerateSwaggerUI(const std::string& outputPath);
    bool GenerateRedoc(const std::string& outputPath);
    bool GenerateStoplight(const std::string& outputPath);
    
    // Access
    std::shared_ptr<APIDocumentation> GetDocumentation() const;
    
    // Statistics
    struct Stats {
        uint32_t filesParsed;
        uint32_t endpointsFound;
        uint32_t modelsFound;
        uint32_t errors;
        uint32_t warnings;
    };
    Stats GetStats() const;
    
private:
    Config config_;
    std::shared_ptr<APIDocumentation> documentation_;
    Stats stats_;
    
    void ParseCommentBlock(const std::string& comment, APIEndpoint* endpoint);
    void ParseAnnotations(const std::string& code, APIEndpoint* endpoint);
    std::string ExtractJsonSchema(const std::string& typeDefinition);
};

// ============================================================================
// Code Example Generator
// ============================================================================

/**
 * Generates code examples for API documentation.
 */
class CodeExampleGenerator {
public:
    // cURL
    static std::string GenerateCurl(const APIEndpoint& endpoint,
                                     const std::map<std::string, std::string>& parameters);
    
    // JavaScript/TypeScript
    static std::string GenerateJavaScript(const APIEndpoint& endpoint,
                                           const std::map<std::string, std::string>& parameters);
    static std::string GenerateTypeScript(const APIEndpoint& endpoint,
                                           const std::map<std::string, std::string>& parameters);
    static std::string GenerateNodeJS(const APIEndpoint& endpoint,
                                       const std::map<std::string, std::string>& parameters);
    
    // Python
    static std::string GeneratePython(const APIEndpoint& endpoint,
                                       const std::map<std::string, std::string>& parameters);
    static std::string GeneratePythonRequests(const APIEndpoint& endpoint,
                                               const std::map<std::string, std::string>& parameters);
    static std::string GeneratePythonAiohttp(const APIEndpoint& endpoint,
                                             const std::map<std::string, std::string>& parameters);
    
    // C#
    static std::string GenerateCSharp(const APIEndpoint& endpoint,
                                       const std::map<std::string, std::string>& parameters);
    static std::string GenerateCSharpHttpClient(const APIEndpoint& endpoint,
                                                 const std::map<std::string, std::string>& parameters);
    static std::string GenerateCSharpRestSharp(const APIEndpoint& endpoint,
                                                const std::map<std::string, std::string>& parameters);
    
    // Java
    static std::string GenerateJava(const APIEndpoint& endpoint,
                                     const std::map<std::string, std::string>& parameters);
    static std::string GenerateJavaOkHttp(const APIEndpoint& endpoint,
                                           const std::map<std::string, std::string>& parameters);
    static std::string GenerateJavaUnirest(const APIEndpoint& endpoint,
                                            const std::map<std::string, std::string>& parameters);
    
    // Go
    static std::string GenerateGo(const APIEndpoint& endpoint,
                                   const std::map<std::string, std::string>& parameters);
    
    // Rust
    static std::string GenerateRust(const APIEndpoint& endpoint,
                                     const std::map<std::string, std::string>& parameters);
    static std::string GenerateRustReqwest(const APIEndpoint& endpoint,
                                            const std::map<std::string, std::string>& parameters);
    
    // Ruby
    static std::string GenerateRuby(const APIEndpoint& endpoint,
                                     const std::map<std::string, std::string>& parameters);
    
    // PHP
    static std::string GeneratePHP(const APIEndpoint& endpoint,
                                    const std::map<std::string, std::string>& parameters);
    
    // Swift
    static std::string GenerateSwift(const APIEndpoint& endpoint,
                                      const std::map<std::string, std::string>& parameters);
    
    // Kotlin
    static std::string GenerateKotlin(const APIEndpoint& endpoint,
                                       const std::map<std::string, std::string>& parameters);
    
    // Generate all
    static std::map<std::string, std::string> GenerateAll(const APIEndpoint& endpoint,
                                                             const std::map<std::string, std::string>& parameters);
};

// ============================================================================
// Client SDK Generator
// ============================================================================

/**
 * Generates client SDKs from API documentation.
 */
class ClientSDKGenerator {
public:
    struct Config {
        std::string packageName;
        std::string packageVersion;
        std::string author;
        std::string description;
        std::string repository;
        std::string license;
    };
    
    explicit ClientSDKGenerator(const Config& config);
    
    // TypeScript/JavaScript
    bool GenerateTypeScriptSDK(const APIDocumentation& docs, const std::string& outputPath);
    bool GenerateJavaScriptSDK(const APIDocumentation& docs, const std::string& outputPath);
    
    // Python
    bool GeneratePythonSDK(const APIDocumentation& docs, const std::string& outputPath);
    bool GeneratePythonAsyncSDK(const APIDocumentation& docs, const std::string& outputPath);
    
    // C#
    bool GenerateCSharpSDK(const APIDocumentation& docs, const std::string& outputPath);
    
    // Java
    bool GenerateJavaSDK(const APIDocumentation& docs, const std::string& outputPath);
    
    // Go
    bool GenerateGoSDK(const APIDocumentation& docs, const std::string& outputPath);
    
    // Rust
    bool GenerateRustSDK(const APIDocumentation& docs, const std::string& outputPath);
    
    // Ruby
    bool GenerateRubySDK(const APIDocumentation& docs, const std::string& outputPath);
    
    // PHP
    bool GeneratePHPSDK(const APIDocumentation& docs, const std::string& outputPath);
    
private:
    Config config_;
    
    std::string GeneratePackageJson() const;
    std::string GenerateSetupPy() const;
    std::string GenerateCsproj() const;
    std::string GeneratePomXml() const;
    std::string GenerateCargoToml() const;
    std::string GenerateGemspec() const;
    std::string GenerateComposerJson() const;
};

} // namespace Docs
