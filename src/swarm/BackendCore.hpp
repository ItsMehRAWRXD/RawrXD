#pragma once

#include "SwarmOrchestrator.hpp"
#include "ArchitectAgent.hpp"
#include <vector>
#include <string>
#include <map>

namespace rawrxd {
namespace swarm {

// API endpoint specification
struct APIEndpoint {
    std::string method;         // "GET", "POST", "PUT", "DELETE", "PATCH"
    std::string path;
    std::string name;
    std::string description;
    std::vector<std::pair<std::string, std::string>> parameters; // name, type
    std::vector<std::pair<std::string, std::string>> bodyFields;
    std::vector<std::pair<std::string, std::string>> responseFields;
    std::vector<std::string> middleware; // "auth", "rate-limit", "validate"
    bool requiresAuth{true};
    std::string rateLimit;      // "100/minute", "1000/hour"
};

// Service specification
struct ServiceSpec {
    std::string name;
    std::string purpose;
    std::vector<APIEndpoint> endpoints;
    std::vector<std::string> dependencies; // other services
    std::string databaseAccess; // "read", "write", "full"
    bool externalAPI{false};
};

// Backend Core - 100 parallel backend agents
class BackendCore {
public:
    struct BackendRequest {
        std::vector<ServiceSpec> services;
        DatabaseSchema database;
        TechStack stack;
        std::vector<std::string> integrations; // "stripe", "auth0", "sendgrid", etc.
        std::string authStrategy; // "jwt", "session", "oauth", "api-key"
    };
    
    struct GeneratedBackend {
        std::map<std::string, std::string> serviceFiles;    // path -> content
        std::map<std::string, std::string> routeFiles;
        std::map<std::string, std::string> modelFiles;
        std::map<std::string, std::string> middlewareFiles;
        std::map<std::string, std::string> configFiles;
        std::map<std::string, std::string> testFiles;
        std::string mainEntry;
        std::string dockerfile;
    };
    
    // Main generation function
    GeneratedBackend generateBackend(const BackendRequest& request);
    
    // Service generators (parallel)
    std::string generateService(const ServiceSpec& spec, const TechStack& stack);
    std::string generateController(const ServiceSpec& spec, const TechStack& stack);
    std::string generateRoutes(const ServiceSpec& spec, const TechStack& stack);
    std::string generateModels(const DatabaseSchema& schema, const TechStack& stack);
    
    // Database layer
    std::string generateMigrations(const DatabaseSchema& schema);
    std::string generateSeeds(const DatabaseSchema& schema);
    std::string generateORMConfig(const TechStack& stack);
    
    // Authentication & Security
    std::string generateAuthMiddleware(const std::string& strategy);
    std::string generateJWTConfig();
    std::string generatePasswordHashing();
    std::string generateCSRFProtection();
    std::string generateRateLimiter(const std::string& config);
    
    // API features
    std::string generateValidation(const APIEndpoint& endpoint);
    std::string generateErrorHandling();
    std::string generateAPIDocumentation(const std::vector<ServiceSpec>& services);
    std::string generateOpenAPISpec(const std::vector<ServiceSpec>& services);
    
    // Integration generators
    std::string generateStripeIntegration(const std::vector<std::string>& features);
    std::string generateAuth0Integration();
    std::string generateSendGridIntegration();
    std::string generateS3Integration();
    std::string generateRedisIntegration();
    std::string generateElasticsearchIntegration();
    
    // Real-time features
    std::string generateWebSocketHandler(const std::string& feature);
    std::string generateSSEEndpoint(const std::string& feature);
    std::string generateGraphQLSchema(const std::vector<ServiceSpec>& services);
    std::string generateGraphQLResolvers(const ServiceSpec& spec);
    
    // Testing
    std::string generateIntegrationTests(const ServiceSpec& spec);
    std::string generateLoadTest(const APIEndpoint& endpoint);
    std::string generateContractTests(const std::vector<ServiceSpec>& services);
    
    // Framework-specific generators
    std::string generateExpressService(const ServiceSpec& spec);
    std::string generateFastAPIService(const ServiceSpec& spec);
    std::string generateSpringService(const ServiceSpec& spec);
    std::string generateDotNetService(const ServiceSpec& spec);
    
    // Deployment
    std::string generatePM2Config();
    std::string generateNginxConfig(const std::vector<ServiceSpec>& services);
    std::string generateK8sDeployment(const ServiceSpec& spec);
    std::string generateK8sService(const ServiceSpec& spec);
    std::string generateHealthCheck();
    std::string generateMetricsEndpoint();
};

} // namespace swarm
} // namespace rawrxd
