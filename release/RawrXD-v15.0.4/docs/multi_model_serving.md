# RawrXD Multi-Model Serving Guide

Comprehensive guide for serving multiple models simultaneously with intelligent routing, A/B testing, and canary deployments.

## Table of Contents

1. [Overview](#overview)
2. [Model Registry](#model-registry)
3. [Model Router](#model-router)
4. [Multi-Model Manager](#multi-model-manager)
5. [A/B Testing](#ab-testing)
6. [Canary Deployments](#canary-deployments)
7. [Feature Flags](#feature-flags)
8. [Best Practices](#best-practices)

## Overview

Multi-model serving enables:

- **10+ models simultaneously**: Load and serve multiple models
- **Dynamic loading/unloading**: Add/remove models without restart
- **Intelligent routing**: Route requests to optimal models
- **A/B testing**: Compare model versions
- **Canary deployments**: Gradual rollout with automatic rollback
- **Feature flags**: Enable features per user/group

## Model Registry

Central registry for all available models.

### Registration

```cpp
ModelMetadata metadata;
metadata.name = "llama-7b";
metadata.version = "v1.0";
metadata.path = "/models/llama-7b.gguf";
metadata.format = "gguf";
metadata.parameter_count = 7'000'000'000;
metadata.memory_required_mb = 16000;
metadata.tags = {"chat", "general"};
metadata.labels["language"] = "en";

registry.registerModel(metadata);
```

### Query

```cpp
// Get specific version
auto model = registry.getModel("llama-7b", "v1.0");

// List all versions
auto versions = registry.listModelVersions("llama-7b");

// Filter by tag
auto chat_models = registry.listModelsByTag("chat");
```

## Model Router

Intelligent request routing to appropriate models.

### Routing Strategies

| Strategy | Description | Use Case |
|----------|-------------|----------|
| Round Robin | Even distribution | Load balancing |
| Least Latency | Route to fastest | Latency-sensitive |
| Weighted | By capacity | Heterogeneous hardware |
| Capability | By model features | Feature-specific |
| Content-Based | By prompt analysis | Task routing |
| Sticky | Session affinity | Stateful conversations |

### Usage

```cpp
ModelRouter router(registry);

// Route with default strategy
RoutingContext context;
context.prompt_tokens = tokenizer.encode(prompt);
auto decision = router.route(context);

// Route with specific strategy
auto decision = router.routeWithStrategy(context, "least_latency");
```

### Custom Routing

```cpp
class MyStrategy : public RoutingStrategy {
public:
    std::string getName() const override { return "my_strategy"; }
    
    RoutingDecision route(const RoutingContext& context,
                          const std::vector<ModelInstance>& candidates) override {
        // Custom logic
        return decision;
    }
};

router.registerStrategy(std::make_unique<MyStrategy>());
```

## Multi-Model Manager

Manage multiple loaded models with resource optimization.

### Configuration

```cpp
MultiModelConfig config;
config.max_loaded_models = 10;
config.max_memory_gb = 80;
config.enable_auto_scaling = true;
config.eviction_policy = "lru";

MultiModelManager manager(config);
manager.initialize(registry);
manager.start();
```

### Loading Models

```cpp
// Blocking load
manager.loadModel("llama-7b:v1.0", "/models/llama-7b.gguf", 0);

// Async load
manager.loadModelAsync("llama-13b:v1.0", "/models/llama-13b.gguf", 1);

// Preload for fast access
manager.preloadModel("llama-7b:v1.0");
```

### Resource Management

```cpp
// Check resources
auto available = manager.getAvailableMemory();
auto used = manager.getUsedMemory();
auto utilization = manager.getMemoryUtilization();

// Auto-scale
manager.scaleModel("llama-7b:v1.0", 3);  // 3 instances
```

## A/B Testing

Compare model versions with statistical significance.

### Setup

```cpp
ExperimentConfig config;
config.experiment_id = "exp_001";
config.name = "Llama 7B vs 13B";
config.model_variants = {"llama-7b:v1.0", "llama-13b:v1.0"};
config.traffic_split = {0.5, 0.5};
config.success_metric = "latency";
config.min_samples = 1000;
config.min_confidence = 0.95;

ab_manager.createExperiment(config);
ab_manager.startExperiment("exp_001");
```

### Traffic Assignment

```cpp
// Get variant for request
std::string variant = ab_manager.getVariant("exp_001", user_id);

// Route to variant
auto decision = router.routeToModel(variant);
```

### Results

```cpp
auto results = ab_manager.getResults("exp_001");
if (results && ab_manager.isStatisticallySignificant("exp_001")) {
    std::cout << "Winner: " << results->winning_variant << std::endl;
}
```

## Canary Deployments

Gradual rollout with automatic rollback.

### Setup

```cpp
CanaryDeployment::Config config;
config.model_full_name = "llama-7b:v2.0";
config.initial_traffic_percent = 1.0f;
config.max_traffic_percent = 100.0f;
config.traffic_increment = 10.0f;
config.error_threshold = 0.01f;
config.auto_rollback = true;

CanaryDeployment canary(config);
canary.start();
```

### Progression

```cpp
// Increase traffic
canary.increaseTraffic(10.0f);

// Evaluate health
if (canary.evaluateHealth()) {
    // Continue rollout
} else if (config.auto_rollback) {
    canary.rollback();
}

// Promote to full deployment
canary.promote();
```

## Feature Flags

Enable features per user/group.

### Management

```cpp
FeatureFlagManager flags;

// Create flag
FeatureFlag flag;
flag.name = "new_model_architecture";
flag.enabled = true;
flag.rollout_percent = 10.0f;
flag.allowed_users = {"user1", "user2"};

flags.createFlag(flag);
```

### Evaluation

```cpp
// Check if enabled
if (flags.isEnabled("new_model_architecture", user_id)) {
    // Use new architecture
}

// Gradual rollout
flags.setRolloutPercent("new_model_architecture", 25.0f);
```

## Best Practices

### Resource Planning

```cpp
// Calculate requirements
size_t total_memory = 0;
for (const auto& model : models) {
    total_memory += model.memory_required_mb;
}

// Ensure 20% headroom
assert(total_memory * 1.2 < available_memory);
```

### Health Monitoring

```cpp
// Per-model health checks
for (auto& instance : instances) {
    bool healthy = checkHealth(instance);
    registry.updateInstanceHealth(instance.instance_id, healthy);
}
```

### Load Balancing

```cpp
// Use least-latency for real-time
// Use round-robin for batch
// Use weighted for heterogeneous GPUs
```

### Security

```cpp
// Validate model signatures
// Isolate models per tenant
// Rate limit per model
```

## Examples

### Multi-Tenant Setup

```cpp
// Different models per tenant
router.registerStrategy(std::make_unique<TenantAwareStrategy>());

// Route by tenant header
context.headers["X-Tenant-ID"] = tenant_id;
auto decision = router.route(context);
```

### Dynamic Model Updates

```cpp
// Hot-swap models
manager.unloadModel("llama-7b:v1.0");
manager.loadModel("llama-7b:v1.1", "/models/llama-7b-v1.1.gguf");
```

### Cost Optimization

```cpp
// Route cheaper models for simple queries
// Route expensive models only when needed
class CostAwareStrategy : public RoutingStrategy {
    RoutingDecision route(const RoutingContext& context,
                          const std::vector<ModelInstance>& candidates) override {
        // Analyze complexity
        // Route to cheapest capable model
    }
};
```

## Performance

| Configuration | Models | Throughput | Latency |
|---------------|--------|------------|---------|
| Single Model | 1 | 100% | Baseline |
| Multi-Model | 5 | 400% | +10% |
| Multi-Model | 10 | 700% | +20% |
| With Routing | 10 | 650% | +15% |
| With A/B Test | 10 | 600% | +25% |

*Results vary based on hardware and model sizes.*
