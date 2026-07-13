# Phase O.5/5: ML Research Features Documentation

## ML Research Guide

This guide covers RawrXD's ML research capabilities including model registry, experiment tracking, A/B testing, and feature store for AI research teams.

---

## Table of Contents

1. [Model Registry](#model-registry)
2. [Experiment Tracking](#experiment-tracking)
3. [A/B Testing](#ab-testing)
4. [Feature Store](#feature-store)
5. [Best Practices](#best-practices)

---

## Model Registry

### Overview

The Model Registry provides versioned model management with full lineage tracking, artifact storage, and lifecycle management.

### Key Concepts

- **Model**: A specific version of an AI model with associated artifacts
- **Version**: Semantic versioning (major.minor.patch)
- **Stage**: Development → Staging → Production → Deprecated → Archived
- **Lineage**: Training history and parent-child relationships

### Quick Start

```cpp
#include <RawrXD/ML/ModelRegistry.hpp>

// Register a new model
RawrXD::ML::ModelDefinition model;
model.name = "llama-3-finetuned";
model.version = {3, 1, 0};  // v3.1.0
model.stage = RawrXD::ML::ModelStage::STAGING;
model.metadata.architecture = "llama";
model.metadata.parameter_count = 7000000000;

// Add artifacts
RawrXD::ML::ModelArtifact weights;
weights.type = RawrXD::ML::ArtifactType::MODEL_WEIGHTS;
weights.format = "gguf";
weights.size_bytes = 4200000000;
weights.checksum = "sha256:abc123...";
model.artifacts.push_back(weights);

// Register
auto registry = RawrXD::ML::g_model_registry;
registry->RegisterModel(model);
```

### Model Lifecycle

```
Development → Staging → Production → Deprecated → Archived
     ↑           ↓          ↓
   Training   Testing   Deployment
```

### Version Aliases

```cpp
// Set aliases for easy reference
registry->SetModelAlias("llama-3-finetuned-v3.1.0", "latest");
registry->SetModelAlias("llama-3-finetuned-v3.1.0", "stable");

// Retrieve by alias
auto model = registry->GetModelByAlias("llama-3-finetuned", "latest");
```

### Lineage Tracking

```cpp
// Record training lineage
RawrXD::ML::ModelLineage lineage;
lineage.model_id = "llama-3-finetuned-v3.1.0";
lineage.parent_model_id = "llama-3-base-v3.0.0";
lineage.training_dataset = "custom-instruction-dataset-v2";
lineage.hyperparameters["learning_rate"] = "2e-5";
lineage.hyperparameters["epochs"] = "3";
lineage.training_cost = 450.50;  // USD

registry->RecordLineage(lineage);

// Get model family
auto family = registry->GetModelFamily("llama-3-finetuned-v3.1.0");
```

---

## Experiment Tracking

### Overview

Track ML experiments with automatic logging of parameters, metrics, and artifacts.

### Quick Start

```cpp
#include <RawrXD/ML/ExperimentTracker.hpp>

// Create experiment
auto tracker = RawrXD::ML::g_experiment_tracker;
std::string experiment_id = tracker->CreateExperiment(
    "project-123",
    "llama-finetuning-run-1",
    {
        {"learning_rate", 2e-5, "Adam learning rate"},
        {"batch_size", 32, "Training batch size"},
        {"epochs", 3, "Number of training epochs"}
    }
);

// Start experiment
tracker->StartExperiment(experiment_id);

// Log metrics during training
for (int epoch = 0; epoch < 3; epoch++) {
    float loss = TrainEpoch();
    tracker->LogMetric(experiment_id, "train_loss", loss, epoch);
    tracker->LogMetric(experiment_id, "learning_rate", 
                       GetCurrentLR(), epoch);
}

// Log final model as artifact
RawrXD::ML::ExperimentArtifact artifact;
artifact.name = "final-model.gguf";
artifact.type = "model";
artifact.path = "/models/final-model.gguf";
tracker->LogArtifact(experiment_id, artifact);

// End experiment
tracker->EndExperiment(experiment_id, true);
```

### Auto-Tracking with RAII

```cpp
{
    // Automatically starts and ends experiment
    RAWRXD_EXPERIMENT("project-123", "auto-tracked-experiment", {
        {"model", "llama-3"},
        {"lora_rank", 16}
    });
    
    // Automatic logging macros
    RAWRXD_LOG_METRIC("loss", 0.5);
    RAWRXD_LOG_PARAM("completed_epochs", 3);
    
    // Experiment automatically ends when scope exits
}
```

### Comparing Experiments

```cpp
// Compare two runs
auto comparison = tracker->CompareRuns("run-1", "run-2");

std::cout << "Overall improvement: " 
          << comparison.overall_improvement << "%\n";

for (const auto& [metric, values] : comparison.metric_differences) {
    std::cout << metric << ": " << values.first 
              << " -> " << values.second << "\n";
}
```

### Best Runs

```cpp
// Get top 5 runs by validation loss
auto best_runs = tracker->GetBestRuns(
    "project-123",
    "val_loss",
    5,      // top_k
    false   // lower is better
);
```

---

## A/B Testing

### Overview

Compare model variants with statistical rigor using automated traffic allocation and significance testing.

### Quick Start

```cpp
#include <RawrXD/ML/ABTesting.hpp>

// Create A/B test
RawrXD::ML::ABTest test;
test.name = "llama-3-vs-mistral";
test.hypothesis = "Llama-3 provides better instruction following";
test.target_models = {"llama-3", "mistral"};

// Define variants
test.variants.push_back({
    .id = "control",
    .name = "Llama-3",
    .model_id = "llama-3-8b",
    .traffic_percentage = 50.0,
    .control = true
});

test.variants.push_back({
    .id = "treatment",
    .name = "Mistral",
    .model_id = "mistral-7b",
    .traffic_percentage = 50.0,
    .control = false
});

// Define success metric
test.primary_metric = {
    .name = "instruction_accuracy",
    .type = RawrXD::ML::SuccessMetric::Type::CONVERSION,
    .direction = RawrXD::ML::SuccessMetric::Direction::HIGHER_IS_BETTER,
    .minimum_detectable_effect = 0.05,  // 5% improvement
    .baseline_value = 0.75
};

// Configure test
test.min_sample_size = 1000;
test.significance_level = 0.05;
test.statistical_power = 0.80;
test.min_duration = std::chrono::hours(24);

// Create and start
auto ab_manager = RawrXD::ML::g_ab_testing_manager;
std::string test_id = ab_manager->CreateTest(test);
ab_manager->StartTest(test_id);
```

### Traffic Assignment

```cpp
// Assign variant to user
auto assignment = ab_manager->AssignVariant(test_id, "user-123");

if (assignment.assigned) {
    std::cout << "User assigned to variant: " 
              << assignment.variant_id << "\n";
    
    // Use the assigned model
    std::string model_id = GetModelForVariant(assignment.variant_id);
    auto response = RunInference(model_id, user_prompt);
    
    // Track impression
    ab_manager->TrackImpression(assignment.assignment_id);
    
    // Track conversion (e.g., user rated response as helpful)
    if (user_liked_response) {
        ab_manager->TrackConversion(assignment.assignment_id, {
            {"rating", 5.0},
            {"latency_ms", response.time_ms}
        });
    }
}
```

### Automatic Assignment

```cpp
// Automatically find and assign to relevant test
auto assignment = ab_manager->AssignVariantAuto(
    "user-123",
    "llama-3",  // base model
    {{"tenant", "enterprise-1"}}
);
```

### Analysis

```cpp
// Check if test is significant
if (ab_manager->IsTestSignificant(test_id)) {
    auto winner = ab_manager->GetWinningVariant(test_id);
    std::cout << "Winning variant: " << winner.value() << "\n";
    
    // Get detailed results
    auto results = ab_manager->AnalyzeAllVariants(test_id);
    for (const auto& result : results) {
        std::cout << result.variant_id << ": "
                  << result.relative_lift * 100 << "% lift, "
                  << "p=" << result.p_value << "\n";
    }
}

// Generate report
ab_manager->GenerateReport(test_id, "/reports/ab-test-1.html", "html");
```

### Statistical Methods

- **Frequentist**: Two-sample t-test, chi-square test
- **Bayesian**: Probability of being best, expected loss
- **Sequential**: Optional stopping with proper bounds
- **Multi-armed bandit**: Thompson sampling, UCB

---

## Feature Store

### Overview

Centralized storage for ML features with online (low-latency) and offline (batch) serving.

### Quick Start

```cpp
#include <RawrXD/ML/FeatureStore.hpp>

auto store = RawrXD::ML::g_feature_store;

// Register a feature
RawrXD::ML::Feature feature;
feature.name = "user_avg_session_duration";
feature.type = RawrXD::ML::FeatureType::NUMERIC;
feature.entity_type = "user";
feature.schema.nullable = true;
feature.schema.default_value = 0.0;
feature.online_serving = true;
feature.offline_serving = true;
feature.ttl_seconds = 3600;  // 1 hour cache

store->RegisterFeature(feature);

// Ingest feature values
RawrXD::ML::FeatureRecord record;
record.entity_id = "user-123";
record.feature_name = "user_avg_session_duration";
record.value = 300.5;  // seconds
record.event_timestamp = std::chrono::system_clock::now();

store->IngestFeature(record);

// Retrieve for online serving
auto value = store->GetOnlineFeature("user-123", "user_avg_session_duration");
if (value) {
    double duration = std::get<double>(*value);
}

// Retrieve multiple features
auto features = store->GetOnlineFeatures("user-123", {
    "user_avg_session_duration",
    "user_total_sessions",
    "user_last_login_days"
});
```

### Feature Sets

```cpp
// Create a feature set
RawrXD::ML::FeatureSet feature_set;
feature_set.name = "user_engagement_features";
feature_set.entity_type = "user";
feature_set.feature_names = {
    "user_avg_session_duration",
    "user_total_sessions",
    "user_last_login_days",
    "user_feature_adoption_score"
};

std::string feature_set_id = store->CreateFeatureSet(feature_set);

// Materialize for serving
store->MaterializeFeatureSet(feature_set_id);

// Schedule regular materialization
store->ScheduleMaterialization(feature_set_id, "0 */6 * * *");  // Every 6 hours
```

### Point-in-Time Correctness

```cpp
// Get features as they were at a specific time
auto features = store->GetFeaturesAtTime(
    "user-123",
    {"user_subscription_tier", "user_monthly_spend"},
    std::chrono::system_clock::now() - std::chrono::days(30)
);
```

### Feature Transformations

```cpp
// Normalize a feature
auto normalized = RawrXD::ML::FeatureTransformer::Normalize(
    value, mean=300.0, std_dev=150.0
);

// Bucketize
auto bucket = RawrXD::ML::FeatureTransformer::Bucketize(
    session_duration, {0, 60, 300, 900, 1800}
);

// Time-based features
auto hour = RawrXD::ML::FeatureTransformer::ExtractHour(timestamp);
auto day_of_week = RawrXD::ML::FeatureTransformer::ExtractDayOfWeek(timestamp);
```

### Feature Monitoring

```cpp
// Detect feature drift
bool drift_detected = store->DetectFeatureDrift(
    "user_avg_session_duration",
    week_ago,
    now
);

// Get feature statistics
auto stats = store->GetFeatureStatistics("user_avg_session_duration");
std::cout << "Mean: " << stats.mean << "\n";
std::cout << "Null ratio: " 
          << (double)stats.null_count / stats.total_count << "\n";
```

---

## Best Practices

### Model Registry

1. **Version consistently**: Use semantic versioning
2. **Document thoroughly**: Include training config, dataset info
3. **Track lineage**: Always record parent models
4. **Stage appropriately**: Don't promote untested models
5. **Use aliases**: "latest", "stable", "production"

### Experiment Tracking

1. **Log everything**: Parameters, metrics, artifacts
2. **Use descriptive names**: Include model and dataset
3. **Tag experiments**: For easy filtering
4. **Compare systematically**: Use controlled comparisons
5. **Archive old runs**: Keep storage manageable

### A/B Testing

1. **Define hypothesis clearly**: Before starting test
2. **Calculate sample size**: Use power analysis
3. **Run for full duration**: Don't peek at results
4. **Check guardrails**: Monitor for degradation
5. **Document learnings**: Even for negative results

### Feature Store

1. **Define schemas strictly**: Validate all values
2. **Set appropriate TTLs**: Balance freshness vs latency
3. **Monitor for drift**: Detect data quality issues
4. **Version features**: When changing definitions
5. **Document lineage**: Track feature dependencies

---

## Integration Example

Complete workflow combining all features:

```cpp
// 1. Register base model
RawrXD::ML::ModelDefinition base_model;
base_model.name = "llama-3";
base_model.version = {3, 0, 0};
// ... configure ...
g_model_registry->RegisterModel(base_model);

// 2. Start experiment
std::string exp_id = g_experiment_tracker->CreateExperiment(
    "fine-tuning-project",
    "medical-qa-finetune",
    {{"lora_rank", 16}, {"learning_rate", 2e-5}}
);
g_experiment_tracker->StartExperiment(exp_id);

// 3. Load features for training
auto features = g_feature_store->GetOfflineFeatures(
    "medical_qa",
    {"question_embedding", "answer_quality_score"},
    training_start, training_end
);

// 4. Train and log metrics
for (int epoch = 0; epoch < epochs; epoch++) {
    float loss = TrainEpoch(features);
    g_experiment_tracker->LogMetric(exp_id, "loss", loss, epoch);
}

// 5. Register fine-tuned model
RawrXD::ML::ModelDefinition finetuned_model;
finetuned_model.name = "llama-3-medical-qa";
finetuned_model.version = {1, 0, 0};
finetuned_model.base_model = "llama-3-v3.0.0";
// ... configure ...
g_model_registry->RegisterModel(finetuned_model);

// 6. Record lineage
RawrXD::ML::ModelLineage lineage;
lineage.model_id = "llama-3-medical-qa-v1.0.0";
lineage.parent_model_id = "llama-3-v3.0.0";
lineage.training_dataset = "medical-qa-dataset-v2";
lineage.hyperparameters["lora_rank"] = "16";
g_model_registry->RecordLineage(lineage);

// 7. Create A/B test
RawrXD::ML::ABTest test;
test.name = "medical-qa-vs-base";
test.variants = {
    {.id = "control", .model_id = "llama-3-v3.0.0", .traffic_percentage = 50},
    {.id = "treatment", .model_id = "llama-3-medical-qa-v1.0.0", .traffic_percentage = 50}
};
test.primary_metric = {.name = "answer_accuracy", .type = CONVERSION};
std::string test_id = g_ab_testing_manager->CreateTest(test);
g_ab_testing_manager->StartTest(test_id);

// 8. End experiment
g_experiment_tracker->EndExperiment(exp_id, true);
```

---

## API Reference

See header files for complete API:
- `src/ml/ModelRegistry.hpp`
- `src/ml/ExperimentTracker.hpp`
- `src/ml/ABTesting.hpp`
- `src/ml/FeatureStore.hpp`

---

**Document Version:** 1.0.0
**Last Updated:** 2026-07-13
**RawrXD Version:** 1.0.0+
