//==============================================================================
// SovereignEvolutionaryDynamics.h - Evolutionary Dynamics Layer
// Adaptive mutation, generational refinement, evolutionary pressure modeling
// Pure C++, no STL, no CRT, no external dependencies
//==============================================================================

#ifndef SOVEREIGN_EVOLUTIONARY_DYNAMICS_H
#define SOVEREIGN_EVOLUTIONARY_DYNAMICS_H

#include "SovereignEmergence.h"

//==============================================================================
// Evolutionary Generation
//==============================================================================

struct Generation {
    unsigned int id;
    unsigned int timestamp;
    unsigned int expertCount;
    unsigned int workflowCount;
    unsigned int segNodeCount;
    unsigned int subsystemCount;
    float avgConfidence;
    float avgLatency;
    float fitnessScore;
    bool isElite;
};

//==============================================================================
// Evolutionary Pressure
//==============================================================================

enum PressureType {
    PRESSURE_PERFORMANCE,    // Latency, throughput
    PRESSURE_ACCURACY,       // Confidence, correctness
    PRESSURE_EFFICIENCY,     // Resource usage
    PRESSURE_ADAPTABILITY,   // Response to change
    PRESSURE_STABILITY       // Consistency over time
};

struct EvolutionaryPressure {
    PressureType type;
    float intensity;          // 0.0 - 1.0
    float direction;        // +1 (increase) or -1 (decrease)
    unsigned int targetComponent; // Which component is under pressure
};

//==============================================================================
// Mutation Types
//==============================================================================

enum MutationType {
    MUTATE_EXPERT_BODY,      // Modify expert implementation
    MUTATE_ROUTING_WEIGHT,   // Change routing heuristics
    MUTATE_WORKFLOW_PATH,    // Alter workflow structure
    MUTATE_SEG_TOPOLOGY,     // Change SEG graph
    MUTATE_SUBSYSTEM_ROLE,   // Reassign subsystem responsibilities
    MUTATE_CAPABILITY_SET,   // Add/remove capabilities
    MUTATE_CONFIDENCE_THRESHOLD // Adjust thresholds
};

struct Mutation {
    MutationType type;
    unsigned int targetId;
    float magnitude;        // How extreme the mutation
    bool isBeneficial;      // Determined post-fitness evaluation
    unsigned int generation;
};

//==============================================================================
// Fitness Landscape
//==============================================================================

struct FitnessLandscape {
    float globalOptimum;     // Theoretical best fitness
    float currentPeak;     // Best fitness achieved
    float populationAvg;     // Average fitness
    float diversityIndex;  // Genetic diversity measure
    unsigned int localOptimaCount;
    bool isConverging;
    bool isExploring;
};

//==============================================================================
// Selection Strategy
//==============================================================================

enum SelectionStrategy {
    SELECT_ELITIST,         // Keep top performers
    SELECT_TOURNAMENT,      // Competitive selection
    SELECT_ROULETTE,        // Fitness-proportionate
    SELECT_RANK,            // Rank-based
    SELECT_BOLTZMANN        // Temperature-based
};

//==============================================================================
// Evolutionary Dynamics Configuration
//==============================================================================

struct EvoDynamicsConfig {
    unsigned int populationSize;
    unsigned int eliteCount;
    float mutationRate;
    float crossoverRate;
    SelectionStrategy selection;
    float pressureIntensity;
    bool enableAdaptiveMutation;
    bool enableSpeciation;
    unsigned int maxGenerations;
    float convergenceThreshold;
};

static const EvoDynamicsConfig EVO_DYNAMICS_DEFAULT = {
    64,                     // populationSize
    4,                      // eliteCount
    0.05f,                  // mutationRate (5%)
    0.7f,                   // crossoverRate (70%)
    SELECT_TOURNAMENT,      // selection
    0.5f,                   // pressureIntensity
    true,                   // enableAdaptiveMutation
    true,                   // enableSpeciation
    1000,                   // maxGenerations
    0.01f                   // convergenceThreshold
};

//==============================================================================
// Evolutionary Dynamics Interface
//==============================================================================

// Initialize evolutionary dynamics
void SovereignEvoDynamics_Initialize(const EvoDynamicsConfig& cfg);

// Run one generation of evolution
void SovereignEvoDynamics_EvolveGeneration();

// Get current generation info
void SovereignEvoDynamics_GetGeneration(Generation* gen);

// Get fitness landscape
void SovereignEvoDynamics_GetLandscape(FitnessLandscape* landscape);

// Apply evolutionary pressure
void SovereignEvoDynamics_ApplyPressure(const EvolutionaryPressure& pressure);

// Get mutation history
void SovereignEvoDynamics_GetMutations(Mutation* mutations, unsigned int* count);

// Check for convergence
bool SovereignEvoDynamics_HasConverged();

// Get best individual
void SovereignEvoDynamics_GetElite(Generation* elite);

// Force speciation (divergence)
void SovereignEvoDynamics_TriggerSpeciation();

// Reset evolution
void SovereignEvoDynamics_Reset();

//==============================================================================
// Adaptive Mutation
//==============================================================================

void SovereignEvoDynamics_AdaptMutationRate();
void SovereignEvoDynamics_AdaptPressureIntensity();

//==============================================================================
// Generational Analysis
//==============================================================================

void SovereignEvoDynamics_AnalyzeGeneration(const Generation* gen);
float SovereignEvoDynamics_CalculateFitness(const Generation* gen);

//==============================================================================
// Selection Operations
//==============================================================================

void SovereignEvoDynamics_SelectElite(Generation* elite, unsigned int count);
void SovereignEvoDynamics_SelectParents(Generation* parents, unsigned int count);

//==============================================================================
// Crossover Operations
//==============================================================================

void SovereignEvoDynamics_Crossover(const Generation* parent1, 
                                     const Generation* parent2,
                                     Generation* offspring);

//==============================================================================
// Mutation Operations
//==============================================================================

void SovereignEvoDynamics_Mutate(Generation* individual, MutationType type);
void SovereignEvoDynamics_MutateRandom(Generation* individual);

//==============================================================================
// Fitness Evaluation
//==============================================================================

void SovereignEvoDynamics_EvaluateFitness(Generation* gen);
void SovereignEvoDynamics_EvaluatePopulation();

//==============================================================================
// IDE Integration
//==============================================================================

void SovereignEvoDynamics_RenderPanel();
void SovereignEvoDynamics_ExportGenerationData(const char* path);

#endif // SOVEREIGN_EVOLUTIONARY_DYNAMICS_H
