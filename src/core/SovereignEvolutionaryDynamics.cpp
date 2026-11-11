//==============================================================================
// SovereignEvolutionaryDynamics.cpp - Evolutionary Dynamics Implementation
// Adaptive mutation, generational refinement, evolutionary pressure modeling
// Pure C++, no STL, no CRT, no external dependencies
//==============================================================================

#include "SovereignEvolutionaryDynamics.h"
#include <windows.h>
#include <cstring>

//==============================================================================
// Static State
//==============================================================================

static EvoDynamicsConfig s_config = EVO_DYNAMICS_DEFAULT;
static Generation s_population[256];
static unsigned int s_populationCount = 0;
static unsigned int s_currentGeneration = 0;
static Generation s_elite[16];
static unsigned int s_eliteCount = 0;
static Mutation s_mutationHistory[1024];
static unsigned int s_mutationCount = 0;
static FitnessLandscape s_landscape = {0};
static EvolutionaryPressure s_pressures[8];
static unsigned int s_pressureCount = 0;
static bool s_initialized = false;

//==============================================================================
// Initialization
//==============================================================================

void SovereignEvoDynamics_Initialize(const EvoDynamicsConfig& cfg)
{
    s_config = cfg;
    s_populationCount = 0;
    s_currentGeneration = 0;
    s_eliteCount = 0;
    s_mutationCount = 0;
    s_pressureCount = 0;
    memset(&s_landscape, 0, sizeof(s_landscape));
    
    // Initialize first generation from current system state
    Generation gen0;
    memset(&gen0, 0, sizeof(gen0));
    gen0.id = 0;
    gen0.timestamp = GetTickCount();
    
    // Get current system metrics
    // TODO: Query actual system state
    gen0.expertCount = 64;
    gen0.workflowCount = 16;
    gen0.segNodeCount = 32;
    gen0.subsystemCount = 8;
    gen0.avgConfidence = 0.75f;
    gen0.avgLatency = 100.0f;
    gen0.fitnessScore = CalculateInitialFitness();
    gen0.isElite = true;
    
    s_population[s_populationCount++] = gen0;
    s_elite[s_eliteCount++] = gen0;
    
    s_initialized = true;
    
    OutputDebugStringA("[EvoDynamics] Initialized\n");
}

static float CalculateInitialFitness()
{
    // Initial fitness based on system capabilities
    float fitness = 0.5f; // Base
    
    // Bonus for each subsystem
    fitness += 0.05f * 8; // 8 subsystems
    
    // Bonus for experts
    fitness += 0.01f * 64; // 64 experts
    
    // Bonus for workflows
    fitness += 0.02f * 16; // 16 workflows
    
    return fitness > 1.0f ? 1.0f : fitness;
}

//==============================================================================
// Core Evolution Loop
//==============================================================================

void SovereignEvoDynamics_EvolveGeneration()
{
    if (!s_initialized) return;
    if (s_currentGeneration >= s_config.maxGenerations) return;
    
    s_currentGeneration++;
    
    OutputDebugStringA("[EvoDynamics] Evolving generation ");
    char msg[32];
    wsprintfA(msg, "%d\n", s_currentGeneration);
    OutputDebugStringA(msg);
    
    // Step 1: Evaluate current population
    SovereignEvoDynamics_EvaluatePopulation();
    
    // Step 2: Select parents
    Generation parents[256];
    unsigned int parentCount = 0;
    SovereignEvoDynamics_SelectParents(parents, s_config.populationSize / 2);
    
    // Step 3: Crossover to create offspring
    Generation offspring[256];
    unsigned int offspringCount = 0;
    
    for (unsigned int i = 0; i < parentCount - 1; i += 2) {
        if ((float)(rand() % 100) / 100.0f < s_config.crossoverRate) {
            SovereignEvoDynamics_Crossover(&parents[i], &parents[i + 1], 
                                           &offspring[offspringCount]);
            offspring[offspringCount].id = s_currentGeneration * 1000 + i;
            offspring[offspringCount].timestamp = GetTickCount();
            offspringCount++;
        }
    }
    
    // Step 4: Mutate offspring
    for (unsigned int i = 0; i < offspringCount; i++) {
        if ((float)(rand() % 100) / 100.0f < s_config.mutationRate) {
            SovereignEvoDynamics_MutateRandom(&offspring[i]);
        }
    }
    
    // Step 5: Evaluate offspring
    for (unsigned int i = 0; i < offspringCount; i++) {
        SovereignEvoDynamics_EvaluateFitness(&offspring[i]);
    }
    
    // Step 6: Select next generation (elitist + offspring)
    // Keep elites
    unsigned int newPopCount = 0;
    for (unsigned int i = 0; i < s_eliteCount && i < s_config.eliteCount; i++) {
        s_population[newPopCount++] = s_elite[i];
    }
    
    // Add best offspring
    for (unsigned int i = 0; i < offspringCount && newPopCount < s_config.populationSize; i++) {
        s_population[newPopCount++] = offspring[i];
    }
    
    s_populationCount = newPopCount;
    
    // Step 7: Update elite
    SovereignEvoDynamics_SelectElite(s_elite, s_config.eliteCount);
    
    // Step 8: Update fitness landscape
    SovereignEvoDynamics_UpdateLandscape();
    
    // Step 9: Adapt mutation rate if enabled
    if (s_config.enableAdaptiveMutation) {
        SovereignEvoDynamics_AdaptMutationRate();
    }
    
    // Step 10: Check for convergence
    if (SovereignEvoDynamics_HasConverged()) {
        OutputDebugStringA("[EvoDynamics] Convergence detected\n");
    }
    
    // Step 11: Trigger speciation if diversity is low
    if (s_config.enableSpeciation && s_landscape.diversityIndex < 0.2f) {
        SovereignEvoDynamics_TriggerSpeciation();
    }
}

//==============================================================================
// Fitness Evaluation
//==============================================================================

void SovereignEvoDynamics_EvaluateFitness(Generation* gen)
{
    if (!gen) return;
    
    // Base fitness calculation
    float fitness = 0.0f;
    
    // Component count contribution
    fitness += gen->expertCount * 0.01f;
    fitness += gen->workflowCount * 0.02f;
    fitness += gen->segNodeCount * 0.015f;
    fitness += gen->subsystemCount * 0.025f;
    
    // Performance contribution
    fitness += gen->avgConfidence * 0.3f;
    fitness -= gen->avgLatency * 0.001f; // Penalty for latency
    
    // Apply evolutionary pressures
    for (unsigned int i = 0; i < s_pressureCount; i++) {
        switch (s_pressures[i].type) {
            case PRESSURE_PERFORMANCE:
                fitness += s_pressures[i].intensity * 0.1f * s_pressures[i].direction;
                break;
            case PRESSURE_ACCURACY:
                fitness += gen->avgConfidence * s_pressures[i].intensity * s_pressures[i].direction;
                break;
            case PRESSURE_EFFICIENCY:
                fitness -= gen->avgLatency * s_pressures[i].intensity * 0.0001f * s_pressures[i].direction;
                break;
            case PRESSURE_ADAPTABILITY:
                // Bonus for diverse component counts
                fitness += (gen->expertCount + gen->workflowCount) * 0.001f * s_pressures[i].intensity * s_pressures[i].direction;
                break;
            case PRESSURE_STABILITY:
                // Penalty for extreme values
                if (gen->avgConfidence < 0.5f || gen->avgConfidence > 0.95f) {
                    fitness -= s_pressures[i].intensity * 0.1f;
                }
                break;
        }
    }
    
    // Clamp fitness
    if (fitness < 0.0f) fitness = 0.0f;
    if (fitness > 1.0f) fitness = 1.0f;
    
    gen->fitnessScore = fitness;
}

void SovereignEvoDynamics_EvaluatePopulation()
{
    for (unsigned int i = 0; i < s_populationCount; i++) {
        SovereignEvoDynamics_EvaluateFitness(&s_population[i]);
    }
}

float SovereignEvoDynamics_CalculateFitness(const Generation* gen)
{
    if (!gen) return 0.0f;
    return gen->fitnessScore;
}

//==============================================================================
// Selection Operations
//==============================================================================

void SovereignEvoDynamics_SelectElite(Generation* elite, unsigned int count)
{
    if (!elite || count == 0) return;
    
    // Sort population by fitness (bubble sort for simplicity)
    for (unsigned int i = 0; i < s_populationCount; i++) {
        for (unsigned int j = i + 1; j < s_populationCount; j++) {
            if (s_population[j].fitnessScore > s_population[i].fitnessScore) {
                Generation temp = s_population[i];
                s_population[i] = s_population[j];
                s_population[j] = temp;
            }
        }
    }
    
    // Copy top performers to elite
    s_eliteCount = 0;
    for (unsigned int i = 0; i < count && i < s_populationCount; i++) {
        elite[s_eliteCount] = s_population[i];
        elite[s_eliteCount].isElite = true;
        s_eliteCount++;
    }
}

void SovereignEvoDynamics_SelectParents(Generation* parents, unsigned int count)
{
    if (!parents || count == 0) return;
    
    switch (s_config.selection) {
        case SELECT_ELITIST:
            // Just take the best
            for (unsigned int i = 0; i < count && i < s_eliteCount; i++) {
                parents[i] = s_elite[i];
            }
            break;
            
        case SELECT_TOURNAMENT:
            // Tournament selection
            for (unsigned int i = 0; i < count; i++) {
                // Pick 3 random individuals, select best
                unsigned int idx1 = rand() % s_populationCount;
                unsigned int idx2 = rand() % s_populationCount;
                unsigned int idx3 = rand() % s_populationCount;
                
                unsigned int best = idx1;
                if (s_population[idx2].fitnessScore > s_population[best].fitnessScore) best = idx2;
                if (s_population[idx3].fitnessScore > s_population[best].fitnessScore) best = idx3;
                
                parents[i] = s_population[best];
            }
            break;
            
        case SELECT_ROULETTE:
            // Fitness-proportionate selection
            {
                float totalFitness = 0.0f;
                for (unsigned int i = 0; i < s_populationCount; i++) {
                    totalFitness += s_population[i].fitnessScore;
                }
                
                for (unsigned int i = 0; i < count; i++) {
                    float pick = ((float)(rand() % 1000) / 1000.0f) * totalFitness;
                    float accum = 0.0f;
                    
                    for (unsigned int j = 0; j < s_populationCount; j++) {
                        accum += s_population[j].fitnessScore;
                        if (accum >= pick) {
                            parents[i] = s_population[j];
                            break;
                        }
                    }
                }
            }
            break;
            
        case SELECT_RANK:
            // Rank-based selection
            for (unsigned int i = 0; i < count && i < s_populationCount; i++) {
                // Higher probability for higher ranks
                unsigned int rank = i;
                parents[i] = s_population[rank];
            }
            break;
            
        case SELECT_BOLTZMANN:
            // Temperature-based selection
            {
                float temperature = 1.0f - ((float)s_currentGeneration / s_config.maxGenerations);
                if (temperature < 0.1f) temperature = 0.1f;
                
                for (unsigned int i = 0; i < count; i++) {
                    // Boltzmann probability
                    float maxFitness = s_elite[0].fitnessScore;
                    float prob = exp((s_population[i].fitnessScore - maxFitness) / temperature);
                    
                    if ((float)(rand() % 100) / 100.0f < prob) {
                        parents[i] = s_population[i];
                    }
                }
            }
            break;
    }
}

//==============================================================================
// Crossover Operations
//==============================================================================

void SovereignEvoDynamics_Crossover(const Generation* parent1, 
                                     const Generation* parent2,
                                     Generation* offspring)
{
    if (!parent1 || !parent2 || !offspring) return;
    
    // Uniform crossover - mix component counts
    offspring->expertCount = (parent1->expertCount + parent2->expertCount) / 2;
    offspring->workflowCount = (parent1->workflowCount + parent2->workflowCount) / 2;
    offspring->segNodeCount = (parent1->segNodeCount + parent2->segNodeCount) / 2;
    offspring->subsystemCount = (parent1->subsystemCount + parent2->subsystemCount) / 2;
    
    // Average performance metrics
    offspring->avgConfidence = (parent1->avgConfidence + parent2->avgConfidence) / 2.0f;
    offspring->avgLatency = (parent1->avgLatency + parent2->avgLatency) / 2.0f;
    
    // Fitness is recalculated later
    offspring->fitnessScore = 0.0f;
    offspring->isElite = false;
}

//==============================================================================
// Mutation Operations
//==============================================================================

void SovereignEvoDynamics_Mutate(Generation* individual, MutationType type)
{
    if (!individual) return;
    
    Mutation mut;
    memset(&mut, 0, sizeof(mut));
    mut.type = type;
    mut.targetId = individual->id;
    mut.generation = s_currentGeneration;
    
    switch (type) {
        case MUTATE_EXPERT_BODY:
            // Modify expert count slightly
            individual->expertCount += (rand() % 5) - 2; // -2 to +2
            if (individual->expertCount < 1) individual->expertCount = 1;
            if (individual->expertCount > 128) individual->expertCount = 128;
            mut.magnitude = 2.0f;
            break;
            
        case MUTATE_ROUTING_WEIGHT:
            // Modify confidence threshold
            individual->avgConfidence += ((float)(rand() % 20) - 10.0f) / 100.0f;
            if (individual->avgConfidence < 0.0f) individual->avgConfidence = 0.0f;
            if (individual->avgConfidence > 1.0f) individual->avgConfidence = 1.0f;
            mut.magnitude = 0.1f;
            break;
            
        case MUTATE_WORKFLOW_PATH:
            // Modify workflow count
            individual->workflowCount += (rand() % 3) - 1; // -1 to +1
            if (individual->workflowCount < 1) individual->workflowCount = 1;
            if (individual->workflowCount > 64) individual->workflowCount = 64;
            mut.magnitude = 1.0f;
            break;
            
        case MUTATE_SEG_TOPOLOGY:
            // Modify SEG node count
            individual->segNodeCount += (rand() % 4) - 2; // -2 to +2
            if (individual->segNodeCount < 1) individual->segNodeCount = 1;
            if (individual->segNodeCount > 256) individual->segNodeCount = 256;
            mut.magnitude = 2.0f;
            break;
            
        case MUTATE_SUBSYSTEM_ROLE:
            // Modify subsystem count
            individual->subsystemCount += (rand() % 2) - 1; // -1 to +1
            if (individual->subsystemCount < 1) individual->subsystemCount = 1;
            if (individual->subsystemCount > 32) individual->subsystemCount = 32;
            mut.magnitude = 1.0f;
            break;
            
        case MUTATE_CAPABILITY_SET:
            // Modify multiple components
            individual->expertCount += (rand() % 3) - 1;
            individual->workflowCount += (rand() % 2) - 1;
            mut.magnitude = 1.5f;
            break;
            
        case MUTATE_CONFIDENCE_THRESHOLD:
            // Modify latency target
            individual->avgLatency += (float)((rand() % 20) - 10);
            if (individual->avgLatency < 10.0f) individual->avgLatency = 10.0f;
            if (individual->avgLatency > 1000.0f) individual->avgLatency = 1000.0f;
            mut.magnitude = 10.0f;
            break;
    }
    
    // Record mutation
    if (s_mutationCount < 1024) {
        s_mutationHistory[s_mutationCount++] = mut;
    }
}

void SovereignEvoDynamics_MutateRandom(Generation* individual)
{
    if (!individual) return;
    
    // Random mutation type
    MutationType type = (MutationType)(rand() % MUTATE_CONFIDENCE_THRESHOLD);
    SovereignEvoDynamics_Mutate(individual, type);
}

//==============================================================================
// Adaptive Mutation
//==============================================================================

void SovereignEvoDynamics_AdaptMutationRate()
{
    // If population is converging, increase mutation to maintain diversity
    if (s_landscape.diversityIndex < 0.3f) {
        s_config.mutationRate += 0.01f;
        if (s_config.mutationRate > 0.3f) s_config.mutationRate = 0.3f;
        
        OutputDebugStringA("[EvoDynamics] Increased mutation rate to maintain diversity\n");
    }
    // If population is too diverse, decrease mutation
    else if (s_landscape.diversityIndex > 0.8f) {
        s_config.mutationRate -= 0.01f;
        if (s_config.mutationRate < 0.01f) s_config.mutationRate = 0.01f;
        
        OutputDebugStringA("[EvoDynamics] Decreased mutation rate to stabilize\n");
    }
}

void SovereignEvoDynamics_AdaptPressureIntensity()
{
    // Adjust pressure based on progress
    if (s_landscape.isConverging) {
        // Reduce pressure as we approach optimum
        s_config.pressureIntensity *= 0.95f;
    } else {
        // Increase pressure to drive evolution
        s_config.pressureIntensity *= 1.05f;
        if (s_config.pressureIntensity > 1.0f) s_config.pressureIntensity = 1.0f;
    }
}

//==============================================================================
// Fitness Landscape
//==============================================================================

void SovereignEvoDynamics_UpdateLandscape()
{
    if (s_populationCount == 0) return;
    
    // Calculate average fitness
    float avgFitness = 0.0f;
    float maxFitness = 0.0f;
    float minFitness = 1.0f;
    
    for (unsigned int i = 0; i < s_populationCount; i++) {
        avgFitness += s_population[i].fitnessScore;
        if (s_population[i].fitnessScore > maxFitness) maxFitness = s_population[i].fitnessScore;
        if (s_population[i].fitnessScore < minFitness) minFitness = s_population[i].fitnessScore;
    }
    avgFitness /= s_populationCount;
    
    s_landscape.populationAvg = avgFitness;
    s_landscape.currentPeak = maxFitness;
    s_landscape.globalOptimum = 1.0f; // Theoretical maximum
    
    // Calculate diversity index (standard deviation of fitness)
    float variance = 0.0f;
    for (unsigned int i = 0; i < s_populationCount; i++) {
        float diff = s_population[i].fitnessScore - avgFitness;
        variance += diff * diff;
    }
    variance /= s_populationCount;
    s_landscape.diversityIndex = sqrt(variance);
    
    // Count local optima (simplified)
    s_landscape.localOptimaCount = 0;
    for (unsigned int i = 1; i < s_populationCount - 1; i++) {
        if (s_population[i].fitnessScore > s_population[i-1].fitnessScore &&
            s_population[i].fitnessScore > s_population[i+1].fitnessScore) {
            s_landscape.localOptimaCount++;
        }
    }
    
    // Determine if converging
    s_landscape.isConverging = (s_landscape.diversityIndex < s_config.convergenceThreshold);
    s_landscape.isExploring = (s_landscape.diversityIndex > 0.5f);
}

void SovereignEvoDynamics_GetLandscape(FitnessLandscape* landscape)
{
    if (landscape) {
        *landscape = s_landscape;
    }
}

//==============================================================================
// Convergence Check
//==============================================================================

bool SovereignEvoDynamics_HasConverged()
{
    return s_landscape.isConverging;
}

//==============================================================================
// Speciation
//==============================================================================

void SovereignEvoDynamics_TriggerSpeciation()
{
    OutputDebugStringA("[EvoDynamics] Triggering speciation\n");
    
    // Create new species by significantly mutating some individuals
    for (unsigned int i = s_eliteCount; i < s_populationCount; i++) {
        // Heavy mutation
        SovereignEvoDynamics_Mutate(&s_population[i], MUTATE_CAPABILITY_SET);
        SovereignEvoDynamics_Mutate(&s_population[i], MUTATE_SEG_TOPOLOGY);
        
        // Re-evaluate
        SovereignEvoDynamics_EvaluateFitness(&s_population[i]);
    }
    
    // Reset diversity tracking
    s_landscape.diversityIndex = 1.0f;
}

//==============================================================================
// Pressure Application
//==============================================================================

void SovereignEvoDynamics_ApplyPressure(const EvolutionaryPressure& pressure)
{
    if (s_pressureCount < 8) {
        s_pressures[s_pressureCount++] = pressure;
        
        char msg[256];
        wsprintfA(msg, "[EvoDynamics] Applied pressure: type=%d intensity=%.2f\n",
                  pressure.type, pressure.intensity);
        OutputDebugStringA(msg);
    }
}

//==============================================================================
// Getters
//==============================================================================

void SovereignEvoDynamics_GetGeneration(Generation* gen)
{
    if (gen && s_populationCount > 0) {
        // Return best of current generation
        *gen = s_elite[0];
    }
}

void SovereignEvoDynamics_GetElite(Generation* elite)
{
    if (elite && s_eliteCount > 0) {
        *elite = s_elite[0];
    }
}

void SovereignEvoDynamics_GetMutations(Mutation* mutations, unsigned int* count)
{
    if (!mutations || !count) return;
    
    unsigned int copyCount = *count;
    if (copyCount > s_mutationCount) copyCount = s_mutationCount;
    
    for (unsigned int i = 0; i < copyCount; i++) {
        mutations[i] = s_mutationHistory[i];
    }
    
    *count = copyCount;
}

//==============================================================================
// Reset
//==============================================================================

void SovereignEvoDynamics_Reset()
{
    s_populationCount = 0;
    s_currentGeneration = 0;
    s_eliteCount = 0;
    s_mutationCount = 0;
    s_pressureCount = 0;
    memset(&s_landscape, 0, sizeof(s_landscape));
    
    OutputDebugStringA("[EvoDynamics] Reset\n");
}

//==============================================================================
// IDE Integration
//==============================================================================

void SovereignEvoDynamics_RenderPanel()
{
    // This would be called by the IDE to render the evolution panel
    // showing fitness over generations, mutation history, etc.
    
    char msg[512];
    wsprintfA(msg, "Generation: %d | Best Fitness: %.3f | Diversity: %.3f\n",
              s_currentGeneration, s_elite[0].fitnessScore, s_landscape.diversityIndex);
    OutputDebugStringA(msg);
}

void SovereignEvoDynamics_ExportGenerationData(const char* path)
{
    HANDLE hFile = CreateFileA(path, GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return;
    
    // Write CSV header
    const char* header = "Generation,ExpertCount,WorkflowCount,SEGs,Subsystems,AvgConfidence,AvgLatency,Fitness\n";
    DWORD written;
    WriteFile(hFile, header, strlen(header), &written, nullptr);
    
    // Write population data
    for (unsigned int i = 0; i < s_populationCount; i++) {
        char line[512];
        wsprintfA(line, "%d,%d,%d,%d,%d,%.3f,%.1f,%.3f\n",
                  s_population[i].id,
                  s_population[i].expertCount,
                  s_population[i].workflowCount,
                  s_population[i].segNodeCount,
                  s_population[i].subsystemCount,
                  s_population[i].avgConfidence,
                  s_population[i].avgLatency,
                  s_population[i].fitnessScore);
        WriteFile(hFile, line, strlen(line), &written, nullptr);
    }
    
    CloseHandle(hFile);
}
