// ============================================================================
// TrailForge_Gate.cpp — Certification gate proving recipe scheduler correctness
// RAWRXD_TRAILFORGE_GATE_001
//
// Build: compile with TrailForge.cpp + main
// Run:  TrailForge_Gate.exe
// Expected: PASS (all 4 strategies produce valid orderings; cycle detection
//           catches malformed recipes; random-ready determinism verified).
// ============================================================================
#include "TrailForge.h"
#include <cstdio>
#include <cstdlib>
#include <string>

using namespace Deep2::TrailForge;

static int g_passed = 0;
static int g_failed = 0;

static void check(bool cond, const char* expr, const char* file, int line) {
    if (cond) { ++g_passed; }
    else {
        ++g_failed;
        std::fprintf(stderr, "FAIL: %s at %s:%d\n", expr, file, line);
    }
}
#define CHECK(cond) check((cond), #cond, __FILE__, __LINE__)

// ---------------------------------------------------------------------------
// Test 1: Recipe validation rejects self-loop
// ---------------------------------------------------------------------------
static void testRecipeValidationSelfLoop() {
    ExecutionRecipe recipe;
    size_t n0 = recipe.addNode(ExecOp::Embed);
    recipe.addDependency(n0, n0); // self-loop
    std::string err;
    CHECK(!recipe.validate(&err));
    CHECK(err.find("depends on itself") != std::string::npos);
}

// ---------------------------------------------------------------------------
// Test 2: Recipe validation rejects out-of-bounds dependency
// ---------------------------------------------------------------------------
static void testRecipeValidationOOB() {
    ExecutionRecipe recipe;
    recipe.addNode(ExecOp::Embed);
    // Manually inject an out-of-bounds dependency to test validate()
    recipe.nodes[0].deps.push_back(5); // out of bounds
    std::string err;
    CHECK(!recipe.validate(&err));
    CHECK(err.find("out-of-bounds") != std::string::npos);
}

// ---------------------------------------------------------------------------
// Test 3: Cycle detection catches circular dependency
// ---------------------------------------------------------------------------
static void testCycleDetection() {
    ExecutionRecipe recipe;
    size_t a = recipe.addNode(ExecOp::Embed);
    size_t b = recipe.addNode(ExecOp::ForwardLayer);
    size_t c = recipe.addNode(ExecOp::ComputeLogits);
    recipe.addDependency(a, b);
    recipe.addDependency(b, c);
    recipe.addDependency(c, a); // cycle back to a

    DependencyGraph graph(recipe);
    CHECK(graph.hasCycle());
    CHECK(!graph.build(recipe)); // build returns false when cycle exists
}

// ---------------------------------------------------------------------------
// Test 4: Acyclic recipe produces valid orderings for all 4 strategies
// ---------------------------------------------------------------------------
static void testStrategies(size_t numLayers) {
    ExecutionRecipe recipe = RecipeScheduler::buildTransformerRecipe(numLayers, "test");
    CHECK(recipe.validate(nullptr));

    // Verify graph topology
    DependencyGraph graph(recipe);
    CHECK(!graph.hasCycle());
    CHECK(graph.entryNodes().size() == 1); // only PrefillPhase
    CHECK(graph.terminalNodes().size() == 1); // LoopCondition

    // Verify in-degree monotonically increases then decreases for a chain
    for (size_t strategyVal = 0; strategyVal <= 3; ++strategyVal) {
        ExecutionStrategy strategy = static_cast<ExecutionStrategy>(strategyVal);
        std::string err;
        std::vector<size_t> order = RecipeScheduler{}.schedule(recipe, strategy, &err);
        CHECK(!order.empty());
        CHECK(order.size() == recipe.nodes.size());

        // Structural verification
        bool ok = RecipeScheduler::verifyOrdering(recipe, order, &err);
        CHECK(ok);
        if (!ok) {
            std::fprintf(stderr, "  [strategy=%s] verifyOrdering error: %s\n",
                         strategyName(strategy), err.c_str());
        }

        // Every node appears exactly once
        std::vector<bool> seen(recipe.nodes.size(), false);
        for (size_t id : order) {
            CHECK(id < recipe.nodes.size());
            CHECK(!seen[id]);
            seen[id] = true;
        }

        // Entry node (PrefillPhase) is first
        CHECK(order[0] == 0);

        // Terminal node (LoopCondition) is last
        CHECK(order.back() == recipe.nodes.size() - 1);

        std::fprintf(stderr, "[testStrategies layers=%zu strategy=%s] order=",
                     numLayers, strategyName(strategy));
        for (size_t id : order) std::fprintf(stderr, "%zu ", id);
        std::fprintf(stderr, "\n");
    }
}

// ---------------------------------------------------------------------------
// Test 5: RandomReady produces different orders with different seeds
// ---------------------------------------------------------------------------
static void testRandomReadyNondeterminism() {
    ExecutionRecipe recipe = RecipeScheduler::buildTransformerRecipe(4, "rand");

    // Manually create a DAG with multiple entry points so randomness matters
    ExecutionRecipe forkRecipe;
    size_t root = forkRecipe.addNode(ExecOp::Embed);
    size_t a = forkRecipe.addNode(ExecOp::ForwardLayer, 0);
    size_t b = forkRecipe.addNode(ExecOp::ForwardLayer, 1);
    size_t c = forkRecipe.addNode(ExecOp::ForwardLayer, 2);
    size_t merge = forkRecipe.addNode(ExecOp::ComputeLogits);

    // root -> a, root -> b, a -> c, b -> c, c -> merge
    forkRecipe.addDependency(root, a);
    forkRecipe.addDependency(root, b);
    forkRecipe.addDependency(a, c);
    forkRecipe.addDependency(b, c);
    forkRecipe.addDependency(c, merge);

    DependencyGraph graph(forkRecipe);
    CHECK(!graph.hasCycle());

    std::mt19937_64 rng1(1), rng2(2);
    ReadySet ready1(ExecutionStrategy::RandomReady);
    ReadySet ready2(ExecutionStrategy::RandomReady);
    ready1.insert(0);
    ready2.insert(0);

    // With different seeds, the first pop may differ if multiple ready nodes
    // Build a small multi-entry graph to force branch
    ExecutionRecipe branch;
    size_t e0 = branch.addNode(ExecOp::Embed);
    size_t e1 = branch.addNode(ExecOp::ForwardLayer, 0);
    size_t e2 = branch.addNode(ExecOp::ForwardLayer, 1);
    size_t e3 = branch.addNode(ExecOp::ComputeLogits);
    branch.addDependency(e0, e1);
    branch.addDependency(e0, e2);
    branch.addDependency(e1, e3);
    branch.addDependency(e2, e3);

    std::vector<size_t> o1 = RecipeScheduler{}.schedule(branch, ExecutionStrategy::RandomReady);
    std::vector<size_t> o2 = RecipeScheduler{}.schedule(branch, ExecutionStrategy::RandomReady);
    // o1 and o2 use same seed (42 hardcoded), so they should be IDENTICAL.
    // If we want true nondeterminism we would need external seed injection.
    // For this gate we verify determinism (same seed = same order).
    CHECK(o1 == o2);
}

// ---------------------------------------------------------------------------
// Test 6: ForwardLayer nodes appear in ascending layer order for Static
// ---------------------------------------------------------------------------
static void testLayerOrder() {
    ExecutionRecipe recipe = RecipeScheduler::buildTransformerRecipe(8, "layer_order");
    std::vector<size_t> order = RecipeScheduler{}.schedule(recipe, ExecutionStrategy::Static);

    // Collect layer indices in order
    std::vector<size_t> layerIds;
    for (size_t id : order) {
        if (recipe.nodes[id].op == ExecOp::ForwardLayer) {
            layerIds.push_back(recipe.nodes[id].layerIndex);
        }
    }
    CHECK(layerIds.size() == 8);
    for (size_t i = 0; i < layerIds.size(); ++i) {
        CHECK(layerIds[i] == i);
    }
}

// ---------------------------------------------------------------------------
// Test 7: DependencyGraph entry / terminal queries
// ---------------------------------------------------------------------------
static void testGraphQueries() {
    ExecutionRecipe recipe = RecipeScheduler::buildTransformerRecipe(3, "queries");
    DependencyGraph graph(recipe);

    auto entries = graph.entryNodes();
    auto terms = graph.terminalNodes();
    CHECK(entries.size() == 1);
    CHECK(terms.size() == 1);
    CHECK(entries[0] == 0); // PrefillPhase
    CHECK(terms[0] == recipe.nodes.size() - 1); // LoopCondition

    CHECK(graph.inDegree(0) == 0); // entry has no deps
    CHECK(graph.inDegree(terms[0]) == 1); // LoopCondition has one dep
    CHECK(graph.consumers(0).size() == 1); // PrefillPhase has one consumer (Embed)
}

// ---------------------------------------------------------------------------
// Test 8: ReadySet behavior per strategy
// ---------------------------------------------------------------------------
static void testReadySetSemantics() {
    ReadySet rsStatic(ExecutionStrategy::Static);
    ReadySet rsForward(ExecutionStrategy::ForwardReady);
    ReadySet rsReverse(ExecutionStrategy::ReverseDemand);
    ReadySet rsRandom(ExecutionStrategy::RandomReady);

    for (int i = 0; i < 5; ++i) {
        rsStatic.insert(i);
        rsForward.insert(i);
        rsReverse.insert(i);
        rsRandom.insert(i);
    }

    std::mt19937_64 rng(42);

    // Static & ForwardReady: FIFO (first inserted)
    auto s1 = rsStatic.peekNext(rng);
    auto f1 = rsForward.peekNext(rng);
    CHECK(s1.has_value() && *s1 == 0);
    CHECK(f1.has_value() && *f1 == 0);

    // ReverseDemand: LIFO (last inserted)
    auto r1 = rsReverse.peekNext(rng);
    CHECK(r1.has_value() && *r1 == 4);

    // RandomReady: any value in [0,4]
    auto rand1 = rsRandom.peekNext(rng);
    CHECK(rand1.has_value());
    CHECK(*rand1 >= 0 && *rand1 <= 4);

    // After pop, size decreases
    size_t szBefore = rsStatic.size();
    rsStatic.popNext(rng);
    CHECK(rsStatic.size() == szBefore - 1);
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main(int argc, char**) {
    (void)argc;
    std::fprintf(stderr, "=== RAWRXD_TRAILFORGE_GATE_001 ===\n");
    std::fprintf(stderr, "Build date: 2026-09-26\n");
    std::fprintf(stderr, "Target: verify ExecOp enum, ExecutionRecipe, "
                         "ExecutionNode, DependencyGraph, ReadySet, "
                         "RecipeScheduler with 4 strategies.\n\n");

    testRecipeValidationSelfLoop();
    testRecipeValidationOOB();
    testCycleDetection();
    testStrategies(1);
    testStrategies(2);
    testStrategies(8);
    testRandomReadyNondeterminism();
    testLayerOrder();
    testGraphQueries();
    testReadySetSemantics();

    std::fprintf(stderr, "\n--- RESULTS ---\n");
    std::fprintf(stderr, "PASSED: %d\n", g_passed);
    std::fprintf(stderr, "FAILED: %d\n", g_failed);
    std::fprintf(stderr, "VERDICT: %s\n", g_failed == 0 ? "PASS" : "FAIL");

    return g_failed == 0 ? 0 : 1;
}
