// RawrXD-Script Operations Benchmark
// Measures ops/sec for critical paths
// Answers: "Is the IC actually faster than no IC?"

#include <iostream>
#include <chrono>
#include <vector>
#include <cmath>
#include <cstring>

// Benchmark framework
struct Benchmark {
    const char* name;
    void (*setup)();
    void (*teardown)();
    uint64_t (*run)(int iterations);
    int iterations;
};

class BenchmarkRunner {
public:
    struct Result {
        const char* name;
        double opsPerSecond;
        double nanosecondsPerOp;
        uint64_t totalOps;
        int64_t durationMs;
    };
    
    std::vector<Result> results;
    
    void RunBenchmark(const Benchmark& bench) {
        std::cout << "\n[Benchmark] " << bench.name << std::endl;
        
        // Warmup
        if (bench.setup) bench.setup();
        bench.run(1000);
        if (bench.teardown) bench.teardown();
        
        // Actual benchmark
        if (bench.setup) bench.setup();
        
        auto start = std::chrono::high_resolution_clock::now();
        uint64_t ops = bench.run(bench.iterations);
        auto end = std::chrono::high_resolution_clock::now();
        
        if (bench.teardown) bench.teardown();
        
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        double seconds = duration.count() / 1000000.0;
        double opsPerSecond = ops / seconds;
        double nsPerOp = (duration.count() * 1000.0) / ops;
        
        Result r = {
            bench.name,
            opsPerSecond,
            nsPerOp,
            ops,
            duration.count() / 1000
        };
        results.push_back(r);
        
        std::cout << "  Operations: " << ops << std::endl;
        std::cout << "  Time: " << duration.count() / 1000 << " ms" << std::endl;
        std::cout << "  Ops/sec: " << std::fixed << opsPerSecond << std::endl;
        std::cout << "  ns/op: " << std::fixed << nsPerOp << std::endl;
    }
    
    void Report() {
        std::cout << "\n========================================" << std::endl;
        std::cout << "Benchmark Summary" << std::endl;
        std::cout << "========================================" << std::endl;
        std::cout << std::left << std::setw(30) << "Benchmark"
                  << std::right << std::setw(15) << "Ops/sec"
                  << std::setw(15) << "ns/op" << std::endl;
        std::cout << "----------------------------------------" << std::endl;
        
        for (const auto& r : results) {
            std::cout << std::left << std::setw(30) << r.name
                      << std::right << std::setw(15) << std::scientific << r.opsPerSecond
                      << std::setw(15) << std::fixed << r.nanosecondsPerOp << std::endl;
        }
        
        std::cout << "========================================" << std::endl;
    }
};

// ============================================================================
// Benchmark 1: Property Access (IC enabled vs disabled)
// ============================================================================

// Simulated object with shape
struct SimObject {
    void* shape;
    void* prototype;
    uint64_t slots[8];  // Inline slots
};

// Simulated IC slot
struct ICSlot {
    void* cachedShape;
    uint64_t cachedOffset;
    uint64_t hits;
    uint64_t misses;
};

static SimObject* testObject;
static ICSlot icSlot;
static void* testShape;

void setup_property_access() {
    testObject = new SimObject();
    testShape = (void*)0x12345678;
    testObject->shape = testShape;
    testObject->slots[0] = 42;  // Property value
    
    // Prime IC
    icSlot.cachedShape = testShape;
    icSlot.cachedOffset = offsetof(SimObject, slots);
    icSlot.hits = 0;
    icSlot.misses = 0;
}

void teardown_property_access() {
    delete testObject;
}

// Benchmark with IC hit
uint64_t bench_property_access_ic_hit(int iterations) {
    uint64_t sum = 0;
    
    for (int i = 0; i < iterations; i++) {
        // Simulated IC hit path (what MASM does)
        if (testObject->shape == icSlot.cachedShape) {
            // IC hit - direct access
            sum += testObject->slots[0];
            icSlot.hits++;
        } else {
            // IC miss - slow path
            icSlot.misses++;
        }
    }
    
    return iterations;
}

// Benchmark without IC (hash lookup simulation)
uint64_t bench_property_access_no_ic(int iterations) {
    uint64_t sum = 0;
    
    for (int i = 0; i < iterations; i++) {
        // Simulated slow path - walk property table
        // In real implementation, would search shape's property table
        for (int j = 0; j < 8; j++) {  // Simulate 8-entry property table walk
            if (j == 0) {  // Found property
                sum += testObject->slots[j];
                break;
            }
        }
    }
    
    return iterations;
}

// ============================================================================
// Benchmark 2: Arithmetic Operations
// ============================================================================
uint64_t bench_arithmetic_int(int iterations) {
    volatile int result = 0;
    
    for (int i = 0; i < iterations; i++) {
        result = (i * 3 + 7) / 2 - 5;
    }
    
    return iterations;
}

uint64_t bench_arithmetic_double(int iterations) {
    volatile double result = 0.0;
    
    for (int i = 0; i < iterations; i++) {
        result = (i * 3.14159 + 2.71828) / 1.41421;
    }
    
    return iterations;
}

// ============================================================================
// Benchmark 3: String Operations
// ============================================================================
static std::string testStringA;
static std::string testStringB;

void setup_string_ops() {
    testStringA = "Hello, World!";
    testStringB = " RawrXD-Script";
}

uint64_t bench_string_concat(int iterations) {
    for (int i = 0; i < iterations; i++) {
        std::string result = testStringA + testStringB;
        (void)result;  // Prevent optimization
    }
    
    return iterations;
}

uint64_t bench_string_length(int iterations) {
    volatile size_t len = 0;
    
    for (int i = 0; i < iterations; i++) {
        len = testStringA.length();
    }
    
    return iterations;
}

// ============================================================================
// Benchmark 4: Function Calls
// ============================================================================

// Simulated JS function call overhead
uint64_t bench_function_call(int iterations) {
    auto dummyFunc = [](int x) -> int { return x + 1; };
    
    volatile int result = 0;
    for (int i = 0; i < iterations; i++) {
        result = dummyFunc(i);
    }
    
    return iterations;
}

// ============================================================================
// Benchmark 5: Object Creation
// ============================================================================
uint64_t bench_object_creation(int iterations) {
    for (int i = 0; i < iterations; i++) {
        SimObject* obj = new SimObject();
        obj->shape = nullptr;
        obj->prototype = nullptr;
        obj->slots[0] = i;
        delete obj;
    }
    
    return iterations;
}

// ============================================================================
// Benchmark 6: Array Operations
// ============================================================================
static std::vector<int> testArray;

void setup_array_ops() {
    testArray.resize(1000);
    for (int i = 0; i < 1000; i++) {
        testArray[i] = i;
    }
}

uint64_t bench_array_push(int iterations) {
    std::vector<int> arr;
    arr.reserve(iterations);
    
    for (int i = 0; i < iterations && i < 1000000; i++) {
        arr.push_back(i);
    }
    
    return arr.size();
}

uint64_t bench_array_index(int iterations) {
    volatile int sum = 0;
    int size = testArray.size();
    
    for (int i = 0; i < iterations; i++) {
        sum += testArray[i % size];
    }
    
    return iterations;
}

// ============================================================================
// Benchmark 7: NaN-boxing Operations
// ============================================================================

// Simulated NaN-boxing (matches MASM implementation)
inline uint64_t BoxInt32(int32_t val) {
    return (static_cast<uint64_t>(val & 0x00007FFFFFFFFFFFULL)) | 0x7FF9000000000000ULL;
}

inline int32_t UnboxInt32(uint64_t val) {
    return static_cast<int32_t>(val & 0x00000000FFFFFFFFULL);
}

inline bool IsInt32(uint64_t val) {
    return (val & 0x7FF9000000000000ULL) == 0x7FF9000000000000ULL;
}

uint64_t bench_nan_boxing(int iterations) {
    volatile uint64_t result = 0;
    
    for (int i = 0; i < iterations; i++) {
        uint64_t boxed = BoxInt32(i);
        if (IsInt32(boxed)) {
            result = UnboxInt32(boxed);
        }
    }
    
    return iterations;
}

// ============================================================================
// Benchmark 8: IC Transition (Monomorphic -> Polymorphic)
// ============================================================================

static SimObject* objects[4];
static void* shapes[4];

void setup_ic_transition() {
    for (int i = 0; i < 4; i++) {
        objects[i] = new SimObject();
        shapes[i] = (void*)(uintptr_t(0x1000) + i);
        objects[i]->shape = shapes[i];
        objects[i]->slots[0] = i;
    }
    
    // Prime IC with first shape
    icSlot.cachedShape = shapes[0];
    icSlot.cachedOffset = offsetof(SimObject, slots);
}

void teardown_ic_transition() {
    for (int i = 0; i < 4; i++) {
        delete objects[i];
    }
}

uint64_t bench_ic_monomorphic(int iterations) {
    // All accesses to same shape (monomorphic)
    uint64_t sum = 0;
    
    for (int i = 0; i < iterations; i++) {
        SimObject* obj = objects[0];
        if (obj->shape == icSlot.cachedShape) {
            sum += obj->slots[0];
        }
    }
    
    return iterations;
}

uint64_t bench_ic_polymorphic(int iterations) {
    // Access 2 different shapes (polymorphic)
    uint64_t sum = 0;
    
    for (int i = 0; i < iterations; i++) {
        SimObject* obj = objects[i % 2];
        if (obj->shape == icSlot.cachedShape) {
            sum += obj->slots[0];
        } else {
            // Miss - would update IC
            icSlot.cachedShape = obj->shape;
        }
    }
    
    return iterations;
}

uint64_t bench_ic_megamorphic(int iterations) {
    // Access 4+ different shapes (megamorphic)
    uint64_t sum = 0;
    
    for (int i = 0; i < iterations; i++) {
        SimObject* obj = objects[i % 4];
        if (obj->shape == icSlot.cachedShape) {
            sum += obj->slots[0];
        } else {
            // Miss - IC becomes useless
            icSlot.cachedShape = obj->shape;
        }
    }
    
    return iterations;
}

// ============================================================================
// Main
// ============================================================================
int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "RawrXD-Script Operations Benchmark" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Measures ops/sec for critical paths" << std::endl;
    std::cout << "Compare: IC enabled vs disabled" << std::endl;
    std::cout << "========================================" << std::endl;
    
    BenchmarkRunner runner;
    
    // Property access benchmarks
    Benchmark propIC = {
        "Property Access (IC hit)",
        setup_property_access,
        teardown_property_access,
        bench_property_access_ic_hit,
        100000000  // 100M iterations
    };
    runner.RunBenchmark(propIC);
    
    Benchmark propNoIC = {
        "Property Access (no IC)",
        setup_property_access,
        teardown_property_access,
        bench_property_access_no_ic,
        10000000   // 10M iterations (slower)
    };
    runner.RunBenchmark(propNoIC);
    
    // Arithmetic benchmarks
    Benchmark arithInt = {
        "Arithmetic (int)",
        nullptr,
        nullptr,
        bench_arithmetic_int,
        1000000000  // 1B iterations
    };
    runner.RunBenchmark(arithInt);
    
    Benchmark arithDouble = {
        "Arithmetic (double)",
        nullptr,
        nullptr,
        bench_arithmetic_double,
        100000000   // 100M iterations
    };
    runner.RunBenchmark(arithDouble);
    
    // String benchmarks
    Benchmark strConcat = {
        "String Concatenation",
        setup_string_ops,
        nullptr,
        bench_string_concat,
        10000000    // 10M iterations
    };
    runner.RunBenchmark(strConcat);
    
    Benchmark strLen = {
        "String Length",
        setup_string_ops,
        nullptr,
        bench_string_length,
        1000000000  // 1B iterations
    };
    runner.RunBenchmark(strLen);
    
    // Function call benchmark
    Benchmark funcCall = {
        "Function Call",
        nullptr,
        nullptr,
        bench_function_call,
        100000000   // 100M iterations
    };
    runner.RunBenchmark(funcCall);
    
    // Object creation benchmark
    Benchmark objCreate = {
        "Object Creation",
        nullptr,
        nullptr,
        bench_object_creation,
        10000000    // 10M iterations
    };
    runner.RunBenchmark(objCreate);
    
    // Array benchmarks
    Benchmark arrPush = {
        "Array Push",
        setup_array_ops,
        nullptr,
        bench_array_push,
        10000000    // 10M iterations
    };
    runner.RunBenchmark(arrPush);
    
    Benchmark arrIndex = {
        "Array Index",
        setup_array_ops,
        nullptr,
        bench_array_index,
        1000000000  // 1B iterations
    };
    runner.RunBenchmark(arrIndex);
    
    // NaN-boxing benchmark
    Benchmark nanBox = {
        "NaN-boxing",
        nullptr,
        nullptr,
        bench_nan_boxing,
        1000000000  // 1B iterations
    };
    runner.RunBenchmark(nanBox);
    
    // IC transition benchmarks
    Benchmark icMono = {
        "IC Monomorphic",
        setup_ic_transition,
        teardown_ic_transition,
        bench_ic_monomorphic,
        100000000   // 100M iterations
    };
    runner.RunBenchmark(icMono);
    
    Benchmark icPoly = {
        "IC Polymorphic",
        setup_ic_transition,
        teardown_ic_transition,
        bench_ic_polymorphic,
        100000000   // 100M iterations
    };
    runner.RunBenchmark(icPoly);
    
    Benchmark icMega = {
        "IC Megamorphic",
        setup_ic_transition,
        teardown_ic_transition,
        bench_ic_megamorphic,
        10000000    // 10M iterations
    };
    runner.RunBenchmark(icMega);
    
    // Final report
    runner.Report();
    
    return 0;
}
