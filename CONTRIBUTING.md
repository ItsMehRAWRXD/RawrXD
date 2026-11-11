# Contributing to RawrXD

Thank you for your interest in contributing to RawrXD! This document provides guidelines for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Testing Requirements](#testing-requirements)
- [Documentation](#documentation)
- [Commit Messages](#commit-messages)
- [Review Process](#review-process)

---

## Code of Conduct

This project adheres to the [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

---

## Getting Started

### Prerequisites

- C++17 compatible compiler (GCC 11+, Clang 14+, MSVC 2022+)
- CMake 3.20+
- Git 2.30+

### Building

```bash
git clone https://github.com/ItsMehRAWRXD/RawrXD.git
cd RawrXD
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

### Running Tests

```bash
make test
# or
ctest --output-on-failure
```

---

## Development Workflow

### Branch Strategy

```
main                    # Production-ready code
├── release/v1.0        # Release branches
├── hotfix/*            # Critical fixes
├── feature/*           # New features
└── bugfix/*            # Bug fixes
```

### Workflow

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/my-feature`
3. **Commit** your changes: `git commit -am 'Add new feature'`
4. **Push** to the branch: `git push origin feature/my-feature`
5. **Submit** a Pull Request

### Pull Request Checklist

Before submitting:

- [ ] Code builds without warnings
- [ ] All tests pass
- [ ] New code has tests
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] Commit messages follow guidelines

---

## Coding Standards

### C++ Style Guide

We follow the [C++ Core Guidelines](https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines).

#### Naming Conventions

```cpp
// Types: PascalCase
class MyClass { };
struct MyStruct { };
enum class MyEnum { };

// Functions: camelCase
void myFunction();

// Variables: snake_case
int my_variable;

// Constants: UPPER_SNAKE_CASE
const int MAX_SIZE = 100;

// Member variables: trailing underscore
class Example {
    int private_member_;
};
```

#### Code Formatting

Use `clang-format` with our style file:

```bash
clang-format -i src/myfile.cpp
```

#### Header Guards

```cpp
#pragma once
// Preferred over #ifndef guards
```

#### Include Order

```cpp
// 1. Corresponding header (for .cpp files)
#include "my_header.hpp"

// 2. Project headers
#include "rawrxd/other.hpp"

// 3. Third-party headers
#include <nlohmann/json.hpp>

// 4. Standard library
#include <vector>
#include <string>
```

---

## Testing Requirements

### Unit Tests

All new code must include unit tests:

```cpp
// test/my_feature_test.cpp
#include <gtest/gtest.h>
#include "rawrxd/my_feature.hpp"

TEST(MyFeatureTest, BasicFunctionality) {
    MyFeature feature;
    EXPECT_TRUE(feature.Initialize());
    EXPECT_EQ(feature.Compute(), 42);
}
```

### Test Coverage

- Minimum 80% coverage for new code
- Critical paths require 90% coverage

### Benchmarks

Performance-critical changes require benchmarks:

```cpp
// benchmarks/my_feature_bench.cpp
static void BM_MyFeature(benchmark::State& state) {
    for (auto _ : state) {
        MyFeature().Compute();
    }
}
BENCHMARK(BM_MyFeature);
```

---

## Documentation

### Code Documentation

Use Doxygen-style comments:

```cpp
/**
 * @brief Brief description
 * @param param1 Description of param1
 * @return Description of return value
 * @throws std::runtime_error When something fails
 */
bool MyFunction(int param1);
```

### API Documentation

Public APIs require:

- Function documentation
- Parameter descriptions
- Return value documentation
- Example usage

### User Documentation

Features require:

- README update (if applicable)
- User guide documentation
- Example code

---

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

Types:

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `style`: Code style (formatting, semicolons, etc.)
- `refactor`: Code refactoring
- `perf`: Performance improvement
- `test`: Adding or correcting tests
- `chore`: Build process or auxiliary tool changes

Examples:

```
feat(inference): add streaming generation support

fix(memory): resolve leak in KV cache

docs(api): update Session documentation with examples

perf(scheduler): improve work-stealing algorithm
```

---

## Review Process

### Review Requirements

- All PRs require at least 2 approvals
- CI must pass
- No merge conflicts

### Review Checklist

Reviewers should verify:

- [ ] Code correctness
- [ ] Test coverage
- [ ] Documentation
- [ ] Performance impact
- [ ] Backward compatibility
- [ ] Security implications

### Review Timeline

- Initial review: 2 business days
- Follow-up reviews: 1 business day

---

## Questions?

- GitHub Discussions: https://github.com/ItsMehRAWRXD/RawrXD/discussions
- Discord: https://discord.gg/rawrxd
- Email: contributors@rawrxd.io

---

Thank you for contributing to RawrXD!
