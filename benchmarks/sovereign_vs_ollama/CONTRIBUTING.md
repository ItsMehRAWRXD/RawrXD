# Contributing to RawrXD Benchmark Suite

Thank you for your interest in contributing to the RawrXD Benchmark Suite! This document provides guidelines and instructions for contributing.

## Table of Contents
1. [Code of Conduct](#code-of-conduct)
2. [Getting Started](#getting-started)
3. [Development Workflow](#development-workflow)
4. [Coding Standards](#coding-standards)
5. [Testing](#testing)
6. [Documentation](#documentation)
7. [Submitting Changes](#submitting-changes)
8. [Security](#security)

## Code of Conduct

This project adheres to a code of conduct that all contributors are expected to follow:

- Be respectful and inclusive
- Welcome newcomers and help them learn
- Focus on constructive feedback
- Respect different viewpoints and experiences

## Getting Started

### Prerequisites

- C++17 compatible compiler (GCC 8+, Clang 7+, MSVC 2019+)
- CMake 3.16+
- Python 3.8+
- Git

### Setting Up Development Environment

```bash
# Clone the repository
git clone https://github.com/ItsMehRAWRXD/rawrxd.git
cd rawrxd/benchmarks/sovereign_vs_ollama

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install Python dependencies
pip install -r requirements-dev.txt

# Build the project
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug -DRAWRXD_BUILD_TESTS=ON
cmake --build . --parallel
```

## Development Workflow

### 1. Create a Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/issue-description
```

Branch naming conventions:
- `feature/description` - New features
- `fix/description` - Bug fixes
- `docs/description` - Documentation updates
- `refactor/description` - Code refactoring
- `test/description` - Test additions/improvements

### 2. Make Changes

- Write clear, concise commit messages
- Keep commits focused on single changes
- Reference issue numbers in commits when applicable

### 3. Test Your Changes

```bash
# Run unit tests
cd build
ctest --output-on-failure

# Run integration tests
../scripts/run_integration_tests.sh

# Run security scan
python3 ../tools/security_scanner.py quick

# Run compliance check
python3 ../tools/compliance_checker.py summary
```

### 4. Update Documentation

- Update relevant documentation files
- Add examples for new features
- Update CHANGELOG.md

## Coding Standards

### C++ Style Guide

We follow the Google C++ Style Guide with some modifications:

#### Naming Conventions

```cpp
// Classes: PascalCase
class BenchmarkRunner { };

// Functions: PascalCase for public, camelCase for private
void RunBenchmark();
void internalHelper();

// Variables: snake_case
int request_count;
std::string backend_name;

// Constants: kPascalCase
constexpr int kMaxRetries = 3;

// Member variables: trailing underscore
class Example {
    int private_member_;
};
```

#### Code Formatting

```cpp
// Use 4 spaces for indentation
// Maximum line length: 100 characters
// Opening brace on same line

class Example {
public:
    void Method() {
        if (condition) {
            DoSomething();
        } else {
            DoOtherThing();
        }
    }
    
private:
    int member_;
};
```

#### Documentation

```cpp
/**
 * @brief Brief description of the function
 * @param param1 Description of first parameter
 * @param param2 Description of second parameter
 * @return Description of return value
 * @throws ExceptionType When this exception is thrown
 * 
 * Detailed description if needed.
 */
ResultType FunctionName(Type1 param1, Type2 param2);
```

### Python Style Guide

We follow PEP 8 with these additions:

```python
# Maximum line length: 100 characters
# Use type hints where appropriate

def process_results(results: List[Dict]) -> Dict[str, Any]:
    """
    Process benchmark results.
    
    Args:
        results: List of result dictionaries
        
    Returns:
        Dictionary containing processed data
    """
    pass
```

### Shell Script Standards

```bash
#!/bin/bash
set -e  # Exit on error

# Use shellcheck-compatible syntax
# Quote all variables
# Use functions for organization

process_data() {
    local input_file="$1"
    local output_file="$2"
    
    # Process data
    cat "$input_file" | grep "pattern" > "$output_file"
}
```

## Testing

### Writing Tests

#### C++ Tests

```cpp
// tests/example_test.cpp
#include <gtest/gtest.h>
#include "my_component.hpp"

TEST(MyComponentTest, BasicFunctionality) {
    MyComponent component;
    EXPECT_TRUE(component.Initialize());
    EXPECT_EQ(component.GetValue(), 42);
}

TEST(MyComponentTest, ErrorHandling) {
    MyComponent component;
    EXPECT_THROW(component.ProcessInvalidInput(), std::invalid_argument);
}
```

#### Python Tests

```python
# tests/test_example.py
import pytest
from tools.analyzer import BenchmarkAnalyzer

def test_analyzer_initialization():
    analyzer = BenchmarkAnalyzer(Path("./results"))
    assert analyzer is not None

def test_statistics_calculation():
    analyzer = BenchmarkAnalyzer(Path("./results"))
    stats = analyzer.calculate_statistics([1.0, 2.0, 3.0])
    assert stats.mean == 2.0
```

### Test Coverage

Aim for:
- Unit tests: 80%+ coverage
- Integration tests: Critical paths covered
- End-to-end tests: Main user workflows

## Documentation

### Code Documentation

- Document all public APIs
- Include usage examples
- Explain complex algorithms
- Document security considerations

### User Documentation

- Keep README.md up to date
- Add entries to CHANGELOG.md
- Update relevant guides in docs/

## Submitting Changes

### Pull Request Process

1. **Before Submitting:**
   - Ensure all tests pass
   - Update documentation
   - Run security scan
   - Update CHANGELOG.md

2. **PR Description:**
   ```markdown
   ## Description
   Brief description of changes
   
   ## Type of Change
   - [ ] Bug fix
   - [ ] New feature
   - [ ] Breaking change
   - [ ] Documentation update
   
   ## Testing
   - [ ] Unit tests pass
   - [ ] Integration tests pass
   - [ ] Manual testing performed
   
   ## Checklist
   - [ ] Code follows style guidelines
   - [ ] Self-review completed
   - [ ] Documentation updated
   - [ ] Security scan passed
   ```

3. **Review Process:**
   - All PRs require at least one review
   - Address review comments
   - Maintain constructive discussion
   - Squash commits if requested

### Commit Message Format

```
type(scope): subject

body (optional)

footer (optional)
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Formatting
- `refactor`: Code restructuring
- `test`: Tests
- `chore`: Maintenance

Examples:
```
feat(security): add RBAC implementation

Add role-based access control with support for
API key and JWT authentication methods.

Closes #123
```

```
fix(http): resolve connection pool leak

Fix memory leak in connection pool when handling
timeouts under high load.

Fixes #456
```

## Security

### Reporting Security Issues

**DO NOT** open public issues for security vulnerabilities.

Instead:
1. Email security@rawrxd.local
2. Include detailed description
3. Provide reproduction steps
4. Allow time for response (48 hours)

### Security Best Practices

- Never commit secrets or credentials
- Use parameterized queries
- Validate all inputs
- Follow OWASP guidelines
- Run security scans before submitting

## Recognition

Contributors will be:
- Listed in CONTRIBUTORS.md
- Mentioned in release notes
- Credited in documentation

## Questions?

- GitHub Discussions: https://github.com/ItsMehRAWRXD/rawrxd/discussions
- Email: dev@rawrxd.local

Thank you for contributing!
