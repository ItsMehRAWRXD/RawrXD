# Contributing to RawrXD

## Phase I Batch 5/5: Community Resources

Thank you for your interest in contributing to RawrXD Sovereign!

---

## Ways to Contribute

### Code Contributions
- Bug fixes
- Feature implementations
- Performance improvements
- Documentation updates

### Non-Code Contributions
- Bug reports
- Feature requests
- Documentation improvements
- Community support
- Translation

---

## Development Setup

### Prerequisites

- Windows 10/11, macOS 11+, or Linux (Ubuntu 20.04+)
- Visual Studio 2022 or GCC 11+
- CMake 3.20+
- Python 3.9+
- Git

### Clone Repository

```bash
git clone https://github.com/ItsMehRAWRXD/RawrXD.git
cd RawrXD
```

### Build Instructions

#### Windows
```powershell
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release
```

#### Linux/macOS
```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

---

## Contribution Workflow

### 1. Fork & Branch

```bash
# Fork the repo on GitHub, then:
git clone https://github.com/YOUR_USERNAME/RawrXD.git
cd RawrXD

# Create feature branch
git checkout -b feature/my-feature
```

### 2. Make Changes

- Follow coding standards
- Add tests for new features
- Update documentation
- Keep commits focused

### 3. Test

```bash
# Run tests
cmake --build . --target test

# Run linting
./scripts/lint.sh
```

### 4. Commit

```bash
git add .
git commit -m "feat: add new feature description"
```

Commit message format:
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation
- `perf:` Performance improvement
- `refactor:` Code refactoring
- `test:` Tests
- `chore:` Maintenance

### 5. Push & PR

```bash
git push origin feature/my-feature
```

Create Pull Request on GitHub with:
- Clear description
- Related issue numbers
- Screenshots (if UI)
- Test results

---

## Coding Standards

### C++ Style Guide

```cpp
// Use camelCase for functions
void processInference();

// Use PascalCase for classes
class InferenceEngine {
public:
    // Use m_ prefix for members
    int m_batchSize;
    
    // Document public APIs
    /// Process a batch of tokens
    /// @param tokens Input tokens
    /// @return Processed output
    std::vector<int> process(const std::vector<int>& tokens);
};
```

### PowerShell Style Guide

```powershell
# Use Verb-Noun naming
function Get-InferenceMetrics {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ModelId
    )
    
    # Use full parameter names
    Write-Log -Message "Getting metrics"
    
    return $metrics
}
```

---

## Testing

### Unit Tests

```cpp
// test_inference.cpp
TEST(InferenceTest, BasicTokenization) {
    Tokenizer tokenizer;
    auto tokens = tokenizer.encode("Hello");
    EXPECT_EQ(tokens.size(), 1);
}
```

### Integration Tests

```powershell
# test_integration.ps1
describe "API Integration" {
    it "should return health status" {
        $response = Invoke-RestMethod "http://localhost:8080/health"
        $response.status | Should -Be "healthy"
    }
}
```

---

## Documentation

### API Documentation

Use OpenAPI/Swagger format:

```yaml
paths:
  /inference:
    post:
      summary: Submit inference request
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                model:
                  type: string
                prompt:
                  type: string
```

### Code Documentation

```cpp
/// Inference engine for transformer models
/// 
/// This class handles the complete inference pipeline
/// including tokenization, model execution, and decoding.
class InferenceEngine {
    /// Maximum batch size for inference
    static constexpr int MAX_BATCH_SIZE = 512;
};
```

---

## Review Process

### PR Checklist

- [ ] Code follows style guide
- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] No breaking changes (or documented)
- [ ] Benchmarks run (if applicable)
- [ ] Security review (if applicable)

### Review Criteria

1. **Correctness:** Does it work as intended?
2. **Performance:** Any performance regressions?
3. **Maintainability:** Is the code readable?
4. **Testing:** Are there adequate tests?
5. **Documentation:** Is it documented?

---

## Community Guidelines

### Code of Conduct

- Be respectful and inclusive
- Welcome newcomers
- Focus on constructive feedback
- Respect differing viewpoints

### Communication

- GitHub Issues: Bug reports, feature requests
- Discussions: Questions, ideas
- Slack: Real-time chat (invite-only)
- Email: security@rawrxd.ai (security issues)

---

## Recognition

Contributors will be:
- Listed in CONTRIBUTORS.md
- Mentioned in release notes
- Eligible for contributor swag
- Invited to contributor events

---

## Questions?

- Join our [Discord](https://discord.gg/rawrxd)
- Post on [GitHub Discussions](https://github.com/ItsMehRAWRXD/RawrXD/discussions)
- Email: community@rawrxd.ai

---

*Thank you for contributing to RawrXD Sovereign!*
