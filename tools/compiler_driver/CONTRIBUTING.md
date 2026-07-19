# Contributing to RAWRXD Compiler Driver

Thank you for your interest in contributing to the RAWRXD Compiler Driver! This document provides guidelines for contributing to the project.

---

## 🤝 Ways to Contribute

### 1. Report Bugs
- Check if the bug has already been reported
- Include steps to reproduce
- Include system information
- Include error messages

### 2. Suggest Features
- Describe the feature clearly
- Explain the use case
- Consider implementation complexity

### 3. Submit Code Changes
- Fix bugs
- Add features
- Improve documentation
- Add tests

### 4. Improve Documentation
- Fix typos
- Clarify instructions
- Add examples
- Translate documentation

---

## 🚀 Getting Started

### Prerequisites
- Visual Studio 2019+ (Windows) or GCC/Clang (Linux/macOS)
- Git
- Basic knowledge of C

### Setup Development Environment
```batch
# Clone the repository
git clone https://github.com/ItsMehRAWRXD/rawrxd-compiler.git
cd rawrxd-compiler

# Run setup script
scripts\setup-dev-env.bat

# Build the project
build.bat

# Run tests
cd tests
smoke_test.bat
```

---

## 📝 Code Guidelines

### C Code Style
- Use 4 spaces for indentation
- Keep lines under 80 characters when possible
- Use descriptive variable names
- Comment complex logic
- Follow existing code style

### Example:
```c
// Good
int rxd_compile_file(const char* source_file,
                     const char* output_file,
                     const rxd_compile_options_t* options,
                     rxd_compile_result_t* result)
{
    // Validate inputs
    if (!source_file || !result) {
        return RXD_RESULT_ERROR_INVALID_INPUT;
    }
    
    // Implementation here
    return RXD_RESULT_OK;
}

// Avoid
int compile(char* s, char* o, void* opt, void* res) {
    if(!s||!res)return -1;
    // ...
}
```

### Commit Messages
- Use clear, descriptive messages
- Start with verb (Add, Fix, Update, Remove)
- Reference issue numbers when applicable

Examples:
```
Add support for C++ backend
Fix memory leak in config system
Update documentation for v1.1.0
Remove deprecated function
```

---

## 🧪 Testing

### Before Submitting
- Run all smoke tests
- Test on clean system
- Verify zero dependencies
- Check documentation

### Test Commands
```batch
# Run smoke tests
cd tests
smoke_test.bat

# Run benchmarks
cd benchmark
benchmark.bat

# Test build
make clean
make
```

---

## 📤 Submitting Changes

### Pull Request Process

1. **Fork the repository**
   ```
   Click "Fork" button on GitHub
   ```

2. **Create a branch**
   ```batch
   git checkout -b feature/my-feature
   # or
   git checkout -b fix/my-bugfix
   ```

3. **Make changes**
   - Write code
   - Add tests
   - Update documentation

4. **Commit changes**
   ```batch
   git add .
   git commit -m "Add: description of changes"
   ```

5. **Push to fork**
   ```batch
   git push origin feature/my-feature
   ```

6. **Create Pull Request**
   - Go to GitHub
   - Click "New Pull Request"
   - Fill in description
   - Submit

### PR Requirements
- [ ] Code follows style guidelines
- [ ] Tests pass
- [ ] Documentation updated
- [ ] Zero dependencies maintained
- [ ] Description explains changes

---

## 🏗️ Project Structure

```
compiler_driver/
├── include/          # Public headers
├── src/              # Source code
│   └── backends/     # Compiler backends
├── tests/            # Test suite
├── vscode-extension/ # IDE integration
├── examples/         # Example projects
├── scripts/          # Utility scripts
└── docs/             # Documentation
```

---

## 🎯 Areas for Contribution

### High Priority
- [ ] C++ backend
- [ ] JavaScript backend
- [ ] Python backend
- [ ] Additional test coverage

### Medium Priority
- [ ] Performance optimizations
- [ ] Documentation improvements
- [ ] Example projects
- [ ] IDE integrations

### Low Priority
- [ ] Code refactoring
- [ ] Comment improvements
- [ ] Typo fixes

---

## 💡 Tips

### For New Contributors
1. Start with documentation fixes
2. Try adding a simple example
3. Look for "good first issue" labels
4. Ask questions in discussions

### For Experienced Contributors
1. Review pull requests
2. Help with architecture decisions
3. Mentor new contributors
4. Improve tooling

---

## 📞 Getting Help

- **GitHub Issues:** Bug reports and feature requests
- **GitHub Discussions:** Questions and ideas
- **Documentation:** Check the docs/ folder

---

## 🏆 Recognition

Contributors will be:
- Listed in CONTRIBUTORS.md
- Mentioned in release notes
- Credited in documentation

---

## 📄 License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to RAWRXD Compiler Driver! 🎉
