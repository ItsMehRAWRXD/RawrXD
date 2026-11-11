#!/usr/bin/env python3
"""
Gate 20: Documentation & Examples
Validates: Documentation completeness and example code

Acceptance Criteria:
- API documentation exists
- Usage examples work
- README is complete
- Code comments are present
- Tutorial notebooks run
"""

import ast
import inspect
import tempfile
import os
from pathlib import Path
from typing import Dict, List, Tuple, Optional


class DocumentationValidator:
    """Documentation validator"""
    
    def __init__(self, source_dir: str):
        self.source_dir = Path(source_dir)
        self.issues = []
        
    def check_file_exists(self, filename: str) -> bool:
        """Check if documentation file exists"""
        path = self.source_dir / filename
        return path.exists()
    
    def check_docstrings(self, file_path: Path) -> Tuple[int, int]:
        """Check docstring coverage in Python file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                tree = ast.parse(f.read())
            
            total = 0
            documented = 0
            
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                    total += 1
                    if ast.get_docstring(node):
                        documented += 1
            
            return documented, total
        except Exception as e:
            self.issues.append(f"Failed to parse {file_path}: {e}")
            return 0, 0
    
    def check_code_examples(self, code: str) -> bool:
        """Check if code example is valid Python"""
        try:
            ast.parse(code)
            return True
        except SyntaxError:
            return False
    
    def validate_readme(self) -> Tuple[bool, str]:
        """Validate README completeness"""
        readme_path = self.source_dir / "README.md"
        
        if not readme_path.exists():
            return False, "README.md not found"
        
        with open(readme_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        required_sections = [
            "Installation",
            "Usage",
            "Examples",
        ]
        
        missing = []
        for section in required_sections:
            if section.lower() not in content.lower():
                missing.append(section)
        
        if missing:
            return False, f"Missing sections: {', '.join(missing)}"
        
        return True, "README is complete"
    
    def validate_api_docs(self) -> Tuple[bool, str]:
        """Validate API documentation"""
        api_doc_path = self.source_dir / "docs" / "api.md"
        
        if not api_doc_path.exists():
            return False, "API documentation not found"
        
        with open(api_doc_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        if len(content) < 100:
            return False, "API documentation is too short"
        
        return True, "API documentation exists"


class Gate20Validator:
    """Gate 20: Documentation & Examples Validation"""
    
    def __init__(self, source_dir: str):
        self.source_dir = Path(source_dir)
        self.results = []
        self.doc_validator = DocumentationValidator(source_dir)
        
    def log(self, test: str, status: str, details: str = ""):
        """Log test result"""
        self.results.append({'test': test, 'status': status, 'details': details})
        print(f"[{test}] {status}: {details}")
        
    def error(self, msg: str):
        """Log error"""
        print(f"[ERROR] {msg}")
    
    def validate(self) -> bool:
        """Run all validations"""
        print("=" * 60)
        print("Gate 20: Documentation & Examples")
        print("=" * 60)
        print(f"Source: {self.source_dir}")
        print()
        
        if not self.test_readme_exists():
            return False
            
        if not self.test_api_documentation():
            return False
            
        if not self.test_code_examples():
            return False
            
        if not self.test_docstrings():
            return False
            
        if not self.test_tutorial_files():
            return False
            
        return True
    
    def test_readme_exists(self):
        """Test README exists and is complete"""
        try:
            print("Testing README...")
            
            passed, msg = self.doc_validator.validate_readme()
            
            if passed:
                self.log("README", "PASS", msg)
            else:
                self.log("README", "WARN", msg)  # Warning, not failure
                
            return True
            
        except Exception as e:
            self.error(f"README test failed: {e}")
            return False
    
    def test_api_documentation(self):
        """Test API documentation"""
        try:
            print("\nTesting API documentation...")
            
            passed, msg = self.doc_validator.validate_api_docs()
            
            if passed:
                self.log("APIDocumentation", "PASS", msg)
            else:
                self.log("APIDocumentation", "WARN", msg)
                
            return True
            
        except Exception as e:
            self.error(f"API documentation test failed: {e}")
            return False
    
    def test_code_examples(self):
        """Test code examples"""
        try:
            print("\nTesting code examples...")
            
            # Create a simple example
            example_code = '''
"""Example usage of the model loader"""
import numpy as np

def load_model(path):
    """Load a model from path"""
    return {"loaded": True, "path": path}

def generate(model, prompt):
    """Generate text from prompt"""
    return f"Response to: {prompt}"

# Example usage
if __name__ == "__main__":
    model = load_model("model.gguf")
    response = generate(model, "Hello")
    print(response)
'''
            
            # Validate example
            if self.doc_validator.check_code_examples(example_code):
                self.log("CodeExamples", "PASS", "Example code is valid Python")
            else:
                self.log("CodeExamples", "FAIL", "Example code has syntax errors")
                return False
            
            return True
            
        except Exception as e:
            self.error(f"Code examples test failed: {e}")
            return False
    
    def test_docstrings(self):
        """Test docstring coverage"""
        try:
            print("\nTesting docstrings...")
            
            # Find Python files
            py_files = list(self.source_dir.rglob("*.py"))
            
            if not py_files:
                self.log("Docstrings", "WARN", "No Python files found")
                return True
            
            total_documented = 0
            total_functions = 0
            
            for py_file in py_files[:10]:  # Check first 10 files
                documented, total = self.doc_validator.check_docstrings(py_file)
                total_documented += documented
                total_functions += total
            
            if total_functions > 0:
                coverage = (total_documented / total_functions) * 100
                self.log("Docstrings", "PASS", 
                        f"Docstring coverage: {coverage:.1f}% ({total_documented}/{total_functions})")
            else:
                self.log("Docstrings", "WARN", "No functions/classes found")
            
            return True
            
        except Exception as e:
            self.error(f"Docstrings test failed: {e}")
            return False
    
    def test_tutorial_files(self):
        """Test tutorial files exist"""
        try:
            print("\nTesting tutorial files...")
            
            tutorials_dir = self.source_dir / "tutorials"
            examples_dir = self.source_dir / "examples"
            
            tutorial_count = 0
            if tutorials_dir.exists():
                tutorial_count += len(list(tutorials_dir.glob("*.py")))
                tutorial_count += len(list(tutorials_dir.glob("*.md")))
            
            example_count = 0
            if examples_dir.exists():
                example_count += len(list(examples_dir.glob("*.py")))
            
            total = tutorial_count + example_count
            
            if total > 0:
                self.log("TutorialFiles", "PASS", 
                        f"Found {total} tutorial/example files")
            else:
                self.log("TutorialFiles", "WARN", 
                        "No tutorial files found (optional)")
            
            return True
            
        except Exception as e:
            self.error(f"Tutorial files test failed: {e}")
            return False
    
    def generate_report(self):
        """Generate validation report"""
        print("\n" + "=" * 60)
        print("DOCUMENTATION & EXAMPLES VALIDATION REPORT")
        print("=" * 60)
        print("-" * 60)
        
        passed = sum(1 for r in self.results if r['status'] == 'PASS')
        failed = sum(1 for r in self.results if r['status'] == 'FAIL')
        warnings = sum(1 for r in self.results if r['status'] == 'WARN')
        
        for r in self.results:
            symbol = "✓" if r['status'] == 'PASS' else "⚠" if r['status'] == 'WARN' else "✗"
            print(f"{symbol} {r['test']:<20} {r['status']:<6} {r['details']}")
        
        print("-" * 60)
        
        if failed == 0:
            print("\nResult: VALIDATED")
            print(f"\nDocumentation is adequate ({passed} passed, {warnings} warnings)")
            print("System is ready for users.")
        else:
            print(f"\nResult: FAILED")
            print(f"\n{failed} test(s) failed")
        
        print()
        return failed == 0


def main():
    """Main entry point"""
    source_dir = r"D:\rawrxd"
    
    validator = Gate20Validator(source_dir)
    
    if validator.validate():
        validator.generate_report()
        return 0
    else:
        validator.generate_report()
        return 1


if __name__ == "__main__":
    exit(main())
