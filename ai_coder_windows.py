#!/usr/bin/env python3
"""
AI Code Generator for Windows 11 - Local AI Coding Assistant
This tool can create files, generate code, and help you build projects from your ideas.

Usage examples (non-interactive):
  - Interactive mode (default):
      python ai_coder_windows.py --interactive

  - Create a project from an idea:
      python ai_coder_windows.py create-project --idea "Web app for notes"

  - Generate code snippet:
      python ai_coder_windows.py generate-code --task "fastapi server" --language python

  - Create a single file:
      python ai_coder_windows.py create-file --filename README.md --content "Hello"

To build a Windows .exe with PyInstaller on Windows:
  py -m pip install --upgrade pip && pip install pyinstaller
  py -m PyInstaller --noconfirm --onefile --console --name AICodeGenerator ai_coder_windows.py

The resulting executable will be in the dist/ directory.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import textwrap
from pathlib import Path
from typing import Any, Dict


class AICodeGenerator:
    def __init__(self, project_dir: Path | None = None) -> None:
        # Cross-platform project root; Windows-friendly paths are handled by pathlib
        self.project_dir: Path = project_dir or Path.cwd()

    def create_file(self, filepath: str, content: str) -> Path:
        """Create a file with the given content."""
        full_path = self.project_dir / filepath
        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.write_text(content, encoding="utf-8")
        print(f"✅ Created: {filepath}")
        return full_path

    def create_project_structure(self, project_name: str, structure: Dict[str, Any]) -> Path:
        """Create a complete project structure from a nested dict of files/dirs."""
        project_path = self.project_dir / project_name
        project_path.mkdir(exist_ok=True)

        def create_structure_recursive(base_path: Path, tree: Dict[str, Any]) -> None:
            for name, content in tree.items():
                item_path = base_path / name
                if isinstance(content, dict):
                    item_path.mkdir(exist_ok=True)
                    create_structure_recursive(item_path, content)
                else:
                    item_path.parent.mkdir(parents=True, exist_ok=True)
                    item_path.write_text(content, encoding="utf-8")
                    print(f"✅ Created: {item_path.relative_to(self.project_dir)}")

        create_structure_recursive(project_path, structure)
        return project_path

    def generate_code(self, prompt: str, language: str = "python") -> str:
        """Generate code using local templates and patterns based on the prompt."""
        templates: Dict[str, Dict[str, str]] = {
            "python": {
                "web_app": """from flask import Flask, render_template, request, jsonify
import os

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/data', methods=['GET', 'POST'])
def api_data():
    if request.method == 'POST':
        data = request.json
        # Process data here
        return jsonify({"status": "success", "data": data})
    return jsonify({"message": "API endpoint"})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
""",
                "cli_tool": """#!/usr/bin/env python3
import argparse
import sys
import os


def main():
    parser = argparse.ArgumentParser(description='CLI Tool')
    parser.add_argument('--input', '-i', help='Input file or data')
    parser.add_argument('--output', '-o', help='Output file')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')

    args = parser.parse_args()

    if args.verbose:
        print(f"Processing: {args.input}")

    # Your main logic here
    print("CLI tool executed successfully!")


if __name__ == '__main__':
    main()
""",
                "data_analysis": """import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns


# Load data
def load_data(filepath):
    return pd.read_csv(filepath)


# Analyze data
def analyze_data(df):
    print("Data shape:", df.shape)
    print("\nData types:")
    print(df.dtypes)
    print("\nMissing values:")
    print(df.isnull().sum())
    print("\nSummary statistics:")
    print(df.describe())


# Visualize data
def visualize_data(df):
    plt.figure(figsize=(12, 8))

    # Create subplots
    fig, axes = plt.subplots(2, 2, figsize=(15, 10))

    # Plot 1: Histogram
    axes[0, 0].hist(df.select_dtypes(include=[np.number]).iloc[:, 0], bins=20)
    axes[0, 0].set_title('Distribution')

    # Plot 2: Correlation heatmap
    numeric_cols = df.select_dtypes(include=[np.number])
    if len(numeric_cols.columns) > 1:
        sns.heatmap(numeric_cols.corr(), ax=axes[0, 1], annot=True)
        axes[0, 1].set_title('Correlation Matrix')

    plt.tight_layout()
    plt.show()


if __name__ == '__main__':
    # Example usage
    # df = load_data('your_data.csv')
    # analyze_data(df)
    # visualize_data(df)
    print("Data analysis script ready!")
""",
                "api_server": """from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional
import uvicorn

app = FastAPI(title="API Server", version="1.0.0")


class Item(BaseModel):
    id: Optional[int] = None
    name: str
    description: Optional[str] = None
    price: float


# In-memory storage
items: List[Item] = []
next_id = 1


@app.get("/")
def read_root():
    return {"message": "Welcome to the API Server"}


@app.get("/items", response_model=List[Item])
def get_items():
    return items


@app.post("/items", response_model=Item)
def create_item(item: Item):
    global next_id
    item.id = next_id
    next_id += 1
    items.append(item)
    return item


@app.get("/items/{item_id}", response_model=Item)
def get_item(item_id: int):
    for item in items:
        if item.id == item_id:
            return item
    raise HTTPException(status_code=404, detail="Item not found")


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
""",
            },
            "javascript": {
                "web_app": """const express = require('express');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.static('public'));

// Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/api/data', (req, res) => {
    res.json({ message: 'API endpoint working!' });
});

app.post('/api/data', (req, res) => {
    const data = req.body;
    // Process data here
    res.json({ status: 'success', data });
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
""",
                "react_app": """import React, { useState, useEffect } from 'react';
import './App.css';

function App() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('/api/data')
      .then(response => response.json())
      .then(data => {
        setData(data);
        setLoading(false);
      })
      .catch(error => {
        console.error('Error:', error);
        setLoading(false);
      });
  }, []);

  if (loading) return <div>Loading...</div>;

  return (
    <div className="App">
      <header className="App-header">
        <h1>React App</h1>
        <p>Data: {JSON.stringify(data)}</p>
      </header>
    </div>
  );
}

export default App;
""",
            },
            "html": {
                "basic": """<!DOCTYPE html>
<html lang=\"en\">
<head>
    <meta charset=\"UTF-8\">
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">
    <title>My Website</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; text-align: center; }
        .content { line-height: 1.6; }
    </style>
</head>
<body>
    <div class=\"container\"> 
        <h1>Welcome to My Website</h1>
        <div class=\"content\">
            <p>This is a basic HTML template. You can customize it to fit your needs.</p>
            <p>Features:</p>
            <ul>
                <li>Responsive design</li>
                <li>Clean and modern styling</li>
                <li>Easy to customize</li>
            </ul>
        </div>
    </div>
</body>
</html>""",
            },
            "batch": {
                "basic": """@echo off
REM Windows Batch Script
echo Hello from Windows!
echo Current directory: %CD%
echo Current date: %DATE%
echo Current time: %TIME%

REM Your commands here
echo Script completed successfully!
pause
""",
                "installer": """@echo off
REM Windows Installer Script
echo Installing application...

REM Create directories
if not exist "C:\\Program Files\\MyApp" mkdir "C:\\Program Files\\MyApp"
if not exist "%APPDATA%\\MyApp" mkdir "%APPDATA%\\MyApp"

REM Copy files
copy "*.exe" "C:\\Program Files\\MyApp\\"
copy "*.dll" "C:\\Program Files\\MyApp\\"

echo Installation completed!
pause
""",
            },
            "asm": {
                "win64_messagebox": "; NASM x86_64 Windows MessageBox example\n; Build (MSYS2 MinGW x64):\n;   nasm -f win64 -o build/main.obj src/main.asm\n;   gcc -o build/asm_app.exe build/main.obj -luser32 -lkernel32\n; Run: .\\build\\asm_app.exe\n\n        default rel\n        extern  MessageBoxA\n        extern  ExitProcess\n\n        section .data\n        title   db  'AI Code Generator', 0\n        text    db  'Hello from x64 Windows ASM!', 0\n\n        section .text\n        global  main\nmain:\n        ; int MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);\n        sub     rsp, 32                 ; shadow space\n        xor     rcx, rcx                ; hWnd = NULL\n        lea     rdx, [rel text]         ; lpText\n        lea     r8,  [rel title]        ; lpCaption\n        mov     r9d, 0                  ; uType = 0\n        call    MessageBoxA\n\n        xor     ecx, ecx                ; exit code 0\n        call    ExitProcess\n",
            },
            "c": {
                "console": """#include <stdio.h>

int main(void) {
    printf("Hello from C!\\n");
    return 0;
}
""",
            },
            "cpp": {
                "console": """#include <iostream>

int main() {
    std::cout << "Hello from C++!" << std::endl;
    return 0;
}
""",
            },
            "cs": {
                "console": """using System;

class Program {
    static void Main(string[] args) {
        Console.WriteLine("Hello from C#!");
    }
}
""",
            },
            "go": {
                "console": """package main
import "fmt"

func main() {
    fmt.Println("Hello from Go!")
}
""",
            },
            "rust": {
                "console": """fn main() {
    println!("Hello from Rust!");
}
""",
            },
            "java": {
                "console": """public class App {
    public static void main(String[] args) {
        System.out.println("Hello from Java!");
    }
}
""",
            },
            "ts": {
                "node": """// TypeScript Node.js example
function main(): void {
  console.log('Hello from TypeScript!');
}
main();
""",
            },
            "bash": {
                "basic": """#!/usr/bin/env bash
set -euo pipefail

echo "Hello from Bash!"
""",
            },
            "powershell": {
                "basic": """Write-Host "Hello from PowerShell!""",
            },
            "sql": {
                "basic": """-- SQL example
CREATE TABLE example (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL
);

INSERT INTO example (id, name) VALUES (1, 'hello');
""",
            },
            "dockerfile": {
                "basic": """# syntax=docker/dockerfile:1
FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -r requirements.txt || true
CMD ["python", "main.py"]
""",
            },
        }

        prompt_lower = prompt.lower()
        if "web" in prompt_lower or "flask" in prompt_lower:
            return templates.get(language, templates["python"]).get("web_app", "")
        elif "cli" in prompt_lower or "command" in prompt_lower:
            return templates.get(language, templates["python"]).get("cli_tool", "")
        elif "data" in prompt_lower or "analysis" in prompt_lower:
            return templates.get(language, templates["python"]).get("data_analysis", "")
        elif "api" in prompt_lower or "server" in prompt_lower:
            return templates.get(language, templates["python"]).get("api_server", "")
        elif "react" in prompt_lower:
            return templates["javascript"]["react_app"]
        elif "html" in prompt_lower or "website" in prompt_lower:
            return templates["html"]["basic"]
        elif "batch" in prompt_lower or "windows" in prompt_lower:
            return templates["batch"]["basic"]
        elif "asm" in prompt_lower or "assembly" in prompt_lower or language == "asm":
            return templates["asm"]["win64_messagebox"]
        elif language in ("c", "cpp", "cs", "go", "rust", "java", "ts", "bash", "powershell", "sql", "dockerfile"):
            # Pick sensible defaults per language
            defaults = {
                "c": "console",
                "cpp": "console",
                "cs": "console",
                "go": "console",
                "rust": "console",
                "java": "console",
                "ts": "node",
                "bash": "basic",
                "powershell": "basic",
                "sql": "basic",
                "dockerfile": "basic",
            }
            return templates[language][defaults[language]]
        else:
            # Default to a Python web app template
            return templates["python"]["web_app"]

    def create_project_from_idea(self, idea: str) -> Path:
        """Create a complete project from an idea."""
        print(f"🚀 Creating project for: {idea}")

        project_name = safe_project_name(idea)
        idea_lower = idea.lower()

        if "web" in idea_lower or "website" in idea_lower:
            return self.create_web_project(project_name, idea)
        elif "api" in idea_lower or "server" in idea_lower:
            return self.create_api_project(project_name, idea)
        elif "data" in idea_lower or "analysis" in idea_lower:
            return self.create_data_project(project_name, idea)
        elif "cli" in idea_lower or "tool" in idea_lower:
            return self.create_cli_project(project_name, idea)
        elif "windows" in idea_lower or "batch" in idea_lower:
            return self.create_windows_project(project_name, idea)
        elif "asm" in idea_lower or "assembly" in idea_lower:
            return self.create_asm_project(project_name, idea)
        else:
            return self.create_generic_project(project_name, idea)

    def create_web_project(self, project_name: str, idea: str) -> Path:
        structure: Dict[str, Any] = {
            "app.py": self.generate_code(f"Create a Flask web app for {idea}", "python"),
            "requirements.txt": "flask==2.3.3\njinja2==3.1.2\n",
            "templates": {
                "index.html": """<!DOCTYPE html>
<html>
<head>
    <title>{{ title }}</title>
    <link rel=\"stylesheet\" href=\"{{ url_for('static', filename='style.css') }}\">
</head>
<body>
    <div class=\"container\">
        <h1>{{ title }}</h1>
        <p>{{ description }}</p>
        <div class=\"content\">
            <!-- Your content here -->
        </div>
    </div>
</body>
</html>""",
                "base.html": """<!DOCTYPE html>
<html>
<head>
    <title>{% block title %}{% endblock %}</title>
    <link rel=\"stylesheet\" href=\"{{ url_for('static', filename='style.css') }}\">
</head>
<body>
    <nav>
        <a href=\"{{ url_for('home') }}\">Home</a>
    </nav>
    <main>
        {% block content %}{% endblock %}
    </main>
</body>
</html>""",
            },
            "static": {
                "style.css": """body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
.container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
nav { background: #333; padding: 10px; margin-bottom: 20px; }
nav a { color: white; text-decoration: none; padding: 10px; }
nav a:hover { background: #555; }""",
                "script.js": """// Your JavaScript code here
console.log('Web app loaded!');

function handleFormSubmit(event) {
    event.preventDefault();
    // Handle form submission
    console.log('Form submitted');
}""",
            },
            "README.md": f"""# {project_name.replace('_', ' ').title()}

A web application for {idea}.

## Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run the application:
```bash
python app.py
```

3. Open http://localhost:5000 in your browser

## Features

- Web interface
- RESTful API endpoints
- Responsive design

## Project Structure

- `app.py` - Main Flask application
- `templates/` - HTML templates
- `static/` - CSS, JavaScript, and other static files
- `requirements.txt` - Python dependencies
""",
        }
        return self.create_project_structure(project_name, structure)

    def create_windows_project(self, project_name: str, idea: str) -> Path:
        structure: Dict[str, Any] = {
            f"{project_name}.bat": self.generate_code(
                f"Create a Windows batch script for {idea}", "batch"
            ),
            "install.bat": (
                """@echo off
echo Installing {project_name}...
echo.
echo This will install the application to your system.
echo.
pause

REM Create program directory
if not exist "C:\\Program Files\\{project_name}" mkdir "C:\\Program Files\\{project_name}"

REM Copy files
copy "*.bat" "C:\\Program Files\\{project_name}\\"
copy "*.exe" "C:\\Program Files\\{project_name}\\"

echo.
echo Installation completed!
echo You can now run the application from the Start menu.
pause
""".format(project_name=project_name)
            ),
            "uninstall.bat": (
                """@echo off
echo Uninstalling {project_name}...
echo.
pause

REM Remove program directory
if exist "C:\\Program Files\\{project_name}" rmdir /s /q "C:\\Program Files\\{project_name}"

echo.
echo Uninstallation completed!
pause
""".format(project_name=project_name)
            ),
            "README.md": f"""# {project_name.replace('_', ' ').title()}

A Windows application for {idea}.

## Installation

1. Run the installer:
```cmd
install.bat
```

2. Or run directly:
```cmd
{project_name}.bat
```

## Uninstallation

```cmd
uninstall.bat
```

## Features

- Windows batch scripts
- Easy installation/uninstallation
- Windows-specific functionality

## Project Structure

- `{project_name}.bat` - Main application script
- `install.bat` - Installation script
- `uninstall.bat` - Uninstallation script
""",
        }
        return self.create_project_structure(project_name, structure)

    def create_api_project(self, project_name: str, idea: str) -> Path:
        structure: Dict[str, Any] = {
            "main.py": self.generate_code(f"Create a FastAPI server for {idea}", "python"),
            "requirements.txt": "fastapi==0.104.1\nuvicorn==0.24.0\npydantic==2.5.0\n",
            "models.py": """from pydantic import BaseModel
from typing import Optional, List


class Item(BaseModel):
    id: Optional[int] = None
    name: str
    description: Optional[str] = None
    price: float


class Response(BaseModel):
    status: str
    message: str
    data: Optional[dict] = None
""",
            "README.md": f"""# {project_name.replace('_', ' ').title()} API

A FastAPI server for {idea}.

## Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run the server:
```bash
uvicorn main:app --reload
```

3. API documentation available at http://localhost:8000/docs

## Endpoints

- `GET /` - Root endpoint
- `GET /items` - Get all items
- `POST /items` - Create new item
- `GET /items/{id}` - Get specific item

## Features

- FastAPI framework
- Automatic API documentation
- Pydantic models for validation
- Hot reload for development
""",
        }
        return self.create_project_structure(project_name, structure)

    def create_data_project(self, project_name: str, idea: str) -> Path:
        structure: Dict[str, Any] = {
            "analysis.py": self.generate_code(
                f"Create a data analysis script for {idea}", "python"
            ),
            "requirements.txt": (
                "pandas==2.1.3\n"
                "numpy==1.25.2\n"
                "matplotlib==3.8.2\n"
                "seaborn==0.13.0\n"
                "jupyter==1.0.0\n"
            ),
            "data": {
                "sample_data.csv": """id,name,value,category
1,Item A,10.5,Category 1
2,Item B,15.2,Category 2
3,Item C,8.7,Category 1
4,Item D,22.1,Category 3
5,Item E,12.3,Category 2""",
            },
            "notebooks": {
                "analysis.ipynb": """{
 "cells": [
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "# Data Analysis Notebook\n",
    "\n",
    "This notebook contains the analysis for the project."
   ]
  },
  {
   "cell_type": "code",
   "execution_count": null,
   "metadata": {},
   "outputs": [],
   "source": [
    "import pandas as pd\n",
    "import numpy as np\n",
    "import matplotlib.pyplot as plt\n",
    "import seaborn as sns\n",
    "\n",
    "# Load data\n",
    "df = pd.read_csv('../data/sample_data.csv')\n",
    "print('Data loaded successfully!')\n",
    "df.head()"
   ]
  }
 ],
 "metadata": {
  "kernelspec": {
   "display_name": "Python 3",
   "language": "python",
   "name": "python3"
  }
 },
 "nbformat": 4,
 "nbformat_minor": 4
}""",
            },
            "README.md": f"""# {project_name.replace('_', ' ').title()}

A data analysis project for {idea}.

## Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run the analysis:
```bash
python analysis.py
```

3. Or use Jupyter notebooks:
```bash
jupyter notebook notebooks/
```

## Features

- Data analysis with pandas
- Visualization with matplotlib and seaborn
- Jupyter notebooks for interactive analysis
- Sample data included

## Project Structure

- `analysis.py` - Main analysis script
- `data/` - Data files
- `notebooks/` - Jupyter notebooks
- `requirements.txt` - Python dependencies
""",
        }
        return self.create_project_structure(project_name, structure)

    def create_cli_project(self, project_name: str, idea: str) -> Path:
        structure: Dict[str, Any] = {
            f"{project_name}.py": self.generate_code(
                f"Create a CLI tool for {idea}", "python"
            ),
            "requirements.txt": "click==8.1.7\nrich==13.7.0\n",
            "setup.py": f"""from setuptools import setup, find_packages

setup(
    name="{project_name}",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "click>=8.1.7",
        "rich>=13.7.0",
    ],
    entry_points={{
        "console_scripts": [
            "{project_name}={project_name}:main",
        ],
    }},
    author="Your Name",
    author_email="your.email@example.com",
    description="A CLI tool for {idea}",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/{project_name}",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)
""",
            "README.md": f"""# {project_name.replace('_', ' ').title()}

A command-line tool for {idea}.

## Installation

```bash
pip install -e .
```

## Usage

```bash
{project_name} --help
{project_name} --input data.txt --output result.txt
```

## Features

- Command-line interface
- Rich output formatting
- Configurable options
- Easy to extend

## Development

1. Install in development mode:
```bash
pip install -e .
```

2. Run the tool:
```bash
python {project_name}.py --help
```
""",
        }
        return self.create_project_structure(project_name, structure)

    def create_generic_project(self, project_name: str, idea: str) -> Path:
        structure: Dict[str, Any] = {
                        "main.py": f"""#!/usr/bin/env python3
\"\"\"
{project_name.replace('_', ' ').title()}
{idea}
\"\"\"


def main():
    print("Hello from {project_name}!")
    print("This project is for: {idea}")

    # Your main logic here
    process_data()


def process_data():
    '''Process data for the project'''
    print("Processing data...")
    # Add your processing logic here


if __name__ == "__main__":
    main()
""",
"requirements.txt": (
                "# Add your dependencies here\n# Example:\n# requests==2.31.0\n# pandas==2.1.3\n"
            ),
            "config.py": """# Configuration file
import os

# Default configuration
DEFAULT_CONFIG = {
    "debug": True,
    "log_level": "INFO",
    "output_dir": "output",
}


# Load configuration from environment variables
def get_config():
    config = DEFAULT_CONFIG.copy()

    if os.getenv("DEBUG"):
        config["debug"] = os.getenv("DEBUG").lower() == "true"

    if os.getenv("LOG_LEVEL"):
        config["log_level"] = os.getenv("LOG_LEVEL")

    if os.getenv("OUTPUT_DIR"):
        config["output_dir"] = os.getenv("OUTPUT_DIR")

    return config
""",
            "utils.py": """# Utility functions
import json
from pathlib import Path
from typing import Any, List


def ensure_dir(directory: str | Path) -> None:
    '''Ensure a directory exists'''
    Path(directory).mkdir(parents=True, exist_ok=True)


def save_json(data: Any, filepath: str | Path) -> None:
    '''Save data as JSON'''
    Path(filepath).parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)


def load_json(filepath: str | Path) -> Any:
    '''Load data from JSON'''
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)


def list_files(directory: str | Path, pattern: str = "*") -> List[Path]:
    '''List files in directory matching pattern'''
    return list(Path(directory).glob(pattern))
""",
            "README.md": f"""# {project_name.replace('_', ' ').title()}

{idea}

## Setup

1. Install dependencies (if any):
```bash
pip install -r requirements.txt
```

2. Run the project:
```bash
python main.py
```

## Project Structure

- `main.py` - Main application file
- `config.py` - Configuration management
- `utils.py` - Utility functions
- `requirements.txt` - Python dependencies

## Features

- Modular design
- Configuration management
- Utility functions
- Easy to extend

## Development

1. Modify `main.py` to implement your logic
2. Add dependencies to `requirements.txt`
3. Use `config.py` for configuration
4. Add utility functions to `utils.py`
""",
        }
        return self.create_project_structure(project_name, structure)

    def create_asm_project(self, project_name: str, idea: str) -> Path:
        """Create a Windows NASM x64 assembly project with MinGW build scripts."""
        structure: Dict[str, Any] = {
            "src": {
                "main.asm": self.generate_code(
                    f"Create a Windows x64 NASM MessageBox demo for {idea}", "asm"
                ),
            },
            "build": {},
            "build_mingw64.bat": (
                """@echo off\nsetlocal\n\nif not exist build mkdir build\n\nwhere nasm >nul 2>nul\nif %ERRORLEVEL% neq 0 (\n  echo NASM not found in PATH. Install via MSYS2: pacman -S mingw-w64-x86_64-nasm\n  exit /b 1\n)\n\nwhere gcc >nul 2>nul\nif %ERRORLEVEL% neq 0 (\n  echo GCC (mingw-w64) not found in PATH. Use MSYS2 MinGW x64 shell and install: pacman -S mingw-w64-x86_64-gcc\n  exit /b 1\n)\n\necho Assembling...\n"""
                + "nasm -f win64 -o build\\main.obj src\\main.asm\n"
                + "echo Linking...\n"
                + "gcc -o build\\asm_app.exe build\\main.obj -luser32 -lkernel32\n"
                + "if exist build\\asm_app.exe (\n  echo ✅ Built: build\\asm_app.exe\n  exit /b 0\n) else (\n  echo ❌ Build failed\n  exit /b 1\n)\n"
            ),
            "README.md": f"""# {project_name.replace('_', ' ').title()} (ASM)

Windows x64 NASM project for {idea}.

## Requirements (MSYS2 MinGW x64)
- nasm (pacman -S mingw-w64-x86_64-nasm)
- gcc/linker (pacman -S mingw-w64-x86_64-gcc)

## Build
```cmd
build_mingw64.bat
```

## Run
```cmd
build\asm_app.exe
```
""",
        }
        return self.create_project_structure(project_name, structure)


# ----------------------------
# CLI and interactive frontend
# ----------------------------

def safe_project_name(idea: str) -> str:
    name = idea.lower().replace(" ", "_").replace("-", "_")
    name = "".join(c for c in name if c.isalnum() or c == "_")
    return name or "project"


def run_interactive(generator: AICodeGenerator) -> int:
    print("🤖 AI Code Generator for Windows 11 - Local AI Coding Assistant")
    print("=" * 60)
    print("This tool can create files, generate code, and help you build projects!")
    print("Works perfectly on Windows 11!")
    print()

    try:
        while True:
            print("\nOptions:")
            print("1. Create a new project from an idea")
            print("2. Generate code for a specific task")
            print("3. Create a single file")
            print("4. Exit")

            choice = input("\nEnter your choice (1-4): ").strip()

            if choice == "1":
                idea = input("Describe your project idea: ").strip()
                if idea:
                    project_path = generator.create_project_from_idea(idea)
                    print(f"\n🎉 Project created successfully at: {project_path}")
                    print("You can now start coding!")

            elif choice == "2":
                task = input("Describe the code you want to generate: ").strip()
                language = (
                    input("Language (python/javascript/html/batch/asm/c/cpp/cs/go/rust/java/ts/bash/powershell/sql/dockerfile): ").strip().lower()
                    or "python"
                )
                if task:
                    code = generator.generate_code(task, language)
                    print(f"\nGenerated code:\n{'-' * 40}")
                    print(code)

                    save = input("\nSave to file? (y/n): ").strip().lower()
                    if save == 'y':
                        filename = input("Filename: ").strip()
                        if filename:
                            generator.create_file(filename, code)

            elif choice == "3":
                filename = input("Filename: ").strip()
                print("Enter file content. End with Ctrl+D (Linux/macOS) or Ctrl+Z then Enter (Windows).")
                print("--- start typing below ---")
                try:
                    content = sys.stdin.read()
                except KeyboardInterrupt:
                    content = ""
                if filename and content:
                    generator.create_file(filename, content)

            elif choice == "4":
                print("Goodbye! 👋")
                return 0
            else:
                print("Invalid choice. Please try again.")
    except KeyboardInterrupt:
        print("\nInterrupted. Goodbye! 👋")
        return 130


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="AI Code Generator for Windows 11 - Local AI Coding Assistant",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    subparsers = parser.add_subparsers(dest="command")

    # Interactive mode
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Run in interactive menu mode",
    )

    # create-project
    sp_create = subparsers.add_parser(
        "create-project", help="Create a new project from an idea"
    )
    sp_create.add_argument("--idea", required=True, help="Project idea/description")

    # generate-code
    sp_gen = subparsers.add_parser(
        "generate-code", help="Generate code for a specific task"
    )
    sp_gen.add_argument("--task", required=True, help="Task description/prompt")
    sp_gen.add_argument(
        "--language",
        default="python",
        choices=[
            "python", "javascript", "html", "batch", "asm",
            "c", "cpp", "cs", "go", "rust", "java", "ts",
            "bash", "powershell", "sql", "dockerfile",
        ],
        help="Target language for code generation",
    )

    # create-file
    sp_file = subparsers.add_parser("create-file", help="Create a single file")
    sp_file.add_argument("--filename", required=True, help="File path to create")
    sp_file.add_argument(
        "--content",
        required=False,
        help=(
            "File content. If omitted, reads from STDIN (end with Ctrl+D or Ctrl+Z+Enter)."
        ),
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    generator = AICodeGenerator()

    # Interactive by flag or when no subcommand is given
    if args.interactive or args.command is None:
        return run_interactive(generator)

    if args.command == "create-project":
        project_path = generator.create_project_from_idea(args.idea)
        print(f"🎉 Project created successfully at: {project_path}")
        return 0

    if args.command == "generate-code":
        code = generator.generate_code(args.task, args.language)
        print(code)
        return 0

    if args.command == "create-file":
        content: str
        if args.content is not None:
            content = args.content
        else:
            # Read from stdin
            content = sys.stdin.read()
        generator.create_file(args.filename, content)
        return 0

    # Fallback
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())