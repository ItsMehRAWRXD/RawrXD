# Scripting Examples
## Sovereign IDE Examples Documentation

**Version:** 1.0.0
**Date:** 2026-07-11
**Status:** ✅ Complete

---

## Overview

Example scripts for automating Sovereign IDE tasks.

---

## Python Examples

### Example 1: Batch Analysis

```python
#!/usr/bin/env python3
"""Batch analyze multiple binaries."""

import sovereign
import os
import json

def analyze_directory(directory):
    """Analyze all binaries in a directory."""
    results = {}
    
    for filename in os.listdir(directory):
        filepath = os.path.join(directory, filename)
        
        if not os.path.isfile(filepath):
            continue
        
        try:
            print(f"Analyzing: {filename}")
            binary = sovereign.load_binary(filepath)
            
            # Run analysis
            analysis = binary.analyze()
            
            # Store results
            results[filename] = {
                'format': binary.format,
                'architecture': binary.architecture,
                'functions': len(binary.functions),
                'imports': len(binary.imports),
                'vulnerabilities': len(analysis.vulnerabilities)
            }
            
        except Exception as e:
            print(f"Error analyzing {filename}: {e}")
            results[filename] = {'error': str(e)}
    
    return results

# Usage
if __name__ == '__main__':
    directory = '/path/to/binaries'
    results = analyze_directory(directory)
    
    # Save results
    with open('analysis_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print("Analysis complete. Results saved to analysis_results.json")
```

### Example 2: Custom Report

```python
#!/usr/bin/env python3
"""Generate custom analysis report."""

import sovereign
from datetime import datetime

def generate_report(binary_path, output_path):
    """Generate HTML report for binary."""
    
    binary = sovereign.load_binary(binary_path)
    analysis = binary.analyze()
    
    html = f"""
    <html>
    <head>
        <title>Analysis Report: {binary.name}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; }}
            h1 {{ color: #333; }}
            table {{ border-collapse: collapse; width: 100%; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #4CAF50; color: white; }}
            .critical {{ color: red; }}
            .warning {{ color: orange; }}
        </style>
    </head>
    <body>
        <h1>Analysis Report: {binary.name}</h1>
        <p>Generated: {datetime.now().isoformat()}</p>
        
        <h2>Basic Information</h2>
        <table>
            <tr><th>Property</th><th>Value</th></tr>
            <tr><td>Format</td><td>{binary.format}</td></tr>
            <tr><td>Architecture</td><td>{binary.architecture}</td></tr>
            <tr><td>Size</td><td>{binary.size} bytes</td></tr>
        </table>
        
        <h2>Vulnerabilities</h2>
        <table>
            <tr>
                <th>Severity</th>
                <th>Type</th>
                <th>Address</th>
                <th>Description</th>
            </tr>
    """
    
    for vuln in analysis.vulnerabilities:
        severity_class = 'critical' if vuln.severity == 'Critical' else 'warning'
        html += f"""
            <tr>
                <td class="{severity_class}">{vuln.severity}</td>
                <td>{vuln.type}</td>
                <td>{hex(vuln.address)}</td>
                <td>{vuln.description}</td>
            </tr>
        """
    
    html += """
        </table>
    </body>
    </html>
    """
    
    with open(output_path, 'w') as f:
        f.write(html)
    
    print(f"Report saved to {output_path}")

# Usage
if __name__ == '__main__':
    generate_report('binary.exe', 'report.html')
```

---

## Lua Examples

### Example 1: Simple Analysis

```lua
#!/usr/bin/env lua
-- Simple binary analysis script

local sovereign = require("sovereign")

-- Load binary
local binary = sovereign.load_binary(arg[1])

-- Print information
print("Binary Analysis Report")
print("=====================")
print("Name: " .. binary.name)
print("Format: " .. binary.format)
print("Architecture: " .. binary.architecture)
print("")

-- List functions
print("Functions:")
for _, func in ipairs(binary.functions) do
    print(string.format("  0x%08x: %s", func.address, func.name))
end

-- List strings
print("")
print("Strings:")
for _, str in ipairs(binary.strings) do
    if #str.value > 4 then
        print(string.format("  0x%08x: %s", str.address, str.value))
    end
end
```

---

## Summary

Scripting Examples provides:

- ✅ **Python examples**
- ✅ **Lua examples**
- ✅ **Batch processing**
- ✅ **Custom reports**
- ✅ **Automation scripts**

**Status:** ✅ Complete
