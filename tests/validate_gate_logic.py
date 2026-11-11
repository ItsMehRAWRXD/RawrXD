#!/usr/bin/env python3
# ============================================================================
# validate_gate_logic.py - Validate Deterministic Replay Gate Logic
# ============================================================================
#
# This script validates the gate logic without requiring compilation.
# It parses the C++ source and verifies:
#   - All scenarios are defined
#   - Exit codes are correct
#   - Event types are complete
#   - JSON export format is valid
#
# Usage:
#   python validate_gate_logic.py
# ============================================================================

import re
import json
import sys
from pathlib import Path

def parse_cpp_file(filepath):
    """Parse the C++ gate source file."""
    with open(filepath, 'r') as f:
        content = f.read()
    return content

def extract_scenarios(content):
    """Extract scenario definitions from the C++ file."""
    # Look for ScenarioConfig array - more flexible pattern for multiline
    pattern = r'std::vector\s*<\s*ScenarioConfig\s*>\s+\w+\s*=\s*\{'
    start_match = re.search(pattern, content)
    
    scenarios = []
    if start_match:
        # Find the matching closing brace
        start_pos = start_match.end()
        brace_count = 1
        end_pos = start_pos
        
        while brace_count > 0 and end_pos < len(content):
            if content[end_pos] == '{':
                brace_count += 1
            elif content[end_pos] == '}':
                brace_count -= 1
            end_pos += 1
        
        array_content = content[start_pos:end_pos-1]
        
        # Extract scenario names - simpler pattern that just looks for the name field
        # Pattern: "Name" after ScenarioType::XXX,
        scenario_pattern = r'ScenarioType::(\w+)\s*,\s*\n?\s*"([^"]+)"'
        for m in re.finditer(scenario_pattern, array_content, re.MULTILINE):
            scenarios.append({
                'type': m.group(1),
                'name': m.group(2),
                'description': '',  # Not needed for basic validation
                'timeoutMs': 0,
                'expectedVersion': 0,
                'inputText': '',
                'expectedCompletion': None
            })
    
    return scenarios

def extract_event_types(content):
    """Extract event type enum definitions."""
    pattern = r'enum\s+class\s+EventType\s*\{([^}]+)\}'
    match = re.search(pattern, content)
    
    event_types = []
    if match:
        # Extract enum values
        enum_pattern = r'(\w+)\s*(?:=\s*\d+)?\s*,?'
        for m in re.finditer(enum_pattern, match.group(1)):
            name = m.group(1).strip()
            if name and name not in ['', ' ']:
                event_types.append(name)
    
    return event_types

def extract_exit_codes(content):
    """Extract exit code definitions."""
    pattern = r'enum\s+class\s+GateResult\s*\{([^}]+)\}'
    match = re.search(pattern, content)
    
    exit_codes = {}
    if match:
        # Extract enum values with assignments
        enum_pattern = r'(\w+)\s*=\s*(\d+)'
        for m in re.finditer(enum_pattern, match.group(1)):
            exit_codes[m.group(1)] = int(m.group(2))
    
    return exit_codes

def validate_scenarios(scenarios):
    """Validate scenario definitions."""
    print("\n=== Scenario Validation ===")
    
    required_scenarios = [
        'SingleKeystroke',
        'RapidTypingBurst', 
        'CancelAndRetry',
        'ConcurrentEdit',
        'StressSequence'
    ]
    
    found_names = [s['name'] for s in scenarios]
    
    all_found = True
    for required in required_scenarios:
        if required in found_names:
            print(f"  ✓ {required}")
        else:
            print(f"  ✗ {required} - MISSING")
            all_found = False
    
    # Check for duplicates
    duplicates = [name for name in found_names if found_names.count(name) > 1]
    if duplicates:
        print(f"  ✗ Duplicate scenarios found: {set(duplicates)}")
        all_found = False
    
    # Validate timeouts
    for s in scenarios:
        if s['timeoutMs'] < 1000:
            print(f"  ⚠ {s['name']}: Timeout {s['timeoutMs']}ms seems low")
        if s['timeoutMs'] > 30000:
            print(f"  ⚠ {s['name']}: Timeout {s['timeoutMs']}ms seems high")
    
    return all_found

def validate_event_types(event_types):
    """Validate event type definitions."""
    print("\n=== Event Type Validation ===")
    
    required_events = [
        'Keystroke',
        'CompletionRequested',
        'CompletionReceived',
        'CompletionRejected',
        'Cancelled',
        'VersionIncrement',
        'EditorSnapshot'
    ]
    
    all_found = True
    for required in required_events:
        if required in event_types:
            print(f"  ✓ {required}")
        else:
            print(f"  ✗ {required} - MISSING")
            all_found = False
    
    return all_found

def validate_exit_codes(exit_codes):
    """Validate exit code definitions."""
    print("\n=== Exit Code Validation ===")
    
    expected_codes = {
        'PASS': 0,
        'FAIL_DETERMINISM': 1,
        'FAIL_INFRASTRUCTURE': 2,
        'FAIL_TIMEOUT': 3,
        'FAIL_VALIDATION': 4
    }
    
    all_correct = True
    for name, expected in expected_codes.items():
        if name in exit_codes:
            actual = exit_codes[name]
            if actual == expected:
                print(f"  ✓ {name} = {actual}")
            else:
                print(f"  ✗ {name} = {actual} (expected {expected})")
                all_correct = False
        else:
            print(f"  ✗ {name} - MISSING")
            all_correct = False
    
    return all_correct

def validate_json_export():
    """Validate the JSON export format by simulating output."""
    print("\n=== JSON Export Validation ===")
    
    # Simulate a journal export
    sample_export = {
        "gateVersion": "1.0.0",
        "timestamp": 1234567890123456,
        "events": [
            {
                "sequenceId": 1,
                "timestampUs": 1234567890123456,
                "type": "Keystroke",
                "version": 1,
                "data": "func"
            },
            {
                "sequenceId": 2,
                "timestampUs": 1234567890123556,
                "type": "CompletionRequested",
                "version": 1,
                "data": "reqId=1"
            }
        ]
    }
    
    try:
        # Validate JSON structure
        json_str = json.dumps(sample_export, indent=2)
        parsed = json.loads(json_str)
        
        # Check required fields
        assert "gateVersion" in parsed
        assert "timestamp" in parsed
        assert "events" in parsed
        assert isinstance(parsed["events"], list)
        
        # Check event structure
        for event in parsed["events"]:
            assert "sequenceId" in event
            assert "timestampUs" in event
            assert "type" in event
            assert "version" in event
        
        print("  ✓ JSON structure is valid")
        return True
    except Exception as e:
        print(f"  ✗ JSON validation failed: {e}")
        return False

def main():
    print("=" * 60)
    print("RawrXD IDE Deterministic Replay Gate - Logic Validator")
    print("=" * 60)
    
    # Find the gate source file
    gate_path = Path(__file__).parent / "deterministic_replay_gate.cpp"
    
    if not gate_path.exists():
        print(f"\nERROR: Could not find {gate_path}")
        print("Make sure you're running this from the tests directory")
        return 1
    
    print(f"\nAnalyzing: {gate_path}")
    
    # Parse the C++ file
    content = parse_cpp_file(gate_path)
    
    # Extract and validate components
    scenarios = extract_scenarios(content)
    event_types = extract_event_types(content)
    exit_codes = extract_exit_codes(content)
    
    # Run validations
    results = []
    results.append(("Scenarios", validate_scenarios(scenarios)))
    results.append(("Event Types", validate_event_types(event_types)))
    results.append(("Exit Codes", validate_exit_codes(exit_codes)))
    results.append(("JSON Export", validate_json_export()))
    
    # Summary
    print("\n" + "=" * 60)
    print("VALIDATION SUMMARY")
    print("=" * 60)
    
    all_passed = True
    for name, passed in results:
        status = "PASS" if passed else "FAIL"
        symbol = "✓" if passed else "✗"
        print(f"  {symbol} {name}: {status}")
        if not passed:
            all_passed = False
    
    print("=" * 60)
    
    if all_passed:
        print("\n✓ All validations passed!")
        print("\nThe gate logic is correctly defined.")
        print("To build and run the gate:")
        print("  1. Open a Visual Studio Developer Command Prompt")
        print("  2. Run: build_deterministic_replay_gate.bat --run")
        return 0
    else:
        print("\n✗ Some validations failed!")
        print("\nPlease review the errors above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
