#!/usr/bin/env python3
"""
Test script for RawrXD MCP Server
Tests JSON-RPC communication over stdio
"""

import subprocess
import json
import sys
import time

def send_message(proc, msg):
    """Send a JSON-RPC message with Content-Length framing"""
    payload = json.dumps(msg)
    content_length = len(payload.encode('utf-8'))
    header = f"Content-Length: {content_length}\r\n\r\n"
    full_message = header + payload
    proc.stdin.write(full_message.encode('utf-8'))
    proc.stdin.flush()
    print(f"\n[Sent] {msg['method'] if 'method' in msg else 'response'}")

def read_message(proc):
    """Read a JSON-RPC response with Content-Length framing"""
    # Read header
    header = b""
    while b"\r\n\r\n" not in header:
        byte = proc.stdout.read(1)
        if not byte:
            return None
        header += byte
    
    # Parse Content-Length
    header_str = header.decode('utf-8')
    content_length = 0
    for line in header_str.split('\r\n'):
        if line.startswith('Content-Length:'):
            content_length = int(line.split(':')[1].strip())
            break
    
    # Read payload
    if content_length > 0:
        payload = proc.stdout.read(content_length)
        return json.loads(payload.decode('utf-8'))
    return None

def test_initialize(proc):
    """Test initialize method"""
    msg = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "test-client", "version": "1.0"}
        }
    }
    send_message(proc, msg)
    response = read_message(proc)
    print(f"[Response] {json.dumps(response, indent=2)}")
    assert response and "result" in response, "Initialize failed"
    print("✅ Initialize test passed")
    return True

def test_tools_list(proc):
    """Test tools/list method"""
    msg = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list"
    }
    send_message(proc, msg)
    response = read_message(proc)
    print(f"[Response] {json.dumps(response, indent=2)}")
    assert response and "result" in response, "Tools list failed"
    tools = response["result"]["tools"]
    tool_names = [t["name"] for t in tools]
    assert "echo" in tool_names, "echo tool not found"
    assert "read_file" in tool_names, "read_file tool not found"
    assert "list_dir" in tool_names, "list_dir tool not found"
    print("✅ Tools/list test passed")
    return True

def test_echo(proc):
    """Test echo tool"""
    msg = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "echo",
            "arguments": {"text": "Hello from MCP test!"}
        }
    }
    send_message(proc, msg)
    response = read_message(proc)
    print(f"[Response] {json.dumps(response, indent=2)}")
    assert response and "result" in response, "Echo failed"
    content = response["result"]["content"][0]["text"]
    assert "Hello from MCP test!" in content, "Echo content mismatch"
    print("✅ Echo test passed")
    return True

def test_read_file(proc):
    """Test read_file tool"""
    # Create a test file
    test_content = "Test file content for MCP server"
    with open("d:\\rawrxd\\src\\asm\\test_mcp_file.txt", "w") as f:
        f.write(test_content)
    
    msg = {
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {"path": "d:\\rawrxd\\src\\asm\\test_mcp_file.txt"}
        }
    }
    send_message(proc, msg)
    response = read_message(proc)
    print(f"[Response] {json.dumps(response, indent=2)}")
    assert response and "result" in response, "Read file failed"
    content = response["result"]["content"][0]["text"]
    assert test_content in content, "File content mismatch"
    print("✅ Read file test passed")
    return True

def test_list_dir(proc):
    """Test list_dir tool"""
    msg = {
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {
            "name": "list_dir",
            "arguments": {"path": "d:\\rawrxd\\src\\asm"}
        }
    }
    send_message(proc, msg)
    response = read_message(proc)
    print(f"[Response] {json.dumps(response, indent=2)}")
    assert response and "result" in response, "List dir failed"
    content = response["result"]["content"][0]["text"]
    assert "RawrXD_MCPServer" in content or "asm" in content, "Directory listing missing expected content"
    print("✅ List dir test passed")
    return True

def test_shutdown(proc):
    """Test shutdown method"""
    msg = {
        "jsonrpc": "2.0",
        "id": 6,
        "method": "shutdown"
    }
    send_message(proc, msg)
    response = read_message(proc)
    print(f"[Response] {json.dumps(response, indent=2)}")
    assert response and "result" in response, "Shutdown failed"
    print("✅ Shutdown test passed")
    return True

def main():
    print("=" * 60)
    print("RawrXD MCP Server Test Suite")
    print("=" * 60)
    
    # Start the MCP server
    print("\n[Starting MCP Server...]")
    proc = subprocess.Popen(
        ["d:\\rawrxd\\src\\asm\\RawrXD_MCPServer.exe"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    try:
        # Run all tests
        tests = [
            ("Initialize", test_initialize),
            ("Tools/List", test_tools_list),
            ("Echo Tool", test_echo),
            ("Read File Tool", test_read_file),
            ("List Directory Tool", test_list_dir),
            ("Shutdown", test_shutdown)
        ]
        
        passed = 0
        failed = 0
        
        for name, test_func in tests:
            print(f"\n{'-' * 40}")
            print(f"Test: {name}")
            print('-' * 40)
            try:
                if test_func(proc):
                    passed += 1
            except Exception as e:
                print(f"❌ Test failed: {e}")
                failed += 1
        
        # Cleanup
        proc.stdin.close()
        proc.stdout.close()
        proc.wait(timeout=2)
        
    except Exception as e:
        print(f"\n❌ Test suite error: {e}")
        proc.terminate()
        return 1
    
    # Summary
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    print(f"Passed: {passed}/{len(tests)}")
    print(f"Failed: {failed}/{len(tests)}")
    
    if failed == 0:
        print("\n✅ All tests passed!")
        return 0
    else:
        print(f"\n❌ {failed} test(s) failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())
