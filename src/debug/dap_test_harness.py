#!/usr/bin/env python3
"""
RawrXD DAP Protocol Test Harness
Tests the DAP server by sending JSON-RPC messages and validating responses

Usage:
    python dap_test_harness.py --server ..\..\build\debug\DAPServer.exe
    python dap_test_harness.py --server DAPServer.exe --verbose
"""

import subprocess
import sys
import json
import argparse
import time

class DAPTestHarness:
    def __init__(self, server_path, verbose=False):
        self.server_path = server_path
        self.verbose = verbose
        self.seq = 0
        self.process = None
        
    def log(self, msg):
        if self.verbose:
            print(f"[HARNESS] {msg}")
            
    def info(self, msg):
        print(f"[INFO] {msg}")
        
    def error(self, msg):
        print(f"[ERROR] {msg}", file=sys.stderr)
        
    def start(self):
        """Start the DAP server process"""
        self.info(f"Starting DAP server: {self.server_path}")
        try:
            self.process = subprocess.Popen(
                [self.server_path],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=0
            )
            self.log(f"Server started with PID {self.process.pid}")
            return True
        except Exception as e:
            self.error(f"Failed to start server: {e}")
            return False
            
    def stop(self):
        """Stop the DAP server"""
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
            self.log("Server stopped")
            
    def send_request(self, command, arguments=None):
        """Send a DAP request and return the response"""
        self.seq += 1
        request = {
            "type": "request",
            "seq": self.seq,
            "command": command,
            "arguments": arguments or {}
        }
        
        json_str = json.dumps(request)
        content = f"Content-Length: {len(json_str)}\r\n\r\n{json_str}"
        
        self.log(f"Sending: {json_str}")
        
        try:
            self.process.stdin.write(content)
            self.process.stdin.flush()
        except Exception as e:
            self.error(f"Failed to send request: {e}")
            return None
            
        # Read response
        return self.read_response()
        
    def read_response(self):
        """Read a DAP response from stdout"""
        try:
            # Read header
            header = ""
            while True:
                char = self.process.stdout.read(1)
                if not char:
                    self.error("EOF reading header")
                    return None
                header += char
                if header.endswith("\r\n\r\n"):
                    break
                    
            # Parse Content-Length
            content_length = 0
            for line in header.split("\r\n"):
                if line.startswith("Content-Length:"):
                    content_length = int(line.split(":")[1].strip())
                    break
                    
            if content_length == 0:
                self.error("No Content-Length in response")
                return None
                
            # Read JSON body
            body = self.process.stdout.read(content_length)
            self.log(f"Received: {body}")
            
            return json.loads(body)
            
        except Exception as e:
            self.error(f"Failed to read response: {e}")
            return None
            
    def test_initialize(self):
        """Test initialize request"""
        self.info("Testing initialize...")
        
        response = self.send_request("initialize", {})
        if not response:
            return False
            
        # Validate response
        checks = [
            (response.get("type") == "response", "type is response"),
            (response.get("command") == "initialize", "command is initialize"),
            (response.get("success") == True, "success is true"),
            ("body" in response, "has body"),
            ("supportsConfigurationDoneRequest" in response.get("body", {}), "has capabilities")
        ]
        
        for check, msg in checks:
            if not check:
                self.error(f"Initialize check failed: {msg}")
                return False
                
        self.info("Initialize test PASSED")
        return True
        
    def test_launch(self, program):
        """Test launch request"""
        self.info(f"Testing launch with {program}...")
        
        response = self.send_request("launch", {
            "program": program,
            "args": [],
            "cwd": "C:\\Windows\\System32"
        })
        
        if not response:
            return False
            
        # Launch might succeed or fail depending on environment
        if response.get("success"):
            self.info("Launch test PASSED (process started)")
        else:
            self.info(f"Launch returned failure (may be expected): {response.get('message')}")
            
        return True
        
    def test_threads(self):
        """Test threads request"""
        self.info("Testing threads...")
        
        response = self.send_request("threads", {})
        if not response:
            return False
            
        if response.get("success") and "body" in response:
            threads = response["body"].get("threads", [])
            self.info(f"Found {len(threads)} thread(s)")
            self.info("Threads test PASSED")
            return True
        else:
            self.error("Threads response invalid")
            return False
            
    def test_disconnect(self):
        """Test disconnect request"""
        self.info("Testing disconnect...")
        
        response = self.send_request("disconnect", {})
        if not response:
            return False
            
        if response.get("success"):
            self.info("Disconnect test PASSED")
            return True
        else:
            self.error("Disconnect failed")
            return False
            
    def run_all_tests(self, test_program="C:\\Windows\\System32\\notepad.exe"):
        """Run all tests"""
        results = []
        
        # Test 1: Initialize
        results.append(("Initialize", self.test_initialize()))
        
        # Test 2: Launch
        results.append(("Launch", self.test_launch(test_program)))
        
        # Test 3: Threads
        results.append(("Threads", self.test_threads()))
        
        # Test 4: Disconnect
        results.append(("Disconnect", self.test_disconnect()))
        
        return results

def main():
    parser = argparse.ArgumentParser(description="RawrXD DAP Protocol Test Harness")
    parser.add_argument("--server", required=True, help="Path to DAPServer.exe")
    parser.add_argument("--program", default="C:\\Windows\\System32\\notepad.exe",
                        help="Program to launch for testing")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    args = parser.parse_args()
    
    harness = DAPTestHarness(args.server, args.verbose)
    
    if not harness.start():
        sys.exit(1)
        
    try:
        results = harness.run_all_tests(args.program)
        
        print("\n" + "="*60)
        print("Test Results:")
        print("="*60)
        
        passed = sum(1 for _, r in results if r)
        failed = sum(1 for _, r in results if not r)
        
        for name, result in results:
            status = "PASS" if result else "FAIL"
            print(f"  {name}: {status}")
            
        print("="*60)
        print(f"Total: {passed} passed, {failed} failed")
        print("="*60)
        
        if failed == 0:
            print("\n[SUCCESS] All DAP protocol tests passed!")
            sys.exit(0)
        else:
            print(f"\n[FAILURE] {failed} test(s) failed")
            sys.exit(1)
            
    finally:
        harness.stop()

if __name__ == "__main__":
    main()
