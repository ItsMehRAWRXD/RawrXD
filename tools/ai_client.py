#!/usr/bin/env python3
"""
RawrXD AI Control Bridge - Example Client

This script demonstrates how an AI can:
1. Monitor RawrXD IDE telemetry
2. Send commands to control the IDE
3. Analyze performance and suggest optimizations

Usage:
    python ai_client.py --monitor
    python ai_client.py --command openFile --params '{"path": "src/main.cpp"}'
    python ai_client.py --diagnose
"""

import json
import time
import argparse
import os
from pathlib import Path
from typing import Dict, Any, Optional

class RawrXDClient:
    """Client for communicating with RawrXD IDE via the AI Control Bridge."""
    
    def __init__(self, working_dir: str = "."):
        self.working_dir = Path(working_dir)
        self.telemetry_path = self.working_dir / "rawrxd_telemetry.json"
        self.command_path = self.working_dir / "ai_control.json"
        self.response_path = self.working_dir / "ai_response.json"
        self.log_path = self.working_dir / "rawrxd_agent.log"
        self.command_id = 1
    
    def read_telemetry(self) -> Optional[Dict[str, Any]]:
        """Read current IDE telemetry."""
        try:
            with open(self.telemetry_path, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return None
    
    def send_command(self, cmd_type: str, params: Dict[str, str] = None) -> bool:
        """Send a command to the IDE."""
        cmd = {
            "type": cmd_type,
            "commandId": self.command_id,
            "parameters": params or {}
        }
        
        try:
            with open(self.command_path, 'w') as f:
                json.dump(cmd, f, indent=2)
            self.command_id += 1
            return True
        except Exception as e:
            print(f"Failed to send command: {e}")
            return False
    
    def read_response(self, timeout: float = 2.0) -> Optional[Dict[str, Any]]:
        """Read response from IDE."""
        start = time.time()
        while time.time() - start < timeout:
            try:
                with open(self.response_path, 'r') as f:
                    return json.load(f)
            except (FileNotFoundError, json.JSONDecodeError):
                time.sleep(0.1)
        return None
    
    def wait_for_file(self, path: Path, timeout: float = 5.0) -> bool:
        """Wait for a file to exist."""
        start = time.time()
        while time.time() - start < timeout:
            if path.exists():
                return True
            time.sleep(0.1)
        return False
    
    def monitor(self, interval: float = 1.0):
        """Continuously monitor IDE telemetry."""
        print("🔍 Monitoring RawrXD IDE telemetry...")
        print("Press Ctrl+C to stop\n")
        
        try:
            while True:
                data = self.read_telemetry()
                if data:
                    self._display_telemetry(data)
                else:
                    print("⏳ Waiting for RawrXD to start...")
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\n👋 Monitoring stopped")
    
    def _display_telemetry(self, data: Dict[str, Any]):
        """Display formatted telemetry."""
        os.system('cls' if os.name == 'nt' else 'clear')
        
        print("=" * 60)
        print("🖥️  RawrXD IDE Telemetry")
        print("=" * 60)
        
        # Memory
        mem = data.get('memory', {})
        print(f"\n💾 Memory:")
        print(f"  Working Set: {mem.get('workingSetBytes', 0) / 1024 / 1024:.1f} MB")
        print(f"  Virtual: {mem.get('virtualMemoryBytes', 0) / 1024 / 1024:.1f} MB")
        print(f"  Peak: {mem.get('peakWorkingSetBytes', 0) / 1024 / 1024:.1f} MB")
        
        # GDI
        gdi = data.get('gdi', {})
        print(f"\n🎨 GDI Objects:")
        print(f"  GDI: {gdi.get('objects', 0)}")
        print(f"  User: {gdi.get('userObjects', 0)}")
        print(f"  Peak: {gdi.get('peakObjects', 0)}")
        
        # Window
        win = data.get('window', {})
        print(f"\n🪟 Window:")
        print(f"  Size: {win.get('width', 0)}x{win.get('height', 0)}")
        print(f"  Foreground: {win.get('isForeground', False)}")
        print(f"  Minimized: {win.get('isMinimized', False)}")
        
        # Editor
        ed = data.get('editor', {})
        print(f"\n📝 Editor:")
        print(f"  Size: {ed.get('width', 0)}x{ed.get('height', 0)}")
        print(f"  Cursor: Line {ed.get('cursorLine', 0)}, Col {ed.get('cursorColumn', 0)}")
        print(f"  Total Lines: {ed.get('totalLines', 0)}")
        print(f"  File: {ed.get('currentFile', 'None')}")
        
        # LSP
        lsp = data.get('lsp', {})
        print(f"\n🔌 LSP:")
        print(f"  Connected: {'✅' if lsp.get('connected') else '❌'}")
        print(f"  Server: {lsp.get('serverName', 'None')}")
        print(f"  Pending: {lsp.get('pendingRequests', 0)}")
        print(f"  Diagnostics: {lsp.get('diagnosticsCount', 0)}")
        
        # Performance
        perf = data.get('performance', {})
        print(f"\n⚡ Performance:")
        print(f"  Frame Time: {perf.get('avgFrameTimeMs', 0):.2f} ms")
        print(f"  FPS: {1000 / perf.get('avgFrameTimeMs', 16):.1f}")
        print(f"  Messages/sec: {perf.get('messagesPerSecond', 0)}")
        
        # Errors
        errs = data.get('errors', {})
        if errs.get('count', 0) > 0:
            print(f"\n⚠️  Errors: {errs.get('count', 0)}")
            print(f"  Last: {errs.get('lastError', 'Unknown')}")
        
        print("\n" + "=" * 60)
    
    def diagnose(self) -> list:
        """Analyze telemetry and return list of issues."""
        data = self.read_telemetry()
        if not data:
            return ["No telemetry available - is RawrXD running?"]
        
        issues = []
        
        # Memory check
        mem = data.get('memory', {})
        working_set = mem.get('workingSetBytes', 0)
        if working_set > 200_000_000:  # 200 MB
            issues.append(f"⚠️  High memory usage: {working_set / 1024 / 1024:.1f} MB")
        
        # GDI check
        gdi = data.get('gdi', {})
        gdi_objects = gdi.get('objects', 0)
        if gdi_objects > 500:
            issues.append(f"⚠️  High GDI object count: {gdi_objects}")
        
        # Performance check
        perf = data.get('performance', {})
        frame_time = perf.get('avgFrameTimeMs', 16)
        if frame_time > 33:  # < 30 FPS
            issues.append(f"⚠️  Low FPS detected: {1000 / frame_time:.1f} FPS")
        
        # LSP check
        lsp = data.get('lsp', {})
        if not lsp.get('connected', False):
            issues.append("⚠️  LSP not connected")
        pending = lsp.get('pendingRequests', 0)
        if pending > 10:
            issues.append(f"⚠️  LSP request backlog: {pending}")
        
        # Errors
        errs = data.get('errors', {})
        if errs.get('count', 0) > 0:
            issues.append(f"⚠️  {errs.get('count', 0)} errors detected")
        
        if not issues:
            issues.append("✅ All systems nominal")
        
        return issues
    
    def open_file(self, path: str) -> bool:
        """Open a file in the IDE."""
        print(f"📂 Opening file: {path}")
        if self.send_command("openFile", {"path": path}):
            time.sleep(0.5)
            response = self.read_response()
            if response and response.get('success'):
                print(f"✅ File opened successfully")
                return True
            else:
                print(f"❌ Failed to open file: {response.get('message', 'Unknown error')}")
        return False
    
    def goto_line(self, line: int) -> bool:
        """Navigate to a specific line."""
        print(f"➡️  Going to line: {line}")
        if self.send_command("gotoLine", {"line": str(line)}):
            time.sleep(0.3)
            response = self.read_response()
            return response and response.get('success')
        return False
    
    def request_completion(self, line: int, column: int) -> Optional[Dict]:
        """Request code completion at position."""
        print(f"🔮 Requesting completion at {line}:{column}")
        if self.send_command("requestCompletion", {"line": str(line), "column": str(column)}):
            time.sleep(1.0)  # LSP might take time
            response = self.read_response(timeout=3.0)
            return response
        return None


def main():
    parser = argparse.ArgumentParser(description='RawrXD AI Control Bridge Client')
    parser.add_argument('--working-dir', default='.', help='Working directory (default: current)')
    parser.add_argument('--monitor', action='store_true', help='Monitor telemetry continuously')
    parser.add_argument('--diagnose', action='store_true', help='Run diagnostics')
    parser.add_argument('--command', help='Send command (e.g., openFile, gotoLine)')
    parser.add_argument('--params', default='{}', help='Command parameters as JSON')
    parser.add_argument('--open', help='Open a file')
    parser.add_argument('--goto', type=int, help='Go to line number')
    
    args = parser.parse_args()
    
    client = RawrXDClient(args.working_dir)
    
    if args.monitor:
        client.monitor()
    
    elif args.diagnose:
        print("🔍 Running diagnostics...\n")
        issues = client.diagnose()
        for issue in issues:
            print(f"  {issue}")
    
    elif args.open:
        client.open_file(args.open)
    
    elif args.goto:
        client.goto_line(args.goto)
    
    elif args.command:
        params = json.loads(args.params)
        print(f"📤 Sending command: {args.command}")
        print(f"   Parameters: {params}")
        
        if client.send_command(args.command, params):
            print("✅ Command sent")
            response = client.read_response()
            if response:
                print(f"📥 Response: {json.dumps(response, indent=2)}")
        else:
            print("❌ Failed to send command")
    
    else:
        # Default: show current telemetry once
        data = client.read_telemetry()
        if data:
            client._display_telemetry(data)
        else:
            print("⏳ No telemetry available. Is RawrXD running?")
            print(f"   Looking for: {client.telemetry_path}")


if __name__ == "__main__":
    main()
