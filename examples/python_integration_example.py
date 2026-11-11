#!/usr/bin/env python3
"""
Sovereign Substrate - Python Integration Example
Shows how to integrate the Sovereign Substrate from Python applications
"""

import json
import subprocess
import asyncio
import aiohttp
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass
from enum import Enum


class ToolStatus(Enum):
    """Tool execution status"""
    SUCCESS = "success"
    FAILURE = "failure"
    INVALID_PARAMS = "invalid_params"
    PERMISSION_DENIED = "permission_denied"
    TIMEOUT = "timeout"


@dataclass
class ToolResult:
    """Result of tool execution"""
    status: ToolStatus
    output: str = ""
    error_message: str = ""
    execution_time_ms: int = 0


@dataclass
class IntentResult:
    """Result of intent execution"""
    success: bool
    message: str
    data: Dict[str, Any] = None
    execution_time_ms: int = 0


class SovereignSubstrate:
    """
    Python interface to the Sovereign Substrate
    
    This class provides a high-level Python API for interacting with
    the Sovereign Substrate autonomous agent system.
    """
    
    def __init__(self, base_url: str = "http://localhost:8080"):
        self.base_url = base_url
        self.session: Optional[aiohttp.ClientSession] = None
        self._event_handlers: Dict[str, List[Callable]] = {}
        
    async def __aenter__(self):
        """Async context manager entry"""
        await self.connect()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.disconnect()
        
    async def connect(self):
        """Connect to the Sovereign Substrate"""
        self.session = aiohttp.ClientSession()
        
        # Verify connection
        try:
            status = await self.get_status()
            print(f"✓ Connected to Sovereign Substrate v{status.get('version', 'unknown')}")
        except Exception as e:
            await self.disconnect()
            raise ConnectionError(f"Failed to connect: {e}")
            
    async def disconnect(self):
        """Disconnect from the Sovereign Substrate"""
        if self.session:
            await self.session.close()
            self.session = None
            print("✓ Disconnected from Sovereign Substrate")
            
    async def _request(self, method: str, endpoint: str, data: Dict = None) -> Dict:
        """Make HTTP request to the API"""
        if not self.session:
            raise RuntimeError("Not connected")
            
        url = f"{self.base_url}{endpoint}"
        
        try:
            async with self.session.request(method, url, json=data) as response:
                response.raise_for_status()
                return await response.json()
        except aiohttp.ClientError as e:
            raise ConnectionError(f"Request failed: {e}")
            
    # System Status
    
    async def get_status(self) -> Dict[str, Any]:
        """Get system status"""
        return await self._request("GET", "/api/v1/status")
        
    async def get_health(self) -> Dict[str, Any]:
        """Get health check"""
        return await self._request("GET", "/health")
        
    # Intent Execution
    
    async def execute_intent(self, action: str, params: Dict[str, Any] = None) -> IntentResult:
        """
        Execute an intent through the Sovereign Substrate
        
        Args:
            action: The intent action to execute
            params: Parameters for the intent
            
        Returns:
            IntentResult with success status and data
        """
        data = {
            "action": action,
            "params": params or {}
        }
        
        result = await self._request("POST", "/api/v1/intents/execute", data)
        
        return IntentResult(
            success=result.get("success", False),
            message=result.get("message", ""),
            data=result.get("data"),
            execution_time_ms=result.get("execution_time_ms", 0)
        )
        
    async def validate_intent(self, action: str, params: Dict[str, Any] = None) -> bool:
        """
        Validate an intent without executing it
        
        Args:
            action: The intent action to validate
            params: Parameters for the intent
            
        Returns:
            True if intent is valid
        """
        data = {
            "action": action,
            "params": params or {}
        }
        
        result = await self._request("POST", "/api/v1/intents/validate", data)
        return result.get("valid", False)
        
    # Tool Execution
    
    async def execute_tool(self, tool_name: str, params: Dict[str, Any] = None) -> ToolResult:
        """
        Execute a tool through the Sovereign Substrate
        
        Args:
            tool_name: Name of the tool to execute
            params: Parameters for the tool
            
        Returns:
            ToolResult with execution status and output
        """
        data = {
            "tool_name": tool_name,
            "params": params or {}
        }
        
        result = await self._request("POST", "/api/v1/tools/execute", data)
        
        return ToolResult(
            status=ToolStatus(result.get("status", "failure")),
            output=result.get("output", ""),
            error_message=result.get("error_message", ""),
            execution_time_ms=result.get("execution_time_ms", 0)
        )
        
    async def list_tools(self) -> List[Dict[str, Any]]:
        """List available tools"""
        result = await self._request("GET", "/api/v1/tools")
        return result.get("tools", [])
        
    # File System Tools
    
    async def read_file(self, file_path: str) -> str:
        """Read a file"""
        result = await self.execute_tool("read_file", {"file_path": file_path})
        if result.status == ToolStatus.SUCCESS:
            return result.output
        raise IOError(f"Failed to read file: {result.error_message}")
        
    async def write_file(self, file_path: str, content: str) -> None:
        """Write a file"""
        result = await self.execute_tool("write_file", {
            "file_path": file_path,
            "content": content
        })
        if result.status != ToolStatus.SUCCESS:
            raise IOError(f"Failed to write file: {result.error_message}")
            
    async def search_files(self, pattern: str, path: str = ".") -> List[str]:
        """Search for files matching pattern"""
        result = await self.execute_tool("search_files", {
            "pattern": pattern,
            "path": path
        })
        if result.status == ToolStatus.SUCCESS:
            return json.loads(result.output)
        return []
        
    # Git Tools
    
    async def git_status(self, repo_path: str = ".") -> str:
        """Get git status"""
        result = await self.execute_tool("git_status", {"repo_path": repo_path})
        if result.status == ToolStatus.SUCCESS:
            return result.output
        raise RuntimeError(f"Git status failed: {result.error_message}")
        
    async def git_diff(self, repo_path: str = ".", commit: str = None) -> str:
        """Get git diff"""
        params = {"repo_path": repo_path}
        if commit:
            params["commit"] = commit
        result = await self.execute_tool("git_diff", params)
        if result.status == ToolStatus.SUCCESS:
            return result.output
        raise RuntimeError(f"Git diff failed: {result.error_message}")
        
    # Repository Memory
    
    async def get_memory_graph(self) -> Dict[str, Any]:
        """Get the repository memory graph"""
        return await self._request("GET", "/api/v1/memory/graph")
        
    async def query_memory(self, query: str) -> List[Dict[str, Any]]:
        """Query the memory graph"""
        result = await self._request("POST", "/api/v1/memory/query", {"query": query})
        return result.get("results", [])
        
    async def save_memory(self, path: str = "project.graph") -> None:
        """Save memory graph to disk"""
        await self._request("POST", "/api/v1/memory/save", {"path": path})
        
    async def load_memory(self, path: str = "project.graph") -> None:
        """Load memory graph from disk"""
        await self._request("POST", "/api/v1/memory/load", {"path": path})
        
    # Telemetry
    
    async def get_telemetry(self, since: str = None) -> Dict[str, Any]:
        """Get telemetry data"""
        params = {}
        if since:
            params["since"] = since
        return await self._request("GET", "/api/v1/telemetry", params)
        
    async def get_metrics(self) -> Dict[str, Any]:
        """Get system metrics"""
        return await self._request("GET", "/metrics")
        
    # Security
    
    async def validate_path(self, path: str) -> bool:
        """Validate a file path for security"""
        result = await self._request("POST", "/api/v1/security/validate_path", {"path": path})
        return result.get("valid", False)
        
    async def check_permission(self, action: str, resource: str) -> bool:
        """Check if action is permitted on resource"""
        result = await self._request("POST", "/api/v1/security/check_permission", {
            "action": action,
            "resource": resource
        })
        return result.get("permitted", False)


# Example usage
async def main():
    """Example usage of the Sovereign Substrate Python client"""
    
    async with SovereignSubstrate("http://localhost:8080") as substrate:
        # Get system status
        status = await substrate.get_status()
        print(f"System Status: {json.dumps(status, indent=2)}")
        
        # List available tools
        tools = await substrate.list_tools()
        print(f"\nAvailable Tools ({len(tools)}):")
        for tool in tools:
            print(f"  - {tool['name']}: {tool['description']}")
            
        # Execute a tool
        print("\n=== Executing Tool ===")
        result = await substrate.read_file("README.md")
        print(f"File content:\n{result[:500]}...")
        
        # Execute an intent
        print("\n=== Executing Intent ===")
        intent_result = await substrate.execute_intent("analyze_code", {
            "target": "src/main.cpp"
        })
        print(f"Intent Result: {intent_result.success}")
        print(f"Message: {intent_result.message}")
        
        # Query memory graph
        print("\n=== Querying Memory ===")
        results = await substrate.query_memory("functions in main")
        print(f"Found {len(results)} results")
        for result in results[:5]:
            print(f"  - {result.get('name', 'unknown')}")
            
        # Get telemetry
        print("\n=== Telemetry ===")
        telemetry = await substrate.get_telemetry()
        print(f"Telemetry entries: {len(telemetry.get('events', []))}")


if __name__ == "__main__":
    asyncio.run(main())
