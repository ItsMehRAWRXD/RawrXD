# swarm.py
# Python bindings for Phase 23 Distributed Swarm
# Network-aware orchestration for heterogeneous compute clusters
#
# Version: 1.0.0-Draft
# Date: 2026-06-30

"""
RawrXD Distributed Swarm - Python Interface

Example usage:
    from swarm import DistributedSwarm, NodeConfig, ShardingStrategy
    
    # Create swarm
    swarm = DistributedSwarm("my-swarm", replication_factor=2)
    
    # Add nodes
    swarm.join(NodeConfig(
        node_id="node-1",
        address="10.0.0.1:8080",
        context_capacity=8192,
        hardware="AMX"
    ))
    
    # Run distributed inference
    with swarm.session(max_tokens=100) as sess:
        response = sess.generate("Hello, world!")
        print(f"Generated {len(response)} tokens")
    
    # Get stats
    stats = swarm.get_stats()
    print(f"Aggregate TPS: {stats.aggregate_tps}")
"""

import ctypes
import os
import sys
import time
import threading
from typing import List, Dict, Optional, Callable, Tuple, Any
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("swarm")


# =============================================================================
# Enums
# =============================================================================

class SwarmError(IntEnum):
    """Error codes from C API"""
    OK = 0
    NETWORK = -1
    NODE_UNAVAILABLE = -2
    TIMEOUT = -3
    INVALID_CONTEXT = -4
    SHARDING_FAILED = -5
    MEMORY = -6
    AUTHENTICATION = -7
    QUOTA_EXCEEDED = -8
    RING_BROKEN = -9
    PARTITION = -10


class HardwareType(IntEnum):
    """Hardware acceleration types"""
    CPU_GENERIC = 1
    CPU_AVX2 = 2
    CPU_AVX512 = 3
    AMX_TILE = 4
    GPU_CUDA = 5
    GPU_VULKAN = 6
    NPU = 7
    REMOTE = 8


class NodeStatus(IntEnum):
    """Node health status"""
    HEALTHY = 0
    DEGRADED = 1
    OVERLOADED = 2
    SUSPECTED = 3
    FAILED = 4


class ShardingStrategy(IntEnum):
    """Context distribution strategies"""
    RING = 0
    SLIDING_WINDOW = 1
    BLOCK = 2
    HASH = 3


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class SwarmAddress:
    """Network address for nodes"""
    host: str
    port: int
    use_tls: bool = True
    
    def __str__(self):
        return f"{self.host}:{self.port}"


@dataclass
class NodeConfig:
    """Node configuration"""
    node_id: str
    address: SwarmAddress
    context_capacity: int = 8192
    hardware: str = "AMX_TILE"
    priority: int = 0
    replication_factor: int = 2


@dataclass
class NodeStats:
    """Real-time node statistics"""
    status: NodeStatus
    current_tps: float
    latency_p50_ms: float
    latency_p99_ms: float
    memory_usage_percent: int
    active_sessions: int
    tokens_processed_total: int
    bytes_received: int
    bytes_sent: int
    phi_score: float


@dataclass
class SwarmStats:
    """Aggregate swarm statistics"""
    total_nodes: int
    healthy_nodes: int
    degraded_nodes: int
    suspected_nodes: int
    failed_nodes: int
    aggregate_tps: float
    average_latency_ms: float
    total_tokens_processed: int
    total_sessions: int
    active_shards: int


@dataclass
class ShardInfo:
    """Context shard information"""
    shard_id: int
    start_token: int
    end_token: int
    primary_node: str
    replica_nodes: List[str]
    last_access_time: float
    access_count: int


@dataclass
class SessionConfig:
    """Inference session configuration"""
    session_id: Optional[str] = None
    max_context_tokens: int = 32768
    temperature: float = 0.7
    top_k: int = 40
    top_p: float = 0.9
    stream_output: bool = False


# =============================================================================
# Exceptions
# =============================================================================

class SwarmException(Exception):
    """Base exception for Swarm errors"""
    def __init__(self, error_code: SwarmError, message: str):
        self.error_code = error_code
        self.message = message
        super().__init__(f"[{error_code.name}] {message}")


class NodeUnavailableException(SwarmException):
    """Raised when a node is not available"""
    pass


class TimeoutException(SwarmException):
    """Raised when operation times out"""
    pass


# =============================================================================
# Distributed Swarm Class
# =============================================================================

class DistributedSwarm:
    """
    Python interface to Phase 23 Distributed Swarm
    
    Manages a cluster of inference nodes with automatic:
    - Context sharding (Ring Attention)
    - Fault tolerance (Phi accrual detection)
    - Load balancing (cost-model based routing)
    - Telemetry and monitoring
    """
    
    def __init__(self, swarm_id: str, replication_factor: int = 2,
                 sharding: ShardingStrategy = ShardingStrategy.RING,
                 heartbeat_interval_ms: int = 100,
                 phi_threshold: float = 8.0):
        """
        Initialize distributed swarm
        
        Args:
            swarm_id: Unique identifier for this swarm
            replication_factor: Number of copies per shard
            sharding: Context distribution strategy
            heartbeat_interval_ms: Heartbeat frequency
            phi_threshold: Failure detection sensitivity (higher = less sensitive)
        """
        self.swarm_id = swarm_id
        self.replication_factor = replication_factor
        self.sharding = sharding
        self.heartbeat_interval_ms = heartbeat_interval_ms
        self.phi_threshold = phi_threshold
        
        self._nodes: Dict[str, NodeConfig] = {}
        self._node_stats: Dict[str, NodeStats] = {}
        self._shards: Dict[int, ShardInfo] = {}
        self._sessions: Dict[str, Any] = {}
        
        self._running = False
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._lock = threading.RLock()
        
        # Callbacks
        self._status_callbacks: List[Callable] = []
        self._heartbeat_callbacks: List[Callable] = []
        
        logger.info(f"Swarm '{swarm_id}' initialized")
    
    def join(self, node: NodeConfig) -> bool:
        """
        Add a node to the swarm
        
        Args:
            node: Node configuration
            
        Returns:
            True if successful
            
        Raises:
            SwarmException: If node cannot be added
        """
        with self._lock:
            if node.node_id in self._nodes:
                raise SwarmException(
                    SwarmError.INVALID_CONTEXT,
                    f"Node {node.node_id} already exists"
                )
            
            self._nodes[node.node_id] = node
            self._node_stats[node.node_id] = NodeStats(
                status=NodeStatus.HEALTHY,
                current_tps=0.0,
                latency_p50_ms=0.0,
                latency_p99_ms=0.0,
                memory_usage_percent=0,
                active_sessions=0,
                tokens_processed_total=0,
                bytes_received=0,
                bytes_sent=0,
                phi_score=0.0
            )
            
            logger.info(f"Node {node.node_id} joined swarm")
            return True
    
    def leave(self, node_id: str) -> bool:
        """
        Remove a node from the swarm
        
        Args:
            node_id: Node to remove
            
        Returns:
            True if successful
        """
        with self._lock:
            if node_id not in self._nodes:
                return False
            
            del self._nodes[node_id]
            del self._node_stats[node_id]
            
            logger.info(f"Node {node_id} left swarm")
            return True
    
    def get_node(self, node_id: str) -> Optional[NodeConfig]:
        """Get node configuration by ID"""
        return self._nodes.get(node_id)
    
    def get_node_stats(self, node_id: str) -> Optional[NodeStats]:
        """Get node statistics"""
        return self._node_stats.get(node_id)
    
    def list_nodes(self) -> List[str]:
        """List all node IDs"""
        return list(self._nodes.keys())
    
    def get_stats(self) -> SwarmStats:
        """
        Get aggregate swarm statistics
        
        Returns:
            SwarmStats with current metrics
        """
        with self._lock:
            total = len(self._nodes)
            healthy = sum(1 for s in self._node_stats.values() if s.status == NodeStatus.HEALTHY)
            degraded = sum(1 for s in self._node_stats.values() if s.status == NodeStatus.DEGRADED)
            suspected = sum(1 for s in self._node_stats.values() if s.status == NodeStatus.SUSPECTED)
            failed = sum(1 for s in self._node_stats.values() if s.status == NodeStatus.FAILED)
            
            aggregate_tps = sum(s.current_tps for s in self._node_stats.values())
            avg_latency = sum(s.latency_p99_ms for s in self._node_stats.values()) / max(total, 1)
            total_tokens = sum(s.tokens_processed_total for s in self._node_stats.values())
            
            return SwarmStats(
                total_nodes=total,
                healthy_nodes=healthy,
                degraded_nodes=degraded,
                suspected_nodes=suspected,
                failed_nodes=failed,
                aggregate_tps=aggregate_tps,
                average_latency_ms=avg_latency,
                total_tokens_processed=total_tokens,
                total_sessions=len(self._sessions),
                active_shards=len(self._shards)
            )
    
    def session(self, **kwargs) -> 'SwarmSession':
        """
        Create inference session
        
        Usage:
            with swarm.session(max_tokens=100) as sess:
                result = sess.generate("Hello")
        
        Returns:
            SwarmSession context manager
        """
        config = SessionConfig(**kwargs)
        return SwarmSession(self, config)
    
    def start(self) -> None:
        """Start swarm services (heartbeat, monitoring)"""
        if self._running:
            return
        
        self._running = True
        self._heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self._heartbeat_thread.start()
        
        logger.info(f"Swarm '{self.swarm_id}' started")
    
    def stop(self) -> None:
        """Stop swarm services"""
        self._running = False
        if self._heartbeat_thread:
            self._heartbeat_thread.join(timeout=5.0)
        
        logger.info(f"Swarm '{self.swarm_id}' stopped")
    
    def _heartbeat_loop(self) -> None:
        """Background heartbeat monitoring"""
        while self._running:
            try:
                self._check_node_health()
                time.sleep(self.heartbeat_interval_ms / 1000.0)
            except Exception as e:
                logger.error(f"Heartbeat error: {e}")
    
    def _check_node_health(self) -> None:
        """Check node health using Phi accrual"""
        # Simplified: In real implementation, would calculate phi from actual heartbeats
        pass
    
    def __enter__(self):
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()


# =============================================================================
# Swarm Session
# =============================================================================

class SwarmSession:
    """
    Inference session within distributed swarm
    
    Manages:
    - Context window across shards
    - Token generation
    - Session lifecycle
    """
    
    def __init__(self, swarm: DistributedSwarm, config: SessionConfig):
        self.swarm = swarm
        self.config = config
        self.session_id = config.session_id or f"sess_{time.time_ns()}"
        self._tokens_used = 0
        self._active = False
    
    def generate(self, prompt: str, max_tokens: Optional[int] = None) -> str:
        """
        Generate text from prompt
        
        Args:
            prompt: Input text
            max_tokens: Maximum tokens to generate (overrides config)
            
        Returns:
            Generated text
        """
        if not self._active:
            raise SwarmException(SwarmError.INVALID_CONTEXT, "Session not active")
        
        max_tok = max_tokens or self.config.max_context_tokens
        
        # Simplified: In real implementation, would:
        # 1. Tokenize prompt
        # 2. Route to optimal node(s)
        # 3. Run distributed inference
        # 4. Detokenize result
        
        logger.info(f"Generating up to {max_tok} tokens")
        
        # Placeholder: Return simulated response
        return f"[Generated {max_tok} tokens for: {prompt[:50]}...]"
    
    def __enter__(self):
        self._active = True
        logger.info(f"Session {self.session_id} started")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self._active = False
        logger.info(f"Session {self.session_id} ended")


# =============================================================================
# Utility Functions
# =============================================================================

def calculate_phi(last_heartbeat_ms: float, mean_interval_ms: float,
                   variance_ms: float) -> float:
    """
    Calculate Phi accrual score for failure detection
    
    Phi = -log10(probability node is still alive)
    
    Higher phi = more likely node has failed
    
    Args:
        last_heartbeat_ms: Milliseconds since last heartbeat
        mean_interval_ms: Historical mean heartbeat interval
        variance_ms: Historical variance
        
    Returns:
        Phi score (typically 0-16)
    """
    import math
    
    if variance_ms == 0:
        variance_ms = 1.0  # Avoid division by zero
    
    # Phi accrual formula
    delta = last_heartbeat_ms - mean_interval_ms
    phi = -math.log10(math.exp(-delta / variance_ms))
    
    return max(0.0, phi)


def quick_test():
    """Quick test of Distributed Swarm"""
    print("=" * 60)
    print("RawrXD Distributed Swarm - Quick Test")
    print("=" * 60)
    
    # Create swarm
    with DistributedSwarm("test-swarm", replication_factor=2) as swarm:
        print(f"✅ Swarm '{swarm.swarm_id}' created")
        
        # Add nodes
        for i in range(3):
            node = NodeConfig(
                node_id=f"node-{i+1}",
                address=SwarmAddress(f"10.0.0.{i+1}", 8080 + i),
                context_capacity=8192,
                hardware="AMX_TILE",
                priority=i
            )
            swarm.join(node)
            print(f"✅ Node {node.node_id} joined")
        
        # Get stats
        stats = swarm.get_stats()
        print(f"\n📊 Swarm Statistics:")
        print(f"   Total Nodes: {stats.total_nodes}")
        print(f"   Healthy: {stats.healthy_nodes}")
        print(f"   Aggregate TPS: {stats.aggregate_tps:.1f}")
        
        # Create session and generate
        with swarm.session(max_context_tokens=32768, temperature=0.7) as sess:
            print(f"\n📝 Session {sess.session_id} created")
            
            response = sess.generate("Hello, world!", max_tokens=50)
            print(f"   Response: {response}")
        
        print(f"\n✅ Test complete!")
    
    print("=" * 60)


if __name__ == "__main__":
    quick_test()