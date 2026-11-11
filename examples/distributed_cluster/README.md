# Distributed Cluster Example

Demonstrates RawrXD's distributed inference capabilities with automatic node discovery and load balancing.

## Features

- **Automatic Node Discovery**: Nodes automatically discover each other via multicast/unicast
- **Load Balancing**: Tasks distributed across available nodes
- **Fault Tolerance**: Automatic failover for failed nodes
- **Heartbeat Monitoring**: Health checks every 5 seconds

## Building

```bash
cd examples/distributed_cluster
mkdir build && cd build
cmake ..
cmake --build .
```

## Running

### Start Coordinator Node

```bash
./distributed_cluster_example coordinator
```

### Start Worker Nodes

```bash
# On machine 2
./distributed_cluster_example node-2 coordinator:7945

# On machine 3
./distributed_cluster_example node-3 coordinator:7945
```

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Coordinator   │◄────│    Worker 1     │     │    Worker 2     │
│   (node-1)      │     │   (node-2)      │     │   (node-3)      │
│                 │     │                 │     │                 │
│ - Discovery     │     │ - Task Execution│     │ - Task Execution│
│ - Load Balancer │     │ - Heartbeat     │     │ - Heartbeat     │
│ - Health Monitor│     │ - Status Report │     │ - Status Report │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

## API Usage

```cpp
// Initialize cluster manager
auto clusterManager = runtime->GetClusterManager();

// Configure cluster
ClusterConfig config;
config.nodeId = "node-1";
config.isCoordinator = true;
config.discoveryPort = 7945;

// Start cluster
clusterManager->Initialize(config);
clusterManager->Start();

// Monitor status
auto status = clusterManager->GetStatus();
std::cout << "Active nodes: " << status.activeNodes << std::endl;
```

## Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `discoveryPort` | 7945 | UDP port for node discovery |
| `heartbeatInterval` | 5s | Health check interval |
| `failureTimeout` | 30s | Node failure detection timeout |
| `loadBalanceStrategy` | "round-robin" | Task distribution strategy |

## See Also

- [API Reference](../../include/rawrxd/distributed/)
- [Architecture Guide](../../docs/Architecture.md#distributed-inference)
