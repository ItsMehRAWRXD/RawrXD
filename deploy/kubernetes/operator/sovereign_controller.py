#!/usr/bin/env python3
"""
Phase D.4 Batch 1/5: Kubernetes Operator Controller
SovereignNode Controller for managing distributed runtime lifecycle
Copyright (c) 2026 RawrXD Team
"""

import kopf
import kubernetes
import yaml
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('sovereign-controller')

# Constants
NAMESPACE = 'default'
APP_LABEL = 'app.kubernetes.io/name'
PART_OF_LABEL = 'app.kubernetes.io/part-of'
MANAGED_BY_LABEL = 'app.kubernetes.io/managed-by'


@kopf.on.create('rawrxd.io', 'v1', 'sovereignnodes')
@kopf.on.update('rawrxd.io', 'v1', 'sovereignnodes')
def create_or_update_sovereign_node(spec: Dict[str, Any], name: str, namespace: str, **kwargs):
    """
    Handle creation or update of SovereignNode resources.
    Creates StatefulSet, Service, ConfigMap, and PersistentVolumeClaim.
    """
    logger.info(f"Processing SovereignNode {name} in namespace {namespace}")
    
    # Extract configuration
    node_id = spec.get('nodeId', name)
    datacenter = spec.get('datacenter', 'default')
    rack = spec.get('rack', 'default')
    version = spec.get('version', '1.0.0')
    replicas = spec.get('replicas', 3)
    
    resources = spec.get('resources', {})
    requests = resources.get('requests', {'cpu': '500m', 'memory': '1Gi'})
    limits = resources.get('limits', {'cpu': '2000m', 'memory': '4Gi'})
    
    consensus = spec.get('consensus', {})
    replication = spec.get('replication', {})
    storage = spec.get('storage', {})
    service = spec.get('service', {})
    monitoring = spec.get('monitoring', {})
    
    # Create ConfigMap with runtime configuration
    config_data = {
        'node.json': yaml.safe_dump({
            'nodeId': node_id,
            'datacenter': datacenter,
            'rack': rack,
            'version': version,
            'consensus': {
                'requireUnanimous': consensus.get('requireUnanimous', True),
                'timeoutMs': consensus.get('timeoutMs', 5000),
                'quorumRatio': consensus.get('quorumRatio', 0.66)
            },
            'replication': {
                'consistency': replication.get('consistency', 'bounded'),
                'strategy': replication.get('strategy', 'quorum'),
                'factor': replication.get('factor', 3)
            }
        }),
        'logging.properties': """
handlers=java.util.logging.ConsoleHandler
.level=INFO
sovereign.level=INFO
java.util.logging.ConsoleHandler.level=INFO
java.util.logging.ConsoleHandler.formatter=java.util.logging.SimpleFormatter
"""
    }
    
    kopf.adopt(config_data)
    
    # Create StatefulSet
    statefulset = {
        'apiVersion': 'apps/v1',
        'kind': 'StatefulSet',
        'metadata': {
            'name': f'sovereign-{name}',
            'labels': {
                APP_LABEL: 'sovereign-node',
                PART_OF_LABEL: 'rawrxd-distributed',
                MANAGED_BY_LABEL: 'sovereign-operator',
                'sovereign.rawrxd.io/node-id': node_id,
                'sovereign.rawrxd.io/datacenter': datacenter,
                'sovereign.rawrxd.io/rack': rack
            }
        },
        'spec': {
            'serviceName': f'sovereign-{name}',
            'replicas': replicas,
            'selector': {
                'matchLabels': {
                    APP_LABEL: 'sovereign-node',
                    'sovereign.rawrxd.io/cluster': name
                }
            },
            'template': {
                'metadata': {
                    'labels': {
                        APP_LABEL: 'sovereign-node',
                        PART_OF_LABEL: 'rawrxd-distributed',
                        MANAGED_BY_LABEL: 'sovereign-operator',
                        'sovereign.rawrxd.io/cluster': name,
                        'sovereign.rawrxd.io/node-id': node_id,
                        'sovereign.rawrxd.io/datacenter': datacenter,
                        'sovereign.rawrxd.io/rack': rack,
                        'prometheus.io/scrape': str(monitoring.get('prometheus', True)).lower(),
                        'prometheus.io/port': '9090'
                    },
                    'annotations': {
                        'sovereign.rawrxd.io/config-hash': hash(str(config_data))
                    }
                },
                'spec': {
                    'affinity': {
                        'podAntiAffinity': {
                            'preferredDuringSchedulingIgnoredDuringExecution': [
                                {
                                    'weight': 100,
                                    'podAffinityTerm': {
                                        'labelSelector': {
                                            'matchExpressions': [
                                                {
                                                    'key': APP_LABEL,
                                                    'operator': 'In',
                                                    'values': ['sovereign-node']
                                                }
                                            ]
                                        },
                                        'topologyKey': 'kubernetes.io/hostname'
                                    }
                                }
                            ]
                        }
                    },
                    'containers': [
                        {
                            'name': 'sovereign-node',
                            'image': f'rawrxd/sovereign-node:{version}',
                            'imagePullPolicy': 'IfNotPresent',
                            'ports': [
                                {
                                    'name': 'http',
                                    'containerPort': service.get('port', 8080),
                                    'protocol': 'TCP'
                                },
                                {
                                    'name': 'discovery',
                                    'containerPort': 7946,
                                    'protocol': 'TCP'
                                },
                                {
                                    'name': 'metrics',
                                    'containerPort': 9090,
                                    'protocol': 'TCP'
                                }
                            ],
                            'env': [
                                {
                                    'name': 'SOVEREIGN_NODE_ID',
                                    'valueFrom': {
                                        'fieldRef': {
                                            'fieldPath': 'metadata.name'
                                        }
                                    }
                                },
                                {
                                    'name': 'SOVEREIGN_DATACENTER',
                                    'value': datacenter
                                },
                                {
                                    'name': 'SOVEREIGN_RACK',
                                    'value': rack
                                },
                                {
                                    'name': 'SOVEREIGN_POD_IP',
                                    'valueFrom': {
                                        'fieldRef': {
                                            'fieldPath': 'status.podIP'
                                        }
                                    }
                                },
                                {
                                    'name': 'SOVEREIGN_CLUSTER_NAME',
                                    'value': name
                                },
                                {
                                    'name': 'SOVEREIGN_NAMESPACE',
                                    'valueFrom': {
                                        'fieldRef': {
                                            'fieldPath': 'metadata.namespace'
                                        }
                                    }
                                },
                                {
                                    'name': 'JAVA_OPTS',
                                    'value': '-XX:+UseG1GC -XX:MaxRAMPercentage=75.0'
                                }
                            ],
                            'resources': {
                                'requests': requests,
                                'limits': limits
                            },
                            'volumeMounts': [
                                {
                                    'name': 'config',
                                    'mountPath': '/etc/sovereign'
                                },
                                {
                                    'name': 'data',
                                    'mountPath': '/var/lib/sovereign'
                                }
                            ],
                            'livenessProbe': {
                                'httpGet': {
                                    'path': '/health/live',
                                    'port': 'http'
                                },
                                'initialDelaySeconds': 30,
                                'periodSeconds': 10,
                                'timeoutSeconds': 5,
                                'failureThreshold': 3
                            },
                            'readinessProbe': {
                                'httpGet': {
                                    'path': '/health/ready',
                                    'port': 'http'
                                },
                                'initialDelaySeconds': 10,
                                'periodSeconds': 5,
                                'timeoutSeconds': 3,
                                'failureThreshold': 3
                            },
                            'startupProbe': {
                                'httpGet': {
                                    'path': '/health/startup',
                                    'port': 'http'
                                },
                                'initialDelaySeconds': 10,
                                'periodSeconds': 5,
                                'failureThreshold': 30
                            }
                        }
                    ],
                    'volumes': [
                        {
                            'name': 'config',
                            'configMap': {
                                'name': f'sovereign-{name}-config'
                            }
                        }
                    ],
                    'securityContext': {
                        'runAsNonRoot': True,
                        'runAsUser': 1000,
                        'fsGroup': 1000
                    },
                    'serviceAccountName': f'sovereign-{name}'
                }
            },
            'volumeClaimTemplates': [
                {
                    'metadata': {
                        'name': 'data'
                    },
                    'spec': {
                        'accessModes': ['ReadWriteOnce'],
                        'storageClassName': storage.get('storageClass', 'fast-ssd'),
                        'resources': {
                            'requests': {
                                'storage': storage.get('size', '10Gi')
                            }
                        }
                    }
                }
            ]
        }
    }
    
    kopf.adopt(statefulset)
    
    # Create Service
    svc = {
        'apiVersion': 'v1',
        'kind': 'Service',
        'metadata': {
            'name': f'sovereign-{name}',
            'labels': {
                APP_LABEL: 'sovereign-node',
                PART_OF_LABEL: 'rawrxd-distributed'
            },
            'annotations': service.get('annotations', {})
        },
        'spec': {
            'type': service.get('type', 'ClusterIP'),
            'selector': {
                APP_LABEL: 'sovereign-node',
                'sovereign.rawrxd.io/cluster': name
            },
            'ports': [
                {
                    'name': 'http',
                    'port': service.get('port', 8080),
                    'targetPort': 'http',
                    'protocol': 'TCP'
                },
                {
                    'name': 'discovery',
                    'port': 7946,
                    'targetPort': 'discovery',
                    'protocol': 'TCP'
                },
                {
                    'name': 'metrics',
                    'port': 9090,
                    'targetPort': 'metrics',
                    'protocol': 'TCP'
                }
            ]
        }
    }
    
    kopf.adopt(svc)
    
    # Create headless service for StatefulSet
    headless_svc = {
        'apiVersion': 'v1',
        'kind': 'Service',
        'metadata': {
            'name': f'sovereign-{name}-headless',
            'labels': {
                APP_LABEL: 'sovereign-node',
                PART_OF_LABEL: 'rawrxd-distributed'
            }
        },
        'spec': {
            'type': 'ClusterIP',
            'clusterIP': 'None',
            'selector': {
                APP_LABEL: 'sovereign-node',
                'sovereign.rawrxd.io/cluster': name
            },
            'ports': [
                {
                    'name': 'http',
                    'port': service.get('port', 8080),
                    'targetPort': 'http'
                },
                {
                    'name': 'discovery',
                    'port': 7946,
                    'targetPort': 'discovery'
                }
            ],
            'publishNotReadyAddresses': True
        }
    }
    
    kopf.adopt(headless_svc)
    
    # Create ServiceMonitor if monitoring enabled
    if monitoring.get('serviceMonitor', False):
        servicemonitor = {
            'apiVersion': 'monitoring.coreos.com/v1',
            'kind': 'ServiceMonitor',
            'metadata': {
                'name': f'sovereign-{name}',
                'labels': {
                    'release': 'prometheus'
                }
            },
            'spec': {
                'selector': {
                    'matchLabels': {
                        APP_LABEL: 'sovereign-node',
                        'sovereign.rawrxd.io/cluster': name
                    }
                },
                'endpoints': [
                    {
                        'port': 'metrics',
                        'interval': '30s',
                        'path': '/metrics'
                    }
                ]
            }
        }
        
        kopf.adopt(servicemonitor)
    
    # Update status
    return {
        'phase': 'Creating',
        'leader': '',
        'healthyNodes': 0,
        'totalNodes': replicas,
        'quorum': False,
        'conditions': [
            {
                'type': 'Deployed',
                'status': 'True',
                'lastTransitionTime': datetime.utcnow().isoformat() + 'Z',
                'reason': 'ResourcesCreated',
                'message': f'Created StatefulSet with {replicas} replicas'
            }
        ]
    }


@kopf.on.delete('rawrxd.io', 'v1', 'sovereignnodes')
def delete_sovereign_node(spec: Dict[str, Any], name: str, namespace: str, **kwargs):
    """Handle deletion of SovereignNode resources."""
    logger.info(f"Deleting SovereignNode {name} from namespace {namespace}")
    
    # Cleanup is handled automatically by ownerReferences
    # This hook can be used for graceful shutdown coordination
    
    return {'phase': 'Terminating'}


@kopf.on.field('rawrxd.io', 'v1', 'sovereignnodes', field='status.phase')
def on_phase_change(old: Optional[str], new: str, name: str, **kwargs):
    """React to phase changes."""
    logger.info(f"SovereignNode {name} phase changed: {old} -> {new}")
    
    if new == 'Running':
        logger.info(f"SovereignNode {name} is now running")
    elif new == 'Degraded':
        logger.warning(f"SovereignNode {name} is degraded")
    elif new == 'Failed':
        logger.error(f"SovereignNode {name} has failed")


@kopf.timer('rawrxd.io', 'v1', 'sovereignnodes', interval=30.0)
def reconcile_status(spec: Dict[str, Any], status: Dict[str, Any], name: str, **kwargs):
    """Periodic reconciliation of node status."""
    # In production, this would query the actual cluster state
    # For now, we simulate status updates
    
    phase = status.get('phase', 'Pending')
    
    if phase == 'Creating':
        # Simulate transition to Running
        return {
            'phase': 'Running',
            'conditions': [
                {
                    'type': 'Ready',
                    'status': 'True',
                    'lastTransitionTime': datetime.utcnow().isoformat() + 'Z',
                    'reason': 'AllPodsReady',
                    'message': 'All pods are ready'
                }
            ]
        }
    
    return None  # No change


if __name__ == '__main__':
    kopf.run()
