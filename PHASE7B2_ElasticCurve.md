# RawRamXD Phase 7B.2: Elastic Residency Validation

## Overview

Phase 7B.2 validates the **TPS collapse → Residency cost model** by running a controlled pressure sweep from 100% to 140% VRAM capacity.

## Pressure Sweep

```
VRAM Residency Pressure
100% ───────────── native VRAM (baseline)
110% ───────────── first spill
120% ───────────── sustained migration
130% ───────────── RAM-backed execution
140% ───────────── NVMe involvement
```

## Telemetry Sources

| Metric | Source | API |
|--------|--------|-----|
| Token/sec | Inference loop | Measured |
| Migration count | RawRamXD scheduler | `GetStats()` |
| Migration bandwidth | Copy engine | Calculated |
| VRAM budget | DXGI | `DXGI_QUERY_VIDEO_MEMORY_INFO` |
| RAM residency | OS | `QueryWorkingSetEx` |
| NVMe queue depth | Storage telemetry | Tracked |
| Scheduler decisions | Policy trace | Logged |

## Expected Output

### CSV: `rawramxd_elastic_curve.csv`

```csv
pressure,tps,latency_ms,vram_gb,ram_gb,nvme_gb,migrations,degradation_factor
1.00,xxx,xx,x,x,x,0,1.00
1.10,xxx,xx,x,x,x,n,0.95
1.20,xxx,xx,x,x,x,n,0.85
1.30,xxx,xx,x,x,x,n,0.70
1.40,xxx,xx,x,x,x,n,0.55
```

### Acceptance Criteria

1. **Native VRAM**: Baseline TPS established
2. **RAM Spill**: Graceful degradation (< 20% TPS loss)
3. **NVMe Spill**: Predictable degradation (< 50% TPS loss)
4. **No Crashes**: All pressure points complete successfully

## Running

```batch
cd d:\rawrxd
Build-Phase7B2-ElasticCurve.bat
```

## Success Metrics

| Pressure | Expected TPS | Expected Latency | Status |
|----------|--------------|------------------|--------|
| 100% | 100% baseline | ~10ms | ✅ Native |
| 110% | ~95% | ~12ms | ✅ Graceful |
| 120% | ~85% | ~15ms | ✅ Acceptable |
| 130% | ~70% | ~20ms | ✅ Degraded |
| 140% | ~55% | ~25ms | ✅ Predictable |

## Next Phase

**Phase 7C: Fabric Intelligence**

```
Telemetry
    ↓
Pressure prediction
    ↓
Tensor hotness model
    ↓
Prefetch before demand
    ↓
Autonomous residency optimization
```

RawRamXD transitions from migration system to memory scheduler.
