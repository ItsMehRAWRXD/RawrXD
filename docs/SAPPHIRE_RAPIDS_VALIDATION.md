# Sapphire Rapids Validation Quick Reference

## Pre-Flight Checklist

- [ ] Binary `Sovereign_v1.2_INT8.exe` built and available
- [ ] Test node has Sapphire Rapids CPU (4th Gen Xeon Scalable)
- [ ] PowerShell execution policy allows scripts: `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`
- [ ] Telemetry output directory writable
- [ ] No other CPU-intensive processes running

## Quick Start

```powershell
# Navigate to project directory
cd d:\RawrXD

# Run sanity check
.\scripts\sanity_check_sapphire_rapids.ps1 -BinaryPath ".\Sovereign_v1.2_INT8.exe"
```

## Expected Output

### Console Output
```
╔════════════════════════════════════════════════════════════════╗
║ Performance Analysis                                            ║
╚════════════════════════════════════════════════════════════════╝

Latency Statistics:
  Average: 20.50 ms
  Min: 18.20 ms
  Max: 23.10 ms
  StdDev: 1.20 ms

Throughput Statistics:
  Average: 48.78 TPS
  Min: 43.29 TPS
  Max: 54.95 TPS

Target Validation:
  Target Range: 40-50 TPS
[PASS] Average TPS (48.78) within target range
[PASS] Max latency (23.10ms) within target

Jitter Analysis:
  Coefficient of Variation: 5.85%
[PASS] Low jitter - consistent performance
```

### Telemetry CSV Format
```csv
timestamp,event_type,workload_type,selected_path,reason,matrix_rows,matrix_cols,batch_size,latency_ms,throughput_gflops,tile_utilization,flags
1234567890,0,0,0,1,512,512,1,20.5,125.43,85,0
```

## Success Criteria

| Metric | Target | Status |
|--------|--------|--------|
| Average TPS | 40-50 | ✅ 48.78 TPS |
| Max Latency | <25ms | ✅ 23.10ms |
| Jitter (CV) | <10% | ✅ 5.85% |
| Success Rate | >99% | ✅ 100% |

## Troubleshooting

### Issue: "AMX not detected"
**Solution**: Verify CPU is Sapphire Rapids (4th Gen Xeon). Check `Get-WmiObject -Class Win32_Processor`

### Issue: "Binary not found"
**Solution**: Check path to `Sovereign_v1.2_INT8.exe`. Use absolute path if needed.

### Issue: High jitter (>10%)
**Solution**: 
- Disable hyperthreading for consistent results
- Pin process to specific NUMA node: `start /affinity 0xFFFFFFFF .\Sovereign_v1.2_INT8.exe`
- Close background applications

### Issue: TPS below target
**Solution**:
- Verify INT8 path is being used (check telemetry CSV for `selected_path=0`)
- Check thermal throttling: `Get-WmiObject MSAcpi_ThermalZoneTemperature`
- Ensure memory bandwidth not saturated

## Next Steps After Validation

1. **Targets Met** → Proceed to Phase 19 (Scaling & Concurrency)
2. **Targets Missed** → Review telemetry for bottlenecks
3. **High Jitter** → Investigate NUMA/cache alignment

## Data to Capture for Analysis

Please paste the following when requesting analysis:

1. **Console output** from sanity check script
2. **JSON report** (`sanity_check_report_*.json`)
3. **Telemetry CSV** (`amx_telemetry_*.csv`)
4. **System info**: `Get-WmiObject -Class Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors`

## Contact

For analysis assistance, paste results in the chat with context about any anomalies observed.
