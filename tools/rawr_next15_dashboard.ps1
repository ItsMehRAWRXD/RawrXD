param([string]$Root=(Split-Path $PSScriptRoot -Parent))
$e=Join-Path $Root 'evidence/RAWRXD_NEXT_15_MOVES_006'
New-Item -ItemType Directory -Force $e | Out-Null
$exe=Join-Path $Root 'build/bin-msvc/Release/rawr.exe'
$items=@(
 [ordered]@{id=1;name='Snapshot and freeze known-good baseline';status=($(if(Test-Path (Join-Path $e 'baseline_snapshot.json')){'PASS'}else{'FAIL'}));evidence='baseline_snapshot.json'},
 [ordered]@{id=2;name='Native HTTP route matrix';status='PASS';evidence='prior smoke: /health /api/engine/capabilities /v1/chat/completions'},
 [ordered]@{id=3;name='Streaming and cancellation';status='PENDING';evidence='No complete disconnect/cancellation receipt'},
 [ordered]@{id=4;name='Gateway authorization';status='PASS';evidence='tool routes fail closed; loopback default'},
 [ordered]@{id=5;name='MASM-to-native integration';status='PARTIAL';evidence='model profile/load/unload routes wired; GUI E2E pending'},
 [ordered]@{id=6;name='Sustained profiling matrix';status='PENDING';evidence='benchmark receipt required'},
 [ordered]@{id=7;name='GPU critical path instrumentation';status='PARTIAL';evidence='existing counters; ranked receipt pending'},
 [ordered]@{id=8;name='Multi-model execution';status='PENDING';evidence='per-model full-model receipts required'},
 [ordered]@{id=9;name='Isolated optimization';status='PENDING';evidence='A/B receipt required'},
 [ordered]@{id=10;name='Dual-GPU scheduling';status='PARTIAL';evidence='device enumeration observed; fault/recovery matrix pending'},
 [ordered]@{id=11;name='Autonomous edit loop';status='PARTIAL';evidence='bounded agent path exists; full E2E receipt pending'},
 [ordered]@{id=12;name='Transactional hotpatch';status='PARTIAL';evidence='rollback components exist; certification receipt pending'},
 [ordered]@{id=13;name='Agent endurance';status='PENDING';evidence='bounded endurance run not completed'},
 [ordered]@{id=14;name='Certification dashboard';status='PASS';evidence='next15_dashboard.json'},
 [ordered]@{id=15;name='Production release certification';status='PENDING';evidence='blocked by required pending gates'}
)
$out=[ordered]@{schema='rawrxd.next15.v1';generated=(Get-Date).ToUniversalTime().ToString('o');git_sha=(git -C $Root rev-parse HEAD);certification='NOT_CERTIFIED';benchmark_pause='preserved';moves=$items}
$out | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $e 'next15_dashboard.json')
$out | ConvertTo-Json -Depth 8
