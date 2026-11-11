# BASELINE_SHA_LEDGER — Track A measured hashes only

```
ASOF_UTC=2026-11-09T12:30:00Z
METHOD=Get-FileHash -Algorithm SHA256 (PowerShell) unless noted RECEIPT_ONLY
FAIL_CLOSED=1
PROMOTE=0
CERTIFIED=0
CONTROLLING_TIP=CC79
A4F_IMMUTABLE=1
ENGINEERING_MATURITY_ESTIMATE=82_PERCENT_UNCHANGED
INVENT=0
```

## Controlling / immutable baselines

| Role | SHA-256 (full) | Size | Path | Status |
|------|----------------|------|------|--------|
| CONTROLLING tip CC79 / tip_final_005 / tip_final_integ_002 | `CC79F6CDD08F5ECEBB672290CC96F7FEEEA0DA6AB6F8B596E5826C3EA22940C4` | 6152704 | `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_002\RawrXD-Win32IDE-Native-Ext.exe` | MEASURED |
| CC79 alias | same | 6152704 | `F:\rawrxd\package\tip_final_005\RawrXD-Win32IDE-Native-Ext.exe` | MEASURED |
| CC79 alias | same | 6152704 | `F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_final_005\RawrXD-Win32IDE-Native-Ext.exe` | MEASURED |
| CC79 alias | same | 6152704 | `F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\tip_final_005\RawrXD-Win32IDE-Native-Ext.exe` | MEASURED |
| Frozen slim A4F | `A4F083DFB9CCD1F78036E1CDCDCA9AF881EF10B3E34170B68C4610D51AC6EF4E` | 2601472 | `F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\RawrXD-Win32IDE-Native.exe` | MEASURED |

## INTEG_004 / tip_final_integ_* candidates

| Role | SHA-256 (full) | Size | Path | Status |
|------|----------------|------|------|--------|
| tip_final_integ_004 LIVE | `69FE3D921FECC3DC66DA9E71901B338A045D706717F00C3B587B3B1BDB1268BB` | 6167040 | `...\candidates\tip_final_integ_004\RawrXD-Win32IDE-Native-Ext.exe` | MEASURED (= SHA256.txt) |
| tip_final_integ_004 Problems/EXT seal | `47451F241262A7F4471D60C3D12454A93EF1C333273BEFF828B9A69F23DC274F` | — | cited in lineage/Problems/EXT receipts | RECEIPT_ONLY; **exe ABSENT_LOCALLY** under candidates |
| tip_final_integ_003 | `DD60FFB8CFB5133ADC0C6E59124C4E4A199E26F310FD00C6A55EC9F7D8A9497C` | 6167040 | `...\candidates\tip_final_integ_003\RawrXD-Win32IDE-Native-Ext.exe` | MEASURED |
| tip_final_integ_001 | `7582A0C9899E0EA587E98F6343BBF8F28364713701CA91CF58319C20D46E2F58` | 2749952 | `...\candidates\tip_final_integ_001\RawrXD-Win32IDE-Native-Ext.exe` | MEASURED |

```
47451F24 ≠ 69FE3D92
SEALED_PROBLEMS_PASS_ON_47451 ≠ LIVE_69FE_CREDIT
```

## T05 marker 0F054F01

| Role | SHA-256 (full) | Size | Path | Status |
|------|----------------|------|------|--------|
| Marker T05 controlling board image | `0F054F01380BA745F760A973E894A6809BBD777FCA871108CDC61AB029CA2F8E` | 1484800 | `F:\rawrxd\build_ide\bin\RawrXD-Win32IDE-Native.exe` | MEASURED |
| Seal docs | same full hash | — | `POST_E59D_CANDIDATE_001\MARKER_SHA_0F054F01.md`, `T05_FORMAL_PASS_0F054F01.md`, `BUILD_IDE_0F054F01_T05_006` | PRESENT |

```
PASS(0F054F01) ≠ FINISH25_HISTORICAL_REWRITE ≠ PROMOTE
CONTROLLING_BOARD=F:\rawrxd\evidence\BUILD_IDE_0F054F01_T05_006
```

## T10 freeze 9C910599

| Role | SHA-256 (full) | Size | Path | Status |
|------|----------------|------|------|--------|
| tip_t10 candidate | `9C91059940A49C970586FF18FC92B1B7BA422AF09E8D579B1C8606387E74A9C8` | 2592256 | `F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\tip_t10_9C910599\RawrXD-Win32IDE-Native.exe` | MEASURED |
| tip_t10 recovery twin | same | 2592256 | `F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_t10_recovery_001\RawrXD-Win32IDE-Native.exe` | MEASURED |
| Freeze bak | same | 2592256 | `F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\RawrXD-Win32IDE-Native.exe.9C910599.bak` | MEASURED |
| package bak shortcut | — | — | `F:\rawrxd\package\RawrXD-Win32IDE-Native.exe.9C910599.bak` | ABSENT_LOCALLY |

## EXT tip ladder (272199BE + later)

| Stage | SHA-256 (full) | Size | Path | Status |
|-------|----------------|------|------|--------|
| tip_ext_host_001 | `272199BE27AF3959D44C741C4F0337E9833291FB73346389167CC62000C189B8` | 2220544 | `...\DAILY_DRIVER_CLOSE_001\package\tip_ext_host_001\RawrXD-Win32IDE-Native.exe` | MEASURED |
| tip_ext_host_002 sealed | `8D8999CD722B3ED46E3E74D437C6ADF6CA4513E9C01128E02F9F0BF4BB579EAD` | 2722304 | `...\tip_ext_host_002\RawrXD-Win32IDE-Native-Ext.exe` | MEASURED |
| tip_ext_host_003 | `0A53EA74C7E2838AD40109B62BE1B8A2D753E446EF0E03A312C29F78311E79BF` | 2722304 | `...\tip_ext_host_003\RawrXD-Win32IDE-Native-Ext.exe` | MEASURED |
| tip_ext_host_004 | `BD529691FE18D7E2EDB77D98E4C33424FF705C0BEE263429DAD600E11F42D25E` | 2722304 | `...\tip_ext_host_004\RawrXD-Win32IDE-Native.exe` | MEASURED |
| tip_ext_host_005 | `B6FA1E737AA721874E5C2EDFCAC0F7BE8A445438680A83C32F1E23BF99483628` | 2727936 | `...\tip_ext_host_005\RawrXD-Win32IDE-Native.exe` | MEASURED |
| tip_ext_host_006 | `633AB013E37612C55F26615CE3B07633B1401536B00F5C4E2D75076451232363` | 2750464 | `...\tip_ext_host_006\RawrXD-Win32IDE-Native-Ext.exe` | MEASURED |
| tip_ext_host_007 | `1F6005131BA855B994C6D05009A7052781D289EFF197E7F5E709C947B0F53E04` | 2755072 | `...\tip_ext_host_007\RawrXD-Win32IDE-Native-Ext.exe` | MEASURED |
| tip_ext_host_oneshot | `7B4267FA5486BEB50C2271C127BD6AAEF9C0E4314CE60D3D86ABBE48A673CB6B` | 2735104 | `...\FULL_FEATURE_ONESHOT_001\candidates\tip_ext_host_oneshot\RawrXD-Win32IDE-Native.exe` | MEASURED |

Receipt-noted prior fail SHA `CF186F4C…` (GATE.md tip ladder): **exe not re-measured this audit** — treat as RECEIPT_ONLY / verify on demand.

## HWND repair / tip006

| Role | SHA-256 (full) | Size | Path | Status |
|------|----------------|------|------|--------|
| tip_hwnd_repair_001 | `3F860429768B836FC19D3ADAD80A295EA1206D9565F7EE9730C8D70BAEF01780` | 2804736 | `F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\package\tip_hwnd_repair_001\RawrXD-Win32IDE-Native-Ext.exe` | MEASURED |
| tip_final_006 (receipt) | `5A71CA26FEF42E927A53208A374FEF8BC4FD9D3F4BF6998C596FE2026CE80211` | — | cited `TIP005_HWND_REPAIR.md` / `MEASURED_TIP006_HWND_RETURN.txt` | RECEIPT_ONLY; **exe ABSENT_LOCALLY** |

## Finish-25 historical baseline SHA (receipt authority; not re-hashed this pass)

From `POST_E59D_CANDIDATE_001\FINISH_25_BACKLOG.md` / `FINISH_25_RECEIPT_AGREEMENT.md`:

```
FINISH25_CONTROLLING_BASELINE_SHA=3B720981EC567D60461B874F0C1EE46E03F85DB58F6E1788CBEE31F8B2CCAD5F
REPAIR_CANDIDATE_SHA=F09F3A21267B2E6643C170E379A87F02A3950C0A2CE2EBC0767B727EF7B83188
PROGRESSION_CANDIDATE_SHA=55BE19B7D594118C9C803D8D7DA3B127E33C0C8C82A62BD50E4956D0AC2298A3
FINISH25_HISTORICAL=19/25
UNACCEPTED_SIX=T05 T07 T08 T18 T19 T25
```

## Explicit absences

| Item | Disposition |
|------|-------------|
| 78-item acceptance register file | ABSENT_LOCALLY |
| integ_004 exe at sealed `47451F24…` | ABSENT_LOCALLY (superseded live `69FE3D92…`) |
| tip_final_006 exe | ABSENT_LOCALLY |
| `F:\rawrxd\package\RawrXD-Win32IDE-Native.exe.9C910599.bak` | ABSENT_LOCALLY |

## Law

```
MEASURED ≠ RECEIPT_ONLY ≠ CONTROLLING
NO_CROSS_SHA_PASS_INHERITANCE=1
NOT_RUN ≠ PASS
PROMOTE=0
CERTIFIED=0
A4F_IMMUTABLE=1
CC79_CONTROLLING=1
```
