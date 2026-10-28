# MODE_SWITCH_UI_001 — matrix

| ID | Item | Status | Note |
|----|------|--------|------|
| M01 | Tip SHA 748B match | PASS | `logs/exe_sha.txt` |
| M02 | Ask HWND switch | RUNTIME | PostMessage 1208 |
| M03 | Plan HWND switch | RUNTIME | PostMessage 1206 |
| M04 | Agent HWND switch | RUNTIME | PostMessage 1207 |
| M05 | Debug HWND switch | NOT_RUN | No tip IDC; source 5008 |
| M06 | ID collision 1206–1208 fixed in source | SOURCE_WIRED | Pending absorb |
| M07 | VSCodeUI / createChatPanel radios | SOURCE_WIRED | Pending absorb |
| M08 | g_pMainIDE ctor bind | SOURCE_WIRED | Pending absorb |
| M09 | MET / PROMOTE | HOLD | `PROMOTE=0` `MET_CLAIM=0` |

`PROMOTE=0` · `TIP_CLIMB=HOLD` · `ABSORB=NOT_AUTHORIZED`
