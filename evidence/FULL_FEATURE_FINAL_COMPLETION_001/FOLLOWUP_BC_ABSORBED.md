# FOLLOWUP_BC_ABSORBED

ASOF_UTC=2026-11-09T10:03:00Z
PROMOTE=0
CERTIFIED=0

```
SOURCE_WORKER=b3b02336-02f6-40d5-8e8a-ae2f71cdef3f
ACTIVE_REPAIR=f8888cfa-ee69-4f2a-998a-5a8bade1d0b2
ABSORBED_INTO=PEER_ABSORPTION.md
```

## Common EXT defect (confirmed on two tips)

| Tip SHA | Result |
|---------|--------|
| BD529691… (tip_ext_host_004) | HWND ok; no receipt; EXIT=-1 |
| 7582A0C9… (tip_final_integ_001) | same |

```
COMMON=EXIT_-1_RECEIPT_MISSING
NO_CROSS_SHA_INHERIT_FROM=8D8999CD
```

## Chat

```
BEST=5/7 on 4CB63C52… (CTRL_ENTER=PASS; UNICODE=FAIL; SEND_BTN=FAIL)
CURRENT_TIP_CHURN=2CB03699… 2/7 FAIL
NEED=exclusive RelWithDebInfo freeze then 7/7
```

## Next (owned by active repair worker)

1. ExtHostWire: write receipt before activate; harden crash path  
2. tip_final_integ_002 exclusive freeze  
3. EXT re-smoke + chat 7/7 on same SHA  
4. PRODUCT_PASS=0 until conjunction  
