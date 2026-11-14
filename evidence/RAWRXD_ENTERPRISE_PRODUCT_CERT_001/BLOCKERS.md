# Highest-priority blockers → CERT gates

| Priority | Defect | Near GATE | Disposition |
|----------|--------|-----------|-------------|
| P0 | M1M2 combine AV 187BFC4C (~Deep2Engine after open fail) | G02-06 G03-08 | addrOk landed; AV_CLOSED=0; tip_bind=1 |
| P0 | GPU/ref ATTN_PRE_O_1 V_1 | G02-04 G02-05 G03-08 | OWNER=ATTN_NORM_1@dim1072; maxULP_f16=1 CLOSE=0 |
| P0 | Multi-family GUI / tip OPEN_SEH bind | G04-01 G06-06 | private OPEN_SKIP TOK=8 on 7FD1; tip 6754 RO |
| P1 | C36 LSP on tip | G07-01 G07-04 | cand 0C6A965A INIT_OK RELATED; tip OPEN |
| P1 | ConPTY on tip | G05-05 G06-05 | cand 3/3 PASS RELATED; tip remasure OPEN |
| P1 | M3 MODEL_SELECTED_TOOL | G05-06 G08-01 | FORCE_TOOL PASS; model-select=0 |
| P2 | M4 Authenticode + CLEAN_VM | G12-02 G12-03 | ABSENT / NOT_RUN |
| P2 | CLI clean rebuild | G01-03 | EXIT=2; CLEAN_MACHINE=0 |

PROMOTE=0 until all 128 PASS + sign-off.
