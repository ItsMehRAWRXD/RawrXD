; RawrXD_TransactionalMutation_x64.inc — transactional mutation authority (no CRT/heap)

TX_MAGIC                EQU 54584E4155544831h ; "TXNAUTH1"
TX_VERSION              EQU 00010000h

TX_STATE_FREE           EQU 0
TX_STATE_BEGUN          EQU 1
TX_STATE_APPROVED       EQU 2
TX_STATE_MUTATING       EQU 3
TX_STATE_COMMITTED      EQU 4
TX_STATE_ROLLBACK       EQU 5
TX_STATE_ROLLED_BACK    EQU 6
TX_STATE_ABORTED        EQU 7
TX_STATE_FAULT          EQU 8

TX_KIND_FILE_WRITE      EQU 1
TX_KIND_FILE_DELETE     EQU 2
TX_KIND_FILE_RENAME     EQU 3
TX_KIND_HOTPATCH        EQU 4
TX_KIND_PROCESS_EXEC    EQU 5
TX_KIND_CONFIG_WRITE    EQU 6
TX_KIND_REPOSITORY      EQU 7

TXC_BASE                EQU 00h
TXC_CAPACITY            EQU 08h
TXC_NEXT_ID             EQU 10h
TXC_ACTIVE              EQU 18h
TXC_COMMITTED           EQU 20h
TXC_ROLLED_BACK         EQU 28h
TXC_FAULTS              EQU 30h
TXC_CHAIN_TAG           EQU 38h
TXC_KEY0                EQU 40h
TXC_KEY1                EQU 48h
TXC_MAGIC               EQU 50h
TXC_VERSION             EQU 58h
TXC_SIZE                EQU 60h

TXR_ID                  EQU 00h
TXR_STATE               EQU 08h
TXR_KIND                EQU 0Ch
TXR_BEGIN_TSC           EQU 10h
TXR_END_TSC             EQU 18h
TXR_APPROVAL_SEQ        EQU 20h
TXR_AUTHORITY_SEQ       EQU 28h
TXR_TARGET_HASH         EQU 30h
TXR_PREIMAGE_HASH       EQU 38h
TXR_POSTIMAGE_HASH      EQU 40h
TXR_BACKUP_HASH         EQU 48h
TXR_BYTES_EXPECTED      EQU 50h
TXR_BYTES_WRITTEN       EQU 58h
TXR_PREV_TAG            EQU 60h
TXR_TAG                 EQU 68h
TXR_ERROR               EQU 70h
TXR_RESERVED            EQU 78h
TXR_SIZE                EQU 80h
