from pathlib import Path
ROOT=Path(__file__).resolve().parent
asm=(ROOT/"r671_open_diag.asm").read_text()
txt=(ROOT/"OPEN_ERROR_MAP.txt").read_text()

checks={
 "named_filesize_local":"R671_LOCAL_FILESIZE equ 38h" in asm,
 "getlasterror_proto":"GetLastError       PROTO" in asm,
 "createfile_capture":"R671_STAGE_CREATEFILE" in asm and "call capture_error" in asm,
 "getfilesize_capture":"R671_STAGE_GETFILESIZE" in asm,
 "mapping_capture":"R671_STAGE_MAPPING" in asm,
 "diag_fields":"win32_last_error" in asm and "open_stage" in asm and "open_rc" in asm,
 "capture_before_cleanup":asm.find("ro_mapping_fail:") < asm.find("ro_cleanup_file_keepdiag:"),
 "slot_explanation":"+38h is the next 8-byte slot" in txt,
}
print("STATIC_AUDIT=",checks)
print("STATIC_AUDIT_RESULT=" + ("PASS" if all(checks.values()) else "FAIL"))
raise SystemExit(0 if all(checks.values()) else 1)
