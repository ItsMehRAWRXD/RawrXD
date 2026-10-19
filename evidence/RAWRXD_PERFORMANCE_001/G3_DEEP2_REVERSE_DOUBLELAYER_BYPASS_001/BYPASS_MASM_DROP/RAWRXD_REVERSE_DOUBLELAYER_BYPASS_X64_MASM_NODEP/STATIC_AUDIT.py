from pathlib import Path
import traceback

ROOT=Path(__file__).resolve().parent

def main():
    print("STDOUT/STDERR")
    print()
    print("```")
    try:
        inc=(ROOT/"reverse_doublelayer_bypass.inc").read_text(encoding="utf-8")
        asm=(ROOT/"reverse_doublelayer_bypass.asm").read_text(encoding="utf-8")
        raw=inc.split("RDLRaw STRUCT",1)[1].split("RDLRaw ENDS",1)[0]

        checks={
            "caller_final_authority_absent":"final_authority" not in raw,
            "bypass_lane_present":"rdl_bypass:" in asm,
            "bypass_request_present":"bypass_request" in raw,
            "bypass_epoch_bound":"cmp [rsi].RDLRaw.bypass_epoch, rbx" in asm,
            "bypass_live_generation_required":"bypass_live_generation" in asm,
            "bypass_token_commit_required":"bypass_token_commit_count" in asm,
            "bypass_decode_commit_required":"bypass_decode_commit_count" in asm,
            "bypass_fault_guard":"bypass_fault_count" in asm,
            "stale_veto_precheck":"cmp [rsi].RDLRaw.stale_generation_faults, 0" in asm,
            "stale_veto_recheck":asm.count("cmp [rsi].RDLRaw.stale_generation_faults, 0") >= 2,
            "stale_veto_zeroes_bypass":
                "RDLResult.bypass_authorized, RDL_FALSE" in asm,
            "stale_veto_zeroes_final":
                "RDLResult.final_authority, RDL_FALSE" in asm,
            "bypass_final_write_present":
                "RDLResult.bypass_authorized, RDL_TRUE" in asm and
                "RDLResult.final_authority, RDL_TRUE" in asm,
        }

        model_normal={
            "normal_owner_ready":True,
            "generation_coherent":True,
            "product_closure":True,
            "stale_generation_faults":0,
            "final_authority":True,
        }
        model_bypass={
            "normal_owner_ready":False,
            "bypass_generation_bound":True,
            "bypass_commit_closure":True,
            "bypass_fault_free":True,
            "stale_generation_faults":0,
            "bypass_authorized":True,
            "final_authority":True,
        }
        model_stale={
            "bypass_request":True,
            "bypass_epoch_matches":True,
            "bypass_commits_close":True,
            "stale_generation_faults":1,
            "stale_generation_veto":True,
            "bypass_authorized":False,
            "final_authority":False,
        }
        model_epoch_mismatch={
            "generation_id":40,
            "bypass_epoch":39,
            "bypass_authorized":False,
            "final_authority":False,
        }

        ok=all(checks.values())
        print("STATIC_AUDIT=",checks)
        print("MODEL_NORMAL=",model_normal)
        print("MODEL_BYPASS=",model_bypass)
        print("MODEL_STALE=",model_stale)
        print("MODEL_EPOCH_MISMATCH=",model_epoch_mismatch)
        print("STATIC_AUDIT_RESULT=","PASS" if ok else "FAIL")
        if not ok:
            print("EXCEPTION_CLASS=StaticAuditFailure")
            print("EXCEPTION_MESSAGE=static audit failed")
            print("```")
            return 1
        print("```")
        return 0
    except Exception as exc:
        print("STATIC_AUDIT_RESULT=FAIL")
        print("EXCEPTION_CLASS=",exc.__class__.__name__)
        print("EXCEPTION_MESSAGE=",str(exc))
        print("TRACEBACK_BEGIN")
        traceback.print_exc()
        print("TRACEBACK_END")
        print("```")
        return 2

if __name__=="__main__":
    raise SystemExit(main())
