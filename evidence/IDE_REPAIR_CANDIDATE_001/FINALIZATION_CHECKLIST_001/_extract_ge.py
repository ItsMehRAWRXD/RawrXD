import json
import re
path = r"C:\Users\Garrett\.cursor\projects\g-dev\agent-transcripts\8b161a97-3488-42e8-aee5-01939be9ee3d\8b161a97-3488-42e8-aee5-01939be9ee3d.jsonl"
out = r"F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\FINALIZATION_CHECKLIST_001\_checklist_extract.txt"
with open(path, "r", encoding="utf-8") as f:
    for i, line in enumerate(f, 1):
        if "Complete Remaining IDE Finalization Checklist" not in line:
            continue
        o = json.loads(line)
        text = o["message"]["content"][0]["text"]
        # keep from Confirmed blockers / G / E sections
        chunks = []
        for pat in [
            r"G01[\s\S]{0,8000}?E12[\s\S]{0,1200}",
            r"B01[\s\S]{0,5000}?B08[\s\S]{0,800}",
            r"37E64080[\s\S]{0,400}",
            r"Editor[\s\S]{0,4000}?E12[\s\S]{0,600}",
            r"GUI[\s\S]{0,4000}?G12[\s\S]{0,600}",
        ]:
            m = re.search(pat, text, re.I)
            if m:
                chunks.append("---MATCH---\n" + m.group(0)[:9000])
        # also dump headings containing G0/E0/B0
        lines = text.splitlines()
        keep = []
        for ln in lines:
            if re.search(r"\b([GEBIA]T?P?H?\d{2}|theme|37E64080|B07|four-panel|editor)\b", ln, re.I):
                keep.append(ln)
        with open(out, "w", encoding="utf-8") as w:
            w.write("LINE_COUNT=%d TEXT_LEN=%d\n" % (len(lines), len(text)))
            w.write("\n".join(keep[:400]))
            w.write("\n\n====CHUNKS====\n")
            w.write("\n\n".join(chunks))
        print("WROTE", out, "KEEP", len(keep), "CHUNKS", len(chunks))
        break
else:
    print("NOT_FOUND")
