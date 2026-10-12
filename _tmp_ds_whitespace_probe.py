import subprocess, os, sys

DIR = r"C:\Users\Garrett\AppData\Local\Temp\kilo\ds"
REF = r"F:\rawrxd\tmp_llama-cpp-cpu\llama-tokenize.exe"
MODEL = r"F:\rawrxd\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf"
MG = os.path.join(DIR, "tok_parity_mg.exe")

cases = [
    "a  b",
    "a   b",
    "  a",
    "a  ",
    "a\n\nb",
    "a\tb",
    "def hello():\n    print('world')",
    "user\nHello\nassistant\n",
    "  indented",
    "tab\there",
    "trailing   ",
    "multiple    spaces    here",
    "Hello world",
    "  ",
    "\n\n",
]

# write corpus (the harness reads ds_prompts.bin; the sweep script regenerates it)
with open(os.path.join(DIR, "ds_prompts.bin"), "wb") as o:
    o.write(__import__("struct").pack("<I", len(cases)))
    for it in cases:
        b = it.encode("utf-8")
        o.write(__import__("struct").pack("<I", len(b)))
        o.write(b)

r = subprocess.run([MG, DIR], capture_output=True)
nat = {}
for line in r.stdout.decode("utf-8", "replace").splitlines():
    if line.startswith("IDS "):
        parts = line.split()
        nat[int(parts[1])] = [int(x) for x in parts[2:]]

for i, c in enumerate(cases):
    rr = subprocess.run([REF, "-m", MODEL, "-p", c, "--ids", "--no-bos",
                         "--no-escape", "--log-disable"], capture_output=True)
    out = rr.stdout.decode("utf-8", "replace").strip()
    body = out[1:-1].strip()
    exp = [int(x) for x in body.split(",") if x.strip()]
    got = nat.get(i, [])
    print("%-4s | %-34s ref=%s\n     | %-34s nat=%s" % (
        "OK" if exp == got else "DIFF",
        repr(c), exp, "", got))
