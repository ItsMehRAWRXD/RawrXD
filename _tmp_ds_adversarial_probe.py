import subprocess, os, struct, sys

DIR = r"C:\Users\Garrett\AppData\Local\Temp\kilo\ds"
REF = r"F:\rawrxd\tmp_llama-cpp-cpu\llama-tokenize.exe"
MODEL = r"F:\rawrxd\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf"
MG = os.path.join(DIR, "tok_parity_mg.exe")

cases = [
    # plain prose
    "Hello world",
    "The quick brown fox jumps over the lazy dog.",
    "The meaning of life is",
    # whitespace runs of every shape
    "a  b", "a   b", "a    b", "  a", "   a", "a  ", "a   ", "  ", "   ",
    "a\nb", "a\n\nb", "a\n\n\nb", "a \n b", "a\n b", "a \nb",
    "a\tb", "\ta", "a\t", "a\t\tb", "  \t  x  ",
    "word  \n\n  word2",
    # code
    "def hello():\n    print('world')",
    "def f():\n        return 1\n",
    "if x == 1:\n        y = 2\n    else:\n        y = 3\n",
    "for i in range(10):\n        total   +=   i\n",
    "x = {'a': [1, 2], 'b': (3, 4)}",
    "    indented_start",
    "SELECT * FROM users WHERE id = 1;",
    # punctuation runs and mixes
    "Hello, world! How are you?",
    "wait... what?!",
    "C++ vs Python: which is faster?",
    "email me at a.b@example.com please",
    "a...b---c...d",
    "!!!???...,,,",
    " 'quoted' \"double\" ",
    "under_score and-dash and.dot",
    # numbers
    "3.14159 and 2.71828",
    "In 2024, models grew to 70B parameters.",
    "abc123def456",
    " 123 456 ",
    "1,234,567",
    "v1.2.3",
    # unicode
    "naïve café résumé",
    "你好世界",
    "你好 world 世界",
    "こんにちは世界",
    "emoji test 😀 🚀 done",
    "emoji 😀😀😀 run",
    "Ω≈ç√∫˜µ≤≥÷",
    "ｆｕｌｌｗｉｄｔｈ ｔｅｘｔ",
    "Ｈｅｌｌｏ １２３",
    # markdown / structure
    "# Title\n\nSome **bold** text\n\n- item one\n- item two\n",
    "| a | b |\n|---|---|\n| 1 | 2 |",
    "```python\nprint(1)\n```",
    # chat templates
    "user\nHello\nassistant\n",
    "<｜User｜>Hello\n\n...an assistant response here...",
    "long text with lots of extra    spacing   between    words",
    "trailing whitespace   ",
    "   leading whitespace",
    "mixed\ttab\tand    spaces",
    "a" * 40,
    "  x  " * 5,
]

with open(os.path.join(DIR, "ds_prompts.bin"), "wb") as o:
    o.write(struct.pack("<I", len(cases)))
    for it in cases:
        b = it.encode("utf-8")
        o.write(struct.pack("<I", len(b)))
        o.write(b)

r = subprocess.run([MG, DIR], capture_output=True)
nat = {}
for line in r.stdout.decode("utf-8", "replace").splitlines():
    if line.startswith("IDS "):
        parts = line.split()
        nat[int(parts[1])] = [int(x) for x in parts[2:]]

ok = 0
bad = 0
for i, c in enumerate(cases):
    rr = subprocess.run([REF, "-m", MODEL, "-p", c, "--ids", "--no-bos",
                         "--no-escape", "--log-disable"], capture_output=True)
    out = rr.stdout.decode("utf-8", "replace").strip()
    body = out[1:-1].strip()
    exp = [int(x) for x in body.split(",") if x.strip()]
    got = nat.get(i, [])
    if exp == got:
        ok += 1
    else:
        bad += 1
        print("DIFF | %r\n     | ref=%s\n     | nat=%s" % (c, exp, got))
print("adversarial match=%d/%d" % (ok, ok + bad))
