# AGENT-FIRST-TOKEN-001 VERDICT

overall=PASS
stick_A_auto=True family=phi3 token=29903 n=954 root=NONE ms=110320
stick_B_chatml=True family=chatml token=29903 n=964 root=NONE ms=99789

decision_tree:
  A fail B pass  -> chat_template frontend (phi3 auto suspect)
  A pass B fail  -> forced ChatML wrong for TinyLlama
  both fail at TOKENIZER -> tokenizer
  both fail at PREFILL -> Deep2 prefill
  both fail at DECODE -> Deep2 decode
  both pass first token -> advance to tool-call / 002b
