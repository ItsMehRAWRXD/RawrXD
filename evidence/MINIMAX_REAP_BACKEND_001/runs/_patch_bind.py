from pathlib import Path
p=Path(r"src/deep2/MultiShardWeightBind.hpp")
t=p.read_text(encoding="utf-8")
old='    else if (n.find("ffn_gate_inp") != std::string::npos) lw.moeRouter = wt;\n    else if (n.find("ffn_up_exps") != std::string::npos) lw.wUp = wt;'
new='    else if (n.find("ffn_gate_inp") != std::string::npos) lw.moeRouter = wt;\n    else if (n.find("exp_probs_b") != std::string::npos) lw.moeExpertBias = wt;\n    else if (n.find("ffn_up_exps") != std::string::npos) lw.wUp = wt;'
if "exp_probs_b" not in t:
    if old not in t: raise SystemExit("bind old missing")
    p.write_text(t.replace(old,new), encoding="utf-8"); print("bind ok")
else: print("bind already")
p=Path(r"src/deep2/MultiShardLayerMaterialize.hpp")
t=p.read_text(encoding="utf-8")
old='    n += MaterializeOne(lw.moeRouter, idx, layer, "moe_router", fail);\n    n += MaterializeOne(lw.wGate, idx, layer, "wGate", fail);'
new='    n += MaterializeOne(lw.moeRouter, idx, layer, "moe_router", fail);\n    n += MaterializeOne(lw.moeExpertBias, idx, layer, "moe_bias", fail);\n    n += MaterializeOne(lw.wGate, idx, layer, "wGate", fail);'
if "moe_bias" not in t:
    if old not in t: raise SystemExit("mat old missing")
    p.write_text(t.replace(old,new), encoding="utf-8"); print("mat ok")
else: print("mat already")
