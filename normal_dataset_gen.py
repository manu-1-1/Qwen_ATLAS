# Generates 3000–5000 instruction-response pairs across 5 templates
import json, random
from mitreattack.stix20 import MitreAttackData

attack   = MitreAttackData("enterprise-attack.json")
with open("index_mappings.json") as f:
    idx = json.load(f)

techniques  = {t.external_references[0].external_id: t
               for t in attack.get_techniques(remove_revoked_deprecated=True)}
groups      = attack.get_groups(remove_revoked_deprecated=True)
mitigations = {m.external_references[0].external_id: m
               for m in attack.get_mitigations(remove_revoked_deprecated=True)}

SYSTEM = ("You are Qwen-ATLAS, an expert threat intelligence analyst specializing "
          "in MITRE ATT&CK. Provide accurate, structured, analyst-grade responses.")

def fmt(instruction, output):
    return {"messages": [
        {"role": "system",  "content": SYSTEM},
        {"role": "user",    "content": instruction},
        {"role": "assistant","content": output},
    ]}

def safe(v): return v if isinstance(v, str) else ""

dataset = []

# ── Template 1: Technique Deep Dive ─────────────────────────────────────────
for tid, t in list(techniques.items())[:800]:
    tactics   = [p.phase_name for p in (t.kill_chain_phases or [])]
    platforms = list(t.x_mitre_platforms or [])
    groups_using = idx["tech_to_groups"].get(tid, [])
    output = (f"**Technique ID:** {tid}\n"
              f"**Name:** {t.name}\n"
              f"**Tactic(s):** {', '.join(tactics)}\n"
              f"**Platforms:** {', '.join(platforms)}\n"
              f"**Description:** {safe(t.description)[:600]}\n"
              f"**Detection:** {safe(getattr(t,'x_mitre_detection',''))[:400]}\n"
              f"**Used by:** {', '.join(groups_using[:5]) or 'No attributed groups'}")
    dataset.append(fmt(f"Explain MITRE ATT&CK technique {tid}: {t.name}", output))

# ── Template 2: Threat Actor Profile ────────────────────────────────────────
for g in groups[:100]:
    gid   = g.external_references[0].external_id
    used  = attack.get_techniques_used_by_group(g.id)
    techs = [(t["object"].external_references[0].external_id, t["object"].name)
             for t in used[:15]]
    tactic_choices = ["persistence","lateral-movement","execution","collection"]
    chosen_tactic  = random.choice(tactic_choices)
    filtered = [(tid,name) for tid,name in techs
                if any(p.phase_name == chosen_tactic
                       for p in (techniques[tid].kill_chain_phases or [])
                       if tid in techniques)][:8]
    output = (f"**Group:** {g.name} ({gid})\n"
              f"**Aliases:** {', '.join(g.aliases or [])}\n"
              f"**Overview:** {safe(g.description)[:400]}\n"
              f"**{chosen_tactic.title()} TTPs:**\n" +
              "\n".join(f"  - {tid}: {name}" for tid,name in filtered))
    dataset.append(fmt(
        f"What {chosen_tactic} techniques does {g.name} commonly use?", output))

# ── Template 3: Detection Strategy ──────────────────────────────────────────
for tid, t in list(techniques.items())[:700]:
    detection = safe(getattr(t, "x_mitre_detection", ""))
    if len(detection) < 50: continue
    output = (f"**Detecting {t.name} ({tid})**\n\n"
              f"**Data Sources:**\n{detection[:500]}\n\n"
              f"**Recommended Actions:**\n"
              f"- Enable command-line logging and process creation auditing\n"
              f"- Monitor for anomalous parent-child process relationships\n"
              f"- Alert on unusual network connections from targeted processes\n"
              f"- Correlate with threat intel for known {t.name} indicators")
    dataset.append(fmt(f"How would a SOC analyst detect {t.name} ({tid})?", output))

# ── Template 4: Scenario Analysis ────────────────────────────────────────────
tactic_pairs = [("initial-access","execution"),
                ("execution","persistence"),
                ("persistence","lateral-movement")]
for t1, t2 in tactic_pairs:
    t1_techs = [techniques[x] for x in idx["tactic_to_techs"].get(t1,[])
                if x in techniques][:5]
    t2_techs = [techniques[x] for x in idx["tactic_to_techs"].get(t2,[])
                if x in techniques][:5]
    for ta in t1_techs:
        for tb in t2_techs:
            ta_id = ta.external_references[0].external_id
            tb_id = tb.external_references[0].external_id
            groups_a = idx["tech_to_groups"].get(ta_id, [])
            groups_b = idx["tech_to_groups"].get(tb_id, [])
            overlap  = list(set(groups_a) & set(groups_b))[:4]
            output = (f"**TTP Analysis: {ta.name} → {tb.name}**\n\n"
                      f"This combination ({ta_id} + {tb_id}) is consistent with "
                      f"{'several known threat actors' if not overlap else ', '.join(overlap)}.\n\n"
                      f"**Assessment:** The use of {ta.name} for {t1.replace('-',' ')} "
                      f"followed by {tb.name} for {t2.replace('-',' ')} is a "
                      f"{'common' if overlap else 'less common'} attack chain.\n\n"
                      f"**Recommended monitoring:** Correlate {ta_id} indicators with "
                      f"{tb_id} artifacts within a 24-hour window.")
            dataset.append(fmt(
                f"An attacker used {ta.name} then {tb.name}. What actor profiles match?",
                output))
            if len(dataset) > 4500: break

# ── Template 5: Lateral Movement Prediction ──────────────────────────────────
lm_techs = [techniques[x] for x in idx["tactic_to_techs"].get("lateral-movement",[])
            if x in techniques]
for g in groups[:60]:
    gid   = g.external_references[0].external_id
    used  = {t["object"].external_references[0].external_id
             for t in attack.get_techniques_used_by_group(g.id)}
    likely_lm = [t for t in lm_techs
                 if t.external_references[0].external_id in used][:6]
    if not likely_lm: continue
    lines = "\n".join(
        f"  - {t.external_references[0].external_id}: {t.name}"
        for t in likely_lm)
    output = (f"**Lateral Movement Prediction for {g.name}**\n\n"
              f"Based on attributed TTPs, monitor for:\n{lines}\n\n"
              f"**Priority:** Focus detection on the first two techniques, "
              f"as they appear most frequently in {g.name} campaigns.\n"
              f"**Detection focus:** Internal SMB/RDP traffic, unusual "
              f"service creation, and credential reuse across hosts.")
    dataset.append(fmt(
        f"{g.name} has initial access and persistence. What lateral movement "
        f"techniques should we monitor?", output))

random.shuffle(dataset)
with open("clean_dataset.jsonl", "w") as f:
    for ex in dataset:
        f.write(json.dumps(ex) + "\n")
print(f"Clean dataset: {len(dataset)} examples → clean_dataset.jsonl")