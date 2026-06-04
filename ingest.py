import json
from mitreattack.stix20 import MitreAttackData
from stix2 import Filter

STIX_FILE = "enterprise-attack.json"

print("Loading ATT&CK STIX data...")
attack = MitreAttackData(STIX_FILE)

techniques  = attack.get_techniques(remove_revoked_deprecated=True)
groups      = attack.get_groups(remove_revoked_deprecated=True)
mitigations = attack.get_mitigations(remove_revoked_deprecated=True)
relationships = attack.src.query([Filter("type", "=", "relationship")])  # ✅ fixed

print(f"✓ {len(techniques)} techniques")
print(f"✓ {len(groups)} groups")
print(f"✓ {len(mitigations)} mitigations")
print(f"✓ {len(relationships)} relationships")

tech_to_groups = {}
for group in groups:
    for t in attack.get_techniques_used_by_group(group.id):
        tid = t["object"].external_references[0].external_id
        tech_to_groups.setdefault(tid, []).append(group.name)

tactic_to_techs = {}
for t in techniques:
    tid = t.external_references[0].external_id
    for phase in (t.kill_chain_phases or []):
        tactic_to_techs.setdefault(phase.phase_name, []).append(tid)

mit_to_techs = {}
for rel in relationships:
    if rel.relationship_type == "mitigates":
        src = attack.src.query([Filter("id", "=", rel.source_ref)])
        tgt = attack.src.query([Filter("id", "=", rel.target_ref)])
        if src and tgt:
            try:
                mid = src[0].external_references[0].external_id
                tid = tgt[0].external_references[0].external_id
                mit_to_techs.setdefault(mid, []).append(tid)
            except (IndexError, AttributeError):
                continue

with open("index_mappings.json", "w") as f:
    json.dump({
        "tech_to_groups": tech_to_groups,
        "tactic_to_techs": tactic_to_techs,
        "mit_to_techs": mit_to_techs
    }, f, indent=2)

print("✓ index_mappings.json saved")