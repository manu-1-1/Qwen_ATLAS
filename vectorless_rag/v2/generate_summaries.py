"""
generate_summaries.py
======================
Batch generate LLM summaries for all MITRE ATT&CK techniques/sub-techniques
using a local Ollama llama3.1:8b model. Saves incrementally to mitre_summaries.json.
"""

import os
import json
import sys
import urllib.request
import urllib.error
import time
import re

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "llama3.1:8b"

def query_ollama(prompt: str) -> str:
    data = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.3
        }
    }
    req = urllib.request.Request(
        OLLAMA_URL,
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            res_data = json.loads(response.read().decode("utf-8"))
            return res_data.get("response", "").strip()
    except Exception as e:
        print(f"  [ERROR] Ollama request failed: {e}")
        return ""

def summarize_attack_pattern(name: str, description: str, detection: str) -> str:
    prompt = f"""
Summarize this MITRE ATT&CK technique in exactly 2 concise sentences. Do not mention the name of the technique inside the summary unless necessary. Focus on what the technique is and how adversaries use it.

Name:
{name}

Description:
{description[:1200]}

Detection:
{detection[:600]}

Return ONLY the 2-sentence summary.
"""
    result = query_ollama(prompt)
    # Clean up response (some models append explanations or quotes)
    result = re.sub(r'^["\']|["\']$', '', result.strip())
    return result

def main():
    json_path = "enterprise-attack.json"
    cache_path = os.path.join(os.path.dirname(__file__), "mitre_summaries.json")

    if not os.path.exists(json_path):
        print(f"Error: {json_path} not found in current directory.")
        sys.exit(1)

    print(f"Loading {json_path}...")
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Load existing summaries cache
    cache = {}
    if os.path.exists(cache_path):
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                cache = json.load(f)
            print(f"Loaded {len(cache)} existing summaries from cache.")
        except Exception as e:
            print(f"Failed to load cache: {e}. Starting fresh.")

    # Find all techniques/sub-techniques
    objects = data.get("objects", [])
    nodes_to_summarize = []
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue

        ext_refs = obj.get("external_references", [])
        mitre_id = next(
            (r["external_id"] for r in ext_refs if r.get("source_name") == "mitre-attack"),
            obj["id"],
        )
        is_sub = obj.get("x_mitre_is_subtechnique", False)
        
        # We only summarize techniques/sub-techniques
        nodes_to_summarize.append({
            "id": mitre_id,
            "name": obj.get("name", ""),
            "description": obj.get("description", ""),
            "detection": obj.get("x_mitre_detection", "")
        })

    print(f"Total attack patterns found: {len(nodes_to_summarize)}")
    
    # Filter nodes that already have summaries
    todo = [node for node in nodes_to_summarize if node["id"] not in cache]
    print(f"Summaries to generate: {len(todo)}")

    if not todo:
        print("All summaries are already generated!")
        return

    # Check if Ollama is running
    print(f"Checking Ollama status at {OLLAMA_URL}...")
    try:
        req = urllib.request.urlopen(OLLAMA_URL.replace("/generate", "/tags"), timeout=5)
        print("  [OK] Ollama is running and accessible.")
    except Exception as e:
        print(f"  [ERROR] Cannot connect to Ollama: {e}")
        print("Please make sure Ollama is running and the model is loaded.")
        print("We will attempt to run anyway, but requests may fail.")

    count = 0
    start_time = time.time()
    
    try:
        for i, node in enumerate(todo):
            print(f"[{i+1}/{len(todo)}] Summarizing {node['id']} - {node['name']}...")
            summary = summarize_attack_pattern(
                node["name"],
                node["description"],
                node["detection"]
            )
            
            if summary:
                cache[node["id"]] = summary
                count += 1
                print(f"  Summary: {summary}")
                
                # Save cache every 5 summaries
                if count % 5 == 0:
                    with open(cache_path, "w", encoding="utf-8") as f:
                        json.dump(cache, f, indent=2)
                    print("  [Saved cache]")
            else:
                print("  [WARNING] Skipped due to empty summary.")
                
            time.sleep(0.1)
            
    except KeyboardInterrupt:
        print("\nProcess interrupted by user. Saving cache before exiting...")
    finally:
        # Final save
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2)
        elapsed = time.time() - start_time
        print(f"\nDone! Generated {count} summaries in {elapsed:.1f}s.")
        print(f"Total summaries in cache: {len(cache)}")

if __name__ == "__main__":
    main()
