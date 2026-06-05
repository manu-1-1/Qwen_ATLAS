from chroma_rag import smart_retrieve
from transformers import AutoTokenizer, AutoModelForCausalLM

MODEL = "Qwen/Qwen2.5-0.5B-Instruct"

print("Loading model...")

tokenizer = AutoTokenizer.from_pretrained(MODEL)

model = AutoModelForCausalLM.from_pretrained(
    MODEL,
    device_map="cpu"
)

query = input("Query: ")

# -------------------------
# Retrieval
# -------------------------

results = smart_retrieve(query)

context = "\n\n".join(
    r["text"]
    for r in results
)

# -------------------------
# Prompt Construction
# -------------------------

messages = [
    {
        "role": "system",
        "content": (
            "You are a cybersecurity threat intelligence assistant. "
            "Use the supplied ATT&CK context as your primary source. "
            "If the answer cannot be fully determined from the context, "
            "state what information is available."
        )
    },
    {
        "role": "user",
        "content": (
            f"ATT&CK Context:\n{context}\n\n"
            f"Question:\n{query}"
        )
    }
]

# -------------------------
# Inference
# -------------------------

text = tokenizer.apply_chat_template(
    messages,
    tokenize=False,
    add_generation_prompt=True
)

inputs = tokenizer(
    text,
    return_tensors="pt",
    truncation=True,
    max_length=2048
)

outputs = model.generate(
    **inputs,
    max_new_tokens=200,
    do_sample=False
)

input_len = inputs["input_ids"].shape[1]

response = tokenizer.decode(
    outputs[0][input_len:],
    skip_special_tokens=True
)

print("\n" + "=" * 80)
print("MODEL RESPONSE")
print("=" * 80)
print(response)