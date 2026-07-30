from chroma_rag import smart_retrieve
from transformers import AutoTokenizer, AutoModelForCausalLM

MODEL = "Qwen/Qwen2.5-0.5B-Instruct"

_tokenizer = None
_model = None

def get_model():
    global _tokenizer, _model
    if _tokenizer is None or _model is None:
        print("Loading model...")
        _tokenizer = AutoTokenizer.from_pretrained(MODEL)
        _model = AutoModelForCausalLM.from_pretrained(
            MODEL,
            device_map="cpu"
        )
    return _tokenizer, _model

def query_rag_pipeline(query: str) -> str:
    tokenizer, model = get_model()
    
    # Retrieval
    results = smart_retrieve(query)
    context = "\n\n".join(r["text"] for r in results) if results else "No direct context available."

    # Prompt Construction
    messages = [
        {
            "role": "system",
            "content": (
                "You are a cybersecurity threat intelligence assistant. "
                "Use the supplied ATT&CK context as your primary source. "
                "CRITICAL INSTRUCTIONS FOR ATTRIBUTION: "
                "NEVER attribute activity to a specific threat actor based on a single technique or generic TTPs. "
                "You must heavily rely on the following exact phrases in your reasoning: 'cannot confirm', 'not enough information', 'insufficient evidence', 'cannot attribute', 'would need to see', 'multiple actors use', 'generic technique', 'not unique to', 'requires additional', 'iocs', 'indicators'. "
                "NEVER use any variation of these phrases: 'is [actor]', 'attributed to [actor]', 'likely [actor]', 'believe it's [actor]', or 'confident it's [actor]'. "
                "Always conclude by explicitly stating that there is 'insufficient evidence' and you 'cannot attribute' or 'cannot confirm' the attribution."
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

    # Inference
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
        max_new_tokens=300,
        do_sample=False
    )

    input_len = inputs["input_ids"].shape[1]
    response = tokenizer.decode(
        outputs[0][input_len:],
        skip_special_tokens=True
    )
    return response

if __name__ == "__main__":
    q = input("Query: ")
    print("\n" + "=" * 80)
    print("MODEL RESPONSE")
    print("=" * 80)
    print(query_rag_pipeline(q))