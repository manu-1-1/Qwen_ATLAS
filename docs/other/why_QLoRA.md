# Why QLoRA Was Chosen for Qwen-ATLAS

## Hardware Constraints

Qwen-ATLAS is being developed using a dual NVIDIA T4 environment (2 × 16 GB VRAM) available through Kaggle.

This provides approximately 32 GB of total GPU memory, which introduces significant constraints when fine-tuning modern large language models.

The project uses Qwen 2.5 7B Instruct as its foundation model. While the model can be loaded in FP16 for inference, full fine-tuning requires substantially more memory due to:

* Model weights
* Gradients
* Optimizer states
* Activations used during backpropagation

As a result, traditional full fine-tuning is not practical within the available hardware budget.

Any chosen fine-tuning strategy must therefore maximize memory efficiency while preserving model quality.

---

# Fine-Tuning Options Considered

## Full Fine-Tuning

Full fine-tuning updates every parameter in the model.

For a 7B parameter model, this requires storing gradients and optimizer states for billions of parameters.

Although this provides maximum flexibility, the memory requirements far exceed what is practical on a dual-T4 setup.

### Why It Was Rejected

* Excessive VRAM requirements
* Long training times
* Large checkpoint sizes
* Poor hardware fit for Kaggle GPUs

The project's objective is domain specialization rather than complete model retraining, making full fine-tuning unnecessary.

---

## Task-Specific Head Training

Task-head training freezes the model and trains only a small output layer.

While computationally efficient, this approach is primarily suited for classification tasks.

Qwen-ATLAS must generate:

* ATT&CK technique explanations
* Threat actor profiles
* Detection recommendations
* Threat intelligence reasoning chains

A task-specific head would not significantly alter the model's internal reasoning process and therefore provides insufficient adaptation capability.

---

## Standard LoRA

LoRA freezes the base model and learns low-rank weight updates.

This dramatically reduces trainable parameters and memory consumption.

However, the full base model must still be stored in memory during training.

For a 7B model:

FP16 Storage ≈ 14 GB

Although possible, memory becomes tight once activations, optimizer states, and larger context lengths are introduced.

This limits experimentation and reduces training flexibility.

---

# Why QLoRA Was Selected

QLoRA combines:

* 4-bit quantization
* LoRA adapters

Instead of storing the base model in FP16, it is stored in 4-bit NF4 format.

The base model remains frozen.

Only the LoRA adapters are trained.

Architecture:

4-bit Quantized Base Model
+
LoRA Adapters
↓
Output

---

# Memory Benefits

Approximate memory requirements for a 7B model:

| Method      | Base Model Storage |
| ----------- | ------------------ |
| FP16        | ~14 GB             |
| NF4 (QLoRA) | ~3.5–5 GB          |

This reduction allows the model to comfortably fit within the available T4 memory budget while leaving room for:

* Activations
* Optimizer states
* Larger batch sizes
* Longer context windows

Without quantization, the project would operate much closer to hardware limits.

---

# Why QLoRA Is Well Suited for Qwen-ATLAS

The objective of Qwen-ATLAS is not to teach the model language, grammar, or general reasoning.

Qwen 2.5 7B already possesses these capabilities.

Instead, the project aims to teach:

* MITRE ATT&CK terminology
* ATT&CK technique relationships
* Threat actor attribution patterns
* Threat intelligence workflows
* Analyst-style response formatting

These changes represent domain adaptation rather than foundational learning.

LoRA was specifically designed for this type of adaptation, while QLoRA makes it practical on limited hardware.

---

# How LoRA Works

Instead of modifying the original weight matrix W₀, LoRA learns a low-rank update.

Original layer:

y = W₀x

LoRA layer:

y = (W₀ + BA)x

Where:

* W₀ = frozen pretrained weights
* A = trainable low-rank matrix
* B = trainable low-rank matrix

Only A and B receive gradients during training.

The original model remains unchanged.

---

# Why Low-Rank Updates Work

Researchers observed that the updates learned during fine-tuning often occupy a much smaller subspace than the full parameter space.

Rather than learning millions of independent weight changes, LoRA assumes that the important adaptation can be represented by a low-rank matrix.

This dramatically reduces the number of trainable parameters while maintaining performance.

---

# How QLoRA Extends LoRA

LoRA reduces trainable parameters.

QLoRA reduces trainable parameters and base model memory.

The base model is stored using NF4 (NormalFloat4) quantization.

During training:

Frozen:

* Quantized base model

Trainable:

* LoRA matrix A
* LoRA matrix B

Only the adapter parameters are updated.

This allows efficient fine-tuning of a 7B model on commodity GPUs.

---

# NF4 Quantization

Standard INT4 quantization assumes values are uniformly distributed.

Neural network weights are not uniformly distributed and are typically concentrated near zero.

NF4 (NormalFloat4) is specifically designed around this distribution.

Advantages:

* Better preservation of model quality
* Lower quantization error
* Improved fine-tuning performance

This is one of the key innovations that makes QLoRA practical.

---

# Final Decision

Qwen-ATLAS uses QLoRA because it provides the best balance between:

* Model quality
* Memory efficiency
* Training speed
* Hardware compatibility

Given the project's dual-T4 Kaggle environment, QLoRA enables effective specialization of Qwen 2.5 7B without requiring enterprise-grade hardware.

It allows the team to focus resources on improving cybersecurity reasoning and ATT&CK knowledge rather than overcoming hardware limitations.
