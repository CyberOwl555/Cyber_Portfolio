# Project 11 — Local AI SOC Analyst: Deploying, Evaluating, and Fine-Tuning LLMs for Security Operations

## Overview

This project evaluates whether a locally-hosted Large Language Model (LLM) can serve as a practical Tier 3 SOC analyst assistant — capable of alert triage, MITRE ATT&CK mapping, multi-alert chain analysis, detection rule generation, and false positive analysis — without sending sensitive data to external cloud services.

The project covers the full lifecycle: model selection, deployment, systematic evaluation, iterative improvement through prompt engineering and Retrieval Augmented Generation (RAG), model comparison across architectures, and fine-tuning a purpose-built security model on real lab data — followed by a second, hypothesis-driven fine-tuning iteration that specifically targeted the weaknesses the first evaluation surfaced. All work runs entirely on local hardware using open-source tooling.

**Hardware:** Acer Predator laptop — Intel i9, 32GB RAM, NVIDIA GeForce RTX 5070 Ti Laptop GPU (12GB VRAM)
**Key finding:** A purpose-built security model fine-tuned on domain-specific training pairs produced better SOC triage results than any general model regardless of size — running entirely locally on consumer hardware. A second, targeted fine-tuning pass improved three specific weak points by design, while also surfacing a real evaluation-harness bug and a genuine open question about output consistency.

---

## Why Local LLMs for Security Operations

The data sovereignty problem is the primary driver. In a real SOC, alert data contains sensitive information — internal IP addresses, hostnames, usernames, domain names, and potentially customer data. Sending this to a public cloud LLM (ChatGPT, Claude, Gemini) creates data exposure risk and may violate compliance requirements (GDPR, ISO 27001, sector-specific regulations).

A local model eliminates this entirely. The model, the data, and the inference all stay within the security perimeter. This is the same architectural argument that drives enterprise adoption of on-premise SIEM over cloud SIEM in high-security environments.

The secondary driver is cost and latency. At scale, cloud LLM API costs for continuous alert triage become significant. A local model has zero per-query cost once deployed.

---

## Tooling and Setup

| Component | Tool | Purpose |
|---|---|---|
| Model serving | Ollama | Local model management and inference |
| Chat interface | Open WebUI v0.11.3 | Browser-based interface, RAG integration |
| Fine-tuning | Unsloth + LoRA | Parameter-efficient fine-tuning |
| Environment | Miniconda (Python 3.12) | Isolated dependencies |
| PyTorch | Nightly cu128 build | Required for RTX 5070 Ti (sm_120 / Blackwell) |

**Notable infrastructure challenge:** The RTX 5070 Ti uses NVIDIA's Blackwell architecture (compute capability sm_120) which is not supported by stable PyTorch releases as of September 2026. The PyTorch nightly build with CUDA 12.8 was required. This is a realistic deployment consideration for organisations with recent GPU hardware.

---

## Evaluation Methodology

Five standardised tests were designed and run consistently across every model and configuration. The same prompts were used for every comparison — no cherry-picking responses. The harness (`evaluate.py`) has gone through several revisions during this project (v3 at time of writing); scores from different harness versions are noted separately rather than treated as directly comparable.

### Test Suite

**Test 1 — Single Alert Analysis**
A real Wazuh alert from the AD attack lab: Event ID 4769, encryption type 0x17, service svc_sql, user jsmith, source 192.168.137.60.
*Ground truth:* T1558.003 Kerberoasting. The 0x17 RC4 encryption type is the definitive indicator. Source is Kali Linux. Do not isolate DC.

**Test 2 — Multi-Alert Chain Analysis**
Three connected alerts over 16 minutes: Kerberoasting (4769/0x17), password spray failure (4625/sadmin), NTLM success (4624/sadmin/Logon Type 3).
*Ground truth:* T1558.003 → T1110.003 → T1550.002. Predicted next step: DCSync (Event 4662). sadmin is Domain Admin — full domain compromise.

**Test 3 — Hallucination / Unknown Rule ID**
Question about Wazuh rule ID 847293 which does not exist.
*Ground truth:* The correct response is to state the rule does not exist and direct the analyst to verify in their SIEM. Any fabricated description is a failure.

**Test 4 — Decoder and Rule Generation**
Request to write a Wazuh decoder and rule for a specific log line.
*Ground truth:* Valid Wazuh XML using prematch/regex/order decoder structure and rule with integer level, decoded_as, field elements.

**Test 5 — False Positive Analysis**
FIM alert: /usr/bin/diff checksum changed on docker-host.
*Ground truth:* Likely false positive. Primary hypothesis: package update. Verify with dpkg -V diffutils before any containment. Do not isolate host.

### Scoring Rubric (per test, out of 10)
- Correct technique identification and MITRE ID: 3 points
- Appropriate confidence expression and reasoning: 2 points
- Correct and specific recommended actions: 2 points
- No dangerous advice (DC isolation, premature containment): 2 points
- Honest uncertainty for unknowns: 1 point

---

## Models Tested

| Configuration | Base Model | Notes |
|---|---|---|
| Baseline | DeepSeek R1 14B | General reasoning model |
| Modelfile update | DeepSeek R1 14B | Improved system prompt |
| RAG | DeepSeek R1 14B + RAG | 4 knowledge base documents |
| Llama 3.1 8B | Llama 3.1 8B | General instruction model |
| Foundation Reasoning | Foundation-Sec-8B-Reasoning | Cisco security-specific model |
| Fine-tuned (v1) | Foundation-Sec-8B-Reasoning + LoRA | Fine-tuned on 10 lab-specific pairs |
| Fine-tuned (v2) | Foundation-Sec-8B-Reasoning + LoRA | Second iteration: 7 additional pairs (17 total) targeting v1's specific weak tests |

---

## Results — Original Comparison

### Complete Comparison Table

| Test | DeepSeek 14B | Modelfile | RAG | Llama 3.1 8B | Foundation Reasoning | Fine-tuned (v1) |
|---|---|---|---|---|---|---|
| Single alert | 6/10 | 4/10 | 4/10 | 7/10 | 7/10 | 7/10 |
| Multi-alert chain | 4/10 | 5/10 | 5/10 | 5/10 | 7/10 | **9/10** |
| Hallucination | 0/10 | 5/10 | **10/10** | 3/10 | 2/10 | 3/10 |
| Rule generation | 5/10 | 5/10 | 5/10 | 5/10 | 6/10 | **8/10** |
| False positive | 2/10 | 3/10 | **5/10** | 4/10 | 6/10 | **9/10** |
| **Average** | **3.4** | **4.4** | **5.8** | **4.8** | **5.6** | **7.2** |

*Measured under an earlier harness version. Kept here as the original record of the project's first evaluation pass.*

---

## Key Findings (Original Evaluation)

### Finding 1 — General purpose LLMs require significant grounding for SOC tasks

DeepSeek R1 14B scored 3.4/10 out of the box. The model consistently:
- Cited wrong MITRE sub-technique IDs (T1003.001 instead of T1558.003 for Kerberoasting)
- Recommended isolating the Domain Controller as a first response — which would take down Kerberos authentication for the entire domain
- Fabricated plausible-sounding rule descriptions for non-existent rule IDs with complete confidence
- Defaulted to "true positive" for a FIM alert on /usr/bin/diff without considering package updates

These failures are not cosmetic. Wrong MITRE IDs in incident reports misdirect response teams. Isolating a DC mid-incident causes more damage than many attacks. Fabricated rule descriptions could lead analysts to close genuine threats.

### Finding 2 — Prompt engineering improves safety but not accuracy

The improved modelfile (temperature 0.25, structured output format, explicit instructions against DC isolation and fabrication) raised the average from 3.4 to 4.4. Critically, dangerous response advice disappeared entirely — the DC isolation recommendation never reappeared after adding the explicit instruction.

However, prompt engineering did not improve MITRE accuracy or false positive reasoning. The model stopped saying dangerous things without starting to say correct things.

### Finding 3 — RAG is the single most impactful intervention for environment-specific queries

Attaching four knowledge base documents (MITRE reference, known rule IDs, Wazuh syntax, SOC ground truth) raised the hallucination test from 0/10 to 10/10. When the model had access to a document listing known rule IDs, it correctly identified that rule 847293 does not exist and cited the source document.

**Critical counter-finding:** RAG produced a false citation on the Kerberoasting test — the model cited lab-known-rules.md as the source for a MITRE technique that document doesn't contain. This is arguably more dangerous than plain hallucination because the citation makes the fabrication look grounded. Human review of MITRE technique IDs remains essential even with RAG.

### Finding 4 — Model size matters less than training data specificity

Llama 3.1 8B (general, 8B parameters) scored 4.8/10.
Foundation-Sec-8B-Reasoning (security-specific, 8B parameters) scored 5.6/10.
The same parameter count with security-specific training data produced measurably better results on every SOC-relevant test. This directly contradicts the intuition that bigger models are always better.

### Finding 5 — Llama 3.1 8B has aggressive tool-calling behaviour

Llama 3.1 was trained for agentic tool use. When presented with JSON-formatted alert data, it consistently responded with function call objects rather than analysis. This required reformatting all alerts as plain key-value text rather than JSON. In a production pipeline that feeds raw Wazuh JSON to the model, this would break every query without explicit tool-call suppression at the API level.

### Finding 6 — Fine-tuning on 10 examples produced dramatic improvement

LoRA fine-tuning of Foundation-Sec-8B-Reasoning on 10 carefully crafted training pairs — the correct answers to the five test prompts plus five additional domain knowledge pairs — raised the average from 5.6/10 to 7.2/10.

Specific improvements:
- Multi-alert chain: 7/10 → 9/10 (all three techniques correctly identified for the first time)
- Rule generation: 6/10 → 8/10 (decoder XML near-functional)
- False positive: 6/10 → 9/10 (correctly led with package update as primary hypothesis)

Training took 3 minutes on the RTX 5070 Ti. The LoRA adapter is approximately 200MB versus 8.5GB for the full model. The marginal cost of fine-tuning was minimal; the improvement was disproportionate.

### Finding 7 — Hallucination is not fixed by fine-tuning with small datasets

The fine-tuned model scored 3/10 on the hallucination test — similar to the untuned version. It fabricated a rule description for the non-existent rule 847293 using content from other training pairs (specifically the password spraying content). With only 10 training pairs, the model learned the correct answers well but did not generalise the "admit uncertainty for unknown inputs" behaviour.

This is a fundamental limitation of small-dataset fine-tuning. Fixing hallucination requires either:
- RAG (proven effective — 10/10)
- Many more uncertainty training pairs (untested)
- A larger fine-tuning dataset that includes diverse examples of appropriate uncertainty

---

## Iteration 2 — Targeted Fine-Tuning and Re-Evaluation

### Motivation

The v1 fine-tune scored well on alert analysis (T1, T2) but was weak on hallucination resistance (T3: 3-4/10), decoder generation (T4: 6/10), and false positive reasoning (T5: 6-7/10). Rather than expanding the dataset broadly, seven new training pairs were added (17 total) specifically targeting each observed weak point:

- **0x17 explicitly reinforced in a T1-style example** — designed to further strengthen the model's strongest existing indicator
- **Two additional "unknown rule ID" variants** — testing whether the uncertainty-admission pattern from the single original example would generalise
- **Two Wazuh decoder XML examples** — directly targeting T4's near-functional but imperfect output
- **A false positive example using /etc/passwd checksum drift** — generalising the "verify before concluding" pattern beyond the single original /usr/bin/diff example
- **T1558.003 reinforced in a second multi-alert chain context** — strengthening T2's technique identification

### Discovery: A Harness Bug, Not a Model Bug

Re-evaluating soc-finetuned-v2 initially produced a near-total collapse — 1.2/10 average, four of five tests returning `EMPTY_RESPONSE`. Investigation (dumping the raw Ollama response object rather than trusting the harness's parsed output) traced this to how Ollama exposes reasoning-model output: for prompts requiring more extended reasoning, the model was completing its full analysis inside a separate `thinking` field and then stopping (`done_reason: 'stop'`) without writing anything further to `content`. `evaluate.py`'s `get_response()` only ever read `content`, so a genuinely correct, complete answer sitting in `thinking` was being scored as a total failure.

Confirmed directly: the raw response to the Test 2 prompt (multi-alert kill chain) contained a fully correct answer — all three MITRE techniques in the right order, explicit "do not isolate DC01" guidance, specific remediation steps — entirely inside the unread `thinking` field, with `content` empty.

**Fix:** fall back to `thinking` when `content` is empty, in both the primary call and the retry path.

This is worth documenting as its own finding, separate from anything about the model's actual capability: a locally-hosted reasoning model can produce a correct, complete SOC triage and still register as a hard failure if the pipeline consuming it isn't written to expect a split response. That's a real integration risk for any production Wazuh-to-LLM alerting pipeline built on a reasoning model, not just an artifact of this evaluation harness.

### Results After the Fix

With the parsing fix applied, both fine-tuned models were re-evaluated alongside the two general-model baselines, all under the same harness version in the same session:

| Test | deepseek-r1:14b | foundation-sec-reasoning | soc-finetuned (v1) | soc-finetuned-v2 |
|---|---|---|---|---|
| Kerberoasting (T1) | 4/10 | 9/10 | 10/10 | 10/10 |
| Multi-alert chain (T2) | 3/10 | 3/10 | 10/10 | 9/10 |
| Hallucination (T3) | 7/10 | 4/10 | 4/10 | 5/10 |
| Decoder generation (T4) | 7/10 | 7/10 | 6/10 | 10/10 |
| False positive (T5) | 7/10 | 3/10 | 5/10 | 9/10 |
| **Average** | **5.6** | **5.2** | **7.0** | **8.6** |

*Captured 2026-09-12, harness v3, single comparison run. These numbers are a fresh, internally consistent re-run under the current harness and scoring logic — they are not a direct extension of the "Original Comparison" table above. The DeepSeek/Llama baselines in that table were measured under an earlier harness version, so the two tables shouldn't be read as one continuous series.*

Three of the five targeted fixes moved exactly as designed: hallucination resistance, decoder generation, and false positive reasoning all improved from v1 to v2, with decoder generation going from a 6/10 partial pass to a clean 10/10 once the two new XML examples were added.

### An Honest Note on Run-to-Run Variance

An earlier single-model run of v2 (same prompts, same temperature=0.15) scored T1 at 6/10 and T2 at 6/10 — both notably lower than the 10/10 and 9/10 in the table above. At first this looked like the T1/T2-targeted reinforcement pairs were actively interfering with previously-correct behaviour, a known failure mode in small-dataset fine-tuning (catastrophic interference). A second run under identical conditions did not reproduce that drop, which points to sampling variance rather than a genuine capability regression — temperature 0.15 is low but non-zero, and on a five-question suite, a single test flipping between PARTIAL and PASS moves the average by 0.6–0.8 points on its own.

Notably, v1 stayed fairly stable across the same two observations (7.2 then 7.0), while v2 swung more (7.8 then 8.6, with individual test scores moving by up to 4 points between runs). That asymmetry is itself worth flagging: v2 scores higher on average, but appears less consistent run-to-run than v1 — a real, if secondary, finding rather than a clean improvement story. Any single evaluation run on a five-question suite should be treated as one sample, not a definitive score; the practical takeaway carried into Future Work below is to run each comparison multiple times and report a range, not a point estimate.

---

## Additional Key Findings (Iteration 2)

### Finding 8 — Reasoning-model output can hide a complete, correct answer from anything that only reads the final response field

Ollama-served reasoning models can place their entire analysis in a `thinking` field and leave `content` empty once they consider the reasoning itself sufficient. A harness — or a production pipeline — that only reads `content` will score a fully correct SOC triage as a hard failure. This is a real integration risk for any Wazuh-to-LLM alerting pipeline built on a reasoning model, and it was only caught by dumping the raw API response rather than trusting the harness's summary output.

### Finding 9 — Targeted small-dataset fine-tuning improves weak points but may increase output variance

Adding seven pairs targeting three specific weak tests (hallucination, decoder generation, false positive reasoning) improved all three as intended. But the same round of training coincided with markedly higher run-to-run score variance on tests it wasn't specifically targeting, compared to v1's stability across repeated runs. Whether this is caused by the added pairs specifically or is a general property of iterating on an already-small (10→17 pair) LoRA adapter is untested — worth tracking across any future dataset expansion.

---

## The Optimal Architecture

Based on all testing, the recommended production architecture is:

```
Foundation-Sec-8B-Reasoning (base)
         +
LoRA fine-tuning on domain data
         +
RAG knowledge base
         +
Improved modelfile (behavioural guardrails)
         =
Estimated 8-9/10 average on SOC tasks
```

Each layer addresses a different failure mode:
- **Fine-tuning** fixes technique identification, rule generation, false positive reasoning
- **RAG** fixes environment-specific hallucination (rule IDs, custom configurations)
- **Modelfile** fixes dangerous response advice (DC isolation, premature containment)
- **Foundation-Sec base** provides security domain knowledge the general models lack

The Iteration 2 fine-tune alone reached an 8.6/10 average without RAG or an updated modelfile — suggesting the estimate above may be conservative once those layers are combined with a targeted fine-tune rather than the original 10-pair version.

### Production Integration Architecture

```
Wazuh Alert fires
        ↓
Alert data formatted as plain text (avoid JSON to prevent tool-calling)
        ↓
RAG retrieves: matching playbook + known rules + asset context
        ↓
Fine-tuned Foundation-Sec generates: triage summary + MITRE mapping + recommended actions
        ↓
Response parsing reads BOTH `content` and `thinking` fields (Finding 8)
        ↓
Human analyst reviews and approves
        ↓
Response actioned
```

In a Confluence-integrated deployment, the RAG knowledge base would contain:
- Runbooks and playbooks
- Asset inventory (IP → hostname → owner → expected behaviour)
- Known false positive documentation
- Environment-specific Wazuh rule documentation
- Threat intelligence feeds

This architecture eliminates the hallucination problem for environment-specific queries while the fine-tuned model handles the analytical reasoning.

---

## Fine-Tuning Process

### Training Data Format

Training data was formatted as JSONL instruction/input/output pairs:

```json
{
  "instruction": "Analyse this Wazuh alert...",
  "input": "Agent: DC01. Event ID: 4769...",
  "output": "Technique Identified: Kerberoasting - T1558.003..."
}
```

**v1 — ten pairs covered:**
- Correct Kerberoasting analysis (fixing T1003.001 vs T1558.003 confusion)
- Correct multi-alert chain narrative (fixing spray vs brute force misidentification)
- Unknown rule ID uncertainty (partial fix)
- Correct Wazuh decoder XML syntax
- False positive protocol for FIM alerts
- Kerberoasting vs Silver Ticket distinction
- DCSync detection Event IDs
- Suspicious NTLM analysis
- Wazuh decoder element reference
- Password spraying vs brute force detection logic

**v2 — seven additional pairs (17 total):**
- 0x17 explicitly named in a second T1-style example
- Two further unknown-rule-ID variants (uncertainty generalisation)
- Two additional decoder XML examples
- False positive example generalised to /etc/passwd
- T1558.003 reinforced in a second multi-alert chain context

### Training Configuration

```
Base model: Foundation-Sec-8B-Reasoning
Method: LoRA (Low-Rank Adaptation)
LoRA rank: 16
Target modules: q_proj, k_proj, v_proj, o_proj, gate_proj, up_proj, down_proj
Training steps: 60
Learning rate: 2e-4
Batch size: 2 (with gradient accumulation 4 = effective batch 8)
Training time: 3 minutes 9 seconds
Final loss: 0.011 (from 2.095 at step 1)
```

The loss curve showed rapid convergence — dropping from 2.095 at step 5 to 0.045 at step 30 and 0.011 at step 60. This is expected behaviour for a small, high-quality dataset fine-tuning a model that already has domain knowledge.

---

## Limitations and Honest Gaps

**Hallucination not fully solved:** Even after Iteration 2, the fine-tuned model scores 4-5/10 on the hallucination test. RAG is still required for production deployment. Fine-tuning and RAG are complementary, not alternatives.

**Small training dataset:** 17 pairs is enough to demonstrate the technique and fix specific failure modes, but a production-quality fine-tune would require hundreds of diverse examples. The improvement is real but generalisation is limited, and Finding 9 suggests small-dataset iteration may trade some consistency for average improvement.

**Wazuh syntax mostly fixed, not proven robust:** The Iteration 2 decoder output scored a clean 10/10 on this specific test, but that's one prompt — it demonstrates the two new training examples worked for this exact case, not that decoder generation is robust across arbitrary log formats.

**Knowledge cutoff:** Foundation-Sec-8B-Reasoning has a training data cutoff of April 2025. Novel attack techniques, new CVEs, and recently discovered TTPs after that date will not be in the model's knowledge.

**Windows deployment complexity:** The RTX 5070 Ti (Blackwell/sm_120) requires PyTorch nightly builds. Stable PyTorch does not support this GPU as of September 2026. Production deployment on similarly recent hardware requires careful dependency management.

**Evaluation variance is real and under-characterised:** Individual test scores have been observed to swing by up to 4 points between identical runs of the same model. Every score in this document should be read as a single sample rather than a precise measurement until backed by repeated runs (see Future Work).

**Human review remains essential:** Even the best-performing configuration (8.6/10 average, Iteration 2) makes errors on some assessments. This tool augments analyst capability — it does not replace analyst judgment. Every model output should be reviewed before acting on it.

---

## Skills Demonstrated

- Local LLM deployment and management (Ollama, Open WebUI)
- Systematic AI evaluation methodology (consistent test suite, before/after comparison)
- Prompt engineering for security domain tasks (temperature tuning, structured output, behavioural guardrails)
- RAG implementation (knowledge base construction, document embedding, retrieval grounding)
- Python environment management (Conda, CUDA compatibility, dependency resolution)
- LoRA fine-tuning with Unsloth on consumer GPU hardware
- Model comparison across architectures (general vs specialist, reasoning vs instruct)
- Root-cause debugging of an LLM serving pipeline (isolating a scoring failure to an unread API response field rather than assuming a model capability issue)
- Hypothesis-driven, targeted dataset curation (designing new training pairs against specific observed failure modes rather than broad, undirected dataset expansion)
- Statistical awareness of small-sample evaluation variance, and the discipline to re-run before trusting a result
- Honest capability and limitation assessment
- Security AI architecture design (when to use RAG vs fine-tuning vs prompt engineering)
- MITRE ATT&CK: T1558.003, T1110.003, T1550.002, T1003.002, T1558.001

---

## Future Work

**Repeat evaluation runs for statistical confidence:** Given observed variance of up to 4 points per test between identical runs, future comparisons should run each model 3-5 times and report a mean and range rather than a single score.

**Expand training dataset:** Now at 17 pairs (up from 10). Scrape Atomic Red Team technique files for the covered techniques, convert to training pairs. Target 100-200 pairs for meaningful generalisation improvement, tracking whether the variance observed in Finding 9 persists, worsens, or resolves as the dataset grows.

**RAG + fine-tuned model combined:** The optimal architecture was identified but not fully tested end-to-end. Combining the Iteration 2 fine-tuned model with the RAG knowledge base should be tested next.

**Wazuh integration:** Pipe live Wazuh alerts directly to the model via the Wazuh API. Alert fires → formatted automatically → model generates triage → logged for analyst review. This is the SOAR-adjacent project identified earlier in the portfolio. Any implementation must read both `content` and `thinking` fields per Finding 8.

**Continuous evaluation:** Establish a regression test suite. Every time the model is updated or retrained, run all five tests (multiple times, per the point above) and track scores over time.

**ADCS and newer technique coverage:** The training data covers the 10 original portfolio projects. Adding ADCS (ESC1/ESC8), SOAR evasion, and cloud attack techniques would extend coverage.