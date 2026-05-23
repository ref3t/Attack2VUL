# VULDAT-RAG

RAG pipeline for ATT&CK2VUL / VULDAT using the existing datasets in this repository.

This version **does not fine-tune MPNet**. It uses `sentence-transformers/multi-qa-mpnet-base-dot-v1` exactly as released, then optionally sends the transformer's top-k CVE candidates to a local Llama-3.1-8B-Instruct endpoint for JSON reranking.

## What It Builds

The code follows the paper pipeline with one deliberate change:

- Stage 1: construct the attack-to-CVE oracle `M(a)` from `../dataset/VULDATDataSet.xlsx`.
- Stage 2: preprocess text and retrieve with frozen MPNet embeddings.
- Stage 3: choose/evaluate top-k values, with `k=20` as the default.
- Stage 4: rerank top-k candidates through a local vLLM endpoint.
- Stage 5: evaluate baseline vs RAG and export candidate missing links for manual validation.

The fine-tuning step is intentionally omitted.

## Install

From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r VULDAT-RAG/requirements.txt
```

For local LLM reranking, also install the Ollama app/CLI. The Python `ollama` package is listed in `requirements.txt`, but `ollama serve` requires the local Ollama runtime.

Without Homebrew, use Ollama's installer:

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

Or download the macOS app from https://ollama.com/download/mac.

Check what this machine can use:

```bash
python VULDAT-RAG/run.py doctor
```

## Run Everything Once

For the local workflow, run the whole pipeline with one command:

```bash
bash VULDAT-RAG/run_all.sh
```

The script runs:

- `doctor`
- `build-dataset`
- frozen MPNet `retrieve --device auto --top-k 20 --rank-limit 200`
- baseline evaluation
- top-k sensitivity
- Ollama RAG reranking
- RAG evaluation
- baseline-vs-RAG comparison
- manual-validation candidate export

Useful options:

```bash
RUN_RAG=0 bash VULDAT-RAG/run_all.sh
RUN_SENSITIVITY=0 bash VULDAT-RAG/run_all.sh
TOP_K=50 RANK_LIMIT=200 bash VULDAT-RAG/run_all.sh
CVE_TEXT_MODE=description_technique RUN_RAG=0 bash VULDAT-RAG/run_all.sh
PULL_OLLAMA_MODEL=1 bash VULDAT-RAG/run_all.sh
RAG_BACKEND=vllm bash VULDAT-RAG/run_all.sh
```

By default, the script uses Ollama locally. If Ollama is installed but not running, it starts `ollama serve` in the background and writes logs to `VULDAT-RAG/outputs/ollama.log`.

## Baseline Retrieval

Build the annotated dataset:

```bash
python VULDAT-RAG/run.py build-dataset
```

Run frozen MPNet retrieval and write top-k/ranking files:

```bash
python VULDAT-RAG/run.py retrieve --device auto --top-k 20 --rank-limit 200
```

`--device auto` tries CUDA first, then Apple Silicon MPS, then CPU. You can force a device with `--device cuda`, `--device mps`, or `--device cpu`.

Evaluate the baseline top-k predictions:

```bash
python VULDAT-RAG/run.py evaluate --predictions VULDAT-RAG/outputs/baseline_top20.jsonl --name baseline
```

Run the sensitivity analysis for `k in {10,20,30,40,50,100,150,200}`:

```bash
python VULDAT-RAG/run.py sensitivity
```

## Technique-Name CVE Text Experiment

This experiment embeds each CVE as:

```text
CVE description + related TechniqueName values
```

Run retrieval with this CVE text mode:

```bash
python VULDAT-RAG/run.py retrieve \
  --device auto \
  --cve-text-mode description_technique \
  --top-k 20 \
  --rank-limit 200
```

Evaluate the result:

```bash
python VULDAT-RAG/run.py evaluate \
  --predictions VULDAT-RAG/outputs/baseline_top20_description_technique.jsonl \
  --name baseline_description_technique \
  --output VULDAT-RAG/outputs/metrics_baseline_description_technique.csv
```

Or run the experiment in one command:

```bash
CVE_TEXT_MODE=description_technique RUN_RAG=0 bash VULDAT-RAG/run_all.sh
```

This is an oracle-enriched ablation because the related technique names come from the existing MITRE-derived mapping.

## RAG Reranking

There are two separate places where hardware matters:

- MPNet retrieval: can run locally and falls back to CPU with `--device auto`.
- LLM reranking: use Ollama for local macOS/CPU testing; use vLLM only on a Linux CUDA GPU server.

### Local macOS / CPU Path

```bash
ollama pull llama3.1:8b
ollama serve
```

In another terminal:

```bash
python VULDAT-RAG/run.py rag \
  --candidates VULDAT-RAG/outputs/baseline_top20.jsonl \
  --base-url http://localhost:11434/v1/chat/completions \
  --model llama3.1:8b
```

Or, if either vLLM or Ollama is already running:

```bash
python VULDAT-RAG/run.py rag-auto \
  --candidates VULDAT-RAG/outputs/baseline_top20.jsonl
```

### Option A: vLLM on a Linux CUDA GPU Server

The paper setup assumes a CUDA GPU server, for example an A100 80 GB. Run this part on a Linux GPU machine, not on a local macOS environment. Use a separate Python 3.10+ environment for vLLM.

Do not run this command on the local Mac:

```bash
vllm serve meta-llama/Llama-3.1-8B-Instruct \
  --dtype auto \
  --max-model-len 8192
```

Create a fresh environment and install vLLM:

```bash
python3.11 -m venv .venv-vllm
source .venv-vllm/bin/activate
python --version
pip install --upgrade pip
pip install vllm --extra-index-url https://download.pytorch.org/whl/cu129
```

Then serve the model:

```bash
vllm serve meta-llama/Llama-3.1-8B-Instruct \
  --dtype auto \
  --max-model-len 8192
```

You may need to log in to Hugging Face and accept the Llama model license before the checkpoint can download:

```bash
huggingface-cli login
```

If you see an error like `TypeError: unsupported operand type(s) for |: 'type' and 'NoneType'`, your vLLM environment is running Python 3.9. Recreate the vLLM environment with Python 3.10 or newer.

If vLLM prints `Automatically detected platform cpu` on macOS, that is also expected: the command is being run in the wrong runtime for the paper setup. Use the Linux GPU server path above, or use the Ollama fallback below for local testing.

Then call the reranker:

```bash
python VULDAT-RAG/run.py rag \
  --candidates VULDAT-RAG/outputs/baseline_top20.jsonl \
  --base-url http://localhost:8000/v1/chat/completions \
  --model meta-llama/Llama-3.1-8B-Instruct
```

The local Ollama path is useful for testing, but it is not the exact vLLM/A100 serving setup described in the paper protocol.

### Practical Local Flow

For local development, run:

```bash
python VULDAT-RAG/run.py doctor
python VULDAT-RAG/run.py retrieve --device auto --top-k 20 --rank-limit 200
```

Then:

- If `doctor` shows a CUDA GPU and a vLLM endpoint, use the vLLM `rag` command.
- If not, start Ollama and use the Ollama `rag` command.

If one of those endpoints is already running, you can let the code pick:

```bash
python VULDAT-RAG/run.py rag-auto \
  --candidates VULDAT-RAG/outputs/baseline_top20.jsonl
```

`rag-auto` prefers vLLM at `localhost:8000`; if that is unavailable, it tries Ollama at `localhost:11434`.

### Other LLM Providers

The RAG code also accepts provider-prefixed model names:

```text
ollama:llama3.1:8b
lmstudio:local-model
gemini:gemini-2.5-flash
groq:MODEL_ID_FROM_GROQ
openrouter:MODEL_ID_FROM_OPENROUTER
huggingface:MODEL_ID_FROM_HUGGINGFACE
mistral:MODEL_ID_FROM_MISTRAL
openai:gpt-4o-mini
anthropic:claude-3-5-sonnet-latest
```

Ollama and LM Studio can run locally without keys. Gemini, Groq, OpenRouter, Hugging Face, Mistral, OpenAI, and Anthropic require their matching API key in an environment variable.

Evaluate RAG:

```bash
python VULDAT-RAG/run.py evaluate --predictions VULDAT-RAG/outputs/rag_predictions.jsonl --name rag
```

Compare baseline and RAG:

```bash
python VULDAT-RAG/run.py compare \
  --baseline VULDAT-RAG/outputs/metrics_baseline.csv \
  --rag VULDAT-RAG/outputs/metrics_rag.csv
```

Export RAG recommendations not already present in the MITRE-derived oracle:

```bash
python VULDAT-RAG/run.py export-new-links \
  --rag VULDAT-RAG/outputs/rag_predictions.jsonl
```

## Outputs

All generated files go under `VULDAT-RAG/outputs/` by default:

- `annotated_attacks.jsonl`: attack rows with `M(a)`.
- `cve_corpus.csv`: deduplicated CVE corpus.
- `rankings.jsonl`: ranked candidates up to `--rank-limit`.
- `baseline_top20.jsonl`: MPNet top-k predictions.
- `rag_predictions.jsonl`: LLM-validated subset of top-k.
- `metrics_*.csv`: per-attack metrics.
- `comparison.csv`: mean/median/delta/significance table.
- `manual_validation_candidates.csv`: RAG links absent from `M(a)`.
