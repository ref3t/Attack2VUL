#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PYTHON_BIN="${PYTHON_BIN:-python}"
TOP_K="${TOP_K:-20}"
RANK_LIMIT="${RANK_LIMIT:-200}"
OUTPUT_DIR="${OUTPUT_DIR:-VULDAT-RAG/outputs}"
RUN_SENSITIVITY="${RUN_SENSITIVITY:-1}"
RUN_RAG="${RUN_RAG:-1}"
RAG_BACKEND="${RAG_BACKEND:-ollama}"
OLLAMA_MODEL="${OLLAMA_MODEL:-llama3.1:8b}"
VLLM_MODEL="${VLLM_MODEL:-meta-llama/Llama-3.1-8B-Instruct}"
OLLAMA_BASE_URL="${OLLAMA_BASE_URL:-http://localhost:11434/v1/chat/completions}"
VLLM_BASE_URL="${VLLM_BASE_URL:-http://localhost:8000/v1/chat/completions}"
START_OLLAMA="${START_OLLAMA:-1}"
PULL_OLLAMA_MODEL="${PULL_OLLAMA_MODEL:-0}"

BASELINE_FILE="$OUTPUT_DIR/baseline_top${TOP_K}.jsonl"
BASELINE_METRICS="$OUTPUT_DIR/metrics_baseline.csv"
RAG_FILE="$OUTPUT_DIR/rag_predictions.jsonl"
RAG_METRICS="$OUTPUT_DIR/metrics_rag.csv"

run_step() {
  printf '\nStep: %s\n' "$1"
}

wait_for_endpoint() {
  local url="$1"
  local attempts="${2:-30}"
  local models_url="${url%/chat/completions}/models"
  for _ in $(seq 1 "$attempts"); do
    if curl -fsS "$models_url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  return 1
}

ensure_ollama() {
  if ! command -v ollama >/dev/null 2>&1; then
    printf 'Ollama is not installed. Install it first from https://ollama.com/download/mac\n' >&2
    exit 1
  fi

  if curl -fsS http://localhost:11434/v1/models >/dev/null 2>&1; then
    return 0
  fi

  if [[ "$START_OLLAMA" != "1" ]]; then
    printf 'Ollama is not running. Start it with: ollama serve\n' >&2
    exit 1
  fi

  mkdir -p "$OUTPUT_DIR"
  run_step "Starting Ollama server"
  ollama serve >"$OUTPUT_DIR/ollama.log" 2>&1 &
  if ! wait_for_endpoint "$OLLAMA_BASE_URL" 30; then
    printf 'Ollama did not become ready. See %s/ollama.log\n' "$OUTPUT_DIR" >&2
    exit 1
  fi
}

run_step "Environment doctor"
"$PYTHON_BIN" VULDAT-RAG/run.py doctor || true

run_step "Build annotated dataset"
"$PYTHON_BIN" VULDAT-RAG/run.py --output-dir "$OUTPUT_DIR" build-dataset

run_step "Frozen MPNet retrieval"
"$PYTHON_BIN" VULDAT-RAG/run.py --output-dir "$OUTPUT_DIR" retrieve \
  --device auto \
  --top-k "$TOP_K" \
  --rank-limit "$RANK_LIMIT" \
  --reuse-cve-embeddings

run_step "Evaluate baseline"
"$PYTHON_BIN" VULDAT-RAG/run.py --output-dir "$OUTPUT_DIR" evaluate \
  --predictions "$BASELINE_FILE" \
  --name baseline \
  --output "$BASELINE_METRICS"

if [[ "$RUN_SENSITIVITY" == "1" ]]; then
  run_step "Top-k sensitivity"
  "$PYTHON_BIN" VULDAT-RAG/run.py --output-dir "$OUTPUT_DIR" sensitivity \
    --rankings "$OUTPUT_DIR/rankings.jsonl"
fi

if [[ "$RUN_RAG" == "1" ]]; then
  if [[ "$RAG_BACKEND" == "ollama" ]]; then
    ensure_ollama
    if [[ "$PULL_OLLAMA_MODEL" == "1" ]]; then
      run_step "Pull Ollama model"
      ollama pull "$OLLAMA_MODEL"
    fi
    BASE_URL="$OLLAMA_BASE_URL"
    MODEL="$OLLAMA_MODEL"
  elif [[ "$RAG_BACKEND" == "vllm" ]]; then
    BASE_URL="$VLLM_BASE_URL"
    MODEL="$VLLM_MODEL"
  else
    printf 'Unsupported RAG_BACKEND=%s. Use ollama or vllm.\n' "$RAG_BACKEND" >&2
    exit 1
  fi

  run_step "RAG reranking via $RAG_BACKEND"
  "$PYTHON_BIN" VULDAT-RAG/run.py --output-dir "$OUTPUT_DIR" rag \
    --candidates "$BASELINE_FILE" \
    --output "$RAG_FILE" \
    --base-url "$BASE_URL" \
    --model "$MODEL"

  run_step "Evaluate RAG"
  "$PYTHON_BIN" VULDAT-RAG/run.py --output-dir "$OUTPUT_DIR" evaluate \
    --predictions "$RAG_FILE" \
    --name rag \
    --output "$RAG_METRICS"

  run_step "Compare baseline vs RAG"
  "$PYTHON_BIN" VULDAT-RAG/run.py --output-dir "$OUTPUT_DIR" compare \
    --baseline "$BASELINE_METRICS" \
    --rag "$RAG_METRICS" \
    --output "$OUTPUT_DIR/comparison.csv"

  run_step "Export manual-validation candidates"
  "$PYTHON_BIN" VULDAT-RAG/run.py --output-dir "$OUTPUT_DIR" export-new-links \
    --rag "$RAG_FILE" \
    --output "$OUTPUT_DIR/manual_validation_candidates.csv"
fi

printf '\nDone. Outputs are in %s\n' "$OUTPUT_DIR"
