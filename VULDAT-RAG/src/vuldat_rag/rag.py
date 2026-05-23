from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

import requests
from requests import HTTPError
from tqdm import tqdm

from .io_utils import read_jsonl, write_jsonl


SYSTEM_PROMPT = """You are a cybersecurity vulnerability analyst. Decide whether each candidate CVE is explicitly or strongly linked to the given attack description. Use only the provided attack text and candidate CVE text."""

USER_TEMPLATE = """Attack description:
{attack_text}

Candidate CVEs:
{candidates}

For each candidate, decide whether it is linked to the attack. Base the decision on three facets:
1. affected component
2. exploitation mechanism
3. observable consequence

Return only valid JSON in this exact shape:
[
  {{"cve_id": "CVE-YYYY-NNNN", "decision": "linked"}},
  {{"cve_id": "CVE-YYYY-NNNN", "decision": "not_linked"}}
]
"""


def split_model_spec(model: str) -> tuple[str, str]:
    known = {
        "openai",
        "anthropic",
        "gemini",
        "groq",
        "openrouter",
        "huggingface",
        "mistral",
        "ollama",
        "lmstudio",
        "vllm",
        "openai-compatible",
    }
    if ":" in model:
        prefix, name = model.split(":", 1)
        if prefix in known:
            return prefix, name
    return "openai-compatible", model


def render_prompt(record: dict) -> str:
    candidate_lines = []
    for index, candidate in enumerate(record.get("candidates", []), start=1):
        candidate_lines.append(
            "\n".join(
                [
                    f"{index}. ID: {candidate['cve_id']}",
                    f"   MPNet similarity: {candidate['similarity']:.4f}",
                    f"   Description: {candidate['description']}",
                ]
            )
        )
    return USER_TEMPLATE.format(
        attack_text=record["attack_text"],
        candidates="\n\n".join(candidate_lines),
    )


def _extract_json_array(text: str) -> list[dict[str, Any]]:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?\s*", "", stripped)
        stripped = re.sub(r"\s*```$", "", stripped)
    decoder = json.JSONDecoder()
    errors = []
    starts = [0] + [match.start() for match in re.finditer(r"\[", stripped)]
    for start in starts:
        candidate = stripped[start:].strip()
        try:
            data, _ = decoder.raw_decode(candidate)
        except json.JSONDecodeError as exc:
            errors.append(exc)
            continue
        if isinstance(data, dict):
            for key in ("decisions", "results", "cves"):
                if isinstance(data.get(key), list):
                    return data[key]
        if isinstance(data, list):
            return data
    match = re.search(r"\[[\s\S]*?\]", stripped)
    if match:
        data = json.loads(match.group(0))
        if isinstance(data, list):
            return data
    if errors:
        raise errors[-1]
    raise ValueError("LLM response must contain a JSON array.")


def _normalize_decisions(data: list[dict[str, Any]], candidate_ids: set[str]) -> list[dict[str, str]]:
    normalized = []
    seen = set()
    for item in data:
        cve_id = str(item.get("cve_id", "")).strip()
        decision = str(item.get("decision", "")).strip().lower().replace("-", "_")
        if decision not in {"linked", "not_linked"}:
            decision = "linked" if decision in {"yes", "true", "related"} else "not_linked"
        if cve_id in candidate_ids:
            normalized.append({"cve_id": cve_id, "decision": decision})
            seen.add(cve_id)
    for cve_id in sorted(candidate_ids - seen):
        normalized.append({"cve_id": cve_id, "decision": "not_linked"})
    return normalized


def query_openai_compatible(
    base_url: str,
    model: str,
    prompt: str,
    temperature: float = 0.0,
    top_p: float = 1.0,
    max_tokens: int = 1024,
    api_key: str | None = None,
) -> str:
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "temperature": temperature,
        "top_p": top_p,
        "max_tokens": max_tokens,
    }
    response = requests.post(base_url, headers=headers, json=payload, timeout=180)
    try:
        response.raise_for_status()
    except HTTPError as exc:
        body = response.text.strip()
        if len(body) > 2000:
            body = body[:2000] + "..."
        raise RuntimeError(f"LLM endpoint returned HTTP {response.status_code}: {body}") from exc
    body = response.json()
    return body["choices"][0]["message"]["content"]


def query_anthropic(
    model: str,
    prompt: str,
    temperature: float = 0.0,
    top_p: float = 1.0,
    max_tokens: int = 1024,
    api_key: str | None = None,
    base_url: str = "https://api.anthropic.com/v1/messages",
) -> str:
    key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise RuntimeError("ANTHROPIC_API_KEY is required for Anthropic models.")
    headers = {
        "Content-Type": "application/json",
        "x-api-key": key,
        "anthropic-version": "2023-06-01",
    }
    payload = {
        "model": model,
        "system": SYSTEM_PROMPT,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": temperature,
        "top_p": top_p,
        "max_tokens": max_tokens,
    }
    response = requests.post(base_url, headers=headers, json=payload, timeout=180)
    try:
        response.raise_for_status()
    except HTTPError as exc:
        body = response.text.strip()
        if len(body) > 2000:
            body = body[:2000] + "..."
        raise RuntimeError(f"Anthropic endpoint returned HTTP {response.status_code}: {body}") from exc
    body = response.json()
    parts = []
    for item in body.get("content", []):
        if item.get("type") == "text":
            parts.append(item.get("text", ""))
    return "\n".join(parts)


def query_llm(
    base_url: str,
    model: str,
    prompt: str,
    temperature: float = 0.0,
    top_p: float = 1.0,
    max_tokens: int = 1024,
    api_key: str | None = None,
) -> str:
    provider, model_name = split_model_spec(model)
    if provider == "anthropic":
        return query_anthropic(model_name, prompt, temperature, top_p, max_tokens, api_key)

    provider_configs = {
        "openai": ("https://api.openai.com/v1/chat/completions", "OPENAI_API_KEY", True),
        "gemini": ("https://generativelanguage.googleapis.com/v1beta/openai/chat/completions", "GEMINI_API_KEY", True),
        "groq": ("https://api.groq.com/openai/v1/chat/completions", "GROQ_API_KEY", True),
        "openrouter": ("https://openrouter.ai/api/v1/chat/completions", "OPENROUTER_API_KEY", True),
        "huggingface": ("https://router.huggingface.co/v1/chat/completions", "HF_TOKEN", True),
        "mistral": ("https://api.mistral.ai/v1/chat/completions", "MISTRAL_API_KEY", True),
        "ollama": ("http://localhost:11434/v1/chat/completions", None, False),
        "lmstudio": ("http://localhost:1234/v1/chat/completions", None, False),
        "vllm": ("http://localhost:8000/v1/chat/completions", None, False),
    }

    if provider in provider_configs:
        endpoint, env_name, needs_key = provider_configs[provider]
        key = api_key
        if env_name:
            key = key or os.environ.get(env_name)
            if env_name == "HF_TOKEN":
                key = key or os.environ.get("HUGGINGFACE_HUB_TOKEN")
        if needs_key and not key:
            raise RuntimeError(f"{env_name} is required for {provider} models.")
        return query_openai_compatible(endpoint, model_name, prompt, temperature, top_p, max_tokens, key)

    return query_openai_compatible(base_url, model_name, prompt, temperature, top_p, max_tokens, api_key)


def run_rag(
    candidates_path: Path,
    output_path: Path,
    base_url: str,
    model: str,
    temperature: float = 0.0,
    top_p: float = 1.0,
    max_tokens: int = 1024,
    api_key: str | None = None,
) -> Path:
    outputs = read_jsonl(output_path) if output_path.exists() else []
    done = {(item.get("attack_type"), item.get("attack_id")) for item in outputs}
    records = read_jsonl(candidates_path)
    for record in tqdm(records, desc="RAG reranking"):
        key = (record.get("attack_type"), record.get("attack_id"))
        if key in done:
            continue
        prompt = render_prompt(record)
        candidate_ids = {str(item["cve_id"]) for item in record.get("candidates", [])}
        if not candidate_ids:
            outputs.append(
                {
                    **record,
                    "decisions": [],
                    "rag_linked_cves": [],
                }
            )
            done.add(key)
            write_jsonl(output_path, outputs)
            continue
        content = query_llm(base_url, model, prompt, temperature, top_p, max_tokens, api_key)
        try:
            decisions = _normalize_decisions(_extract_json_array(content), candidate_ids)
        except Exception as exc:
            retry_prompt = prompt + f"\n\nYour previous response could not be parsed: {exc}. Return only the JSON array."
            content = query_llm(base_url, model, retry_prompt, temperature, top_p, max_tokens, api_key)
            try:
                decisions = _normalize_decisions(_extract_json_array(content), candidate_ids)
            except Exception as retry_exc:
                decisions = [{"cve_id": cve_id, "decision": "not_linked"} for cve_id in sorted(candidate_ids)]
                outputs.append(
                    {
                        **record,
                        "decisions": decisions,
                        "rag_linked_cves": [],
                        "parse_error": str(retry_exc),
                        "raw_llm_response": content[:2000],
                    }
                )
                done.add(key)
                write_jsonl(output_path, outputs)
                continue

        linked = [item["cve_id"] for item in decisions if item["decision"] == "linked"]
        outputs.append(
            {
                **record,
                "decisions": decisions,
                "rag_linked_cves": linked,
            }
        )
        done.add(key)
        write_jsonl(output_path, outputs)

    write_jsonl(output_path, outputs)
    return output_path


def export_new_links(rag_predictions_path: Path, output_path: Path) -> Path:
    import pandas as pd

    rows = []
    for record in read_jsonl(rag_predictions_path):
        truth = {str(item) for item in record.get("ground_truth_cves", [])}
        linked = {str(item) for item in record.get("rag_linked_cves", [])}
        candidates_by_id = {item["cve_id"]: item for item in record.get("candidates", [])}
        for cve_id in sorted(linked - truth):
            candidate = candidates_by_id.get(cve_id, {})
            rows.append(
                {
                    "attack_type": record["attack_type"],
                    "attack_id": record["attack_id"],
                    "attack_name": record.get("attack_name", ""),
                    "attack_text": record["attack_text"],
                    "cve_id": cve_id,
                    "cve_description": candidate.get("description", ""),
                    "mpnet_similarity": candidate.get("similarity", ""),
                    "reviewer_1_label": "",
                    "reviewer_2_label": "",
                    "resolved_label": "",
                    "notes": "",
                }
            )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows).to_csv(output_path, index=False)
    return output_path
