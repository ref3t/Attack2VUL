from __future__ import annotations

import json
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
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError:
        match = re.search(r"\[[\s\S]*\]", stripped)
        if not match:
            raise
        data = json.loads(match.group(0))
    if not isinstance(data, list):
        raise ValueError("LLM response must be a JSON array.")
    return data


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
    outputs = []
    records = read_jsonl(candidates_path)
    for record in tqdm(records, desc="RAG reranking"):
        prompt = render_prompt(record)
        candidate_ids = {str(item["cve_id"]) for item in record.get("candidates", [])}
        content = query_openai_compatible(base_url, model, prompt, temperature, top_p, max_tokens, api_key)
        try:
            decisions = _normalize_decisions(_extract_json_array(content), candidate_ids)
        except Exception as exc:
            retry_prompt = prompt + f"\n\nYour previous response could not be parsed: {exc}. Return only the JSON array."
            content = query_openai_compatible(base_url, model, retry_prompt, temperature, top_p, max_tokens, api_key)
            decisions = _normalize_decisions(_extract_json_array(content), candidate_ids)

        linked = [item["cve_id"] for item in decisions if item["decision"] == "linked"]
        outputs.append(
            {
                **record,
                "decisions": decisions,
                "rag_linked_cves": linked,
            }
        )

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
