from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Iterable

import pandas as pd

from .config import DatasetConfig, SCHEMAS
from .io_utils import write_jsonl
from .text import clean_text

CVE_TEXT_MODES = {"description", "description_technique"}


def _as_id(value: object) -> str:
    if pd.isna(value):
        return ""
    text = str(value).strip()
    return text[:-2] if text.endswith(".0") else text


def _first_non_empty(values: Iterable[object]) -> str:
    for value in values:
        if not pd.isna(value) and str(value).strip():
            return str(value).strip()
    return ""


def _unique_non_empty(values: Iterable[object]) -> list[str]:
    seen = set()
    out = []
    for value in values:
        if pd.isna(value):
            continue
        text = str(value).strip()
        if text and text not in seen:
            seen.add(text)
            out.append(text)
    return out


def load_mapping_table(config: DatasetConfig) -> pd.DataFrame:
    df = pd.read_excel(config.cve_mapping_file, sheet_name=0)
    required = {"CVEID", "CVEDescription"}
    missing = required.difference(df.columns)
    if missing:
        raise ValueError(f"{config.cve_mapping_file} is missing required columns: {sorted(missing)}")
    return df


def cve_corpus_path(output_dir: Path, text_mode: str) -> Path:
    if text_mode == "description":
        return output_dir / "cve_corpus.csv"
    return output_dir / f"cve_corpus_{text_mode}.csv"


def build_cve_corpus(mapping_df: pd.DataFrame, text_mode: str = "description") -> pd.DataFrame:
    if text_mode not in CVE_TEXT_MODES:
        raise ValueError(f"Unsupported CVE text mode: {text_mode}")

    corpus = mapping_df.dropna(subset=["CVEID"]).copy()
    corpus["cve_id"] = corpus["CVEID"].map(_as_id)

    rows = []
    for cve_id, group in corpus.groupby("cve_id", dropna=False):
        description = _first_non_empty(group["CVEDescription"])
        technique_names = _unique_non_empty(group["TechniqueName"]) if "TechniqueName" in group else []
        embedding_text = description
        if text_mode == "description_technique" and technique_names:
            embedding_text = f"{description} {' '.join(technique_names)}"
        rows.append(
            {
                "cve_id": cve_id,
                "cve_description": description,
                "related_technique_names": "; ".join(technique_names),
                "embedding_text": embedding_text,
                "clean_cve_text": clean_text(embedding_text),
            }
        )

    return pd.DataFrame(rows).sort_values("cve_id").reset_index(drop=True)


def build_ground_truth(mapping_df: pd.DataFrame) -> dict[tuple[str, str], set[str]]:
    truth: dict[tuple[str, str], set[str]] = defaultdict(set)
    for attack_type, schema in SCHEMAS.items():
        if schema.id_col not in mapping_df.columns:
            continue
        for _, row in mapping_df.dropna(subset=[schema.id_col, "CVEID"]).iterrows():
            attack_id = _as_id(row[schema.id_col])
            cve_id = _as_id(row["CVEID"])
            if attack_id and cve_id:
                truth[(attack_type, attack_id)].add(cve_id)

                if attack_type == "Technique" and "." in attack_id:
                    base_id = attack_id.split(".", 1)[0]
                    truth[(attack_type, base_id)].add(cve_id)
    return truth


def _records_from_mapping(mapping_df: pd.DataFrame, truth: dict[tuple[str, str], set[str]]) -> dict[tuple[str, str], dict]:
    records: dict[tuple[str, str], dict] = {}
    for attack_type, schema in SCHEMAS.items():
        if schema.id_col not in mapping_df.columns or schema.desc_col not in mapping_df.columns:
            continue

        grouped = mapping_df.dropna(subset=[schema.id_col]).groupby(schema.id_col, dropna=False)
        for attack_id_raw, group in grouped:
            attack_id = _as_id(attack_id_raw)
            key = (attack_type, attack_id)
            name = _first_non_empty(group[schema.name_col]) if schema.name_col and schema.name_col in group else ""
            desc = _first_non_empty(group[schema.desc_col])
            text = f"{name} {desc}".strip() if name else desc
            records[key] = {
                "attack_type": attack_type,
                "attack_id": attack_id,
                "attack_name": name,
                "attack_text": text,
                "clean_attack_text": clean_text(text),
                "ground_truth_cves": sorted(truth.get(key, set())),
                "source": "mapping",
            }

        if attack_type == "Technique":
            for attack_id in sorted({item.split(".", 1)[0] for item in mapping_df[schema.id_col].dropna().map(_as_id)}):
                key = (attack_type, attack_id)
                if key in records:
                    continue
                sub_rows = mapping_df[mapping_df[schema.id_col].fillna("").map(_as_id).str.startswith(f"{attack_id}.")]
                if sub_rows.empty:
                    continue
                name = _first_non_empty(sub_rows[schema.name_col]) if schema.name_col in sub_rows else ""
                desc = _first_non_empty(sub_rows[schema.desc_col])
                text = f"{name} {desc}".strip() if name else desc
                records[key] = {
                    "attack_type": attack_type,
                    "attack_id": attack_id,
                    "attack_name": name,
                    "attack_text": text,
                    "clean_attack_text": clean_text(text),
                    "ground_truth_cves": sorted(truth.get(key, set())),
                    "source": "mapping_base_technique",
                }
    return records


def _records_from_splits(config: DatasetConfig, truth: dict[tuple[str, str], set[str]]) -> dict[tuple[str, str], dict]:
    records: dict[tuple[str, str], dict] = {}
    for attack_type, files in config.split_files.items():
        schema = SCHEMAS[attack_type]
        for path in files:
            if not path.exists():
                continue
            df = pd.read_excel(path, sheet_name=0)
            if schema.id_col not in df.columns or schema.desc_col not in df.columns:
                continue
            for attack_id_raw, group in df.dropna(subset=[schema.id_col]).groupby(schema.id_col, dropna=False):
                attack_id = _as_id(attack_id_raw)
                key = (attack_type, attack_id)
                if key in records:
                    continue
                name = _first_non_empty(group[schema.name_col]) if schema.name_col and schema.name_col in group else ""
                desc = _first_non_empty(group[schema.desc_col])
                text = f"{name} {desc}".strip() if name else desc
                records[key] = {
                    "attack_type": attack_type,
                    "attack_id": attack_id,
                    "attack_name": name,
                    "attack_text": text,
                    "clean_attack_text": clean_text(text),
                    "ground_truth_cves": sorted(truth.get(key, set())),
                    "source": str(path.relative_to(config.cve_mapping_file.parents[1])),
                }
    return records


def build_annotated_dataset(config: DatasetConfig, cve_text_mode: str = "description") -> tuple[list[dict], pd.DataFrame]:
    mapping_df = load_mapping_table(config)
    truth = build_ground_truth(mapping_df)
    records = _records_from_mapping(mapping_df, truth)

    for key, record in _records_from_splits(config, truth).items():
        records.setdefault(key, record)

    annotated = sorted(records.values(), key=lambda row: (row["attack_type"], row["attack_id"]))
    cve_corpus = build_cve_corpus(mapping_df, cve_text_mode)
    return annotated, cve_corpus


def write_annotated_outputs(config: DatasetConfig, output_dir: Path, cve_text_mode: str = "description") -> tuple[Path, Path]:
    annotated, cve_corpus = build_annotated_dataset(config, cve_text_mode)
    annotated_path = output_dir / "annotated_attacks.jsonl"
    cve_path = cve_corpus_path(output_dir, cve_text_mode)
    write_jsonl(annotated_path, annotated)
    output_dir.mkdir(parents=True, exist_ok=True)
    cve_corpus.to_csv(cve_path, index=False)
    return annotated_path, cve_path
