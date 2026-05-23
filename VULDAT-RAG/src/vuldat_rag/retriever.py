from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
from sentence_transformers import SentenceTransformer
from tqdm import tqdm

from .config import DEFAULT_MODEL_NAME
from .io_utils import read_jsonl, write_jsonl
from .runtime import detect_torch_device


def load_model(model_name: str = DEFAULT_MODEL_NAME, device: str | None = None) -> SentenceTransformer:
    if device in (None, "auto"):
        device = detect_torch_device()
    print(f"Loading SentenceTransformer on device: {device}")
    kwargs = {"device": device}
    return SentenceTransformer(model_name, **kwargs)


def encode_cve_corpus(
    model: SentenceTransformer,
    cve_corpus_path: Path,
    output_dir: Path,
    batch_size: int = 64,
) -> tuple[pd.DataFrame, np.ndarray]:
    cve_df = pd.read_csv(cve_corpus_path)
    texts = cve_df["clean_cve_text"].fillna("").astype(str).tolist()
    embeddings = model.encode(
        texts,
        batch_size=batch_size,
        normalize_embeddings=True,
        show_progress_bar=True,
    )
    embeddings = np.asarray(embeddings, dtype="float32")
    output_dir.mkdir(parents=True, exist_ok=True)
    np.save(output_dir / "cve_embeddings.npy", embeddings)
    cve_df.to_csv(output_dir / "cve_corpus.csv", index=False)
    return cve_df, embeddings


def load_cached_cve_embeddings(output_dir: Path) -> tuple[pd.DataFrame, np.ndarray]:
    cve_df = pd.read_csv(output_dir / "cve_corpus.csv")
    embeddings = np.load(output_dir / "cve_embeddings.npy")
    return cve_df, embeddings


def _candidate_record(row: pd.Series, score: float) -> dict:
    return {
        "cve_id": row["cve_id"],
        "description": row["cve_description"],
        "similarity": float(score),
    }


def retrieve(
    model: SentenceTransformer,
    annotated_path: Path,
    cve_df: pd.DataFrame,
    cve_embeddings: np.ndarray,
    output_dir: Path,
    top_k: int,
    rank_limit: int,
    batch_size: int = 32,
) -> tuple[Path, Path]:
    attacks = read_jsonl(annotated_path)
    texts = [row["clean_attack_text"] for row in attacks]
    attack_embeddings = model.encode(
        texts,
        batch_size=batch_size,
        normalize_embeddings=True,
        show_progress_bar=True,
    )
    attack_embeddings = np.asarray(attack_embeddings, dtype="float32")

    max_needed = max(top_k, rank_limit if rank_limit > 0 else len(cve_df))
    max_needed = min(max_needed, len(cve_df))

    rankings: list[dict] = []
    top_predictions: list[dict] = []
    for attack, attack_vector in tqdm(list(zip(attacks, attack_embeddings)), desc="Ranking CVEs"):
        scores = cve_embeddings @ attack_vector
        if max_needed == len(scores):
            order = np.argsort(scores)[::-1]
        else:
            rough = np.argpartition(scores, -max_needed)[-max_needed:]
            order = rough[np.argsort(scores[rough])[::-1]]

        candidates = [_candidate_record(cve_df.iloc[idx], scores[idx]) for idx in order]
        top_candidates = candidates[:top_k]
        base = {
            "attack_type": attack["attack_type"],
            "attack_id": attack["attack_id"],
            "attack_name": attack.get("attack_name", ""),
            "attack_text": attack["attack_text"],
            "ground_truth_cves": attack["ground_truth_cves"],
        }
        rankings.append({**base, "candidates": candidates})
        top_predictions.append({**base, "predicted_cves": [item["cve_id"] for item in top_candidates], "candidates": top_candidates})

    rankings_path = output_dir / "rankings.jsonl"
    top_path = output_dir / f"baseline_top{top_k}.jsonl"
    write_jsonl(rankings_path, rankings)
    write_jsonl(top_path, top_predictions)
    return rankings_path, top_path
