from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pandas as pd

from .io_utils import read_jsonl


@dataclass(frozen=True)
class SetMetrics:
    tp: int
    fp: int
    fn: int
    precision: float
    recall: float
    f1: float
    jaccard: float
    mapping_accuracy: float
    detection_accuracy: float


def compute_set_metrics(predicted: set[str], truth: set[str]) -> SetMetrics:
    tp = len(predicted & truth)
    fp = len(predicted - truth)
    fn = len(truth - predicted)
    precision = tp / len(predicted) if predicted else 0.0
    recall = tp / len(truth) if truth else 0.0
    f1 = 0.0 if precision + recall == 0 else 2 * precision * recall / (precision + recall)
    union = predicted | truth
    jaccard = len(predicted & truth) / len(union) if union else 1.0
    mapping_accuracy = 1.0 if predicted == truth else 0.0
    detection_accuracy = 1.0 if bool(predicted) == bool(truth) else 0.0
    return SetMetrics(tp, fp, fn, precision, recall, f1, jaccard, mapping_accuracy, detection_accuracy)


def prediction_ids(record: dict) -> set[str]:
    if "rag_linked_cves" in record:
        return {str(item) for item in record["rag_linked_cves"]}
    if "predicted_cves" in record:
        return {str(item) for item in record["predicted_cves"]}
    return {
        str(item["cve_id"])
        for item in record.get("decisions", [])
        if item.get("decision") == "linked"
    }


def evaluate_predictions(predictions_path: Path, output_path: Path, name: str) -> pd.DataFrame:
    rows = []
    for record in read_jsonl(predictions_path):
        predicted = prediction_ids(record)
        truth = {str(item) for item in record.get("ground_truth_cves", [])}
        metrics = compute_set_metrics(predicted, truth)
        rows.append(
            {
                "pipeline": name,
                "attack_type": record["attack_type"],
                "attack_id": record["attack_id"],
                "attack_name": record.get("attack_name", ""),
                "truth_count": len(truth),
                "prediction_count": len(predicted),
                "tp": metrics.tp,
                "fp": metrics.fp,
                "fn": metrics.fn,
                "precision": metrics.precision,
                "recall": metrics.recall,
                "f1": metrics.f1,
                "jaccard": metrics.jaccard,
                "mapping_accuracy": metrics.mapping_accuracy,
                "detection_accuracy": metrics.detection_accuracy,
                "ground_truth_cves": sorted(truth),
                "predicted_cves": sorted(predicted),
            }
        )
    df = pd.DataFrame(rows)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_path, index=False)
    return df


def compare_metrics(baseline_path: Path, rag_path: Path, output_path: Path) -> pd.DataFrame:
    baseline = pd.read_csv(baseline_path)
    rag = pd.read_csv(rag_path)
    key_cols = ["attack_type", "attack_id"]
    merged = baseline.merge(rag, on=key_cols, suffixes=("_baseline", "_rag"))
    metric_cols = ["precision", "recall", "f1", "jaccard", "mapping_accuracy", "detection_accuracy"]

    try:
        from scipy.stats import wilcoxon
    except Exception:
        wilcoxon = None

    rows = []
    for metric in metric_cols:
        base_values = merged[f"{metric}_baseline"]
        rag_values = merged[f"{metric}_rag"]
        delta = rag_values - base_values
        p_value = None
        if wilcoxon is not None and len(delta) > 0 and (delta != 0).any():
            p_value = float(wilcoxon(rag_values, base_values).pvalue)
        rows.append(
            {
                "metric": metric,
                "baseline_mean": base_values.mean(),
                "rag_mean": rag_values.mean(),
                "delta_mean": delta.mean(),
                "baseline_median": base_values.median(),
                "rag_median": rag_values.median(),
                "delta_median": delta.median(),
                "paired_wilcoxon_p": p_value,
                "n": len(merged),
            }
        )
    df = pd.DataFrame(rows)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_path, index=False)
    return df
