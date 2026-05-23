from __future__ import annotations

from pathlib import Path
import random

import pandas as pd

from .io_utils import read_jsonl
from .metrics import compute_set_metrics


DEFAULT_K_VALUES = [10, 20, 30, 40, 50, 100, 150, 200]


def _choose_probe(records: list[dict], seed: int, positive_count: int, negative_count: int) -> list[dict]:
    rng = random.Random(seed)
    positives = [row for row in records if row.get("ground_truth_cves")]
    negatives = [row for row in records if not row.get("ground_truth_cves")]
    rng.shuffle(positives)
    rng.shuffle(negatives)
    return positives[:positive_count] + negatives[:negative_count]


def run_sensitivity(
    rankings_path: Path,
    output_dir: Path,
    k_values: list[int] | None = None,
    seed: int = 42,
    positive_count: int = 50,
    negative_count: int = 50,
) -> tuple[pd.DataFrame, Path | None]:
    k_values = k_values or DEFAULT_K_VALUES
    records = read_jsonl(rankings_path)
    probe = _choose_probe(records, seed, positive_count, negative_count)
    if len(probe) < positive_count + negative_count:
        print(f"[warn] Probe set has {len(probe)} attacks; requested {positive_count + negative_count}.")

    rows = []
    for record in probe:
        truth = {str(item) for item in record.get("ground_truth_cves", [])}
        candidates = record.get("candidates", [])
        for k in k_values:
            predicted = {str(item["cve_id"]) for item in candidates[:k]}
            metrics = compute_set_metrics(predicted, truth)
            rows.append(
                {
                    "k": k,
                    "attack_type": record["attack_type"],
                    "attack_id": record["attack_id"],
                    "truth_count": len(truth),
                    "precision": metrics.precision,
                    "recall": metrics.recall,
                    "f1": metrics.f1,
                    "jaccard": metrics.jaccard,
                }
            )

    df = pd.DataFrame(rows)
    output_dir.mkdir(parents=True, exist_ok=True)
    csv_path = output_dir / "sensitivity_topk.csv"
    df.to_csv(csv_path, index=False)

    plot_path = output_dir / "sensitivity_topk_boxplots.png"
    try:
        import matplotlib.pyplot as plt
        import seaborn as sns

        melted = df.melt(
            id_vars=["k", "attack_type", "attack_id"],
            value_vars=["precision", "recall", "f1"],
            var_name="metric",
            value_name="score",
        )
        grid = sns.catplot(
            data=melted,
            x="k",
            y="score",
            col="metric",
            kind="box",
            sharey=True,
            height=4,
            aspect=1.15,
        )
        grid.set_axis_labels("k", "score")
        grid.set_titles("{col_name}")
        plt.tight_layout()
        grid.savefig(plot_path, dpi=200)
        plt.close("all")
    except Exception as exc:
        print(f"[warn] Could not render sensitivity plot: {exc}")
        plot_path = None

    return df, plot_path

