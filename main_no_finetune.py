import argparse
import os

import pandas as pd
from sentence_transformers import SentenceTransformer

from config import CVE_CORPUS_XLSX, DATA_VARIANTS, RESULTS_DIR, SENTENCE_TRANSFORMERS_MODELS, SIM_THRESHOLD
from src.data_io import read_cve_corpus, read_test_groups
from src.evaluator import Evaluator
from src.metrics import AttackLevelConfusion
from src.utils import ensure_dirs, get_device, setup_logging


def parse_args():
    parser = argparse.ArgumentParser(description="Run the ATT&CK2VUL src pipeline without fine-tuning.")
    parser.add_argument("--results-dir", default=os.path.abspath("./Results_NoFineTune"))
    parser.add_argument("--models", nargs="+", default=SENTENCE_TRANSFORMERS_MODELS)
    parser.add_argument("--variants", nargs="+", default=list(DATA_VARIANTS.keys()))
    parser.add_argument("--threshold", type=float, default=SIM_THRESHOLD)
    return parser.parse_args()


def safe_name(value):
    return value.replace("/", "_").replace(":", "_")


def main():
    args = parse_args()
    setup_logging()
    ensure_dirs(args.results_dir)
    device = get_device()
    print(f"Using device: {device}")
    print("Fine-tuning: disabled")

    data_cve = read_cve_corpus(CVE_CORPUS_XLSX)
    summary = pd.DataFrame(columns=["Data", "Model", "precision", "Recall", "F1"])

    for variant in args.variants:
        if variant not in DATA_VARIANTS:
            raise ValueError(f"Unknown variant: {variant}")

        test_groups = read_test_groups(DATA_VARIANTS[variant]["test"], variant)

        for model_name in args.models:
            print(f"Processing model: {model_name} with infodata: {variant}")
            model = SentenceTransformer(model_name, device=device)
            evaluator = Evaluator(model, model_name, threshold=args.threshold, device=device)
            confusion = AttackLevelConfusion(threshold=args.threshold)

            evaluator.evaluate_variant(variant, test_groups, data_cve, confusion)

            precision, recall, f1 = confusion.summary_prf()
            summary = pd.concat(
                [
                    summary,
                    pd.DataFrame(
                        [
                            {
                                "Data": variant,
                                "Model": model_name,
                                "precision": precision,
                                "Recall": recall,
                                "F1": f1,
                            }
                        ]
                    ),
                ],
                ignore_index=True,
            )

            model_file = safe_name(model_name)
            confusion.df_main.to_excel(
                os.path.join(args.results_dir, f"Results_{model_file}_Main_{variant}_NoFineTune.xlsx"),
                index=False,
            )
            confusion.df_details.to_excel(
                os.path.join(args.results_dir, f"Results_{model_file}_Details_{variant}_NoFineTune.xlsx"),
                index=False,
            )
            confusion.df_jaccard_all_models.to_excel(
                os.path.join(args.results_dir, f"AllModels_{model_file}_{variant}_NoFineTune.xlsx"),
                index=False,
            )

    summary.to_excel(os.path.join(args.results_dir, "Summary_PRF_NoFineTune.xlsx"), index=False)
    print(f"Done. Results written to {args.results_dir}")


if __name__ == "__main__":
    main()
