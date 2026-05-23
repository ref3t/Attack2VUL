import argparse
import os
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity

RAG_SRC = Path(__file__).resolve().parent / "VULDAT-RAG" / "src"
if str(RAG_SRC) not in sys.path:
    sys.path.insert(0, str(RAG_SRC))

from config import CVE_CORPUS_XLSX, DATA_VARIANTS, SENTENCE_TRANSFORMERS_MODELS, SIM_THRESHOLD
from src.data_io import read_cve_corpus, read_test_groups
from src.metrics import AttackLevelConfusion
from src.text_cleaning import bulk_clean
from src.types import VulData
from src.utils import ensure_dirs, get_device, setup_logging
from vuldat_rag.io_utils import write_jsonl
from vuldat_rag.metrics import compare_metrics, evaluate_predictions
from vuldat_rag.rag import export_new_links, run_rag


def parse_args():
    parser = argparse.ArgumentParser(description="Run no-fine-tune ATT&CK2VUL with RAG reranking.")
    parser.add_argument("--results-dir", default=os.path.abspath("./Results_NoFineTune_RAG"))
    parser.add_argument("--models", nargs="+", default=[SENTENCE_TRANSFORMERS_MODELS[0]])
    parser.add_argument("--variants", nargs="+", default=list(DATA_VARIANTS.keys()))
    parser.add_argument("--threshold", type=float, default=SIM_THRESHOLD)
    parser.add_argument("--top-k", type=int, default=20)
    parser.add_argument("--rank-limit", type=int, default=200)
    parser.add_argument("--base-url", default="http://localhost:11434/v1/chat/completions")
    parser.add_argument("--llm-model", default="llama3.1:8b")
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--top-p", type=float, default=1.0)
    parser.add_argument("--max-tokens", type=int, default=1024)
    parser.add_argument("--api-key", default=None)
    parser.add_argument("--skip-rag", action="store_true")
    return parser.parse_args()


def safe_name(value):
    return value.replace("/", "_").replace(":", "_")


def join_text(value):
    if isinstance(value, list):
        return " ".join(str(item) for item in value if str(item).strip())
    return "" if value is None else str(value)


def attack_text(variant, value):
    if variant in ("CAPEC", "CAPECImbalanced"):
        return join_text(value["CAPECDescription"])
    if variant in ("Tactic", "TacticImbalanced"):
        return join_text(value["TacticDescription"])
    if variant in ("Procedure", "ProcedureImbalanced"):
        return join_text(value["ProcedureDescription"])
    name = join_text(value.get("TechniqueName", []))
    desc = join_text(value.get("TechniqueDescription", []))
    return f"{name} {desc}".strip()


def cve_texts(data_cve):
    descriptions = data_cve["CVEDescription"].fillna("").astype(str).tolist()
    if "TechniqueName" not in data_cve.columns:
        return descriptions
    names = data_cve["TechniqueName"].fillna("").astype(str).tolist()
    return [f"{names[index]} {descriptions[index]}".strip() for index in range(len(descriptions))]


def attack_ground_truth(variant, key, data_cve):
    if variant in ("CAPEC", "CAPECImbalanced"):
        attack_rows = data_cve[data_cve["CAPECID"].astype(str) == str(key)]
        not_attack_rows = data_cve[data_cve["CAPECID"].astype(str) != str(key)]
    elif variant in ("Tactic", "TacticImbalanced"):
        attack_rows = data_cve[data_cve["TacticId"].astype(str) == str(key)]
        not_attack_rows = data_cve[data_cve["TacticId"].astype(str) != str(key)]
    elif variant in ("Procedure", "ProcedureImbalanced"):
        attack_rows = data_cve[data_cve["ProcedureID"].astype(str) == str(key)]
        not_attack_rows = data_cve[data_cve["ProcedureID"].astype(str) != str(key)]
    else:
        base_key = str(key).split(".", 1)[0]
        technique_ids = data_cve["TechniqueID"].fillna("").astype(str)
        attack_rows = data_cve[technique_ids.str.startswith(base_key)]
        not_attack_rows = data_cve[~technique_ids.str.startswith(base_key)]

    cves_attack = sorted(set(attack_rows["CVEID"].dropna().astype(str).tolist()))
    cves_not_attack = sorted(set(not_attack_rows["CVEID"].dropna().astype(str).tolist()) - set(cves_attack))
    return cves_attack, cves_not_attack


def ranked_candidates(data_cve, scores, limit):
    count = len(scores) if limit <= 0 else min(limit, len(scores))
    if count == len(scores):
        order = np.argsort(scores)[::-1]
    else:
        rough = np.argpartition(scores, -count)[-count:]
        order = rough[np.argsort(scores[rough])[::-1]]

    seen = set()
    candidates = []
    vul_data = []
    for index in order:
        cve_id = str(data_cve.iloc[index]["CVEID"])
        if cve_id in seen:
            continue
        seen.add(cve_id)
        score = float(scores[index])
        description = str(data_cve.iloc[index]["CVEDescription"])
        candidates.append(
            {
                "cve_id": cve_id,
                "description": description,
                "similarity": score,
            }
        )
        vul_data.append(VulData(CVE_ID=cve_id, CVE_Des=description, CVE_Smiliraty=f"{score:.4f}"))
    return candidates, vul_data


def add_threshold_result(confusion, model_name, key, vul_data, cves_attack, cves_not_attack, threshold):
    positives = []
    negatives = []
    attack_set = set(cves_attack)
    for item in vul_data:
        if float(item.CVE_Smiliraty) > threshold:
            if item.CVE_ID in attack_set:
                positives.append(item.CVE_ID)
            else:
                negatives.append(item.CVE_ID)
    confusion.add_attack_result(model_name, str(key), vul_data, cves_attack, positives, negatives, cves_not_attack)


def write_candidate_file(path, records):
    write_jsonl(path, records)
    print(f"Wrote {path}")


def evaluate_candidate_files(results_dir, model_file, variant, candidate_path, rag_path):
    baseline_metrics = Path(results_dir) / f"Metrics_BaselineTopK_{model_file}_{variant}.csv"
    rag_metrics = Path(results_dir) / f"Metrics_RAG_{model_file}_{variant}.csv"
    comparison_path = Path(results_dir) / f"Comparison_RAG_vs_BaselineTopK_{model_file}_{variant}.csv"
    manual_path = Path(results_dir) / f"ManualValidationCandidates_{model_file}_{variant}.csv"

    evaluate_predictions(candidate_path, baseline_metrics, f"baseline_topk_{variant}")
    evaluate_predictions(rag_path, rag_metrics, f"rag_{variant}")
    compare_metrics(baseline_metrics, rag_metrics, comparison_path)
    export_new_links(rag_path, manual_path)

    print(f"Wrote {baseline_metrics}")
    print(f"Wrote {rag_metrics}")
    print(f"Wrote {comparison_path}")
    print(f"Wrote {manual_path}")


def run_variant_model(args, variant, model_name, data_cve, device):
    model_file = safe_name(model_name)
    test_groups = read_test_groups(DATA_VARIANTS[variant]["test"], variant)
    model = SentenceTransformer(model_name, device=device)
    embeddings = model.encode(cve_texts(data_cve), device=device, show_progress_bar=True)
    confusion = AttackLevelConfusion(threshold=args.threshold)
    candidate_records = []

    for count, (key, value) in enumerate(test_groups.items(), start=1):
        print(f"Processing {variant} {key} ({count}/{len(test_groups)})")
        text = bulk_clean([attack_text(variant, value)])
        attack_embedding = model.encode(text, device=device, show_progress_bar=False)
        scores = cosine_similarity(attack_embedding.reshape(1, -1), embeddings)[0]

        all_candidates, all_vul_data = ranked_candidates(data_cve, scores, 0)
        top_candidates = all_candidates[: args.top_k]
        cves_attack, cves_not_attack = attack_ground_truth(variant, key, data_cve)
        add_threshold_result(confusion, model_name, key, all_vul_data, cves_attack, cves_not_attack, args.threshold)

        candidate_records.append(
            {
                "attack_type": variant,
                "attack_id": str(key),
                "attack_name": "",
                "attack_text": attack_text(variant, value),
                "ground_truth_cves": cves_attack,
                "predicted_cves": [item["cve_id"] for item in top_candidates],
                "candidates": top_candidates,
            }
        )

    candidate_path = Path(args.results_dir) / f"Candidates_Top{args.top_k}_{model_file}_{variant}.jsonl"
    write_candidate_file(candidate_path, candidate_records)

    confusion.df_main.to_excel(
        Path(args.results_dir) / f"Results_{model_file}_Main_{variant}_NoFineTuneThreshold.xlsx",
        index=False,
    )
    confusion.df_details.to_excel(
        Path(args.results_dir) / f"Results_{model_file}_Details_{variant}_NoFineTuneThreshold.xlsx",
        index=False,
    )
    confusion.df_jaccard_all_models.to_excel(
        Path(args.results_dir) / f"AllModels_{model_file}_{variant}_NoFineTuneThreshold.xlsx",
        index=False,
    )

    precision, recall, f1 = confusion.summary_prf()
    threshold_summary = {
        "Data": variant,
        "Model": model_name,
        "precision": precision,
        "Recall": recall,
        "F1": f1,
    }

    if args.skip_rag:
        return threshold_summary

    rag_path = Path(args.results_dir) / f"RAG_Predictions_{model_file}_{variant}.jsonl"
    run_rag(
        candidate_path,
        rag_path,
        args.base_url,
        args.llm_model,
        args.temperature,
        args.top_p,
        args.max_tokens,
        args.api_key,
    )
    evaluate_candidate_files(args.results_dir, model_file, variant, candidate_path, rag_path)
    return threshold_summary


def main():
    args = parse_args()
    setup_logging()
    ensure_dirs(args.results_dir)
    device = get_device()
    print(f"Using device: {device}")
    print("Fine-tuning: disabled")

    data_cve = read_cve_corpus(CVE_CORPUS_XLSX)
    threshold_rows = []

    for variant in args.variants:
        if variant not in DATA_VARIANTS:
            raise ValueError(f"Unknown variant: {variant}")
        for model_name in args.models:
            print(f"Processing model: {model_name} with infodata: {variant}")
            threshold_rows.append(run_variant_model(args, variant, model_name, data_cve, device))

    summary = pd.DataFrame(threshold_rows)
    summary_path = Path(args.results_dir) / "Summary_PRF_NoFineTuneThreshold.xlsx"
    summary.to_excel(summary_path, index=False)
    print(f"Wrote {summary_path}")
    print(f"Done. Results written to {args.results_dir}")


if __name__ == "__main__":
    main()
