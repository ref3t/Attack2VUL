from __future__ import annotations

import argparse
from pathlib import Path

from .config import (
    DEFAULT_MODEL_NAME,
    DEFAULT_RANK_LIMIT,
    DEFAULT_TOP_K,
    OUTPUT_DIR,
    DatasetConfig,
)

DEFAULT_K_VALUES = [10, 20, 30, 40, 50, 100, 150, 200]


def _path(value: str) -> Path:
    return Path(value).expanduser().resolve()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Frozen-MPNet baseline and RAG reranking for VULDAT.")
    parser.add_argument("--output-dir", type=_path, default=OUTPUT_DIR, help="Directory for generated artifacts.")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("doctor", help="Show local Python, Torch, GPU, vLLM, and Ollama runtime status.")

    build = sub.add_parser("build-dataset", help="Build annotated attacks and CVE corpus from existing Excel files.")
    build.add_argument("--mapping-file", type=_path, default=None, help="Override dataset/VULDATDataSet.xlsx.")
    build.add_argument("--cve-text-mode", choices=["description", "description_technique"], default="description")

    ret = sub.add_parser("retrieve", help="Encode with frozen MPNet and produce rankings/top-k predictions.")
    ret.add_argument("--model-name", default=DEFAULT_MODEL_NAME)
    ret.add_argument("--device", default="auto", help="SentenceTransformer device: auto, cpu, cuda, or mps.")
    ret.add_argument("--cve-text-mode", choices=["description", "description_technique"], default="description")
    ret.add_argument("--top-k", type=int, default=DEFAULT_TOP_K)
    ret.add_argument("--rank-limit", type=int, default=DEFAULT_RANK_LIMIT, help="0 means keep all CVEs per attack.")
    ret.add_argument("--batch-size", type=int, default=64)
    ret.add_argument("--rebuild-dataset", action="store_true")
    ret.add_argument("--reuse-cve-embeddings", action="store_true")

    sens = sub.add_parser("sensitivity", help="Compute Precision/Recall/F1@k and box plots.")
    sens.add_argument("--rankings", type=_path, default=OUTPUT_DIR / "rankings.jsonl")
    sens.add_argument("--k-values", type=int, nargs="+", default=DEFAULT_K_VALUES)
    sens.add_argument("--seed", type=int, default=42)
    sens.add_argument("--positive-count", type=int, default=50)
    sens.add_argument("--negative-count", type=int, default=50)

    rag = sub.add_parser("rag", help="Send top-k candidates to a local OpenAI-compatible vLLM endpoint.")
    rag.add_argument("--candidates", type=_path, default=OUTPUT_DIR / f"baseline_top{DEFAULT_TOP_K}.jsonl")
    rag.add_argument("--output", type=_path, default=OUTPUT_DIR / "rag_predictions.jsonl")
    rag.add_argument("--base-url", default="http://localhost:8000/v1/chat/completions")
    rag.add_argument("--model", default="meta-llama/Llama-3.1-8B-Instruct")
    rag.add_argument("--temperature", type=float, default=0.0)
    rag.add_argument("--top-p", type=float, default=1.0)
    rag.add_argument("--max-tokens", type=int, default=1024)
    rag.add_argument("--api-key", default=None)

    rag_auto = sub.add_parser("rag-auto", help="Use a running vLLM endpoint if available, otherwise a running Ollama endpoint.")
    rag_auto.add_argument("--candidates", type=_path, default=OUTPUT_DIR / f"baseline_top{DEFAULT_TOP_K}.jsonl")
    rag_auto.add_argument("--output", type=_path, default=OUTPUT_DIR / "rag_predictions.jsonl")
    rag_auto.add_argument("--temperature", type=float, default=0.0)
    rag_auto.add_argument("--top-p", type=float, default=1.0)
    rag_auto.add_argument("--max-tokens", type=int, default=1024)
    rag_auto.add_argument("--api-key", default=None)

    eval_cmd = sub.add_parser("evaluate", help="Evaluate a baseline or RAG prediction JSONL.")
    eval_cmd.add_argument("--predictions", type=_path, required=True)
    eval_cmd.add_argument("--name", required=True)
    eval_cmd.add_argument("--output", type=_path, default=None)

    comp = sub.add_parser("compare", help="Compare baseline and RAG metric CSVs.")
    comp.add_argument("--baseline", type=_path, required=True)
    comp.add_argument("--rag", type=_path, required=True)
    comp.add_argument("--output", type=_path, default=OUTPUT_DIR / "comparison.csv")

    manual = sub.add_parser("export-new-links", help="Export RAG predictions absent from ground truth for manual validation.")
    manual.add_argument("--rag", type=_path, default=OUTPUT_DIR / "rag_predictions.jsonl")
    manual.add_argument("--output", type=_path, default=OUTPUT_DIR / "manual_validation_candidates.csv")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    output_dir: Path = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    dataset_config = DatasetConfig()
    if getattr(args, "mapping_file", None):
        dataset_config = DatasetConfig(cve_mapping_file=args.mapping_file)

    if args.command == "doctor":
        from .runtime import print_doctor_report

        print_doctor_report()
        return

    if args.command == "build-dataset":
        from .data import write_annotated_outputs

        annotated_path, cve_path = write_annotated_outputs(dataset_config, output_dir, args.cve_text_mode)
        print(f"Wrote {annotated_path}")
        print(f"Wrote {cve_path}")
        return

    if args.command == "retrieve":
        from .data import cve_corpus_path, write_annotated_outputs
        from .retriever import encode_cve_corpus, load_cached_cve_embeddings, load_model, retrieve

        annotated_path = output_dir / "annotated_attacks.jsonl"
        cve_path = cve_corpus_path(output_dir, args.cve_text_mode)
        if args.rebuild_dataset or not annotated_path.exists() or not cve_path.exists():
            annotated_path, cve_path = write_annotated_outputs(dataset_config, output_dir, args.cve_text_mode)

        model = load_model(args.model_name, args.device)
        emb_dir = output_dir / "embeddings" / args.cve_text_mode
        if args.reuse_cve_embeddings and (emb_dir / "cve_embeddings.npy").exists() and (emb_dir / "cve_corpus.csv").exists():
            cve_df, cve_embeddings = load_cached_cve_embeddings(emb_dir)
        else:
            cve_df, cve_embeddings = encode_cve_corpus(model, cve_path, emb_dir, args.batch_size)

        output_suffix = "" if args.cve_text_mode == "description" else args.cve_text_mode

        rankings_path, top_path = retrieve(
            model,
            annotated_path,
            cve_df,
            cve_embeddings,
            output_dir,
            args.top_k,
            args.rank_limit,
            args.batch_size,
            output_suffix,
        )
        print(f"Wrote {rankings_path}")
        print(f"Wrote {top_path}")
        return

    if args.command == "sensitivity":
        from .sensitivity import run_sensitivity

        df, plot_path = run_sensitivity(
            args.rankings,
            output_dir,
            args.k_values,
            args.seed,
            args.positive_count,
            args.negative_count,
        )
        print(f"Wrote {output_dir / 'sensitivity_topk.csv'}")
        if plot_path:
            print(f"Wrote {plot_path}")
        print(df.groupby("k")[["precision", "recall", "f1"]].mean())
        return

    if args.command == "rag":
        from .rag import run_rag

        out = run_rag(
            args.candidates,
            args.output,
            args.base_url,
            args.model,
            args.temperature,
            args.top_p,
            args.max_tokens,
            args.api_key,
        )
        print(f"Wrote {out}")
        return

    if args.command == "rag-auto":
        from .rag import run_rag
        from .runtime import select_rag_backend

        backend, base_url, model = select_rag_backend()
        print(f"Using RAG backend: {backend} ({base_url}, model={model})")
        out = run_rag(
            args.candidates,
            args.output,
            base_url,
            model,
            args.temperature,
            args.top_p,
            args.max_tokens,
            args.api_key,
        )
        print(f"Wrote {out}")
        return

    if args.command == "evaluate":
        from .metrics import evaluate_predictions

        output = args.output or output_dir / f"metrics_{args.name}.csv"
        df = evaluate_predictions(args.predictions, output, args.name)
        print(f"Wrote {output}")
        print(df[["precision", "recall", "f1", "jaccard", "mapping_accuracy", "detection_accuracy"]].mean())
        return

    if args.command == "compare":
        from .metrics import compare_metrics

        df = compare_metrics(args.baseline, args.rag, args.output)
        print(f"Wrote {args.output}")
        print(df)
        return

    if args.command == "export-new-links":
        from .rag import export_new_links

        out = export_new_links(args.rag, args.output)
        print(f"Wrote {out}")
        return


if __name__ == "__main__":
    main()
