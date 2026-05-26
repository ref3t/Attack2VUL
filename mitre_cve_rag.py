import argparse
import json
import math
import os
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import pandas as pd
from sentence_transformers import SentenceTransformer

RAG_SRC = Path(__file__).resolve().parent / "VULDAT-RAG" / "src"
if str(RAG_SRC) not in sys.path:
    sys.path.insert(0, str(RAG_SRC))

from config import CVE_CORPUS_XLSX, DATA_VARIANTS
from src.data_io import read_test_groups
from vuldat_rag.io_utils import write_jsonl
from vuldat_rag.rag import _extract_json_array, query_llm
from vuldat_rag.text import clean_text


def parse_args():
    parser = argparse.ArgumentParser(description="Hybrid MITRE-grounded RAG for CVE prediction from attack descriptions.")
    parser.add_argument("--output-dir", default=os.path.abspath("./Results_MITRE_CVE_RAG"))
    parser.add_argument("--variant", default="Technique", choices=list(DATA_VARIANTS.keys()))
    parser.add_argument("--query", default=None)
    parser.add_argument("--cve-source", choices=["vuldat", "cvelist"], default="vuldat")
    parser.add_argument("--cve-json-root", default=None)
    parser.add_argument("--embedding-model", default="sentence-transformers/all-mpnet-base-v2")
    parser.add_argument("--top-k", type=int, default=20)
    parser.add_argument("--top-n", type=int, default=10)
    parser.add_argument("--alpha", type=float, default=0.65)
    parser.add_argument("--beta", type=float, default=0.30)
    parser.add_argument("--gamma", type=float, default=0.05)
    parser.add_argument("--limit-attacks", type=int, default=None)
    parser.add_argument("--limit-cves", type=int, default=None)
    parser.add_argument("--llm-model", default=None)
    parser.add_argument("--base-url", default="http://localhost:11434/v1/chat/completions")
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--top-p", type=float, default=1.0)
    parser.add_argument("--max-tokens", type=int, default=1024)
    parser.add_argument("--api-key", default=None)
    return parser.parse_args()


def safe_value(value):
    if pd.isna(value):
        return ""
    return str(value).strip()


def unique_values(values):
    seen = set()
    out = []
    for value in values:
        text = safe_value(value)
        if text and text not in seen:
            seen.add(text)
            out.append(text)
    return out


def first_value(values):
    for value in values:
        text = safe_value(value)
        if text:
            return text
    return ""


def load_vuldat_table():
    return pd.read_excel(CVE_CORPUS_XLSX, sheet_name=0)


def build_vuldat_cve_docs(df):
    records = []
    data = df.dropna(subset=["CVEID"]).copy()
    data["CVEID"] = data["CVEID"].astype(str)
    for cve_id, group in data.groupby("CVEID", dropna=False):
        cwe_ids = unique_values(group["Related Weaknesses"]) if "Related Weaknesses" in group else []
        cwe_names = unique_values(group["CWE-Name"]) if "CWE-Name" in group else []
        technique_names = unique_values(group["TechniqueName"]) if "TechniqueName" in group else []
        capec_names = unique_values(group["CAPECName"]) if "CAPECName" in group else []
        description = first_value(group["CVEDescription"])
        title = " ".join(technique_names[:3])
        weakness = " ".join([*cwe_ids, *cwe_names])
        references = ""
        document_text = "\n".join(
            [
                f"CVE_ID: {cve_id}",
                f"Title: {title}",
                f"Description: {description}",
                "Vendor: ",
                "Product: ",
                "Affected versions: ",
                f"Weakness: {weakness}",
                f"Attack context: {' '.join(technique_names + capec_names)}",
                f"References: {references}",
            ]
        )
        records.append(
            {
                "cve_id": cve_id,
                "title": title,
                "description": description,
                "vendor": "",
                "product": "",
                "versions": "",
                "cwe": "; ".join(cwe_ids),
                "weakness": "; ".join(cwe_names),
                "references": references,
                "cvss": "",
                "published": "",
                "updated": "",
                "raw_path": "",
                "document_text": document_text,
                "clean_text": clean_text(document_text),
            }
        )
    return records


def load_cvelist_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def flatten_strings(values):
    out = []
    for value in values:
        if isinstance(value, list):
            out.extend(flatten_strings(value))
        elif isinstance(value, dict):
            out.extend(flatten_strings(value.values()))
        else:
            text = str(value).strip()
            if text:
                out.append(text)
    return out


def extract_cvss(metrics):
    values = []
    for item in metrics or []:
        if not isinstance(item, dict):
            continue
        for key, value in item.items():
            if key.lower().startswith("cvss") and isinstance(value, dict):
                score = value.get("baseScore", "")
                severity = value.get("baseSeverity", "")
                vector = value.get("vectorString", "")
                values.append(" ".join(str(x) for x in [score, severity, vector] if str(x).strip()))
    return "; ".join(x for x in values if x)


def build_cvelist_doc(path):
    data = load_cvelist_json(path)
    metadata = data.get("cveMetadata", {})
    cna = data.get("containers", {}).get("cna", {})
    cve_id = metadata.get("cveId", path.stem)
    title = cna.get("title", "")
    descriptions = cna.get("descriptions", [])
    description = " ".join(item.get("value", "") for item in descriptions if isinstance(item, dict))
    affected = cna.get("affected", [])
    vendors = unique_values(item.get("vendor", "") for item in affected if isinstance(item, dict))
    products = unique_values(item.get("product", "") for item in affected if isinstance(item, dict))
    versions = []
    for item in affected:
        if not isinstance(item, dict):
            continue
        for version in item.get("versions", []) or []:
            if isinstance(version, dict):
                versions.append(" ".join(flatten_strings(version.values())))
    problem_types = cna.get("problemTypes", [])
    weaknesses = []
    cwes = []
    for item in problem_types:
        for desc in item.get("descriptions", []) if isinstance(item, dict) else []:
            if isinstance(desc, dict):
                if desc.get("cweId"):
                    cwes.append(desc.get("cweId"))
                if desc.get("description"):
                    weaknesses.append(desc.get("description"))
    references = []
    for item in cna.get("references", []) or []:
        if isinstance(item, dict):
            references.append(item.get("url", ""))
    cvss = extract_cvss(cna.get("metrics", []))
    document_text = "\n".join(
        [
            f"CVE_ID: {cve_id}",
            f"Title: {title}",
            f"Description: {description}",
            f"Vendor: {' '.join(vendors)}",
            f"Product: {' '.join(products)}",
            f"Affected versions: {' '.join(versions)}",
            f"Weakness: {' '.join(cwes + weaknesses)}",
            f"References: {' '.join(references[:10])}",
            f"CVSS: {cvss}",
            f"Published: {metadata.get('datePublished', '')}",
            f"Updated: {metadata.get('dateUpdated', '')}",
        ]
    )
    return {
        "cve_id": cve_id,
        "title": title,
        "description": description,
        "vendor": "; ".join(vendors),
        "product": "; ".join(products),
        "versions": "; ".join(versions),
        "cwe": "; ".join(unique_values(cwes)),
        "weakness": "; ".join(unique_values(weaknesses)),
        "references": "; ".join(unique_values(references)),
        "cvss": cvss,
        "published": metadata.get("datePublished", ""),
        "updated": metadata.get("dateUpdated", ""),
        "raw_path": str(path),
        "document_text": document_text,
        "clean_text": clean_text(document_text),
    }


def build_cvelist_docs(root, limit=None):
    root_path = Path(root)
    paths = sorted(root_path.rglob("CVE-*.json"))
    if limit:
        paths = paths[:limit]
    records = []
    for path in paths:
        try:
            records.append(build_cvelist_doc(path))
        except Exception as exc:
            print(f"Skipping {path}: {exc}")
    return records


def attack_text(variant, value):
    if variant == "CAPEC":
        return " ".join(value.get("CAPECDescription", []))
    if variant == "Tactic":
        return " ".join(value.get("TacticDescription", []))
    if variant == "Procedure":
        return " ".join(value.get("ProcedureDescription", []))
    name = " ".join(value.get("TechniqueName", []))
    desc = " ".join(value.get("TechniqueDescription", []))
    return f"{name} {desc}".strip()


def ground_truth_for_attack(variant, attack_id, df):
    if variant == "CAPEC":
        rows = df[df["CAPECID"].astype(str) == str(attack_id)]
    elif variant == "Tactic":
        rows = df[df["TacticId"].astype(str) == str(attack_id)]
    elif variant == "Procedure":
        rows = df[df["ProcedureID"].astype(str) == str(attack_id)]
    else:
        base_id = str(attack_id).split(".", 1)[0]
        rows = df[df["TechniqueID"].fillna("").astype(str).str.startswith(base_id)]
    return sorted(set(rows["CVEID"].dropna().astype(str).tolist()))


def load_attack_records(args, vuldat_df):
    if args.query:
        return [
            {
                "attack_id": "query",
                "attack_type": "query",
                "attack_text": args.query,
                "ground_truth_cves": [],
            }
        ]
    groups = read_test_groups(DATA_VARIANTS[args.variant]["test"], args.variant)
    records = []
    for attack_id, value in groups.items():
        records.append(
            {
                "attack_id": str(attack_id),
                "attack_type": args.variant,
                "attack_text": attack_text(args.variant, value),
                "ground_truth_cves": ground_truth_for_attack(args.variant, attack_id, vuldat_df),
            }
        )
    if args.limit_attacks:
        records = records[: args.limit_attacks]
    return records


class BM25:
    def __init__(self, documents):
        self.k1 = 1.5
        self.b = 0.75
        self.documents = [doc.split() for doc in documents]
        self.lengths = [len(doc) for doc in self.documents]
        self.avgdl = sum(self.lengths) / len(self.lengths) if self.lengths else 0
        self.df = defaultdict(int)
        for doc in self.documents:
            for token in set(doc):
                self.df[token] += 1
        self.n = len(self.documents)

    def score(self, query):
        terms = query.split()
        scores = np.zeros(self.n, dtype="float32")
        for index, doc in enumerate(self.documents):
            counts = Counter(doc)
            length = self.lengths[index] or 1
            total = 0.0
            for term in terms:
                freq = counts.get(term, 0)
                if freq == 0:
                    continue
                df = self.df.get(term, 0)
                idf = math.log(1 + (self.n - df + 0.5) / (df + 0.5))
                denom = freq + self.k1 * (1 - self.b + self.b * length / (self.avgdl or 1))
                total += idf * freq * (self.k1 + 1) / denom
            scores[index] = total
        return scores


def normalize(values):
    values = np.asarray(values, dtype="float32")
    if len(values) == 0:
        return values
    low = float(values.min())
    high = float(values.max())
    if high == low:
        return np.zeros_like(values)
    return (values - low) / (high - low)


def metadata_score(query_text, docs):
    query_tokens = set(clean_text(query_text).split())
    scores = []
    for doc in docs:
        fields = " ".join(
            [
                doc.get("vendor", ""),
                doc.get("product", ""),
                doc.get("cwe", ""),
                doc.get("weakness", ""),
                doc.get("title", ""),
            ]
        )
        tokens = set(clean_text(fields).split())
        score = len(query_tokens & tokens)
        scores.append(min(score / 3, 1.0))
    return np.asarray(scores, dtype="float32")


def ranked_retrieval(record, docs, dense_scores, bm25_scores, metadata_scores, args):
    dense_norm = normalize(dense_scores)
    bm25_norm = normalize(bm25_scores)
    final_scores = args.alpha * dense_norm + args.beta * bm25_norm + args.gamma * metadata_scores
    order = np.argsort(final_scores)[::-1][: args.top_k]
    candidates = []
    for rank, index in enumerate(order, start=1):
        doc = docs[index]
        candidates.append(
            {
                "rank": rank,
                "cve_id": doc["cve_id"],
                "title": doc.get("title", ""),
                "description": doc.get("description", ""),
                "vendor": doc.get("vendor", ""),
                "product": doc.get("product", ""),
                "cwe": doc.get("cwe", ""),
                "weakness": doc.get("weakness", ""),
                "references": doc.get("references", ""),
                "final_score": float(final_scores[index]),
                "dense_score": float(dense_norm[index]),
                "bm25_score": float(bm25_norm[index]),
                "metadata_score": float(metadata_scores[index]),
            }
        )
    return {
        **record,
        "retrieved_cves": [item["cve_id"] for item in candidates],
        "candidates": candidates,
    }


def retrieval_metrics(retrieved, truth, k):
    retrieved_k = retrieved[:k]
    truth_set = set(truth)
    retrieved_set = set(retrieved_k)
    hits = [index + 1 for index, cve_id in enumerate(retrieved_k) if cve_id in truth_set]
    precision = len(retrieved_set & truth_set) / k if k else 0
    recall = len(retrieved_set & truth_set) / len(truth_set) if truth_set else 0
    hit = 1 if hits else 0
    mrr = 1 / hits[0] if hits else 0
    dcg = sum(1 / math.log2(rank + 1) for rank in hits)
    ideal_hits = min(len(truth_set), k)
    idcg = sum(1 / math.log2(rank + 1) for rank in range(1, ideal_hits + 1))
    ndcg = dcg / idcg if idcg else 0
    return {
        "precision_at_k": precision,
        "recall_at_k": recall,
        "hit_at_k": hit,
        "mrr": mrr,
        "ndcg_at_k": ndcg,
    }


def prediction_metrics(predicted, truth):
    pred = list(dict.fromkeys(predicted))
    truth_set = set(truth)
    pred_set = set(pred)
    tp = len(pred_set & truth_set)
    fp = len(pred_set - truth_set)
    fn = len(truth_set - pred_set)
    precision = tp / len(pred_set) if pred_set else 0
    recall = tp / len(truth_set) if truth_set else 0
    f1 = 0 if precision + recall == 0 else 2 * precision * recall / (precision + recall)
    return {
        "exact_match": 1 if pred_set == truth_set else 0,
        "top1_accuracy": 1 if pred[:1] and pred[0] in truth_set else 0,
        "top3_accuracy": 1 if truth_set & set(pred[:3]) else 0,
        "top5_accuracy": 1 if truth_set & set(pred[:5]) else 0,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "tp": tp,
        "fp": fp,
        "fn": fn,
    }


def prediction_prompt(record):
    lines = []
    for item in record["candidates"][:10]:
        lines.append(
            "\n".join(
                [
                    f"Rank: {item['rank']}",
                    f"CVE_ID: {item['cve_id']}",
                    f"Description: {item['description']}",
                    f"Vendor: {item['vendor']}",
                    f"Product: {item['product']}",
                    f"Weakness: {item['cwe']} {item['weakness']}",
                    f"Score: {item['final_score']:.4f}",
                ]
            )
        )
    return f"""You are a cybersecurity analyst.
Given the attack description and retrieved CVE records, identify the most likely CVE ID or IDs.
Use only the retrieved evidence. Do not invent CVE IDs.
If evidence is insufficient, return an empty JSON array.

Attack description:
{record["attack_text"]}

Retrieved CVE records:
{chr(10).join(lines)}

Return only a JSON array:
[
  {{"cve_id": "CVE-YYYY-NNNN", "confidence": 0.0, "explanation": "short reason", "evidence": "field evidence"}}
]
"""


def llm_predict(record, args):
    if not args.llm_model:
        return []
    content = query_llm(
        args.base_url,
        args.llm_model,
        prediction_prompt(record),
        args.temperature,
        args.top_p,
        args.max_tokens,
        args.api_key,
    )
    try:
        data = _extract_json_array(content)
    except Exception:
        data = []
    candidate_ids = {item["cve_id"] for item in record["candidates"]}
    predictions = []
    for item in data:
        cve_id = str(item.get("cve_id", "")).strip()
        if cve_id in candidate_ids:
            predictions.append(
                {
                    "cve_id": cve_id,
                    "confidence": item.get("confidence", ""),
                    "explanation": item.get("explanation", ""),
                    "evidence": item.get("evidence", ""),
                }
            )
    return predictions


def write_summary(path, rows):
    df = pd.DataFrame(rows)
    df.to_csv(path, index=False)
    means = df.select_dtypes(include=["number"]).mean().to_frame("mean").reset_index().rename(columns={"index": "metric"})
    summary_path = path.with_name(path.stem + "_summary.csv")
    means.to_csv(summary_path, index=False)
    print(f"Wrote {path}")
    print(f"Wrote {summary_path}")


def main():
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    vuldat_df = load_vuldat_table()

    if args.cve_source == "cvelist":
        if not args.cve_json_root:
            raise ValueError("--cve-json-root is required when --cve-source cvelist")
        docs = build_cvelist_docs(args.cve_json_root, args.limit_cves)
    else:
        docs = build_vuldat_cve_docs(vuldat_df)
        if args.limit_cves:
            docs = docs[: args.limit_cves]

    attacks = load_attack_records(args, vuldat_df)
    print(f"CVE documents: {len(docs)}")
    print(f"Attack queries: {len(attacks)}")

    model = SentenceTransformer(args.embedding_model)
    doc_texts = [doc["clean_text"] for doc in docs]
    doc_embeddings = model.encode(doc_texts, normalize_embeddings=True, show_progress_bar=True)
    bm25 = BM25(doc_texts)

    retrieval_records = []
    retrieval_metric_rows = []
    prediction_records = []
    prediction_metric_rows = []

    for count, record in enumerate(attacks, start=1):
        print(f"Processing query {count}/{len(attacks)}: {record['attack_id']}")
        query_clean = clean_text(record["attack_text"])
        query_embedding = model.encode([query_clean], normalize_embeddings=True, show_progress_bar=False)[0]
        dense_scores = np.asarray(doc_embeddings) @ np.asarray(query_embedding)
        bm25_scores = bm25.score(query_clean)
        meta_scores = metadata_score(record["attack_text"], docs)
        retrieved = ranked_retrieval(record, docs, dense_scores, bm25_scores, meta_scores, args)
        retrieval_records.append(retrieved)

        if record["ground_truth_cves"]:
            metrics = retrieval_metrics(retrieved["retrieved_cves"], record["ground_truth_cves"], args.top_k)
            prediction_base = prediction_metrics(retrieved["retrieved_cves"], record["ground_truth_cves"])
            retrieval_metric_rows.append({**record, **metrics, **{f"prediction_{k}": v for k, v in prediction_base.items()}})

        predictions = llm_predict(retrieved, args)
        if predictions:
            predicted_ids = [item["cve_id"] for item in predictions]
        else:
            predicted_ids = retrieved["retrieved_cves"][: args.top_n] if not args.llm_model else []

        prediction_record = {
            **retrieved,
            "llm_model": args.llm_model or "",
            "predictions": predictions,
            "predicted_cves": predicted_ids,
        }
        prediction_records.append(prediction_record)

        if record["ground_truth_cves"]:
            prediction_metric_rows.append({**record, **prediction_metrics(predicted_ids, record["ground_truth_cves"])})

    retrieval_path = output_dir / "retrieval_candidates.jsonl"
    prediction_path = output_dir / "predictions.jsonl"
    write_jsonl(retrieval_path, retrieval_records)
    write_jsonl(prediction_path, prediction_records)
    print(f"Wrote {retrieval_path}")
    print(f"Wrote {prediction_path}")

    if retrieval_metric_rows:
        write_summary(output_dir / "retrieval_metrics.csv", retrieval_metric_rows)
    if prediction_metric_rows:
        write_summary(output_dir / "prediction_metrics.csv", prediction_metric_rows)

    manual_rows = []
    for record in prediction_records:
        truth = set(record.get("ground_truth_cves", []))
        for cve_id in record.get("predicted_cves", []):
            if cve_id not in truth:
                manual_rows.append(
                    {
                        "attack_id": record["attack_id"],
                        "attack_type": record["attack_type"],
                        "attack_text": record["attack_text"],
                        "cve_id": cve_id,
                        "reviewer_1_label": "",
                        "reviewer_2_label": "",
                        "resolved_label": "",
                        "notes": "",
                    }
                )
    manual_path = output_dir / "manual_validation_candidates.csv"
    pd.DataFrame(manual_rows).to_csv(manual_path, index=False)
    print(f"Wrote {manual_path}")


if __name__ == "__main__":
    main()
