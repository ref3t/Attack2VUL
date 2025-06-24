
# Predicting CVEs from Attack News

This repository presents our research project on **automatically predicting software vulnerabilities (CVEs) from real-world cyberattack news** using semantic similarity models.

## Overview

The increasing frequency of cyberattacks reported in unstructured news articles presents a challenge for automated vulnerability tracking. Traditional systems rely heavily on structured repositories such as MITRE's CVE, ATT&CK, and CAPEC, but often lack the capability to infer connections from unstructured threat reports.

Our work aims to **bridge this gap** by using sentence transformer models to semantically link natural language attack descriptions in the news to known software vulnerabilities.

## Key Contributions

-  **Dataset**: A curated dataset of cybersecurity news articles from sources like SecurityWeek, labeled with relevant CVEs (both manually and through automated methods).
-  **Evaluation**: Performance evaluation using precision, recall, and F1-score with both manual and oracle-based validation strategies.
-  **Threshold Tuning**: Sensitivity analysis to select optimal cosine similarity threshold.

## Methodology

1. **Data Preprocessing**:
   - Collect and clean news articles.
   - Extract CVE ground truth labels from structured repositories and annotations.

2. **Embedding Generation**:
   - Use MPNet to encode both the attack news and CVE descriptions into dense vectors.

3. **Similarity Computation**:
   - Compute cosine similarity between each attack report and all CVE entries.
   - Predict top-k most similar CVEs per article.

4. **Evaluation**:
   - Manual validation of true positives.
   - Oracle-based validation using MITRE and external annotations.

## Dependencies

- Python 3.9+
- PyTorch
- Transformers (Hugging Face)
- Sentence-Transformers
- Pandas, NumPy, Scikit-learn

Install with:

```bash
pip install -r requirements.txt
