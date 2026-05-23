# ATT&CK2VUL — Automate Linking of Attack Descriptions to CVEs

## Overview
**ATT&CK2VUL** is an approach designed to identify vulnerabilities based on attack descriptions. Given a textual attack description, it retrieves the most relevant vulnerabilities from the CVE (Common Vulnerabilities and Exposures) repository. The attack text can be sourced from MITRE repositories (ATT&CK, CAPEC). This tool helps cybersecurity professionals assess risks, investigate incidents, and strengthen defense mechanisms.

**ATT&CK2VUL** uses information from the MITRE repositories, such as **ATT&CK**, **CAPEC**, **CWE**, and **CVE**, to create a dataset of attacks and vulnerabilities. It also employs a sentence transformer model to compute semantic similarity between attack texts and vulnerability descriptions, producing a ranked list of relevant CVEs.

Here’s the methodology diagram for ATT&CK2VUL:
![Methodology Diagram](Methodology.JPG?raw=true)


## Data Description

The ATT&CK2VUL approach uses four datasets from the MITRE repositories, which are:

- **ATT&CK**: A repository of information about adversary tactics and techniques gathered from real-world observations. It serves as a basis for the development of specific threat methodologies and approaches within the domain of cybersecurity.
  
- **CAPEC**: A catalogue of common attack patterns, tactics, and techniques adversaries use to exploit vulnerabilities. It provides a common language for describing and analyzing cyberattacks.
  
- **CWE**: A community-developed collection of common software weaknesses, coding errors, and security flaws. It provides a standard framework for identifying and classifying software vulnerabilities and their root causes.
  
- **CVE**: A list of publicly known cybersecurity vulnerabilities and exposures, each with a unique identification number and a brief description. It provides a reference point for vulnerability information and facilitates information sharing among security communities.

#### Data Mapping
The mapping **M: A → C** explicit links between an attack **A** and a set of CVE reports **C**. The links occur when a direct reference between an attack and a CVE exists in the repositories.  

The full dataset used in this project is available here:  [**VULDATDataSet**](https://figshare.com/articles/dataset/VULDATDataSet_xlsx/25828102?file=46347484) or Under dataset folder "VULDATDataSet.xlsx"
- Each row in the dataset represents a complete linkage across multiple MITRE repositories

##### Example Row
| Tactic ID | Technique ID | Procedure ID | CAPEC ID | CWE ID | CVE ID |
|-----------|--------------|--------------|----------|--------|--------|
| TA0009    | T1005        | C0015        | 37      | CWE-1258 | CVE-2021-33080 |
| TA0009    | T1005        | C0017        | 37      | CWE-1258 | CVE-2022-31162 |
| TA0009    | T1005        | C0017        | 37      | CWE-311  | CVE-2004-1852  |

## Instructions to Run ATT&CK2VUL

Ensure the following libraries are installed:

- Python 3.x
- pandas
- torch
- sentence-transformers
- openpyxl

  ```bash
  pip install -r requirements.txt
  python main.py #We will have for each model files for each attack type that contain all information
  ```

To run the same `src/` evaluation pipeline without fine-tuning the sentence transformer:

```bash
python main_no_finetune.py
```

For a smaller test run:

```bash
python main_no_finetune.py --models multi-qa-mpnet-base-dot-v1 --variants Technique
```

To run the same no-fine-tune pipeline with RAG reranking and manual-validation output:

```bash
python main_no_finetune_rag.py --models multi-qa-mpnet-base-dot-v1 --variants Technique
```

With local Ollama:

```bash
ollama serve
ollama pull llama3.1:8b
python main_no_finetune_rag.py \
  --models multi-qa-mpnet-base-dot-v1 \
  --variants Technique \
  --base-url http://localhost:11434/v1/chat/completions \
  --llm-model llama3.1:8b
```

To compare multiple LLMs in one run, pass more than one model name:

```bash
ollama pull llama3.1:8b
ollama pull llama3.2:3b
python main_no_finetune_rag.py \
  --models multi-qa-mpnet-base-dot-v1 \
  --variants Technique \
  --base-url http://localhost:11434/v1/chat/completions \
  --llm-model llama3.1:8b llama3.2:3b
```

You can also compare OpenAI and Claude models. Use the provider prefix in `--llm-model`:

```bash
export OPENAI_API_KEY=your_openai_key
export ANTHROPIC_API_KEY=your_anthropic_key

python main_no_finetune_rag.py \
  --models multi-qa-mpnet-base-dot-v1 \
  --variants Technique \
  --llm-model openai:gpt-4o-mini anthropic:claude-3-5-sonnet-latest
```

You can mix local and API models in the same command:

```bash
python main_no_finetune_rag.py \
  --models multi-qa-mpnet-base-dot-v1 \
  --variants Technique \
  --base-url http://localhost:11434/v1/chat/completions \
  --llm-model ollama:llama3.1:8b openai:gpt-4o-mini anthropic:claude-3-5-sonnet-latest
```

Free-tier providers still require a free API key. Use the provider prefix and set the matching environment variable:

```bash
export GEMINI_API_KEY=your_key
export GROQ_API_KEY=your_key
export OPENROUTER_API_KEY=your_key
export HF_TOKEN=your_key
export MISTRAL_API_KEY=your_key

python main_no_finetune_rag.py \
  --models multi-qa-mpnet-base-dot-v1 \
  --variants Technique \
  --llm-model \
    gemini:gemini-2.5-flash \
    groq:MODEL_ID_FROM_GROQ \
    openrouter:MODEL_ID_FROM_OPENROUTER \
    huggingface:MODEL_ID_FROM_HUGGINGFACE \
    mistral:MODEL_ID_FROM_MISTRAL
```

For completely local, no-key testing:

```bash
ollama pull llama3.1:8b
python main_no_finetune_rag.py \
  --models multi-qa-mpnet-base-dot-v1 \
  --variants Technique \
  --llm-model ollama:llama3.1:8b
```

LM Studio also works if its local OpenAI-compatible server is running on port `1234`:

```bash
python main_no_finetune_rag.py \
  --models multi-qa-mpnet-base-dot-v1 \
  --variants Technique \
  --llm-model lmstudio:local-model
```

With a vLLM server:

```bash
python main_no_finetune_rag.py \
  --models multi-qa-mpnet-base-dot-v1 \
  --variants Technique \
  --base-url http://localhost:8000/v1/chat/completions \
  --llm-model meta-llama/Llama-3.1-8B-Instruct
```

The RAG runner writes candidate files, comparison tables, threshold-based no-fine-tune results, and manual-validation candidate CSVs to `Results_NoFineTune_RAG/`. The before-RAG performance uses the similarity threshold. The RAG input is the same threshold-selected transformer output, and the after-RAG performance evaluates the LLM-filtered subset against the MITRE ground truth. The two main performance files are:

```text
Results_NoFineTune_RAG/Performance_Before_RAG.csv
Results_NoFineTune_RAG/Performance_After_RAG.csv
```

The summary PRF files use the same format as the no-fine-tune threshold summary:

```text
Results_NoFineTune_RAG/Summary_PRF_Before_RAG.xlsx
Results_NoFineTune_RAG/Summary_PRF_After_RAG.xlsx
Results_NoFineTune_RAG/Summary_PRF_After_RAG_All_LLMs.xlsx
Results_NoFineTune_RAG/LLM_RAG_Comparison.csv
```

The default threshold is `0.58`. To change it:

```bash
python main_no_finetune_rag.py --models multi-qa-mpnet-base-dot-v1 --variants Technique --threshold 0.58
```

## References

Here are some of the relevant papers related to this project:

- [From attack descriptions to vulnerabilities: A sentence transformer-based approach](https://linkinghub.elsevier.com/retrieve/pii/S0164121225002845)
- [Cybersecurity Defenses: Exploration of CVE Types through Attack Descriptions](https://ieeexplore.ieee.org/abstract/document/10803317)
- [A Comparison of Vulnerability Feature Extraction Methods from Textual Attack Patterns](https://ieeexplore.ieee.org/abstract/document/10803510)
