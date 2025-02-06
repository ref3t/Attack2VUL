# ATT&CK2V

## Overview
ATT&CK2V is a tool that, when given an attack text, outputs a prioritized list of vulnerabilities in the CVE repository associated with the attack. The attack text can be sourced from MITRE repositories or any news document.

## Methodology
The tool follows these steps:
1. **Data Collection:** Retrieves attack and vulnerability data from MITRE ATT&CK, CAPEC, CWE, and CVE repositories.
2. **Text Preprocessing:** Cleans and processes input text by removing noise, lowercasing, tokenization, stemming, and stop-word removal.
3. **Embedding Generation:** Uses sentence transformers to generate embeddings for attack texts and CVE descriptions.
4. **Similarity Computation:** Applies cosine similarity to match attack texts with CVE reports.
5. **Vulnerability Identification:** Outputs a ranked list of CVEs relevant to the attack text.

## Data Sets
The mapping between attacks and vulnerabilities is established using:
- **ATT&CK** for attack tactics, techniques, and procedures (TTPs).
- **CAPEC** for attack patterns.
- **CWE** for weakness reports.
- **CVE** for documented vulnerabilities.

### Data Mapping
The mapping **M: A → C** associates an attack **A** with a set of CVE reports **C** derived from repository links. Explicit links between repositories help refine the mapping, with floating entries indicating missing knowledge.

## Text Preprocessing
- Lowercasing
- URL and citation removal
- Tokenization
- Stemming and lemmatization
- Stop-word removal
- Punctuation handling

## Performance Evaluation
ATT&CK2V's performance is evaluated by comparing predicted CVEs against ground-truth mappings. The effectiveness is measured using:
- Precision
- Recall
- F1-score

## Dependencies
To run ATT&CK2V, install the following dependencies:
```bash
pip install transformers numpy pandas scikit-learn
```

## Usage
To use ATT&CK2V, run the following command:
```python
from attack2v import ATTACK2V

model = ATTACK2V()
attack_text = "Example attack description"
results = model.predict(attack_text)
print(results)
```

## Future Work
- Enhancing the dataset with additional repositories.
- Improving the classification model.
- Expanding evaluation metrics for better accuracy.

## License
This project is licensed under the MIT License.
