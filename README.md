# ATT&CK2V

## Overview
ATT&CK2V is a tool designed to identify software vulnerabilities based on attack descriptions. Given a textual attack description, it retrieves the most relevant vulnerabilities from the CVE (Common Vulnerabilities and Exposures) repository. The attack text can be sourced from MITRE repositories (ATT&CK, CAPEC, CWE) or security news articles. This tool helps cybersecurity professionals assess risks, investigate incidents, and strengthen defense mechanisms.

ATT&CK2V uses information from the MITRE repositories, such as **ATT&CK**, **CAPEC**, **CWE**, and **CVE**, to create a dataset of attacks and vulnerabilities. It also employs a sentence transformer model to compute semantic similarity between attack texts and vulnerability descriptions, producing a ranked list of relevant CVEs.

## Data Description

The VULDAT approach uses four datasets from the MITRE repositories, which are:

- **ATT&CK**: A repository of information about adversary tactics and techniques gathered from real-world observations. It serves as a basis for the development of specific threat methodologies and approaches within the domain of cybersecurity.
  
- **CAPEC**: A catalogue of common attack patterns, tactics, and techniques adversaries use to exploit vulnerabilities. It provides a common language for describing and analyzing cyberattacks.
  
- **CWE**: A community-developed collection of common software weaknesses, coding errors, and security flaws. It provides a standard framework for identifying and classifying software vulnerabilities and their root causes.
  
- **CVE**: A list of publicly known cybersecurity vulnerabilities and exposures, each with a unique identification number and a brief description. It provides a reference point for vulnerability information and facilitates information sharing among security communities.

## How To Use The Scripts

### Pre-Requirements

Ensure the following libraries are installed:

- Python 3.x
- pandas
- torch
- sentence-transformers
- openpyxl
- datasets
- pyarrow
- pandas[all]
- transformers[torch]
- sklearn

You can install them using `pip`:

```bash
pip install sklearn gensim numpy nltk
## Methodology
ATT&CK2V follows a structured methodology to map attack descriptions to vulnerabilities:

1. **Data Collection:**  
   - Retrieves attack data from MITRE ATT&CK (techniques, tactics, and procedures).  
   - Gathers vulnerability information from CVE, CWE, and CAPEC repositories.  
   - Combines structured and unstructured text sources for a comprehensive dataset.  

2. **Text Preprocessing:**  
   - Cleans and processes input text by removing noise (e.g., URLs, special characters).  
   - Converts text to lowercase to ensure consistency.  
   - Tokenizes text into meaningful components.  
   - Applies stemming and lemmatization to standardize words.  
   - Removes stop-words to focus on essential information.  

3. **Embedding Generation:**  
   - Utilizes sentence transformers (e.g., MiniLM, RoBERTa) to convert attack descriptions and CVE reports into numerical embeddings.  
   - Captures semantic relationships between attack patterns and vulnerabilities.  

4. **Similarity Computation:**  
   - Employs cosine similarity to measure the closeness between attack embeddings and vulnerability descriptions.  
   - Generates a ranked list of CVEs based on their relevance to the attack text.  

5. **Vulnerability Identification:**  
   - Outputs a prioritized list of CVEs that match the given attack description.  
   - Highlights potential security weaknesses that could be exploited by similar attack techniques.  

## Data Sets
The system utilizes multiple data repositories to establish attack-to-vulnerability mappings:

- **MITRE ATT&CK:** Provides structured knowledge on adversarial tactics, techniques, and procedures (TTPs).  
- **CAPEC (Common Attack Pattern Enumeration and Classification):** Contains a collection of attack patterns used by cybercriminals.  
- **CWE (Common Weakness Enumeration):** Offers a taxonomy of software weaknesses that may lead to security issues.  
- **CVE (Common Vulnerabilities and Exposures):** Maintains a database of publicly known security vulnerabilities.  

### Data Mapping
The mapping **M: A → C** establishes relationships between an attack **A** and a set of CVE reports **C**.  
- **Explicit mappings** occur when a direct reference between an attack and a CVE exists in the repositories.  
- **Implicit mappings** are inferred using machine learning models that identify connections between attack descriptions and vulnerabilities.  
- **Floating entries** represent attack descriptions that lack explicit CVE associations but can still be mapped through similarity analysis.  

## Text Preprocessing  
To ensure accurate vulnerability predictions, ATT&CK2V applies the following text preprocessing steps:  

- **Lowercasing:** Converts all text to lowercase for uniformity.  
- **URL and Citation Removal:** Eliminates links and citations that do not contribute to meaning.  
- **Tokenization:** Breaks text into individual words or phrases.  
- **Stemming and Lemmatization:** Reduces words to their root form (e.g., "running" → "run").  
- **Stop-word Removal:** Filters out common words like "the," "is," and "and."  
- **Punctuation Handling:** Removes unnecessary punctuation marks.  

## Performance Evaluation  
ATT&CK2V’s accuracy is assessed by comparing predicted CVEs with known ground-truth mappings. The evaluation metrics include:  

- **Precision:** Measures the proportion of retrieved vulnerabilities that are relevant.  
- **Recall:** Evaluates the proportion of relevant vulnerabilities correctly identified.  
- **F1-score:** Balances precision and recall to provide an overall performance measure.  

## Dependencies  
To install the required dependencies, run the following command:  
```bash
pip install transformers numpy pandas scikit-learn
```

## Usage  
To use ATT&CK2V, follow these steps:  

1. Import the model:  
```python
from attack2v import ATTACK2V
```
2. Initialize the model:  
```python
model = ATTACK2V()
```
3. Provide an attack description:  
```python
attack_text = "Example attack description"
```
4. Get the ranked list of vulnerabilities:  
```python
results = model.predict(attack_text)
print(results)
```

## Future Work  
To improve ATT&CK2V, future enhancements will focus on:  

- **Expanding Data Sources:** Incorporating more security databases and threat intelligence feeds.  
- **Enhancing Classification Models:** Experimenting with deep learning approaches for better accuracy.  
- **Optimizing Performance:** Reducing computational overhead and improving real-time prediction capabilities.  
- **Integrating with Security Tools:** Providing API support for integration with SIEMs (Security Information and Event Management) and IDS (Intrusion Detection Systems).  

## License  
This project is licensed under the MIT License.  

