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

The full dataset used in this project is available here:  [**VULDATDataSet**](https://figshare.com/articles/dataset/VULDATDataSet_xlsx/25828102?file=46347484)
- Each row in the dataset represents a complete linkage across multiple MITRE repositories

##### Example Row
| Tactic ID | Technique ID | Procedure ID | CAPEC ID | CWE ID | CVE ID |
|-----------|--------------|--------------|----------|--------|--------|
| TA0009    | T1005        | C0015        | 37      | CWE-1258 | CVE-2021-33080 |
| TA0009    | T1005        | C0017        | 37      | CWE-1258 | CVE-2022-31162 |
| TA0009    | T1005        | C0017        | 37      | CWE-311  | CVE-2004-1852  |

### Instructions to Run ATT&CK2VUL

Ensure the following libraries are installed:

- Python 3.x
- pandas
- torch
- sentence-transformers
- openpyxl

  ```bash
  pip install -r requirements.txt
  python main.py

## References

Here are some of the relevant papers related to this project:

- [Cybersecurity Defenses: Exploration of CVE Types through Attack Descriptions](https://ieeexplore.ieee.org/abstract/document/10803317)
- [A Comparison of Vulnerability Feature Extraction Methods from Textual Attack Patterns](https://ieeexplore.ieee.org/abstract/document/10803510)


