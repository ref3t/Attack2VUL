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

### Data Mapping
The mapping **M: A → C** establishes relationships between an attack **A** and a set of CVE reports **C**.  
- **Explicit mappings** occur when a direct reference between an attack and a CVE exists in the repositories.  
- **Implicit mappings** are inferred using machine learning models that identify connections between attack descriptions and vulnerabilities.  
- **Floating entries** represent attack descriptions that lack explicit CVE associations but can still be mapped through similarity analysis.  



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


## References

Here are some of the relevant papers related to this project:

- [Cybersecurity Defenses: Exploration of CVE Types through Attack Descriptions]([https://ieeexplore.ieee.org/abstract/document/10803317](https://ieeexplore.ieee.org/abstract/document/10803317))
- [A Comparison of Vulnerability Feature Extraction Methods from Textual Attack Patterns]([https://link.springer.com/chapter/10.1007/978-3-031-46077-7_36](https://ieeexplore.ieee.org/abstract/document/10803510))




