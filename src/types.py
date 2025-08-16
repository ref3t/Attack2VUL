# attack2vul/types.py
from dataclasses import dataclass

@dataclass
class VulData:
    CVE_ID: str = ""
    CVE_Des: str = ""
    CVE_Smiliraty: str = "0.0"
