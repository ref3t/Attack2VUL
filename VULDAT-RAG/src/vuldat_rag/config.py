from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import os


PROJECT_ROOT = Path(os.environ.get("VULDAT_PROJECT_ROOT", Path(__file__).resolve().parents[3]))
PACKAGE_ROOT = PROJECT_ROOT / "VULDAT-RAG"
OUTPUT_DIR = PACKAGE_ROOT / "outputs"

DEFAULT_MODEL_NAME = "sentence-transformers/multi-qa-mpnet-base-dot-v1"
DEFAULT_TOP_K = 20
DEFAULT_RANK_LIMIT = 200
DEFAULT_THRESHOLD = 0.0


@dataclass(frozen=True)
class AttackSchema:
    attack_type: str
    id_col: str
    desc_col: str
    name_col: str | None


SCHEMAS: dict[str, AttackSchema] = {
    "Technique": AttackSchema("Technique", "TechniqueID", "TechniqueDescription", "TechniqueName"),
    "Tactic": AttackSchema("Tactic", "TacticId", "TacticDescription", None),
    "Procedure": AttackSchema("Procedure", "ProcedureID", "ProcedureDescription", "ProcedureName"),
    "CAPEC": AttackSchema("CAPEC", "CAPECID", "CAPECDescription", "CAPECName"),
}


@dataclass(frozen=True)
class DatasetConfig:
    cve_mapping_file: Path = PROJECT_ROOT / "dataset" / "VULDATDataSet.xlsx"
    split_files: dict[str, list[Path]] = field(
        default_factory=lambda: {
            "Technique": [
                PROJECT_ROOT / "dataset" / "attackInfo" / "Techniques" / "Tech_train_data_Balanced.xlsx",
                PROJECT_ROOT / "dataset" / "attackInfo" / "Techniques" / "Tech_val_data_Balanced.xlsx",
                PROJECT_ROOT / "dataset" / "attackInfo" / "Techniques" / "Tech_test_data_Balanced.xlsx",
            ],
            "Tactic": [
                PROJECT_ROOT / "dataset" / "attackInfo" / "Tactics" / "Tactic_train_data_Balanced.xlsx",
                PROJECT_ROOT / "dataset" / "attackInfo" / "Tactics" / "Tactic_val_data_Balanced.xlsx",
                PROJECT_ROOT / "dataset" / "attackInfo" / "Tactics" / "Tactic_test_data_Balanced.xlsx",
            ],
            "Procedure": [
                PROJECT_ROOT / "dataset" / "attackInfo" / "Procedures" / "Proc_train_data_Balanced.xlsx",
                PROJECT_ROOT / "dataset" / "attackInfo" / "Procedures" / "Proc_val_data_Balanced.xlsx",
                PROJECT_ROOT / "dataset" / "attackInfo" / "Procedures" / "Proc_test_data_Balanced.xlsx",
            ],
            "CAPEC": [
                PROJECT_ROOT / "dataset" / "attackInfo" / "CAPECs" / "Capec_train_data_Balanced.xlsx",
                PROJECT_ROOT / "dataset" / "attackInfo" / "CAPECs" / "Capec_val_data_Balanced.xlsx",
                PROJECT_ROOT / "dataset" / "attackInfo" / "CAPECs" / "Capec_test_data_Balanced.xlsx",
            ],
        }
    )
