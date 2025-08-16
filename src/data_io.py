import pandas as pd
from typing import List, Tuple, Dict, Any
from sentence_transformers import InputExample
from .text_cleaning import bulk_clean, remove_citations_and_urls

_SCHEMAS = {
    'CAPEC':      ('CAPECDescription', 'CAPECID', 'CAPECName'),
    'CAPECImbalanced': ('CAPECDescription', 'CAPECID', 'CAPECName'),
    'Tactic':     ('TacticDescription', 'TacticId', None),
    'TacticImbalanced': ('TacticDescription', 'TacticId', None),
    'Procedure':  ('ProcedureDescription', 'ProcedureID', 'ProcedureName'),
    'ProcedureImbalanced': ('ProcedureDescription', 'ProcedureID', 'ProcedureName'),
    'Technique':  ('TechniqueDescription', 'TechniqueID', 'TechniqueName'),
    'TechniqueImbalanced': ('TechniqueDescription', 'TechniqueID', 'TechniqueName'),
}

def read_attack_pairs(xlsx_path: str, variant: str) -> List[Tuple[str, str, List[str], float]]:
    """Return list of (id, attack_desc, [cve_desc], label)."""
    df = pd.read_excel(xlsx_path, sheet_name=0)
    atk_col, id_col, _name_col = _SCHEMAS.get(variant, ('TechniqueDescription','TechniqueID','TechniqueName'))
    data = []
    for _, r in df.iterrows():
        attack_desc = r[atk_col]
        idv = r[id_col]
        cve_desc = r['CVEDescription']
        label = r['Label']
        data.append((idv, attack_desc, [cve_desc], label))
    return data

def to_input_examples(pairs: List[Tuple[str, str, List[str], float]]) -> List[InputExample]:
    ex = []
    for _id, attack, cves, label in pairs:
        for c in cves:
            ex.append(InputExample(texts=[str(attack), str(c)], label=float(label)))
    return ex
def read_test_groups(xlsx_path: str, variant: str) -> Dict[str, Dict[str, Any]]:
    df = pd.read_excel(xlsx_path, sheet_name=0)
    atk_col, id_col, name_col = _SCHEMAS.get(
        variant, ('TechniqueDescription', 'TechniqueID', 'TechniqueName')
    )

    agg_dict = {atk_col: list, 'CVEDescription': list, 'Label': list}
    has_name = bool(name_col) and (name_col in df.columns)
    if has_name:
        agg_dict[name_col] = list

    grouped = (
        df.groupby(id_col, dropna=False)
          .agg(agg_dict)
          .reset_index()
    )

    out: Dict[str, Dict[str, Any]] = {}
    for _, row in grouped.iterrows():
        entry = {
            atk_col: row[atk_col],
            'CVEDescription': row['CVEDescription'],
            'Label': row['Label'],
        }
        if has_name:
            entry[name_col] = row[name_col]
        else:
            entry['attack_name'] = [] 
        out[str(row[id_col])] = entry

    return out

def read_cve_corpus(xlsx_path: str):
    df = pd.read_excel(xlsx_path, sheet_name=0)
    df['CVEDescription'] = bulk_clean(df['CVEDescription'].values)
    return df
