# attack2vul/evaluator.py
import numpy as np
from typing import Dict, Any, List
from sklearn.metrics.pairwise import cosine_similarity
from .text_cleaning import bulk_clean
from .types import VulData
from .metrics import AttackLevelConfusion

class Evaluator:
    def __init__(self, model, model_name, threshold: float ,device: str = "cpu"):
        self.model = model
        self.threshold = threshold
        self.device = device
        self.model_name = model_name

    def _encode_cve_corpus(self, dataCVE):
        descriptions   = dataCVE['CVEDescription'].values.tolist()
        techniquesName = dataCVE['TechniqueName'].values.tolist()
        descriptions   = descriptions[:len(descriptions)]
        techniquesName = techniquesName[:len(techniquesName)]
        joined_list = [techniquesName[i] + " " + descriptions[i]
                       for i in range(min(len(descriptions), len(techniquesName)))]
        embeddings = self.model.encode(joined_list, device=self.device, show_progress_bar=True)
        return embeddings

    def evaluate_variant(
        self,
        variant: str,
        test_groups: Dict[str, Dict[str, Any]],
        dataCVE,
        confusion: AttackLevelConfusion,
    ):
        CVEmbeddings = self._encode_cve_corpus(dataCVE)
        org = dataCVE  

        for countT, (key, value) in enumerate(test_groups.items()):
            print(f"ID: {key} ttttt {countT}")

            if variant in ("CAPEC", "CAPECImbalanced"):
                texts = bulk_clean([f"{value['CAPECDescription']}"])
            elif variant in ("Tactic", "TacticImbalanced"):
                texts = bulk_clean([f"{value['TacticDescription']}"])
            elif variant in ("Procedure", "ProcedureImbalanced"):
                texts = bulk_clean([f"{value['ProcedureDescription']}"])
            else:  
                tech_name = " ".join(value.get('TechniqueName', []))
                tech_desc = " ".join(value.get('TechniqueDescription', []))
                texts = bulk_clean([f"{tech_name} {tech_desc}"])

            atk_emb = self.model.encode(texts, device=self.device, show_progress_bar=True)
            sims = cosine_similarity(atk_emb.reshape(1, -1), CVEmbeddings)[0]
            top_idx = np.argsort(sims)[-181000:][::-1]

            vul_data_list: List[VulData] = []
            seen = set()
            for idx in top_idx:
                if org.loc[idx] is not None:
                    cve_id = dataCVE.loc[idx]['CVEID']
                    if cve_id not in seen:
                        seen.add(cve_id)
                        vd = VulData(
                            CVE_ID=cve_id,
                            CVE_Des=dataCVE.loc[idx]['CVEDescription'],
                            CVE_Smiliraty=f"{sims[idx]:.4f}",
                        )
                        vul_data_list.append(vd)

            if variant in ("CAPEC", "CAPECImbalanced"):
                trainAndTest = dataCVE[dataCVE['CAPECID'] == key]
                notAttack = dataCVE[dataCVE['CAPECID'] != key]
            elif variant in ("Tactic", "TacticImbalanced"):
                trainAndTest = dataCVE[dataCVE['TacticId'] == key]
                notAttack = dataCVE[dataCVE['TacticId'] != key]
            elif variant in ("Procedures", "ProceduresImBalanced"):
                trainAndTest = dataCVE[dataCVE['ProceduresID'] == key]
                notAttack = dataCVE[dataCVE['ProceduresID'] != key]
            else:  
                k = key.split(".")[0] if "." in key else key
                trainAndTest = dataCVE[dataCVE['TechniqueID'].str.startswith(k)]
                notAttack = dataCVE[~dataCVE['TechniqueID'].str.startswith(k)]

            cves_attack = list(set(trainAndTest['CVEID'].tolist()))
            cves_not_attack = list(set(x for x in notAttack['CVEID'].tolist() if x not in cves_attack))

            positives, negatives = [], []
            for item in vul_data_list:
                if float(item.CVE_Smiliraty) > self.threshold:
                    if item.CVE_ID in cves_attack:
                        positives.append(item.CVE_ID)
                    else:
                        negatives.append(item.CVE_ID)

            # Record into confusion matrix
            confusion.add_attack_result(
                model_name=self.model._first_module().__class__.__name__ if len(self.model_name) == 0 else self.model_name,
                tech_id=key,
                vul_data_list=vul_data_list,
                cves_attack=cves_attack,
                positives=positives,
                negatives=negatives,
                cves_not_attack=cves_not_attack,
            )
