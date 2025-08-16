# attack2vul/metrics.py
import pandas as pd
from typing import List, Tuple, Dict, Iterable
from .types import VulData

class AttackLevelConfusion:
    
    def __init__(self, threshold: float):
        
        self.threshold = threshold
        self.df_main = pd.DataFrame(columns=[
            'Threshold','TechID','TP','FP','FN','TN',
            'AttackTP','AttackTN','AttackFP','AttackFN','CountMapping'
        ])
        self.df_details = pd.DataFrame(columns=[
            'TechID','TP','FP','FN','TN',
            'AttackTP','AttackTN','AttackFP','AttackFN','CountMapping',
            'Lpositive','countLpositive','LNegatives','countLNegatives','Mapping'
        ])
        self.df_jaccard_all_models = pd.DataFrame(columns=[
            'modelName','LintersectM','L_M','M','M_L','L_Sum','Jaccard'
        ])

        # attack-level counters
        self.AttackTPsum = 0
        self.AttackTNsum = 0
        self.AttackFPsum = 0
        self.AttackFNsum = 0

    @staticmethod
    def _true_negatives(vul_data: Iterable[VulData], cve_ids_not_attack: List[str], th: float) -> Tuple[int, int]:
        # TN among retrieved (sim<th, and in not-attack set)
        tn_retrieved = sum(
            1 for vd in vul_data
            if float(vd.CVE_Smiliraty) < th and vd.CVE_ID in cve_ids_not_attack
        )
        # TN not retrieved at all (present in not-attack but never appeared)
        seen = {vd.CVE_ID for vd in vul_data}
        tn_not_retrieved = sum(1 for cid in cve_ids_not_attack if cid not in seen)
        return tn_retrieved, tn_not_retrieved

    def add_attack_result(
        self,
        model_name: str,
        tech_id: str,
        vul_data_list: List[VulData],
        cves_attack: List[str],
        positives: List[str],
        negatives: List[str],
        cves_not_attack: List[str]
    ):
        th = self.threshold

        mapping_cves = list({vd.CVE_ID for vd in vul_data_list if vd.CVE_ID in cves_attack})
        count_mapping = len(mapping_cves)

        
        low_sim_attack = list({vd.CVE_ID for vd in vul_data_list
                               if float(vd.CVE_Smiliraty) < th and vd.CVE_ID in cves_attack})
        not_retrieved_attack = list({cid for cid in cves_attack
                                     if cid not in {vd.CVE_ID for vd in vul_data_list}})
        FN = len(low_sim_attack) + len(not_retrieved_attack)

        
        tn_retrieved, tn_not_retrieved = self._true_negatives(vul_data_list, cves_not_attack, th)
        TN = tn_retrieved + tn_not_retrieved

        
        L_pos = list(set(positives))
        L_neg = list(set(negatives))
        L_len = len(L_pos) + len(L_neg)

        AttackTP = AttackTN = AttackFP = AttackFN = 0
        if (L_len > 0) and (count_mapping > 0):
            AttackTP = 1; self.AttackTPsum += 1
        elif (L_len == 0) and (count_mapping == 0):
            AttackTN = 1; self.AttackTNsum += 1
        elif (L_len > 0) and (count_mapping == 0):
            AttackFP = 1; self.AttackFPsum += 1
        elif (L_len == 0) and (count_mapping > 0):
            AttackFN = 1; self.AttackFNsum += 1

        LintersectM = len(L_pos)                  
        M = count_mapping
        L_M = len(L_neg)
        M_L = M - LintersectM
        L_Sum = LintersectM + L_M
        Jaccard = 0 if (L_Sum == 0 and M_L == 0) else (LintersectM / (L_Sum + M_L))

        # self.df_jaccard_all_models = pd.concat([self.df_jaccard_all_models, pd.DataFrame([{
        #     'modelName': model_name,
        #     'LintersectM': LintersectM, 'L_M': L_M, 'M': M, 'M_L': M_L, 'L_Sum': L_Sum, 'Jaccard': Jaccard
        # }])], ignore_index=True)
        self.df_jaccard_all_models = pd.concat([self.df_jaccard_all_models, pd.DataFrame([{
            'modelName': model_name,
            'LintersectM': LintersectM, 'L_M': L_M, 'M': M, 'M_L': M_L, 'L_Sum': L_Sum
        }])], ignore_index=True)
        # Main row
        self.df_main = pd.concat([self.df_main, pd.DataFrame([{
            'Threshold': th*100, 'TechID': tech_id,
            'TP': len(L_pos), 'FP': len(L_neg), 'FN': FN, 'TN': TN,
            'AttackTP': AttackTP, 'AttackTN': AttackTN, 'AttackFP': AttackFP, 'AttackFN': AttackFN,
            'CountMapping': count_mapping
        }])], ignore_index=True)

        # Detail row
        self.df_details = pd.concat([self.df_details, pd.DataFrame([{
            'TechID': tech_id,
            'TP': len(L_pos), 'FP': len(L_neg), 'FN': FN, 'TN': TN,
            'AttackTP': AttackTP, 'AttackTN': AttackTN, 'AttackFP': AttackFP, 'AttackFN': AttackFN,
            'CountMapping': count_mapping,
            'Lpositive': L_pos, 'countLpositive': len(L_pos),
            'LNegatives': L_neg, 'countLNegatives': len(L_neg),
            'Mapping': mapping_cves
        }])], ignore_index=True)

    def summary_prf(self):
        tp, fp, fn = self.AttackTPsum, self.AttackFPsum, self.AttackFNsum
        if (tp + fp) == 0 or (tp + fn) == 0:
            precision = tp
            recall = fp
            f1 = fn
        else:
            precision = tp / (tp + fp)
            recall = tp / (tp + fn)
            f1 = 0 if (precision+recall)==0 else (2*precision*recall/(precision+recall))
        return precision, recall, f1
