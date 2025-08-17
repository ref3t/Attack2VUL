import os

# Models to fine-tune/evaluate
SENTENCE_TRANSFORMERS_MODELS = [
    'multi-qa-mpnet-base-dot-v1',
    # 'paraphrase-multilingual-MiniLM-L12-v2',
    # 'multi-qa-MiniLM-L6-cos-v1',
    # 'multi-qa-distilbert-cos-v1',
    # 'all-MiniLM-L12-v2',
    # 'all-distilroberta-v1',
    # 'all-MiniLM-L6-v2',
    # 'all-mpnet-base-v2',
    # 'paraphrase-MiniLM-L6-v2',
    # 'paraphrase-albert-small-v2',
    # 'msmarco-bert-base-dot-v5',
    # 'all-roberta-large-v1',
    # 'gtr-t5-xxl',
    # 'paraphrase-TinyBERT-L6-v2',
]

SIM_THRESHOLD = 0.58

EPOCHS = 4
EVAL_STEPS = 500
WARMUP_STEPS = 100

RESULTS_DIR = os.path.abspath("./Results")
MODELS_DIR  = os.path.abspath("./models")

# CVE_CORPUS_XLSX = "./dataset/VULDATDataSetWithoutProcedures.xlsx"
CVE_CORPUS_XLSX = "./dataset/VULDATDataSet2.xlsx"


DATA_VARIANTS = {
    "Technique": {
        "train": 'dataset/attackInfo/Techniques/Tech_train_data_Balanced.xlsx',
        "val":   'dataset/attackInfo/Techniques/Tech_val_data_Balanced.xlsx',
        "test":  'dataset/attackInfo/Techniques/Tech_test_data_Balanced.xlsx',
    },
    "CAPEC": {
        "train": 'dataset/attackInfo/CAPECs/Capec_train_data_Balanced.xlsx',
        "val":   'dataset/attackInfo/CAPECs/Capec_val_data_Balanced.xlsx',
        "test":  'dataset/attackInfo/CAPECs/Capec_test_data_Balanced.xlsx',
    },
    "Tactic": {
        "train": 'dataset/attackInfo/Tactics/Tactic_train_data_Balanced.xlsx',
        "val":   'dataset/attackInfo/Tactics/Tactic_val_data_Balanced.xlsx',
        "test":  'dataset/attackInfo/Tactics/Tactic_test_data_Balanced.xlsx',
    },
    "Procedure": {
        "train": 'dataset/attackInfo/Procedures/Proc_train_data_Balanced.xlsx',
        "val":   'dataset/attackInfo/Procedures/Proc_val_data_Balanced.xlsx',
        "test":  'dataset/attackInfo/Procedures/Proc_test_data_Balanced.xlsx',
    }
    # ,
    # "TacticImbalanced": {
    #     "train": 'dataset/attackInfo/Tactics/Tactic_train_data_Imbalanced.xlsx',
    #     "val":   'dataset/attackInfo/Tactics/Tactic_val_data_Imbalanced.xlsx',
    #     "test":  'dataset/attackInfo/Tactics/Tactic_test_data_ImBalanced.xlsx',
    # },
    # "ProcedureImbalanced": {
    #     "train": 'dataset/attackInfo/Procedures/Proc_train_data_Imbalanced.xlsx',
    #     "val":   'dataset/attackInfo/Procedures/Proc_val_data_Imbalanced.xlsx',
    #     "test":  'dataset/attackInfo/Procedures/Proc_test_data_Imbalanced.xlsx',
    # },
    # "TechniqueImbalanced": {
    #     "train": 'dataset/attackInfo/Techniques/Tech_train_data_ImBalanced.xlsx',
    #     "val":   'dataset/attackInfo/Techniques/Tech_val_data_ImBalanced.xlsx',
    #     "test":  'dataset/attackInfo/Techniques/Tech_test_data_ImBalanced.xlsx',
    # },
    # "CAPECImbalanced": {
    #     "train": 'dataset/attackInfo/CAPECs/Capec_train_data_ImBalanced.xlsx',
    #     "val":   'dataset/attackInfo/CAPECs/Capec_val_data_ImBalanced.xlsx',
    #     "test":  'dataset/attackInfo/CAPECs/Capec_test_data_ImBalanced.xlsx',
    # },
}
