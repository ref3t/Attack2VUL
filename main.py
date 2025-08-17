import os
import pandas as pd
from sentence_transformers import SentenceTransformer, losses
from torch.utils.data import DataLoader
from sentence_transformers.evaluation import EmbeddingSimilarityEvaluator

from config import (
    SENTENCE_TRANSFORMERS_MODELS, DATA_VARIANTS,
    SIM_THRESHOLD, EPOCHS, EVAL_STEPS, WARMUP_STEPS,
    RESULTS_DIR, MODELS_DIR, CVE_CORPUS_XLSX
)
from src.utils import ensure_dirs, setup_logging, get_device
from src.data_io import read_attack_pairs, to_input_examples, read_test_groups, read_cve_corpus
from src.evaluator import Evaluator
from src.metrics import AttackLevelConfusion

def main():
    setup_logging()
    ensure_dirs(RESULTS_DIR, MODELS_DIR)
    device = get_device()
    print(f"Using device: {device}")
    dataframeResults = pd.DataFrame(columns=['Data','Model','precision','Recall','F1'])

    for variant, files in DATA_VARIANTS.items():
        train_pairs = read_attack_pairs(files['train'], variant)
        val_pairs   = read_attack_pairs(files['val'],   variant)
        test_groups = read_test_groups(files['test'],   variant)

        train_examples = to_input_examples(train_pairs)
        val_examples   = to_input_examples(val_pairs)

        train_dataloader = DataLoader(train_examples, shuffle=True,  batch_size=16)
        val_evaluator    = EmbeddingSimilarityEvaluator.from_input_examples(val_examples, name=f"val-{variant}")

        for model_name in SENTENCE_TRANSFORMERS_MODELS:
            print(f"Processing model: {model_name} with infodata: {variant}")
            model = SentenceTransformer(model_name, device=device)
            train_loss = losses.CosineSimilarityLoss(model=model)

            out_dir = os.path.join(MODELS_DIR, f"fine_tuned_{model_name.replace('/', '_')}_{variant}")
            os.makedirs(out_dir, exist_ok=True)
         
            model.fit(
                train_objectives=[(train_dataloader, train_loss)],
                evaluator=val_evaluator,
                epochs=EPOCHS,
                evaluation_steps=EVAL_STEPS,
                warmup_steps=WARMUP_STEPS,
                output_path=out_dir
            )          
            fine_tuned_model = SentenceTransformer(out_dir, device=device)

            # fine_tuned_model = SentenceTransformer (model_name, device=device)
            dataCVE = read_cve_corpus(CVE_CORPUS_XLSX)
            evaluator = Evaluator(fine_tuned_model, threshold=SIM_THRESHOLD)
            confusion = AttackLevelConfusion(threshold=SIM_THRESHOLD)

            evaluator.evaluate_variant(variant, test_groups, dataCVE, confusion)

            precision, recall, f1 = confusion.summary_prf()
            dataframeResults = pd.concat([dataframeResults, pd.DataFrame([{
                'Data': variant, 'Model': model_name,
                'precision': precision, 'Recall': recall, 'F1': f1
            }])], ignore_index=True)

            confusion.df_main.to_excel(os.path.join(RESULTS_DIR, f"Results{model_name}_Main.xlsx"), index=False)
            confusion.df_details.to_excel(os.path.join(RESULTS_DIR, f"Results{model_name}_Details.xlsx"), index=False)
            confusion.df_jaccard_all_models.to_excel(os.path.join(RESULTS_DIR, "AllModelsNFineTuned.xlsx"), index=False)

    dataframeResults.to_excel(os.path.join(RESULTS_DIR, "Summary_PRF.xlsx"), index=False)
    print("Done.")

if __name__ == "__main__":
    main()
