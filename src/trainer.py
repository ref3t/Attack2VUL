# attack2vul/trainer.py
import os
from torch.utils.data import DataLoader
from sentence_transformers import SentenceTransformer, losses
from sentence_transformers.evaluation import EmbeddingSimilarityEvaluator

class Trainer:
    def __init__(self, model_name: str, output_dir: str, epochs=4, eval_steps=500, warmup_steps=100, batch_size=16, device="cpu"):
        self.model_name = model_name
        self.output_dir = output_dir
        self.epochs = epochs
        self.eval_steps = eval_steps
        self.warmup_steps = warmup_steps
        self.batch_size = batch_size
        self.device = device

    def fit(self, train_examples, val_examples):
        model = SentenceTransformer(self.model_name, device=self.device)
        train_dataloader = DataLoader(train_examples, shuffle=True, batch_size=self.batch_size)
        train_loss = losses.CosineSimilarityLoss(model=model)
        evaluator = EmbeddingSimilarityEvaluator.from_input_examples(val_examples, name="val-evaluator")

        os.makedirs(self.output_dir, exist_ok=True)
        model.fit(
            train_objectives=[(train_dataloader, train_loss)],
            evaluator=evaluator,
            epochs=self.epochs,
            evaluation_steps=self.eval_steps,
            warmup_steps=self.warmup_steps,
            output_path=self.output_dir
        )
        return SentenceTransformer(self.output_dir, device=self.device)
