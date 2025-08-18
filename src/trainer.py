# attack2vul/trainer.py
import os
from torch.utils.data import DataLoader
from sentence_transformers import SentenceTransformer, losses
from sentence_transformers.evaluation import EmbeddingSimilarityEvaluator
from config import (LARGE)

class Trainer:
    def __init__(self, model_name: str, output_dir: str, epochs=4, eval_steps=500, warmup_steps=100, batch_size=16, device="cpu",use_amp: bool = False,
        enable_gradient_checkpointing: bool = False):
        self.model_name = model_name
        self.output_dir = output_dir
        self.epochs = epochs
        self.eval_steps = eval_steps
        self.warmup_steps = warmup_steps
        self.batch_size = batch_size
        self.device = device
        self.use_amp = use_amp
        self.enable_gradient_checkpointing = enable_gradient_checkpointing

    def fit(self, train_examples, val_examples):
        is_large= self.model_name.endswith(LARGE)
        self.batch_size=1 if is_large else self.batch_size
        self.use_amp=True if is_large else self.enable_gradient_checkpointing
        self.enable_gradient_checkpointing=True if is_large else self.enable_gradient_checkpointing
        model = SentenceTransformer(self.model_name, device=self.device)
        if self.enable_gradient_checkpointing:
            try:
                model._first_module().auto_model.gradient_checkpointing_enable()
            except Exception as e:
                print(f"[warn] gradient checkpointing not enabled: {e}")
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
            output_path=self.output_dir,
            use_amp=self.use_amp,
        )
        return SentenceTransformer(self.output_dir, device=self.device)
