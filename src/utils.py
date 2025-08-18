import os
import logging
from sentence_transformers import LoggingHandler
import torch
def ensure_dirs(*paths):
    for p in paths:
        os.makedirs(p, exist_ok=True)

def setup_logging():
    logging.basicConfig(
        format='%(asctime)s - %(message)s',
        level=logging.INFO,
        handlers=[LoggingHandler()]
    )
def get_device() -> str:
    """Return 'cuda:N' if CUDA is available, else 'cpu'."""
    if torch.cuda.is_available():
        return f'cuda:{torch.cuda.current_device()}'
    return 'cpu'