import re


CITATION_RE = re.compile(r"\(Citation:.*?\)", re.IGNORECASE)
URL_RE = re.compile(r"http[s]?://\S+|www\.\S+", re.IGNORECASE)
CODE_RE = re.compile(r"<code>.*?</code>", re.IGNORECASE | re.DOTALL)
NOISE_RE = re.compile(r"[^a-z0-9]+")


def clean_text(value: object) -> str:
    text = "" if value is None else str(value)
    text = text.lower()
    text = CITATION_RE.sub(" ", text)
    text = URL_RE.sub(" ", text)
    text = CODE_RE.sub(" ", text)
    text = NOISE_RE.sub(" ", text)
    return " ".join(text.split())
