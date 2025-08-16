# attack2vul/text_cleaning.py
import re

_CITATION = r'\(Citation:.*?\)'
_URL = r'http[s]?://(?:[a-zA-Z0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F]{2}))+'

def remove_citations_and_urls(text: str) -> str:
    text = re.sub(_CITATION, '', text)
    text = re.sub(_URL, '', text)
    text = re.sub("^<code>.*</code>$", "", text, flags=re.MULTILINE)
    text = " ".join(text.split())
    text = re.sub("[^A-Za-z0-9]", " ", text) 
    return text

def clean_attack_description(s: str) -> str:
    s = re.sub(r'^[\[\]"\s]+|[\[\]"\s]+$', '', str(s))
    s = s.replace("\\xa0\\n\\n", "").replace("\n", " ").replace("\\n", " ").replace("\\xa0", " ")
    s = re.sub(r'\s+', ' ', s).strip()
    return remove_citations_and_urls(s)

def bulk_clean(texts):
    return [remove_citations_and_urls(str(t)) for t in texts]
