import spacy
import numpy as np
from transformers import AutoTokenizer, AutoModel
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.feature_extraction.text import TfidfVectorizer

# Load the MPNet model and tokenizer
tokenizer = AutoTokenizer.from_pretrained("sentence-transformers/all-mpnet-base-v2")
model = AutoModel.from_pretrained("sentence-transformers/all-mpnet-base-v2")

# Load SpaCy model for Named Entity Recognition (NER)
nlp = spacy.load("en_core_web_sm")

def get_embeddings(text):
    """Generate embeddings for a given text using MPNet."""
    inputs = tokenizer(text, return_tensors="pt", truncation=True, padding=True)
    outputs = model(**inputs)
    embeddings = outputs.last_hidden_state.mean(dim=1).detach().numpy()
    return embeddings

def extract_keywords_entities(text):
    """Extract keywords and named entities using SpaCy."""
    doc = nlp(text)
    keywords = [chunk.text for chunk in doc.noun_chunks]
    entities = [ent.text for ent in doc.ents]
    return keywords + entities

def calculate_similarity_score(text1, text2):
    """Calculate cosine similarity score between embeddings of two texts."""
    emb1 = get_embeddings(text1)
    emb2 = get_embeddings(text2)
    score = cosine_similarity(emb1, emb2)[0][0]
    return score

def validate_cve_news_pair(cve_description, news_content, threshold=0.58):
    """Validate if a CVE matches a news article based on similarity and keyword/entity overlap."""
    
    # Step 1: Calculate initial similarity
    initial_score = calculate_similarity_score(cve_description, news_content)
    if initial_score < threshold:
        return False, initial_score  # Reject if similarity is below threshold

    # Step 2: Extract keywords and entities from both texts
    cve_keywords_entities = set(extract_keywords_entities(cve_description))
    news_keywords_entities = set(extract_keywords_entities(news_content))
    
    # Step 3: Check for overlap between keywords/entities
    overlap = cve_keywords_entities.intersection(news_keywords_entities)
    
    # Step 4: Apply a secondary validation if overlap exists
    if overlap:
        refined_score = calculate_similarity_score(" ".join(overlap), news_content)
        return refined_score >= 0.70, refined_score  # Retain if refined score is above 0.70

    return False, initial_score

# Example data
cve_description = "The vCenter Server contains a heap-overflow vulnerability in the implementation of the DCERPC protocol. A malicious actor with network access to vCenter Server may trigger this vulnerability by sending a specially crafted network packet potentially leading to remote code execution."
news_content = "The VMware vCenter Server contains a memory corruption vulnerability in the implementation of the DCERPC protocol. A malicious actor with network access to vCenter Server may trigger a memory corruption vulnerability which may bypass authentication."

# Validate CVE-News pair
is_valid, score = validate_cve_news_pair(cve_description, news_content)
print("Validation Result:", is_valid)
print("Score:", score)
