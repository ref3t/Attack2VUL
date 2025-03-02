import pandas as pd
import random
from sklearn.model_selection import train_test_split
from sentence_transformers import SentenceTransformer, util
from sentence_transformers import losses
from torch.utils.data import DataLoader
import torch
import numpy as np
import torch
from sentence_transformers import SentenceTransformer, losses, InputExample
from torch.utils.data import DataLoader
from sentence_transformers.evaluation import EmbeddingSimilarityEvaluator
import pandas as pd
import random


model = SentenceTransformer('multi-qa-mpnet-base-dot-v1')  

def readTechWithNegative():
    file_pathNegative = './dataset/FinalTechniquesNegative.xlsx'  # Path to your negative dataset
    data = pd.read_excel(file_pathNegative, header=0, names=['TechnqiueID', 'TechnqiueName', 'TechnqiueDescription'])
    
    # Group by TechnqiueID and aggregate descriptions into lists
    grouped_data = data.groupby('TechnqiueID').agg(lambda x: x.tolist()).reset_index()
    
    # Extract only the descriptions (no TechnqiueID or TechnqiueName)
    descriptions = grouped_data['TechnqiueDescription'].tolist()

    # Randomly select 100 descriptions
    random_descriptions = random.sample(descriptions, 1)
    
    return random_descriptions

# Load the dataset
dataset_path = "./dataset/VULDATDataSetTechniquesTest.xlsx"  # Replace with your dataset path
df = pd.read_excel(dataset_path, sheet_name=0)

# Step 1: Extract unique attack descriptions (positive attacks)
unique_TechnqiueDescriptions = df['TechnqiueDescription'].unique()

# Step 2: Assume you have a corresponding CVE column, extract the CVEs for each attack description
positive_pairs = []
for attack in unique_TechnqiueDescriptions:
    cve_list = df[df['TechnqiueDescription'] == attack]['CVEDescription'].tolist()  # Assuming CVEs are in 'CVE' column
    positive_pairs.append((attack, cve_list))

# Step 3: Create negative pairs with the same CVEs
negative_attacks = readTechWithNegative()

# Create negative pairs (same CVEs as positive pairs, but labeled as negative)
negative_pairs = []
for i in range(len(negative_attacks)):
    # For each negative attack, pair it with the CVEs from a corresponding positive attack
    positive_attack, positive_cves = positive_pairs[i % len(positive_pairs)]  # Use modulo to match negative with positive
    negative_pairs.append((negative_attacks[i], positive_cves, 0))  # Same CVEs, labeled as negative

# Step 4: Combine positive and negative pairs
balanced_data = []
for attack, cves in positive_pairs:
    balanced_data.append((attack, cves, 1))  # Label positive pairs as 1

balanced_data.extend(negative_pairs)  # Add negative pairs

# Step 5: Shuffle the dataset to mix positive and negative pairs
random.shuffle(balanced_data)

# Step 6: Split into train, validation, and test sets (80-10-10 split)
train_data, temp_data = train_test_split(balanced_data, test_size=0.2, random_state=42)
val_data, test_data = train_test_split(temp_data, test_size=0.5, random_state=42)

# Now you have a balanced dataset
print(f"Training Data: {len(train_data)} examples")
print(f"Validation Data: {len(val_data)} examples")
print(f"Test Data: {len(test_data)} examples")

# Compute cosine similarity between attack and CVE descriptions
def compute_similarity(attack_desc, cve_desc_list):
    # Check if attack_desc is a string and cve_desc_list is a list of strings
    if not isinstance(attack_desc, str):
        raise ValueError("Attack description should be a string.")
    
    if not all(isinstance(cve, str) for cve in cve_desc_list):
        raise ValueError("Each CVE description should be a string.")
    
    # Encode the attack description and the list of CVE descriptions using the MPNet model
    attack_embeddings = model.encode([attack_desc], convert_to_tensor=True)
    
    # Ensure the cve_desc_list is not empty
    if len(cve_desc_list) == 0:
        raise ValueError("CVE description list is empty.")

    cve_embeddings = model.encode(cve_desc_list, convert_to_tensor=True)

    # Compute cosine similarity between the attack and each CVE description
    similarities = util.pytorch_cos_sim(attack_embeddings, cve_embeddings)[0]
    
    return similarities

# Example: Compute similarity for the first attack and its corresponding CVEs
attack_example = train_data[0][0]  # First attack description in the training set
cve_example = train_data[0][1]  # Corresponding CVE descriptions

similarities = compute_similarity(attack_example, cve_example)

# Print the similarities between the attack description and the corresponding CVEs
for i, cve_desc in enumerate(cve_example):
    print(f"Similarity between attack and CVE {i+1}: {similarities[i]:.4f}")


# Prepare training data
train_examples = []
for _, row in df.iterrows():
    attack_desc = row['TechnqiueDescription']  # Replace with the column name for attack descriptions
    cve_desc = row['CVEDescription']  # Replace with the column name for CVE descriptions
    label = 1.0  # Cosine similarity label for positive pairs (1.0 for similar)
 
    # Append as InputExample
    train_examples.append(InputExample(texts=[attack_desc, cve_desc], label=label))

# Create DataLoader
train_dataloader = DataLoader(train_examples, shuffle=True, batch_size=8)

# Define the loss function
train_loss = losses.CosineSimilarityLoss(model=model)

# Fine-tune the model
model.fit(
    train_objectives=[(train_dataloader, train_loss)],
    evaluator=None,  # Placeholder for validation evaluator
    epochs=4,  # Adjust the number of epochs as needed
    warmup_steps=100,
    evaluation_steps=500,  # Optionally evaluate on validation set every X steps
    output_path='./fine_tuned_mpnet1'
)

# Load the fine-tuned model
fine_tuned_model = SentenceTransformer('./fine_tuned_mpnet')

# Function to compute similarity
def compute_similarity(attack_desc, cve_desc_list):
    # Encode the attack description
    attack_embeddings = fine_tuned_model.encode(attack_desc, convert_to_tensor=True)

    # Encode the CVE descriptions
    cve_embeddings = fine_tuned_model.encode(cve_desc_list, convert_to_tensor=True)

    # Compute cosine similarity
    similarities = torch.nn.functional.cosine_similarity(attack_embeddings, cve_embeddings)
    return similarities

# Example to calculate similarity
attack_example = df.iloc[0]['TechnqiueDescription']  # Replace with example attack
cve_examples = df.iloc[:3]['CVEDescription'].tolist()  # Replace with example CVEs

# Calculate similarity
similarities = compute_similarity(attack_example, cve_examples)

print("\nCosine Similarity After Fine-tuning:")
for i, similarity in enumerate(similarities):
    print(f"Similarity with CVE {i+1}: {similarity.item():.4f}")
