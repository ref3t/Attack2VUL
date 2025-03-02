import pandas as pd
import random
from sentence_transformers import SentenceTransformer, util
from sklearn.model_selection import train_test_split

# Load the sentence transformer model
model = SentenceTransformer('multi-qa-mpnet-base-dot-v1')

def compute_similarity(text1, text2):
    """Compute cosine similarity between two texts."""
    embedding1 = model.encode(text1, convert_to_tensor=True)
    embedding2 = model.encode(text2, convert_to_tensor=True)
    return util.pytorch_cos_sim(embedding1, embedding2).item()

def read_tech_negative(file_path):
    """Read negative technique descriptions."""
    data = pd.read_excel(file_path, header=0, names=['TacticId', 'TacticName', 'TacticDescription'])
    return data[['TacticId', 'TacticName', 'TacticDescription']].dropna()

# Load datasets
positive_dataset_path = "./dataset/VULDATDataSetTactics.xlsx"
negative_dataset_path = "./FinalResultSeperate/Tactic/FinalTacticNegative.xlsx"

positive_df = pd.read_excel(positive_dataset_path, sheet_name=0)
negative_samples = read_tech_negative(negative_dataset_path)

# Remove duplicate rows from positive dataset
positive_df = positive_df.drop_duplicates(subset=['TacticId', 'TacticDescription', 'CVEID', 'CVEDescription'])

# Create positive pairs (Keep all positives)
positive_pairs = [
    (row['TacticId'], row['TacticDescription'], row['CVEID'], row['CVEDescription'], 1)
    for _, row in positive_df.iterrows()
]

# Define imbalance ratio (e.g., 2x or 3x negatives compared to positives)
imbalance_ratio = 3  # Change this to increase/decrease negative samples

negative_pairs = []
seen_pairs = set()
negative_sample_count = len(positive_pairs) / imbalance_ratio  # More negatives than positives

negative_samples = negative_samples.sample(frac=1, random_state=42).reset_index(drop=True)

i = 0
while len(negative_pairs) < negative_sample_count:
    print(str(len(negative_pairs)))
    tactic_id, name, description = negative_samples.iloc[i % len(negative_samples)]
    positive_row = positive_df.sample(n=1, random_state=i).iloc[0]
    
    similarity = compute_similarity(description, positive_row['CVEDescription'])
    
    pair = (tactic_id, description, positive_row['CVEID'], positive_row['CVEDescription'], 0)
    
    if similarity < 0.25 and pair not in seen_pairs:
        negative_pairs.append(pair)
        seen_pairs.add(pair)

    i += 1

print(f"Imbalanced Dataset: {len(negative_pairs)} negatives, {len(positive_pairs)} positives (Ratio: {len(negative_pairs) / len(positive_pairs):.2f}:1)")

# Combine positive and negative pairs
imbalanced_data = positive_pairs + negative_pairs
random.shuffle(imbalanced_data)

# Convert to DataFrame
df_imbalanced = pd.DataFrame(imbalanced_data, columns=['TacticId', 'TacticDescription', 'CVEID', 'CVEDescription', 'Label'])

# Save to Excel
df_imbalanced.to_excel('dataset/attackInfo/Tactics/Tactic_data_Imbalanced.xlsx', index=False)

# Train-test split (keeping imbalance ratio)
train_data, temp_data = train_test_split(df_imbalanced, test_size=0.2, stratify=df_imbalanced['Label'], random_state=42)
val_data, test_data = train_test_split(temp_data, test_size=0.5, stratify=temp_data['Label'], random_state=42)

# Save splits
train_data.to_excel('dataset/attackInfo/Tactics/Tactic_train_data_Imbalanced.xlsx', index=False)
val_data.to_excel('dataset/attackInfo/Tactics/Tactic_val_data_Imbalanced.xlsx', index=False)
test_data.to_excel('dataset/attackInfo/Tactics/Tactic_test_data_Imbalanced.xlsx', index=False)
