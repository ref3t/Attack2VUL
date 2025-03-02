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

def read_tech_negative(file_path, selected_ids):
    """Read negative technique descriptions and filter only the required ones."""
    data = pd.read_excel(file_path, header=0, names=['ProceduresID', 'ProcedureDescription'])
    cleaned_data = data.dropna()
    return cleaned_data[cleaned_data['ProceduresID'].isin(selected_ids)]  # Keep only selected negatives

# Load datasets
positive_dataset_path = "./dataset/VULDATDataSetProcedures.xlsx"
negative_dataset_path = "./FinalResultSeperate/Procedures/ProceduresNegatives.xlsx"

positive_df = pd.read_excel(positive_dataset_path, sheet_name=0)

# Keep all 721 positive samples
positive_df = positive_df.drop_duplicates(subset=['ProceduresID', 'ProcedureDescription', 'CVEID', 'CVEDescription'])

# Load and shuffle negative samples
negative_samples = pd.read_excel(negative_dataset_path, sheet_name=0)
negative_samples = negative_samples.sample(frac=1, random_state=42).reset_index(drop=True)

# Step 1: Create positive pairs (Keep all associated CVEIDs)
positive_pairs = [
    (row['ProceduresID'], row['ProcedureDescription'], row['CVEID'], row['CVEDescription'], 1)
    for _, row in positive_df.iterrows()
]

# Step 2: Define imbalance ratio (e.g., 2x or 3x negatives compared to positives)
imbalance_ratio = 10  # Change this to increase/decrease negative samples
negative_sample_count = int(len(positive_pairs) / imbalance_ratio)  # More negatives than positives

negative_pairs = []
seen_pairs = set()
positive_CVE_pairs = positive_df.drop_duplicates(subset=['CVEID', 'CVEDescription'])

i = 0
while len(negative_pairs) < negative_sample_count:  # Ensure required number of negatives
    print("$$$$$$"+str(negative_sample_count)+"$$$$$$$$$$$$"+str(len(negative_pairs)))
    CAPEC_id, description = negative_samples.iloc[i % len(negative_samples)]
    
    # Select a random positive CVE to ensure negatives are diverse
    positive_row = positive_CVE_pairs.sample(n=1, random_state=i).iloc[0]

    # Compute similarity
    similarity = compute_similarity(description, positive_row['CVEDescription'])

    # Only add if similarity is < 0.3 and the pair is unique
    pair = (CAPEC_id, description, positive_row['CVEID'], positive_row['CVEDescription'], 0)
    
    if similarity < 0.3 and pair not in seen_pairs:
        negative_pairs.append(pair)
        seen_pairs.add(pair)

    i += 1

print(f"Final Imbalanced Dataset: {len(negative_pairs)} negatives, {len(positive_pairs)} positives (Ratio: {imbalance_ratio}x)")

# Combine positive and negative pairs (Imbalanced Dataset)
imbalanced_data = positive_pairs + negative_pairs
random.shuffle(imbalanced_data)

# Convert list to DataFrame before saving
df_imbalanced = pd.DataFrame(imbalanced_data, columns=['ProceduresID', 'ProcedureDescription', 'CVEID', 'CVEDescription', 'Label'])

# Save to Excel
df_imbalanced.to_excel('dataset/attackInfo/Procedures/Proc_data_Imbalanced.xlsx', index=False)

# Train-test split while keeping the imbalance ratio
train_data, temp_data = train_test_split(df_imbalanced, test_size=0.2, stratify=df_imbalanced['Label'], random_state=42)
val_data, test_data = train_test_split(temp_data, test_size=0.5, stratify=temp_data['Label'], random_state=42)

# Save splits
train_data.to_excel('dataset/attackInfo/Procedures/Proc_train_data_Imbalanced.xlsx', index=False)
val_data.to_excel('dataset/attackInfo/Procedures/Proc_val_data_Imbalanced.xlsx', index=False)
test_data.to_excel('dataset/attackInfo/Procedures/Proc_test_data_Imbalanced.xlsx', index=False)
