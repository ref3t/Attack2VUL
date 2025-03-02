import pandas as pd
import random
from sentence_transformers import SentenceTransformer, util

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
    return cleaned_data[cleaned_data['ProceduresID'].isin(selected_ids)]  # Keep only selected 88 negatives

# Load datasets
positive_dataset_path = "./dataset/VULDATDataSetProcedures.xlsx"
negative_dataset_path = "./FinalResultSeperate/Procedures/ProceduresNegatives.xlsx"

positive_df = pd.read_excel(positive_dataset_path, sheet_name=0)

# Step 1: Select 88 unique "ProceduresID" for positives and get all their rows
unique_positive_ids = positive_df['ProceduresID'].drop_duplicates().sample(n=88, random_state=42)
positive_df = positive_df[positive_df['ProceduresID'].isin(unique_positive_ids)]

# Step 2: Select 88 unique "ProceduresID" for negatives
negative_samples = pd.read_excel(negative_dataset_path, sheet_name=0)
unique_negative_ids = negative_samples['ProceduresID'].drop_duplicates().sample(n=88, random_state=42)
negative_samples = read_tech_negative(negative_dataset_path, unique_negative_ids)

# Step 3: Create positive pairs (Keep all associated CVEIDs)
positive_pairs = [
    (row['ProceduresID'], row['ProcedureDescription'], row['CVEID'], row['CVEDescription'], 1)
    for _, row in positive_df.iterrows()
]

# Step 4: Create negative pairs (Match structure)
negative_pairs = []
seen_pairs = set()
positive_CVE_pairs = positive_df.drop_duplicates(subset=['CVEID', 'CVEDescription'])

# Shuffle negative samples
negative_samples = negative_samples.sample(frac=1, random_state=42).reset_index(drop=True)

i = 0
count = 0
while len(negative_pairs) < len(positive_pairs):  # Ensure same count
    print(str(len(negative_pairs))+"$$$$$$"+str(len(positive_pairs))+"$$$$$$$$$$$$")
    count = count +1
    CAPEC_id, description = negative_samples.iloc[i % len(negative_samples)]
    
    # Select a random positive CVE to ensure negatives are diverse
    positive_row = positive_CVE_pairs.sample(n=1, random_state=i).iloc[0]

    # Compute similarity
    similarity = compute_similarity(description, positive_row['CVEDescription'])

    # Only add if similarity is < 0.3 and the pair is unique
    pair = (CAPEC_id, description, positive_row['CVEID'], positive_row['CVEDescription'], 0)
    
    if similarity < 0.35 and pair not in seen_pairs:
        negative_pairs.append(pair)
        seen_pairs.add(pair)

    i += 1  

print(f"Final Balanced Dataset: {len(negative_pairs)} negatives, {len(positive_pairs)} positives")

# Combine positive and filtered negative pairs
balanced_data = positive_pairs + negative_pairs
random.shuffle(balanced_data)

# Convert list to DataFrame before saving
df_balanced = pd.DataFrame(balanced_data, columns=['ProceduresID', 'ProcedureDescription', 'CVEID', 'CVEDescription', 'Label'])

# Save to Excel
df_balanced.to_excel('dataset/attackInfo/Procedures/Proc_data_Balanced.xlsx', index=False)

# Train-test split
from sklearn.model_selection import train_test_split

train_data, temp_data = train_test_split(df_balanced, test_size=0.2, random_state=42)
val_data, test_data = train_test_split(temp_data, test_size=0.5, random_state=42)

# Save to Excel files
train_data.to_excel('dataset/attackInfo/Procedures/Proc_train_data_Balanced.xlsx', index=False)
val_data.to_excel('dataset/attackInfo/Procedures/Proc_val_data_Balanced.xlsx', index=False)
test_data.to_excel('dataset/attackInfo/Procedures/Proc_test_data_Balanced.xlsx', index=False)
