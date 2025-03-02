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

def read_tech_negative(file_path, numberofPositive):
    """Read negative technique descriptions."""
    data = pd.read_excel(file_path, header=0, names=['TechniqueID', 'TechniqueName', 'TechniqueDescription'])
    cleaned_data = data[['TechniqueID', 'TechniqueName', 'TechniqueDescription']].dropna()
    return cleaned_data.sample(n=numberofPositive, random_state=42)

# Load datasets
positive_dataset_path = "./dataset/VULDATDataSetWithoutProcedures.xlsx"
negative_dataset_path = "./dataset/FinalTechniquesNegative.xlsx"

positive_df = pd.read_excel(positive_dataset_path, sheet_name=0)
unique_positive_techniques = positive_df['TechniqueID'].nunique()
negative_samples = read_tech_negative(negative_dataset_path, unique_positive_techniques)

# Remove duplicate rows from positive_df before creating positive_pairs
positive_df = positive_df.drop_duplicates(subset=['TechniqueID', 'TechniqueName', 'TechniqueDescription', 'CVEID', 'CVEDescription'])

# Remove duplicate rows from positive_df before creating positive_pairs
positive_CVE_pairs = positive_df.drop_duplicates(subset=['CVEID', 'CVEDescription'])

# Create positive pairs
positive_pairs = [
    (row['TechniqueID'], row['TechniqueName'], row['TechniqueDescription'], row['CVEID'], row['CVEDescription'], 1)
    for _, row in positive_df.iterrows()
]

# Create negative pairs with similarity check for CVE descriptions < 0.15
negative_pairs = []
seen_pairs = set()  # Track already added pairs
positive_sample_count = len(positive_CVE_pairs)

# Shuffle negative samples to ensure diversity
negative_samples = negative_samples.sample(frac=1, random_state=42).reset_index(drop=True)

# Ensure we collect enough negative pairs
i = 0
while len(negative_pairs) < len(positive_pairs):
    CAPEC_id, name, description = negative_samples.iloc[i % len(negative_samples)]
    
    # Select a random positive CVE to ensure negatives are diverse
    positive_row = positive_CVE_pairs.sample(n=1, random_state=i).iloc[0]

    # Compute similarity
    similarity = compute_similarity(description, positive_row['CVEDescription'])

    # Only add if similarity is < 0.15 and the pair is unique
    pair = (CAPEC_id, name, description, positive_row['CVEID'], positive_row['CVEDescription'], 0)
    
    if similarity < 0.15 and pair not in seen_pairs:
        negative_pairs.append(pair)
        seen_pairs.add(pair)

    i += 1  # Increment index to iterate through negative samples

print(f"Final Balanced Dataset: {len(negative_pairs)} negatives, {len(positive_pairs)} positives")

# # Create negative pairs
# negative_pairs = []
# negative_sample_count = len(positive_pairs)

# for i in range(negative_sample_count):
#     technique_id, name, description = negative_samples.iloc[i % len(negative_samples)]
#     positive_row = positive_df.iloc[i]
    
#     # Compute similarity
#     similarity = compute_similarity(description, positive_row['CVEDescription'])
    
#       # Only add if similarity is less than 0.2 and include CVE details
#     if similarity < 0.3:
#         negative_pairs.append((technique_id, name, description, positive_row['CVEID'], positive_row['CVEDescription'], 0))  # Keep CVE details


# Combine positive and filtered negative pairs
balanced_data = positive_pairs + negative_pairs
random.shuffle(balanced_data)
# Convert list to DataFrame before saving
df_balanced = pd.DataFrame(balanced_data, columns=['TechniqueID', 'TechniqueName', 'TechniqueDescription', 'CVEID', 'CVEDescription', 'Label'])

# Save to Excel
df_balanced.to_excel('dataset/attackInfo/Techniques/Tech_data_Balanced.xlsx', index=False)
# Convert to DataFrame
final_df = pd.DataFrame(balanced_data, columns=['TechniqueID', 'TechniqueName', 'TechniqueDescription', 'CVEID', 'CVEDescription', 'Label'])

# Train-test split
from sklearn.model_selection import train_test_split

train_data, temp_data = train_test_split(final_df, test_size=0.2, random_state=42)
val_data, test_data = train_test_split(temp_data, test_size=0.5, random_state=42)

# Save to Excel files
train_data.to_excel('dataset/attackInfo/Techniques/Tech_train_data_Balanced.xlsx', index=False)
val_data.to_excel('dataset/attackInfo/Techniques/Tech_val_data_Balanced.xlsx', index=False)
test_data.to_excel('dataset/attackInfo/Techniques/Tech_test_data_Balanced.xlsx', index=False)
