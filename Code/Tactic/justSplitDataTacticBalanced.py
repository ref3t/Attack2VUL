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

def read_tech_negative(file_path):
    """Read negative technique descriptions."""
    data = pd.read_excel(file_path, header=0, names=['TacticId', 'TacticName', 'TacticDescription'])
    cleaned_data = data[['TacticId', 'TacticName', 'TacticDescription']].dropna()
    return cleaned_data

# Load the datasets
positive_dataset_path = "./dataset/VULDATDataSetTactics.xlsx"
negative_dataset_path = "./FinalResultSeperate/Tactic/FinalTacticNegative.xlsx"  # Negative dataset path

# Read datasets
positive_df = pd.read_excel(positive_dataset_path, sheet_name=0)

negative_samples = read_tech_negative(negative_dataset_path)

# Remove duplicate rows from positive_df before creating positive_pairs
positive_df = positive_df.drop_duplicates(subset=['TacticId', 'TacticDescription', 'CVEID', 'CVEDescription'])

# Randomly select 3 unique TacticId values
random_tactics = positive_df['TacticId'].drop_duplicates().sample(n=3, random_state=42)  # Set random_state for reproducibility

positive_df = positive_df[positive_df['TacticId'].isin(random_tactics)]

# Remove duplicate rows from positive_df before creating positive_pairs
positive_CVE_pairs = positive_df.drop_duplicates(subset=['CVEID', 'CVEDescription'])

# Create positive pairs
positive_pairs = [
    (row['TacticId'], row['TacticDescription'], row['CVEID'], row['CVEDescription'], 1)
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
count = 0

while len(negative_pairs) < len(positive_pairs):
    print(str(count)+"$$$$$$"+str(i)+"$$$$$$$$$$$$"+str(len(negative_pairs)))
    count = count +1
    CAPEC_id, name, description = negative_samples.iloc[i % len(negative_samples)]
    
    # Select a random positive CVE to ensure negatives are diverse
    positive_row = positive_CVE_pairs.sample(n=1, random_state=i).iloc[0]

    # Compute similarity
    similarity = compute_similarity(description, positive_row['CVEDescription'])

    # Only add if similarity is < 0.15 and the pair is unique
    pair = (CAPEC_id, description, positive_row['CVEID'], positive_row['CVEDescription'], 0)
    
    if similarity < 0.30 and pair not in seen_pairs:
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
df_balanced = pd.DataFrame(balanced_data, columns=['TacticId', 'TacticDescription', 'CVEID', 'CVEDescription', 'Label'])

# Save to Excel
df_balanced.to_excel('dataset/attackInfo/Tactics/Tactic_data_Balanced.xlsx', index=False)
# Convert to DataFrame
final_df = pd.DataFrame(balanced_data, columns=['TacticId', 'TacticDescription', 'CVEID', 'CVEDescription', 'Label'])

# Train-test split
from sklearn.model_selection import train_test_split

train_data, temp_data = train_test_split(final_df, test_size=0.2, random_state=42)
val_data, test_data = train_test_split(temp_data, test_size=0.5, random_state=42)

# Save to Excel files
train_data.to_excel('dataset/attackInfo/Tactics/Tactic_train_data_Balanced.xlsx', index=False)
val_data.to_excel('dataset/attackInfo/Tactics/Tactic_val_data_Balanced.xlsx', index=False)
test_data.to_excel('dataset/attackInfo/Tactics/Tactic_test_data_Balanced.xlsx', index=False)

