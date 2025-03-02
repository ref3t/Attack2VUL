import pandas as pd
import random

def read_tech_negative(file_path, numberofPositive):
    data = pd.read_excel(file_path, header=0, names=['TechnqiueID', 'TechnqiueName', 'TechnqiueDescription'])
    cleaned_data = data[['TechnqiueID', 'TechnqiueName', 'TechnqiueDescription']].dropna()
    
    # Return 100 rows (or less if there are not enough rows)
    return cleaned_data.sample(n=numberofPositive, random_state=42)

# Load the datasets
positive_dataset_path = "./dataset/VULDATDataSetWithoutProcedures.xlsx"  # Path to positive dataset
negative_dataset_path = "./dataset/FinalTechniquesNegative.xlsx"  # Path to negative dataset

# Positive samples
positive_df = pd.read_excel(positive_dataset_path, sheet_name=0)


# Calculate number of unique TechnqiueID in the positive dataset
unique_positive_techniques = positive_df['TacticID'].nunique()

# # Negative samples
# negative_samples = read_tech_negative(negative_dataset_path, unique_positive_techniques)

# Create positive pairs (same as before)
positive_pairs = []
for _, row in positive_df.iterrows():
    positive_pairs.append((row['TechnqiueID'], row['TechnqiueName'], row['TechnqiueDescription'], row['CVEID'], row['CVEDescription'], 1))  # Label as 1

# # Create negative pairs (same size as positive pairs)
# negative_pairs = []
# negative_sample_count = len(positive_pairs)
# for i in range(negative_sample_count):
#     # Loop through negative dataset and match the number of positive pairs
#     technique_id, name, description = negative_samples.iloc[i % len(negative_samples)]
#     positive_row = positive_df.iloc[i]
#     negative_pairs.append((technique_id, name, description, "", "", 0))  # Label as 0

# Combine positive and negative pairs
# balanced_data = positive_pairs + negative_pairs
random.shuffle(positive_pairs)

# Convert to DataFrame
final_df = pd.DataFrame(positive_pairs, columns=['TacticID', 'TacticDescription','CVEID', 'CVEDescription', 'Label'])

# # Save to Excel
# final_df.to_excel('balanced_dataset.xlsx', index=False)

# print("Balanced dataset has been saved to 'balanced_dataset.xlsx'.")

from sklearn.model_selection import train_test_split

# Split the dataset into 80% train and 20% temp (for validation and test)
train_data, temp_data = train_test_split(final_df, test_size=0.2, random_state=42)

# Split the temp data into 50% validation and 50% test
val_data, test_data = train_test_split(temp_data, test_size=0.5, random_state=42)

# Save to Excel files (optional)
train_data.to_excel('Tactic_train_data.xlsx', index=False)
val_data.to_excel('Tactic_val_data.xlsx', index=False)
test_data.to_excel('Tactic_test_data.xlsx', index=False)
