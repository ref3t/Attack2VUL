import pandas as pd
from sentence_transformers import SentenceTransformer, util

# Load the technique descriptions and techIDs from Excel files
pos_df = pd.read_excel('./datasets/TechData/FinalTechniquesPositive.xlsx', engine='openpyxl')
neg_df = pd.read_excel('./datasets/TechData/FinalTechniquesNegative.xlsx', engine='openpyxl')

# Assuming 'TechnqiueID' and 'TechnqiueDescription' are the columns in both files
pos_techIDs = pos_df['TechnqiueID'].tolist()
pos_descriptions = pos_df['TechnqiueDescription'].tolist()

neg_techIDs = neg_df['TechnqiueID'].tolist()
neg_descriptions = neg_df['TechnqiueDescription'].tolist()

# Load the pre-trained model
model = SentenceTransformer('sentence-transformers/multi-qa-mpnet-base-dot-v1')

# Encode the descriptions
pos_embeddings = model.encode(pos_descriptions, convert_to_tensor=True)
neg_embeddings = model.encode(neg_descriptions, convert_to_tensor=True)

# Calculate cosine similarity between positive and negative descriptions
cosine_similarities = util.cos_sim(pos_embeddings, neg_embeddings)

# Convert the similarity scores to a DataFrame for better readability
# The rows will be the positive techIDs and the columns will be the negative techIDs
similarity_df = pd.DataFrame(cosine_similarities.numpy(), 
                             index=pos_techIDs, 
                             columns=neg_techIDs)

# Filter the DataFrame to include only similarity scores >= 0.7 (70%)
filtered_similarity_df = similarity_df[similarity_df >= 0.7].dropna(how='all').dropna(axis=1, how='all')

# Save the filtered similarity scores to an Excel file
filtered_similarity_df.to_excel('filtered_technique_similarity_scores_with_techID.xlsx')

print("Filtered similarity scores with techID saved to 'filtered_technique_similarity_scores_with_techID.xlsx'")
