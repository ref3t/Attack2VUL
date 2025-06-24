import pandas as pd
from sentence_transformers import SentenceTransformer, util

# Load the technique descriptions and techIDs from Excel files
CVE_df = pd.read_excel('./datasets/News/cve_data.xlsx', engine='openpyxl')
News_df = pd.read_excel('./datasets/News/infosecurity_magazine_news.xlsx', engine='openpyxl')
print("1")
# Extract titles and descriptions from the news and CVE data
News_Titles = News_df['Title'].tolist()
News_Descriptions = News_df['Text'].tolist()
CVE_ID = CVE_df['CVE_ID'].tolist()
CVE_description = CVE_df['Description'].tolist()
print("2")
# Load the pre-trained model
model = SentenceTransformer('sentence-transformers/multi-qa-mpnet-base-dot-v1')

# Encode the descriptions
pos_embeddings = model.encode(News_Descriptions, convert_to_tensor=True)
print("3")
neg_embeddings = model.encode(CVE_description, convert_to_tensor=True)
print("4")
# Calculate cosine similarity between news descriptions and CVE descriptions
cosine_similarities = util.cos_sim(pos_embeddings, neg_embeddings)
print("5")
# Convert the similarity scores to a DataFrame for better readability
similarity_df = pd.DataFrame(cosine_similarities.numpy(), 
                             index=News_Titles, 
                             columns=CVE_ID)

print("6")
# Filter the DataFrame to include only similarity scores >= 0.55 (55%)
filtered_similarity_df = similarity_df[similarity_df >= 0.65].dropna(how='all').dropna(axis=1, how='all')
print("7")
# Create a new DataFrame to store news titles and related CVE_IDs
news_cve_df = pd.DataFrame(columns=['News_Title', 'Related_CVE_IDs'])
print("8")
for news_title in filtered_similarity_df.index:
    related_cves = filtered_similarity_df.loc[news_title].dropna().index.tolist()
    news_cve_df = news_cve_df._append({'News_Title': news_title, 'Related_CVE_IDs': ', '.join(related_cves)}, ignore_index=True)
print
# Save the news titles and related CVE_IDs to an Excel file
news_cve_df.to_excel('NewsCVEResutls2.xlsx', index=False)


# import pandas as pd
# from sentence_transformers import SentenceTransformer, util

# # Load the technique descriptions and techIDs from Excel files
# CVE_df = pd.read_excel('./datasets/News/cve_data.xlsx', engine='openpyxl')
# News_df = pd.read_excel('./datasets/News/infosecurity_magazine_news.xlsx', engine='openpyxl')

# # Assuming 'TechnqiueID' and 'TechnqiueDescription' are the columns in both files
# News_Titles = News_df['Title'].tolist()
# News_Descriptions = News_df['Text'].tolist()

# CVE_ID = CVE_df['CVE_ID'].tolist()
# CVE_description = CVE_df['Description'].tolist()
# print("-1")
# # Load the pre-trained model
# model = SentenceTransformer('sentence-transformers/multi-qa-mpnet-base-dot-v1')
# print("0")
# # Encode the descriptions
# pos_embeddings = model.encode(News_Descriptions, convert_to_tensor=True)
# print("1")
# neg_embeddings = model.encode(CVE_description, convert_to_tensor=True)
# print("2")
# # Calculate cosine similarity between positive and negative descriptions
# cosine_similarities = util.cos_sim(pos_embeddings, neg_embeddings)
# print("3")
# # Convert the similarity scores to a DataFrame for better readability
# # The rows will be the positive techIDs and the columns will be the negative techIDs
# similarity_df = pd.DataFrame(cosine_similarities.numpy(), 
#                              index=News_Titles, 
#                              columns=CVE_ID)
# print("4")
# # Filter the DataFrame to include only similarity scores >= 0.7 (70%)
# filtered_similarity_df = similarity_df[similarity_df >= 0.55].dropna(how='all').dropna(axis=1, how='all')
# print("5")
# # Save the filtered similarity scores to an Excel file
# filtered_similarity_df.to_excel('NewsCVEResutls.xlsx')
