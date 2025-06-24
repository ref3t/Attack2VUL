import random
from sentence_transformers import SentenceTransformer, InputExample, losses
from torch.utils.data import DataLoader
from sklearn.metrics.pairwise import cosine_similarity
import pandas as pd

def readTechWithNegative():
    file_pathPositive = './datasets/FinalTechniquesPositive.xlsx'
    # Read the Excel file
    data = pd.read_excel(file_pathPositive, header=0, names=['TechnqiueID', 'TechnqiueName', 'TechnqiueDescription'])
    
    # Group by 'ID' and aggregate other columns into lists
    grouped_data = data.groupby('TechnqiueID').agg(lambda x: x.tolist()).reset_index()

    # Create a dictionary from the grouped data
    data_dictP = grouped_data.set_index('TechnqiueID').to_dict(orient='index')

    file_pathNegative = './datasets/FinalTechniquesNegative.xlsx'
    data = pd.read_excel(file_pathNegative, header=0, names=['TechnqiueID', 'TechnqiueName', 'TechnqiueDescription'])
    grouped_data = data.groupby('TechnqiueID').agg(lambda x: x.tolist()).reset_index()
    data_dictNegative = grouped_data.set_index('TechnqiueID').to_dict(orient='index')

    # Convert dictionary items to a list
    dict_items = list(data_dictNegative.items())

    # Randomly select 100 items
    random_items = random.sample(dict_items, 100)

    # Convert the selected items back to a dictionary
    data_dictNegative = dict(random_items)

    data_dictP.update(data_dictNegative)
    return data_dictP

def readAllTechPositives():
    file_pathPositive = './datasets/FinalTechniquesPositive.xlsx'
    # Read the Excel file
    data = pd.read_excel(file_pathPositive, header=0, names=['TechnqiueID', 'TechnqiueName', 'TechnqiueDescription'])
    
    # Group by 'ID' and aggregate other columns into lists
    grouped_data = data.groupby('TechnqiueID').agg(lambda x: x.tolist()).reset_index()

    # Create a dictionary from the grouped data
    data_dictP = grouped_data.set_index('TechnqiueID').to_dict(orient='index')

    # for key, value in data_dictP.items():
    #     #print(f"{count}ID: {key}\tTechnique: {value['TechnqiueName']}\tDescription: {value['TechnqiueDescription']}")
    #     count = count +1

    # Return the dictionary if needed
    return data_dictP

# Load the pre-trained MPNet model
model = SentenceTransformer('sentence-transformers/all-mpnet-base-v2')

tech_dict = readTechWithNegative()
techniques = list(tech_dict.keys())

allLinksFile = "./datasets/VULDATDataSetWithoutProcedures.xlsx"
dataCve = pd.read_excel(allLinksFile, sheet_name=0)

# Prepare your training data
training_texts = []
for key in techniques[:80]:  # Use the first 80 techniques for training
    cve_list = dataCve[dataCve['TechnqiueID'].str.startswith(key)]['CVEDescription'].tolist()
    training_texts.append((key, cve_list))

train_examples = []
for attack, cve_list in training_texts:
    for cve in cve_list:
        train_examples.append(InputExample(texts=[attack, cve], label=1))

# Create a DataLoader
train_dataloader = DataLoader(train_examples, shuffle=True, batch_size=16)

# Define a loss function
train_loss = losses.CosineSimilarityLoss(model)

# Train the model
model.fit(train_objectives=[(train_dataloader, train_loss)], epochs=1, warmup_steps=100)

# Evaluate the model
test_texts = techniques[80:]  # Use the remaining 20 techniques for testing
test_embeddings = model.encode(test_texts)

# Encode all CVE texts
cve_texts = dataCve['CVEDescription'].tolist()
cve_embeddings = model.encode(cve_texts)

# Find the CVE texts with similarity score above 58% for each attack text
threshold = 0.58  # 58% similarity threshold

results = []
for i, test_embedding in enumerate(test_embeddings):
    similarities = cosine_similarity([test_embedding], cve_embeddings)[0]
    similar_cves_ids = [dataCve['CVEID'][i] for i in range(len(similarities)) if similarities[i] > threshold]
    results.append({"TechnqiueID": techniques[80 + i], "CVEs": similar_cves_ids})

# Save results to an Excel file
results_df = pd.DataFrame(results)
results_df.to_excel("finetuningResult.xlsx", index=False)

print("Results saved to finetuningResult.xlsx")