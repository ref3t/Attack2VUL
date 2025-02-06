import pandas as pd
from torch.utils.data import DataLoader
from sentence_transformers import SentenceTransformer, InputExample, losses, util
from sentence_transformers.evaluation import EmbeddingSimilarityEvaluator
from sentence_transformers import LoggingHandler
import re
from vulDataClass import VulData

import numpy as np
import random
from sklearn.metrics.pairwise import cosine_similarity



df = pd.DataFrame(columns=['Threshold','TechID','TP', 'FP', 'FN', 'TN','AttackTP','AttackTN','AttackFP','AttackFN','CountMapping'])
dfRes = pd.DataFrame(columns=['TechID','Negative','Positive', 'Retrieved by VULDAT', 'Not retrieved by VULDAT','Predicted Positives (>50)','Predicted Negatives (<50)','True Positives (>50)','False Positives (>50)','True Negatives ( <50)','True Negatives (not retrieved)','False Negatives (<50)','False Negatives (not retrieved)','AttackTP','AttackTN','AttackFP','AttackFN'])


def trueNegativeSUM(vul_data_array,cve_ids_A_not_attack,Threeshold):
    count = 0
    if len(cve_ids_A_not_attack) > 0:
        for vuldat in vul_data_array:
            if float(vuldat.CVE_Smiliraty) < Threeshold:
                if vuldat.CVE_ID in cve_ids_A_not_attack:
                    count = count +1
    # #print("*******************************************total CVEs from VULDAT less 50 And Exist In A***************************************************")
    # #print(count)

    count2 = 0
    if len(cve_ids_A_not_attack) > 0:
        for item in cve_ids_A_not_attack:
            flag = 0 
            for vuldat in vul_data_array:
                if item == vuldat.CVE_ID:
                    flag = 1 
                    break
            if flag == 0:
                count2 = count2 +1
    # #print("*******************************************not In VULDAT But In A ***************************************************")
    # #print(count2)

    #print("**********TTTTTTTTNNNNNNNNNN ***************************************************")
    #print((count2+count))
    return count,count2



def ResTrueNegatives(vul_data_array, CvesNotAttack,Threeshold):
    return trueNegativeSUM(vul_data_array,CvesNotAttack,Threeshold)

def falseNegativeSUMAlltech2222(vul_data_array,CVEsAttack,techniquesID,arrayPositive ,arrayNegative,CvesNotAttack, Threeshold
                               , AttackTPsum,    AttackTNsum,    AttackFPsum,     AttackFNsum, dataframeResultsForallModels, modelName):
    global df
    global dfRes
    global procedure_dict
    
    arrayPositive2 = arrayPositive
    arrayPositive = len(arrayPositive)
    arrayNegative2 = arrayNegative
    arrayNegative = len(arrayNegative)
    countMapping = 0
    MappingCVEsVuldatForAttack = []
    MappingCVEsVuldatNotForAttack = []
    if len(CVEsAttack) > 0:
        for vuldat in vul_data_array:
            # if float(vuldat.CVE_Smiliraty) < smilarityThreshold:
            if vuldat.CVE_ID in CVEsAttack:
                MappingCVEsVuldatForAttack.append(vuldat.CVE_ID)
                countMapping = countMapping +1
    # #print("*******************************************total CVEs from VULDAT less 50 And Exist In C***************************************************")
    # #print(count)
    MappingCVEsVuldatForAttack = list(set(MappingCVEsVuldatForAttack))
    countMapping = len(MappingCVEsVuldatForAttack)

    
    count = 0
    CVEsVuldatForAttack = []
    CVEsVuldatNotForAttack = []
    if len(CVEsAttack) > 0:
        for vuldat in vul_data_array:
            if float(vuldat.CVE_Smiliraty) < Threeshold:
                if vuldat.CVE_ID in CVEsAttack:
                    CVEsVuldatForAttack.append(vuldat.CVE_ID)
                    count = count +1
    # #print("*******************************************total CVEs from VULDAT less 50 And Exist In C***************************************************")
    # #print(count)
    CVEsVuldatForAttack = list(set(CVEsVuldatForAttack))
    count = len(CVEsVuldatForAttack)

    count2 = 0
    for item in CVEsAttack:
        flag = 0 
        for vuldat in vul_data_array:
            if item == vuldat.CVE_ID:
                flag = 1 
                break
        if flag == 0:
            CVEsVuldatNotForAttack.append(item)
            count2 = count2 +1
    CVEsVuldatNotForAttack = list(set(CVEsVuldatNotForAttack))
    count2 = len(CVEsVuldatNotForAttack)
    # #print("*******************************************not In VULDAT But In C ***************************************************")
    # #print(count2)

    # #print("**********FFFFFFFFFFFFFFFNNNNNNNNNN ***************************************************")
    # #print("FN:" + str(count2+count))
    # #print("***************************************************")
    # PredictedNegatives2 = PredictedNegatives(vul_data_array,Threeshold)
    # PredictedPositives2 = PredictedPositives(vul_data_array,Threeshold)
    trueNeativeResless, trueNeativeResNotRetrived  = ResTrueNegatives(vul_data_array, CvesNotAttack,Threeshold)
    AttackTP = 0 
    AttackTN =0 
    AttackFP=0 
    AttackFN =0
    
    if ((arrayNegative+arrayPositive)) > 0  and countMapping > 0:
        AttackTP = 1 
        AttackTPsum = AttackTPsum + 1
    elif ((arrayNegative+arrayPositive)) == 0  and countMapping == 0:
        AttackTN = 1 
        AttackTNsum = AttackTNsum + 1
    elif ((arrayNegative+arrayPositive)) > 0  and countMapping == 0:
        AttackFP = 1 
        AttackFPsum = AttackFPsum + 1
    elif ((arrayNegative+arrayPositive)) == 0  and countMapping > 0:
        AttackFN = 1
        AttackFNsum = AttackFNsum + 1
    # if ((arrayPositive)) > 0  and countMapping > 0:
    #     AttackTP = 1 
    # elif (arrayPositive) == 0  and countMapping == 0:
    #     AttackTN = 1 
    # elif (arrayPositive) > 0  and countMapping == 0:
    #     AttackFP = 1 
    # elif (arrayPositive) == 0  and countMapping > 0:
    #     AttackFN = 1 
    
    LintersectM = len(arrayPositive2)
    M =countMapping
    L_M = len(arrayNegative2)
    M_L = M-LintersectM
    L_Sum = LintersectM + L_M
    if L_Sum == 0 and M_L == 0:
        jaccard = 0
    else:
        jaccard = LintersectM/(L_Sum+M_L)
    dataframeResultsForallModels = pd.concat([dataframeResultsForallModels, pd.DataFrame({'modelName':[modelName],'LintersectM':[LintersectM],'L_M':[L_M],'M':[M],'M_L':[M_L],'L_Sum':[L_Sum],'Jaccard':[jaccard]})], ignore_index=True)
    df = pd.concat([df, pd.DataFrame({'Threshold':[Threeshold*100],'TechID':[techniquesID],'TP': [arrayPositive], 'FP': [arrayNegative], 'FN': [(count2+count)], 'TN': [(trueNeativeResless+trueNeativeResNotRetrived)], 'AttackTP': [(AttackTP)], 'AttackTN': [(AttackTN)], 'AttackFP': [(AttackFP)], 'AttackFN': [(AttackFN)],'CountMapping':[(countMapping)]})], ignore_index=True)
    # dfRes = pd.concat([dfRes, pd.DataFrame({'TechID':[capecID], 'AttackTP': [(AttackTP)], 'AttackTN': [(AttackTN)], 'AttackFP': [(AttackFP)], 'AttackFN': [(AttackFN)],'CountMapping':[(countMapping)],'Lpositive':[arrayPositive2],'LNegatives':[arrayNegative2],"Mapping":[MappingCVEsVuldatForAttack]})], ignore_index=True)
    dfRes = pd.concat([dfRes, pd.DataFrame({'TechID':[techniquesID],'TP': [arrayPositive], 'FP': [arrayNegative], 'FN': [(count2+count)], 'TN': [(trueNeativeResless+trueNeativeResNotRetrived)],  'AttackTP': [(AttackTP)], 'AttackTN': [(AttackTN)], 'AttackFP': [(AttackFP)], 'AttackFN': [(AttackFN)],'CountMapping':[(countMapping)],'Lpositive':[arrayPositive2],'countLpositive' :[len(arrayPositive2)],'LNegatives':[arrayNegative2],'countLNegatives' :[len(arrayNegative2)],"Mapping":[MappingCVEsVuldatForAttack]})], ignore_index=True)
    return AttackTPsum,    AttackTNsum,    AttackFPsum,     AttackFNsum ,dataframeResultsForallModels


def remove_citations_and_urls(text):
    
    # Regular expression pattern to match citations
    citation_pattern = r'\(Citation:.*?\)'

    # Regular expression pattern to match URLs
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'

    # Find all occurrences of citations in the text
    citations = re.findall(citation_pattern, text)

    # Remove each citation from the text
    for citation in citations:
        text = text.replace(citation, '')

    # Find all occurrences of URLs in the text
    urls = re.findall(url_pattern, text)

    # Remove each URL from the text
    for url in urls:
        text = text.replace(url, '')
    regex = "^<code>.*</code>$"
    text = re.sub(regex, "",text, flags=re.MULTILINE) 
    text = " ".join(text.split()) # remove extra spaces
    text = re.sub("[^A-Za-z0-9]", " ", text) # replace anything that is not alphanumeric with empty string
    # text = text.replace("\t", " ")
    return text

def removeURLandCitationBulk(texts):
    return [remove_citations_and_urls(text) for text in texts]

def getTechniqueID(attackDes):
    allLinksFile3 = "./FinalResultSeperate/Techniqes/AllTechniques.xlsx"
    dataCve = pd.read_excel(allLinksFile3, sheet_name=0)

    # Iterate through each row of the DataFrame
    for _, row in dataCve.iterrows():
        attack = clean_attack_description(row['TechniqueDescription'])
        attackDes = clean_attack_description(attackDes)
        attack = re.sub(r'\s+', ' ', attack)
        attackDes = re.sub(r'\s+', ' ', attackDes)
        if attack.rstrip() == attackDes.rstrip():
            return row['TechniqueID']
    
    # Return None if no match is found
    return None
def clean_attack_description(attackDes):
    # Regular expression to check if the string starts and ends with [" Text "]
    cleaned = re.sub(r'^[\[\]"\s]+|[\[\]"\s]+$', '', attackDes)
    # Remove occurrences of "\xa0\n\n"
    attackDes = cleaned.replace("\\xa0\\n\\n", "")
    
    # Remove all occurrences of "\n"
    attackDes = attackDes.replace("\n", "")
    
    # Remove extra spaces (more than one space replaced with a single space)
    attackDes = re.sub(r'\s+', ' ', attackDes)
    
    attackDes = attackDes.replace("\\n", " ")
    
    attackDes = re.sub(r'\s+', ' ', attackDes)

    # Replace literal "\\xa0" sequences with a space
    attackDes = attackDes.replace("\\xa0", " ")
    
    # Remove extra spaces (more than one space replaced with a single space)
    attackDes = re.sub(r'\s+', ' ', attackDes)
    # Strip leading and trailing spaces
    attackDes = attackDes.strip()
    
    return remove_citations_and_urls(attackDes)

def readAllTech():
    file_pathPositive = './FinalResultSeperate/TechniqesAndSub/allTechSub2.xlsx'
    # Read the Excel file
    data = pd.read_excel(file_pathPositive, header=0, names=['TechniqueID', 'TechniqueName', 'TechniqueDescription'])
    
    # Group by 'ID' and aggregate other columns into lists
    grouped_data = data.groupby('TechniqueID').agg(lambda x: x.tolist()).reset_index()

    # Create a dictionary from the grouped data
    data_dictP = grouped_data.set_index('TechniqueID').to_dict(orient='index')

    return data_dictP

def readTechWithNegative():
    file_pathPositive = './dataset/FinalTechniquesPositive.xlsx'
    # Read the Excel file
    data = pd.read_excel(file_pathPositive, header=0, names=['TechniqueID', 'TechniqueName', 'TechniqueDescription'])
    
    # Group by 'ID' and aggregate other columns into lists
    grouped_data = data.groupby('TechniqueID').agg(lambda x: x.tolist()).reset_index()

    # Create a dictionary from the grouped data
    data_dictP = grouped_data.set_index('TechniqueID').to_dict(orient='index')

    file_pathNegative = './dataset/FinalTechniquesNegative.xlsx'
    data = pd.read_excel(file_pathNegative, header=0, names=['TechniqueID', 'TechniqueName', 'TechniqueDescription'])
    grouped_data = data.groupby('TechniqueID').agg(lambda x: x.tolist()).reset_index()
    data_dictNegative = grouped_data.set_index('TechniqueID').to_dict(orient='index')

    # Convert dictionary items to a list
    dict_items = list(data_dictNegative.items())

    # Randomly select 59 items
    random_items = random.sample(dict_items, 50)

    # Convert the selected items back to a dictionary
    data_dictNegative = dict(random_items)

    data_dictP.update(data_dictNegative)
    return data_dictP


def readsubTechniques():
    file_pathPositive = './FinalResultSeperate/SubTechniques/FinalSubTechniquesPositive.xlsx'
    # Read the Excel file
    data = pd.read_excel(file_pathPositive, header=0, names=['TechniqueID', 'TechniqueName', 'TechniqueDescription'])
    
    # Group by 'ID' and aggregate other columns into lists
    grouped_data = data.groupby('TechniqueID').agg(lambda x: x.tolist()).reset_index()

    # Create a dictionary from the grouped data
    data_dictP = grouped_data.set_index('TechniqueID').to_dict(orient='index')
    file_pathNegative = './FinalResultSeperate/SubTechniques/FinalSubTechniquesNegative.xlsx'
    data = pd.read_excel(file_pathNegative, header=0, names=['TechniqueID', 'TechniqueName', 'TechniqueDescription'])
    grouped_data = data.groupby('TechniqueID').agg(lambda x: x.tolist()).reset_index()
    data_dictNegative = grouped_data.set_index('TechniqueID').to_dict(orient='index')

    # Convert dictionary items to a list
    dict_items = list(data_dictNegative.items())

    # Randomly select 59 items
    random_items = random.sample(dict_items, 50)

    # Convert the selected items back to a dictionary
    data_dictNegative = dict(random_items)
    count = 0
    data_dictP.update(data_dictNegative)
     # Print the resulting dictionary using a for loop
    # for key, value in data_dictP.items():
    #     #print(f"{count}ID: {key}\tTechnique: {value['TechniqueName']}\tDescription: {value['TechniqueDescription']}")
    #     count = count +1

    # Return the dictionary if needed
    return data_dictP
def readCAPEC():
    file_pathPositive = './FinalResultSeperate/CAPEC/ALLAttackPatterns.xlsx'
    # Read the Excel fileCAPECID	CAPECName	CAPECDescription

    data = pd.read_excel(file_pathPositive, header=0, names=['CAPECID', 'CAPECName', 'CAPECDescription'])
    
    # Group by 'ID' and aggregate other columns into lists
    grouped_data = data.groupby('CAPECID').agg(lambda x: x.tolist()).reset_index()

    # Create a dictionary from the grouped data
    data_dictP = grouped_data.set_index('CAPECID').to_dict(orient='index')
    # Return the dictionary if needed
    return data_dictP

def readCVEData(file):
    
    dataCve = pd.read_excel(file, sheet_name=0)
    descriptions = dataCve['CVEDescription'].values
    dataCve['CVEDescription'] = removeURLandCitationBulk(descriptions)
    return dataCve

SentenceTransformersModels = [
                            # 'multi-qa-mpnet-base-dot-v1',
                            
                            # 'paraphrase-multilingual-MiniLM-L12-v2',
                            # 'multi-qa-MiniLM-L6-cos-v1',
                            # 'multi-qa-distilbert-cos-v1',
                            #     'all-MiniLM-L12-v2',
                            #     'all-distilroberta-v1',
                            
                            # 'all-MiniLM-L6-v2',
                            # 'all-mpnet-base-v2',
                            # 'paraphrase-MiniLM-L6-v2',

                            # 'paraphrase-albert-small-v2',
                                'msmarco-bert-base-dot-v5',
                                'all-roberta-large-v1',
                              'gtr-t5-xxl',
                                'paraphrase-TinyBERT-L6-v2'
                                ]
# Function to read the Excel file and convert to the correct format

def read_excel_file(file_path):
    df = pd.read_excel(file_path, sheet_name=0)
    # data = []
    # for _, row in df.iterrows():
    #     attack_desc = row['TechniqueDescription']
    #     cve_desc = row['CVEDescription']
    #     label = row['Label']
    #     data.append((attack_desc, [cve_desc], label))  # Create a tuple with the CVE as a list
    return df

import pandas as pd
import numpy as np
from sentence_transformers import SentenceTransformer
from sklearn.model_selection import train_test_split
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
import tensorflow.compat.v1 as tf
tf.disable_v2_behavior()

# DataFrame to store results
dataframeResults = pd.DataFrame(columns=['Data','Model','Precision','Recall','F1'])

# Information sources
informationData = ["Technique", "CAPEC"]

for infoData in informationData:
    # Load data based on information type
    if infoData == "Technique":
        test_data = readTechWithNegative()
        test_data2 = readsubTechniques()
        test_data.update(test_data2)
    elif infoData == "CAPEC":
        test_data = readCAPEC()

    allLinksFile = "./dataset/VULDATDataSetWithoutProcedures.xlsx"
    dataCVE = readCVEData(allLinksFile)

    for mod in SentenceTransformersModels:
        model = SentenceTransformer(mod)
        descriptions = dataCVE['CVEDescription'].values.tolist()
        techniquesName = dataCVE['TechniqueName'].values.tolist()
        joined_list = [techniquesName[i] + " " + descriptions[i] for i in range(len(descriptions))]

        CVEmbeddings = model.encode(joined_list)
        orgDescriptions = dataCVE

        all_data = []  # Store (CVE_ID, similarity_score, label) for training

        for key, value in test_data.items():
            print(f"Processing ID: {key}")

            # Prepare attack description embedding
            if infoData == "CAPEC":
                attack_texts = removeURLandCitationBulk([f"{value['CAPECDescription']}"])
            else:
                attack_texts = removeURLandCitationBulk([f"{value['TechniqueName']} {value['TechniqueDescription']}"])

            attack_texts = removeURLandCitationBulk([f"{attack_texts}]"])
            AttackEmbedding = model.encode(attack_texts)

            # Compute cosine similarity
            similarities = np.dot(AttackEmbedding, CVEmbeddings.T)  # Faster similarity computation

            # Find related CVEs
            if infoData == "CAPEC":
                trainAndTestSet = dataCVE[dataCVE['CAPECID'] == key]
            else:
                if "." in key:
                    key = key.split(".")[0]
                trainAndTestSet = dataCVE[dataCVE['TechniqueID'].str.startswith(key)]

            related_CVEs = set(trainAndTestSet['CVEID'].tolist())
            unrelated_CVEs = set(dataCVE['CVEID'].tolist()) - related_CVEs

            # Prepare dataset for classification (label = 1 for related, 0 for unrelated)
            for i, similarity_score in enumerate(similarities):
                cve_id = orgDescriptions.loc[i]['CVEID']
                label = 1 if cve_id in related_CVEs else 0
                all_data.append((similarity_score, label))

        # Convert data to DataFrame
        df_labeled = pd.DataFrame(all_data, columns=['Similarity', 'Label'])

        # Split into training and testing sets
        X_train, X_test, y_train, y_test = train_test_split(
            df_labeled[['Similarity']].values, 
            df_labeled['Label'].values, 
            test_size=0.2, 
            random_state=42
        )

        # Build a Neural Network for classification
        classifier = keras.Sequential([
            keras.Input(shape=(1,)),  # Explicitly define input layer
            layers.Dense(16, activation='relu'),  
            layers.Dense(8, activation='relu'),
            layers.Dense(1, activation='sigmoid')  # Binary classification
        ])
        
        classifier.compile(
            optimizer='adam', 
            loss='binary_crossentropy', 
            metrics=['accuracy']
        )

        # Train the model
        classifier.fit(X_train, y_train, epochs=10, batch_size=16, verbose=1)

        # Evaluate the model
        loss, accuracy = classifier.evaluate(X_test, y_test, verbose=0)
        print(f"Model Accuracy: {accuracy:.4f}")

        # Compute Precision, Recall, and F1-score
        y_pred = (classifier.predict(X_test) > 0.5).astype("int32")  # Convert probabilities to binary

        TP = sum((y_pred == 1) & (y_test == 1))
        FP = sum((y_pred == 1) & (y_test == 0))
        FN = sum((y_pred == 0) & (y_test == 1))

        precision = TP / (TP + FP) if (TP + FP) != 0 else 0
        recall = TP / (TP + FN) if (TP + FN) != 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) != 0 else 0

        # Save results
        dataframeResults = pd.concat([
            dataframeResults,
            pd.DataFrame({'Data': [infoData], 'Model': [mod], 'Precision': [precision], 'Recall': [recall], 'F1': [f1]})
        ], ignore_index=True)

    # Save final results
    dataframeResults.to_excel("Results/ClassificationResults.xlsx", index=False)




# dataframeResults = pd.DataFrame(columns=['Data', 'Model', 'Precision', 'Recall', 'F1'])
# dataframeResultsForallModels = pd.DataFrame(columns=['LintersectM', 'L_M', 'M', 'M_L', 'L_Sum', 'Jaccard'])

# informationData = ["Technique", "CAPEC"]

# for infoData in informationData:
#     if infoData == "Technique":
#         test_data = readTechWithNegative()
#         test_data.update(readsubTechniques())
#     elif infoData == "CAPEC":
#         test_data = readCAPEC()
    
#     allLinksFile = "./dataset/VULDATDataSetWithoutProcedures.xlsx"
#     dataCVE = readCVEData(allLinksFile)
    
#     for mod in SentenceTransformersModels:
#         model = SentenceTransformer(mod)
#         descriptions = dataCVE['CVEDescription'].tolist()
#         techniquesName = dataCVE['TechniqueName'].tolist()
#         joined_list = [f"{techniquesName[i]} {descriptions[i]}" for i in range(min(len(descriptions), len(techniquesName)))]
        
#         CVEmbeddings = model.encode(joined_list)
#         Threeshold = 0.58
#         AttackTPsum, AttackTNsum, AttackFPsum, AttackFNsum = 0, 0, 0, 0
        
#         for key, value in test_data.items():
#             print(f"Processing ID: {key}")
#             attack_texts = removeURLandCitationBulk([value['CAPECDescription']]) if infoData == "CAPEC" else removeURLandCitationBulk([f"{value['TechniqueName']} {value['TechniqueDescription']}"])
            
#             AttackEmbedding = model.encode(attack_texts)
#             similarities = util.pytorch_cos_sim(AttackEmbedding, CVEmbeddings).numpy()[0]
#             top_10_indices = np.argsort(similarities)[-181000:][::-1]
            
#             finalRes, vul_data_array, array = [], [], []
#             for index in top_10_indices:
#                 if dataCVE.loc[index] is not None and dataCVE.loc[index]['CVEID'] not in array:
#                     array.append(dataCVE.loc[index]['CVEID'])
#                     vul_data = VulData()
#                     vul_data.CVE_ID = dataCVE.loc[index]['CVEID']
#                     vul_data.CVE_Des = dataCVE.loc[index]['CVEDescription']
#                     vul_data.CVE_Smiliraty = f"{similarities[index]:.4f}"
#                     finalRes.append(f"{vul_data.CVE_ID}#{vul_data.CVE_Des}#{vul_data.CVE_Smiliraty}")
#                     vul_data_array.append(vul_data)
            
#             trainAndTestSet = dataCVE[dataCVE['CAPECID'] == key] if infoData == "CAPEC" else dataCVE[dataCVE['TechniqueID'].str.startswith(key.split(".")[0])]
#             trainAndTestSetCVEs = list(set(trainAndTestSet['CVEID'].tolist()))
            
#             CvesNotAttack = dataCVE[dataCVE['CAPECID'] != key] if infoData == "CAPEC" else dataCVE[~dataCVE['TechniqueID'].str.startswith(key.split(".")[0])]
#             CvesNotAttack = list(set(filter(lambda x: x not in trainAndTestSetCVEs, CvesNotAttack['CVEID'].tolist())))
            
#             arrayPositive, arrayNegative = [], []
#             for item in vul_data_array:
#                 if float(item.CVE_Smiliraty) > Threeshold:
#                     if item.CVE_ID in trainAndTestSetCVEs:
#                         arrayPositive.append(item.CVE_ID)
#                     else:
#                         arrayNegative.append(item.CVE_ID)
            
#             print(f"TP: {len(arrayPositive)}, FP: {len(arrayNegative)}, ID: {key}")
            
#             AttackTPsum, AttackTNsum, AttackFPsum, AttackFNsum, dataframeResultsForallModels = falseNegativeSUMAlltech2222(vul_data_array, trainAndTestSetCVEs, key, arrayPositive, arrayNegative, CvesNotAttack, 
#                                             Threeshold, AttackTPsum, AttackTNsum, AttackFPsum, AttackFNsum, dataframeResultsForallModels, model)
            
#         if (AttackTPsum + AttackFPsum) != 0:
#             preci = AttackTPsum / (AttackTPsum + AttackFPsum)
#             Recal = AttackTPsum / (AttackTPsum + AttackFNsum)
#             F1score = 2 * preci * Recal / (preci + Recal)
#             dataframeResults = pd.concat([dataframeResults, pd.DataFrame({'Data': [infoData], 'Model': [mod], 'Precision': [preci], 'Recall': [Recal], 'F1': [F1score]})], ignore_index=True)
#         else:
#             dataframeResults = pd.concat([dataframeResults, pd.DataFrame({'Data': [infoData], 'Model': [mod], 'Precision': [AttackTPsum], 'Recall': [AttackFPsum], 'F1': [AttackFNsum]})], ignore_index=True)
        
#         dataframeResults.to_excel("Results/AllModelsResultsBalanced.xlsx", index=False)
