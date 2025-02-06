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
                            'multi-qa-mpnet-base-dot-v1',
                            
                            'paraphrase-multilingual-MiniLM-L12-v2',
                            'multi-qa-MiniLM-L6-cos-v1',
                            'multi-qa-distilbert-cos-v1',
                                'all-MiniLM-L12-v2',
                                'all-distilroberta-v1',
                            
                            'all-MiniLM-L6-v2',
                            'all-mpnet-base-v2',
                            'paraphrase-MiniLM-L6-v2',

                            'paraphrase-albert-small-v2',
                                'msmarco-bert-base-dot-v5',
                            #     'all-roberta-large-v1',
                            #   'gtr-t5-xxl',
                            #     'paraphrase-TinyBERT-L6-v2'
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
dataframeResults = pd.DataFrame(columns=['Data','Model','precision','Recall','F1']) 
dataframeResultsForallModels = pd.DataFrame(columns=['LintersectM','L_M','M','M_L','L_Sum','Jaccard'])
# informationData = ["Tactic", "Technique","Procedures","CAPEC"]
informationData = ["CAPEC"]
for infoData in informationData:
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
        descriptions = descriptions[:len(descriptions)]
        techniquesName = techniquesName[:len(techniquesName)]
        joined_list = [ techniquesName[i]+ " " + descriptions[i] for i in range(min(len(descriptions), len(techniquesName)))]
        orgDescriptions = dataCVE
        CVEmbeddings = model.encode(joined_list)
        countT = 0
        Threeshold = 0.58
        AttackTPsum = 0 
        AttackTNsum =0 
        AttackFPsum=0 
        AttackFNsum =0
        
        techIDs = [] 
        for key, value in test_data.items():
            print(f"ID: {key} ttttt {countT} ")
            countT = countT+1
            if infoData == "CAPEC":
                # attack_texts = removeURLandCitationBulk([f"{value['CAPECName']} {value['CAPECDescription']}"])
                attack_texts = removeURLandCitationBulk([f"{value['CAPECDescription']}"])
            else:
                attack_texts = removeURLandCitationBulk([f"{value['TechniqueName']} {value['TechniqueDescription']}"])
                    
            attack_texts = removeURLandCitationBulk([f"{attack_texts}]"])
            vul_data_array =[]
            
            AttackEmbedding = model.encode(attack_texts)

            similarities = util.pytorch_cos_sim(AttackEmbedding, CVEmbeddings)


            similarities = cosine_similarity(AttackEmbedding.reshape(1, -1), CVEmbeddings)[0]

            top_10_indices = np.argsort(similarities)[-181000:][::-1]

            finalRes =[]
            array = []

            for index in top_10_indices:
                
                if orgDescriptions.loc[index] is not None:
                    if not dataCVE.loc[index]['CVEID'] in array:
                        array.append(dataCVE.loc[index]['CVEID'])
                        vul_data = VulData()
                        vul_data.CVE_ID = orgDescriptions.loc[index]['CVEID']
                        vul_data.CVE_Des = orgDescriptions.loc[index]['CVEDescription']
                        vul_data.CVE_Smiliraty  = f"{similarities[index]:.4f}"
                        finalRes.append(vul_data.CVE_ID + "#" +vul_data.CVE_Des+"#"+vul_data.CVE_Smiliraty )
                        vul_data_array.append(vul_data)

            # trainAndTestSet = dataCVE[dataCVE['TechniqueID'].str.startswith(technique_id)]
            if infoData == "CAPEC":
                trainAndTestSet = dataCVE[dataCVE['CAPECID'] == key]
            else:
                if "." in key:
                    key = key.split(".")[0]
                trainAndTestSet = dataCVE[dataCVE['TechniqueID'].str.startswith(key)]

            trainAndTestSetCVEs = trainAndTestSet['CVEID']
            trainAndTestSetCVEs2 = trainAndTestSetCVEs.tolist()
            trainAndTestSetCVEs = list(set(trainAndTestSetCVEs2))


            # CvesNotAttack = dataCVE[~dataCVE['TechniqueID'].str.startswith(technique_id)]
            if infoData == "CAPEC":
                CvesNotAttack = dataCVE[dataCVE['CAPECID'] != key]
            else:
                if "." in key:
                    key = key.split(".")[0]
                CvesNotAttack = dataCVE[~dataCVE['TechniqueID'].str.startswith(key)]

            CvesNotAttack = CvesNotAttack['CVEID']
            CvesNotAttack = CvesNotAttack.tolist()
            CvesNotAttack = list(set(CvesNotAttack))
            CvesNotAttack = list(filter(lambda x: x not in trainAndTestSetCVEs, CvesNotAttack))

            arrayPositive = []
            arrayNegative = []

            for item in vul_data_array:
                if float(item.CVE_Smiliraty) > Threeshold:
                    flag = 1
                    for cve in trainAndTestSetCVEs:
                        if item.CVE_ID == cve:
                            arrayPositive.append(item.CVE_ID)
                            flag = 0
                            break
                    if flag == 1:
                        arrayNegative.append(item.CVE_ID)
            arrayPositive = list(set(arrayPositive))
            arrayNegative = list(set(arrayNegative))
            # #print("******************************************Tppp****************************************************")
            print(f"TP:{str(len(arrayPositive))}    FP: {str(len(arrayNegative))}   {str(key)}")
            
            AttackTPsum,    AttackTNsum,    AttackFPsum,     AttackFNsum, dataframeResultsForallModels= falseNegativeSUMAlltech2222(vul_data_array,trainAndTestSetCVEs,key,arrayPositive , arrayNegative,CvesNotAttack, Threeshold, AttackTPsum,    AttackTNsum,    AttackFPsum,     AttackFNsum,dataframeResultsForallModels, model)

        
        # preci=AttackTPsum/(AttackTPsum+AttackFPsum)
        # Recal=AttackTPsum/(AttackTPsum+AttackFNsum)
        # F1score= 2*preci*Recal/(preci+Recal)
        # dataframeResults = pd.concat([dataframeResults, pd.DataFrame({'Data':[infoData],'Model':[mod],'precision':[preci],'Recall':[Recal],'F1':[F1score]})], ignore_index=True)
        if(AttackTPsum+AttackFPsum)!=0:   
            preci=AttackTPsum/(AttackTPsum+AttackFPsum)
            Recal=AttackTPsum/(AttackTPsum+AttackFNsum)
            F1score= 2*preci*Recal/(preci+Recal)
            dataframeResults = pd.concat([dataframeResults, pd.DataFrame({'Data':[infoData],'Model':[mod],'precision':[preci],'Recall':[Recal],'F1':[F1score]})], ignore_index=True)
        else:
            dataframeResults = pd.concat([dataframeResults, pd.DataFrame({'Data':[infoData],'Model':[mod],'precision':[AttackTPsum],'Recall':[AttackFPsum],'F1':[AttackFNsum]})], ignore_index=True)

        # dataframeResultsForallModels = pd.DataFrame(columns=['LintersectM','L_M','M','M_L','L_Sum'])
        # df.to_excel(f"Final{model_parts[1]}full.xlsx", index=False)

        print(model)
        # dataframeResultsForallModels.to_excel(f"./Results/AllModelsJaccardN{str(Threeshold)}50.xlsx", index=False)
        dataframeResults.to_excel(f"Results/AllModelsResultsBalanced.xlsx", index=False)


# # Example Evaluation on the test data
# test_results = evaluate_similarity(model, test_data)

# # Convert the results into a DataFrame
# results_df = pd.DataFrame(test_results, columns=["AttackDescription", "CVEDescription", "Similarity", "Label"])

# # Save the results to an Excel file
# output_file = "./Fine-tuning/Results/Techniques/test_resultsBeforeFine.xlsx"
# results_df.to_excel(output_file, index=False, sheet_name="Similarity Results")

# print(f"Results saved to {output_file}")




# # Load the fine-tuned model
# fine_tuned_model = SentenceTransformer('./fine_tuned_mpnet')

# # Function to evaluate similarity for each attack and CVE pair
# def evaluate_similarity(model, data):
#     results = []
#     for attack, cves, label in data:
#         attack_embedding = model.encode(attack, convert_to_tensor=True)
#         for cve in cves:
#             cve_embedding = model.encode(cve, convert_to_tensor=True)
#             similarity = util.pytorch_cos_sim(attack_embedding, cve_embedding)[0][0].item()  # Extract similarity value
#             results.append((attack, cve, similarity, label))  # Append tuple with attack, CVE, similarity, and label
#     return results

# # Evaluate the fine-tuned model on the test data
# test_results = evaluate_similarity(fine_tuned_model, test_data)

# # Convert the results into a DataFrame
# results_df = pd.DataFrame(test_results, columns=["AttackDescription", "CVEDescription", "Similarity", "Label"])

# # Save the results to an Excel file
# output_file = "./Fine-tuning/Results/Techniques/test_resultsAfterFineTune.xlsx"
# results_df.to_excel(output_file, index=False, sheet_name="Similarity Results")

# print(f"Test results have been saved to {output_file}")