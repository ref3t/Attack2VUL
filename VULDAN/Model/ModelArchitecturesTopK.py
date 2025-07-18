
import pandas as pd
import re
import numpy as np
import random
from sklearn.metrics.pairwise import cosine_similarity
import sys
# sys.path.append('VwDet/vulDataClass/')
from vulDataClass import VulData
from sentence_transformers import SentenceTransformer, util
import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
from nltk.stem import PorterStemmer, WordNetLemmatizer
from sklearn import preprocessing
nltk.download('stopwords')
nltk.download('punkt')
nltk.download('wordnet')
import re

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


def readTechWithNegative():
    file_pathPositive = 'VULDAT/Dataset/FinalTechniquesPositive.xlsx'
    # Read the Excel file
    data = pd.read_excel(file_pathPositive, header=0, names=['TechnqiueID', 'TechnqiueName', 'TechnqiueDescription'])
    
    # Group by 'ID' and aggregate other columns into lists
    grouped_data = data.groupby('TechnqiueID').agg(lambda x: x.tolist()).reset_index()

    # Create a dictionary from the grouped data
    data_dictP = grouped_data.set_index('TechnqiueID').to_dict(orient='index')

    file_pathNegative = 'VULDAT/Dataset/FinalTechniquesNegative.xlsx'
    data = pd.read_excel(file_pathNegative, header=0, names=['TechnqiueID', 'TechnqiueName', 'TechnqiueDescription'])
    grouped_data = data.groupby('TechnqiueID').agg(lambda x: x.tolist()).reset_index()
    data_dictNegative = grouped_data.set_index('TechnqiueID').to_dict(orient='index')

    # Convert dictionary items to a list
    dict_items = list(data_dictNegative.items())

    # Randomly select 59 items
    random_items = random.sample(dict_items, 50)

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

# checkCVEUsingBert()
def removeUrls (text):
    # print (text)
    text = re.sub(r'(https|http)?:\/\/(\w|\.|\/|\?|\=|\&|\%)*\b', '', text, flags=re.MULTILINE)
    text = re.sub(r'(?i)NOTE:.*', '', text)
    # text = re.sub(r'\b\w*\d+\w*\b|\b\w*\.\w*\b', '', text)
    # text = re.sub(r'\.\w+\b', '', text)
    # text = re.sub(r'[^\w\s]', '', text)
    # text = re.sub(r'\b\w*\d+\w*\b', '', text)
    # text = re.sub(r'\s+', ' ', text)
    # text = re.sub(r'\d+', '', text)
    # text = re.sub(r'[,."()]', '', text)
    text = re.sub(r'\b\d+(\.\d+)*\b', '', text) #remove digits 
    # print (text)
    return(text)


def removeCitation(text):
    position = text.find('(Citation:')
    if position > 0:
        return text[:position]
    else:
        return text

def removeURLandCitationBulk(texts):
    return [remove_citations_and_urls(text) for text in texts]
# red = removeURLandCitationBulk(['Untrusted search path vulnerability in  PGP Desktop 9.9.0 Build 397, 9.10.x, 10.0.0 Build 2732,and probably other versions allows local users,and possibly remote attackers,to execute arbitrary code and conduct DLL hijacking attacks via a Trojan horse tsp.dll or tvttsp.dll that is located in the same folder as a .p12,.pem,.pgp,.prk,.prvkr,.pubkr,.rnd or .skr file.'])

def dataPreprocessingStopWords(texts):
    return [preprocess_text_stop_words(text) for text in texts]

def dataPreprocessingStemming(texts):
    return [preprocess_text_stemming(text) for text in texts]

def dataPreprocessingLemmatization(texts):
    return [preprocess_text_lemmatization(text) for text in texts]

def preprocess_text_stop_words(text):
    # Tokenization
    tokens = word_tokenize(text)
    stop_words = set(stopwords.words('english'))

    # Stop words removal
    tokens = [token for token in tokens if token not in stop_words]
        
    return tokens
#Stemming is the process of finding the root of words
def preprocess_text_stemming(text):
    # Tokenization
    tokens = word_tokenize(text)
    stemmer = PorterStemmer()
    # Stemming
    stemmed_tokens = [stemmer.stem(token) for token in tokens]
    
    return stemmed_tokens
#Lemmatization is the process of finding the form of the related word in the dictionary.
def preprocess_text_lemmatization(text):
    # Tokenization
    tokens = word_tokenize(text)
    
    lemmatizer = WordNetLemmatizer()
    # Lemmatization
    lemmatized_tokens = [lemmatizer.lemmatize(token) for token in tokens]
    
    return lemmatized_tokens
# df = pd.DataFrame(columns=['Threshold','TechID','TP', 'FP', 'FN', 'TP0,1', 'FP0,1','FN0,1','TPNormalize','FPNormalize','FNNormalize'])

df = pd.DataFrame(columns=['Threshold','TechID','TP', 'FP', 'FN', 'TN','AttackTP','AttackTN','AttackFP','AttackFN','CountMapping'])
dfRes = pd.DataFrame(columns=['TechID','Negative','Positive', 'Retrieved by VULDAT', 'Not retrieved by VULDAT','Predicted Positives (>50)','Predicted Negatives (<50)','True Positives (>50)','False Positives (>50)','True Negatives ( <50)','True Negatives (not retrieved)','False Negatives (<50)','False Negatives (not retrieved)','AttackTP','AttackTN','AttackFP','AttackFN'])


# New function to compute precision and recall for top-k
def compute_top_k_metrics(vul_data_array, CVEsAttack, k_values):
    # Sort the vul_data_array by similarity score (CVE_Smiliraty)
    sorted_vuldat = sorted(vul_data_array, key=lambda x: float(x.CVE_Smiliraty), reverse=True)
    
    results = {}
    for k in k_values:
        top_k_vuldat = sorted_vuldat[:k]
        
        # True Positives (TP_k): The number of CVEs in both top-k and ground truth (CVEsAttack)x
        TP_CVEs = [vuldat for vuldat in top_k_vuldat if vuldat.CVE_ID in CVEsAttack]
        TP_k = len([vuldat for vuldat in top_k_vuldat if vuldat.CVE_ID in CVEsAttack])
        
        # False Positives (FP_k): The number of CVEs in top-k but not in the ground truth (CVEsAttack)
        FP_k = len([vuldat for vuldat in top_k_vuldat if vuldat.CVE_ID not in CVEsAttack])
        
        # False Negatives (FN_k): The number of CVEs in the ground truth (CVEsAttack) that are not in the top-k
        FN_k = len([cve for cve in CVEsAttack if cve not in [vuldat.CVE_ID for vuldat in top_k_vuldat]])
        
        # Precision @ k
        P_k = TP_k / (TP_k + FP_k) if (TP_k + FP_k) > 0 else 0
        
        # Recall @ k
        R_k = TP_k / (TP_k + FN_k) if (TP_k + FN_k) > 0 else 0
        
        # Store results for this k
        results[k] = {'Precision': P_k, 'Recall': R_k, 'TP': TP_k, 'FP': FP_k, 'FN': FN_k, 'T_CVEs': TP_CVEs}
    
    return results
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
    
    k_values = [20]
    # k_values = list(range(31))
    top_k_results = compute_top_k_metrics(vul_data_array, CVEsAttack, k_values)

    # Store top-k results in the dataframe for each k
    for k, metrics in top_k_results.items():
        df = pd.concat([df, pd.DataFrame({
            'Threshold': [Threeshold * 100], 'TechID': [techniquesID], 'TP': [arrayPositive], 'FP': [arrayNegative],
            'FN': [(count2 + count)], 'TN': [(trueNeativeResless + trueNeativeResNotRetrived)],
            'AttackTP': [AttackTP], 'AttackTN': [AttackTN], 'AttackFP': [AttackFP], 'AttackFN': [AttackFN],
            'CountMapping': [countMapping], 'TopK': [k], 'Precision@K': [metrics['Precision']], 'Recall@K': [metrics['Recall']],
            'TP@K': [metrics['TP']], 'FP@K': [metrics['FP']], 'FN@K': [metrics['FN']], 'T_CVEs': [metrics['T_CVEs']],
        })], ignore_index=True)

    # df = pd.concat([df, pd.DataFrame({'Threshold':[Threeshold*100],'TechID':[techniquesID],'TP': [arrayPositive], 'FP': [arrayNegative], 'FN': [(count2+count)], 'TN': [(trueNeativeResless+trueNeativeResNotRetrived)], 'AttackTP': [(AttackTP)], 'AttackTN': [(AttackTN)], 'AttackFP': [(AttackFP)], 'AttackFN': [(AttackFN)],'CountMapping':[(countMapping)]})], ignore_index=True)
    # dfRes = pd.concat([dfRes, pd.DataFrame({'TechID':[capecID], 'AttackTP': [(AttackTP)], 'AttackTN': [(AttackTN)], 'AttackFP': [(AttackFP)], 'AttackFN': [(AttackFN)],'CountMapping':[(countMapping)],'Lpositive':[arrayPositive2],'LNegatives':[arrayNegative2],"Mapping":[MappingCVEsVuldatForAttack]})], ignore_index=True)
    
    
    dfRes = pd.concat([dfRes, pd.DataFrame({'TechID':[techniquesID],'TP': [arrayPositive], 'FP': [arrayNegative], 'FN': [(count2+count)], 'TN': [(trueNeativeResless+trueNeativeResNotRetrived)],  'AttackTP': [(AttackTP)], 'AttackTN': [(AttackTN)], 'AttackFP': [(AttackFP)], 'AttackFN': [(AttackFN)],'CountMapping':[(countMapping)],'Lpositive':[arrayPositive2],'countLpositive' :[len(arrayPositive2)],'LNegatives':[arrayNegative2],'countLNegatives' :[len(arrayNegative2)],"Mapping":[MappingCVEsVuldatForAttack]})], ignore_index=True)
    return AttackTPsum,    AttackTNsum,    AttackFPsum,     AttackFNsum ,dataframeResultsForallModels ,df



procedure_dict = {}
def ResTrueNegatives(vul_data_array, CvesNotAttack,Threeshold):
    return trueNegativeSUM(vul_data_array,CvesNotAttack,Threeshold)
def PredictedNegatives(vul_data_array,Threeshold):
    count = 0 
    for vuldat in vul_data_array:
        if float(vuldat.CVE_Smiliraty) < Threeshold:
            count = count + 1
    return count
def PredictedPositives(vul_data_array, Threeshold):
    count = 0 
    for vuldat in vul_data_array:
        if float(vuldat.CVE_Smiliraty) >= Threeshold:
            count = count + 1
    return count

def reportConvisionMatrix(vul_data_array,MCVEsAttack,key,arrayTruePositiveAttack,falsePositiveAttack,Threeshold):
    global df
    global dfRes
    global procedure_dict
    MCVEsAttack = list(set(MCVEsAttack))
    FalseNegative = list(filter(lambda x: x not in arrayTruePositiveAttack, MCVEsAttack))
    AttackTP = 0 
    AttackFP=0 
    AttackFN =0
    if len(arrayTruePositiveAttack)> 0:
        AttackTP = 1 
    if len(falsePositiveAttack)> 0:
        AttackFP = 1 
    if len(FalseNegative)> 0:
        AttackFN = 1
    ListModel = [len(arrayTruePositiveAttack),len(falsePositiveAttack),len(FalseNegative)]
    normalized_array = np.array(ListModel)

    normalized_arr = preprocessing.normalize([normalized_array])
    df = pd.concat([df, pd.DataFrame({'Threshold':[Threeshold*100],'TechID':[key],'TP': [len(arrayTruePositiveAttack)], 'FP': [len(falsePositiveAttack)], 'FN': [len(FalseNegative)], 'TP0,1': [(AttackTP)], 'FP0,1': [(AttackFP)], 'FN0,1': [(AttackFN)], 'TPNormalize': [(normalized_arr[0][0])], 'FPNormalize': [(normalized_arr[0][1])], 'FNNormalize': [(normalized_arr[0][2])]})], ignore_index=True)


def checkCVEUsingAllTech():
    global df
    global dfRes
    dataframeResults = pd.DataFrame(columns=['Model','precision','Recall','F1'])
    dataframeResultsForallModels = pd.DataFrame(columns=['LintersectM','L_M','M','M_L','L_Sum','Jaccard'])
    # SentenceTransformersModels = ['sentence-transformers/paraphrase-albert-small-v2',
    #                               'sentence-transformers/msmarco-bert-base-dot-v5',
    #                               'sentence-transformers/multi-qa-distilbert-dot-v1',
    #                               'sentence-transformers/all-distilroberta-v1',
    #                               'sentence-transformers/all-MiniLM-L12-v2',
    #                               'sentence-transformers/multi-qa-mpnet-base-dot-v1',
    #                               'sentence-transformers/all-roberta-large-v1',
    #                               'sentence-transformers/gtr-t5-xxl',
    #                               'sentence-transformers/paraphrase-TinyBERT-L6-v2']
    # SentenceTransformersModels = [
    #         "sentence-transformers/paraphrase-albert-small-v2",
    #         "sentence-transformers/msmarco-bert-base-dot-v5",
    #         "sentence-transformers/multi-qa-distilbert-cos-v1",
    #         "sentence-transformers/multi-qa-distilbert-dot-v1",
    #         "sentence-transformers/msmarco-distilbert-dot-v5",
    #         "sentence-transformers/msmarco-distilbert-base-tas-b",
    #         "sentence-transformers/all-distilroberta-v1",
    #         "sentence-transformers/paraphrase-distilroberta-base-v2",
    #         "sentence-transformers/multi-qa-MiniLM-L6-cos-v1",
    #         "sentence-transformers/all-MiniLM-L12-v2",
    #         "sentence-transformers/all-MiniLM-L12-v1",
    #         "sentence-transformers/all-MiniLM-L6-v2",
    #         "sentence-transformers/multi-qa-MiniLM-L6-dot-v1",
    #         "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2",
    #         "sentence-transformers/all-MiniLM-L6-v1",
    #         "sentence-transformers/paraphrase-MiniLM-L12-v2",
    #         "sentence-transformers/paraphrase-MiniLM-L6-v2",
    #         "sentence-transformers/multi-qa-mpnet-base-dot-v1",
    #         "sentence-transformers/all-mpnet-base-v2",
    #         "sentence-transformers/all-mpnet-base-v1",
    #         "sentence-transformers/paraphrase-mpnet-base-v2",
    #         "sentence-transformers/paraphrase-multilingual-mpnet-base-v2",
    #         "sentence-transformers/all-roberta-large-v1",
    #         "sentence-transformers/gtr-t5-xxl",
    #         "sentence-transformers/sentence-t5-xxl",
    #         "sentence-transformers/gtr-t5-xxl",
    #         "sentence-transformers/gtr-t5-large",
    #         "sentence-transformers/sentence-t5-xxl",
    #         "sentence-transformers/sentence-t5-xl",
    #         "sentence-transformers/gtr-t5-base",
    #         "sentence-transformers/sentence-t5-large",
    #         "sentence-transformers/sentence-t5-base",
    #         "sentence-transformers/paraphrase-TinyBERT-L6-v2"
    # ]

    SentenceTransformersModels = ['sentence-transformers/multi-qa-mpnet-base-dot-v1']
    for mod in SentenceTransformersModels:
        model = SentenceTransformer(mod)

        allLinksFile = "./datasets/VULDATDataSetWithoutProcedures.xlsx"
        print ("Im here1")
        dataCve = pd.read_excel(allLinksFile, sheet_name=0)
        descriptions = dataCve['CVEDescription'].values
        orgDescriptions = dataCve
        dataCve2= dataCve
        print ("Im here2")

        descriptions = removeURLandCitationBulk(descriptions)
        # descriptions = dataPreprocessingStopWords(descriptions)
        # descriptions = [' '.join(item) for item in descriptions]    
        # print ("Im here3")
        # descriptions = dataPreprocessingStemming(descriptions)
        # descriptions = [' '.join(item) for item in descriptions]
        # descriptions = dataPreprocessingLemmatization(descriptions)
        # descriptions = [' '.join(item) for item in descriptions]
        dataCve['CVEDescription'] = descriptions 
        print ("Im here3")
        
        descriptions = dataCve['CVEDescription'].values.tolist()
        techniquesName = dataCve['TechnqiueName'].values.tolist()
        # CWEName = dataCve['CAPECName'].values.tolist()
        # CapecDes = dataCve['CAPECDescription'].values.tolist()
        descriptions = descriptions[:len(descriptions)]
        techniquesName = techniquesName[:len(techniquesName)]
        # CWEName = CWEName[:len(CWEName)]

        joined_list = [ techniquesName[i]+ " " + descriptions[i] for i in range(min(len(descriptions), len(techniquesName)))]
        print ("Im here4")

        sentences = joined_list
        embeddings = model.encode(sentences)

        techniquesName = dataCve['TechnqiueName'].values.tolist()
        print ("Im here5")
        informationData = ["Technique"]
        AttackTPsum = 0 
        AttackTNsum =0 
        AttackFPsum=0 
        AttackFNsum =0
        
        for infoData in informationData:
            if infoData == "Technique":
                # tech_dict = readTechWithNegative()
                tech_dict = readAllTechPositives()
        
            for Threeshold in [0]:
                df = df.iloc[0:0]
                dfRes = df.iloc[0:0]
                countT = 0
                print(str(Threeshold) + " Threshold")
                for key, value in tech_dict.items():
                    print(f"ID: {key} ttttt {countT} ")
                    countT = countT+1
                    attack_texts = [f"{value['TechnqiueName']} {value['TechnqiueDescription']}"]
                   
                    attack_texts = removeURLandCitationBulk([f"{value['TechnqiueName']} {value['TechnqiueDescription']}"])
                    # attack_texts = dataPreprocessingStemming(attack_texts)
                    # attack_texts = [' '.join(item) for item in attack_texts]        
                    vul_data_array =[]
                
                    external_embedding = model.encode(attack_texts)

                    similarities = util.pytorch_cos_sim(external_embedding, embeddings)


                    similarities = cosine_similarity(external_embedding.reshape(1, -1), embeddings)[0]

                    top_10_indices = np.argsort(similarities)[-181000:][::-1]

                    finalRes =[]
                    array = []
                    
                    for index in top_10_indices:
                        
                        if orgDescriptions.loc[index] is not None:
                            if not dataCve.loc[index]['CVEID'] in array:
                                array.append(dataCve.loc[index]['CVEID'])
                                vul_data = VulData()
                                vul_data.Tech_ID = key
                                vul_data.CVE_ID = orgDescriptions.loc[index]['CVEID']
                                vul_data.CVE_Des = orgDescriptions.loc[index]['CVEDescription']
                                # vul_data.CWE_ID = orgDescriptions.loc[index]['CWE-ID']
                                # vul_data.CWE_NAME = orgDescriptions.loc[index]['CWE-Name']
                                vul_data.CVE_Smiliraty  = f"{similarities[index]:.4f}"
                                finalRes.append(vul_data.CVE_ID + "#" +vul_data.CVE_Des+"#"+vul_data.CVE_Smiliraty )
                                vul_data_array.append(vul_data)
                    dataCve =dataCve2
                    if infoData == "Tactic":
                        trainAndTestSet = dataCve[dataCve['TacticID'] == key]
                    elif infoData == "Procedures" or infoData == "prcedirePositive":
                        trainAndTestSet = dataCve[dataCve['ProceduresID'] == key]
                    elif infoData == "CAPEC":
                        trainAndTestSet = dataCve[dataCve['CAPECID'] == key]
                    else:
                        # if "." in key:
                        #     key = key.split(".")[0]
                        trainAndTestSet = dataCve[dataCve['TechnqiueID'].str.startswith(key)]

                    trainAndTestSetCVEs = trainAndTestSet['CVEID']
                    trainAndTestSetCVEs2 = trainAndTestSetCVEs.tolist()
                    trainAndTestSetCVEs = list(set(trainAndTestSetCVEs2))
                    #### not attack
                    if infoData == "Tactic":
                        CvesNotAttack = dataCve[dataCve['TacticID'] != key]
                    elif infoData == "Procedures" or infoData == "prcedirePositive":
                        CvesNotAttack = dataCve[dataCve['ProceduresID'] != key]
                    elif infoData == "CAPEC":
                        CvesNotAttack = dataCve[dataCve['CAPECID'] != key]
                    else:
                        # if "." in key:
                        #     key = key.split(".")[0]
                        CvesNotAttack = dataCve[~dataCve['TechnqiueID'].str.startswith(key)]
                    # CvesNotAttack = dataCve[dataCve['TechnqiueID'] != key]
                    # CvesNotAttack = dataCve[~dataCve['TechnqiueID'].str.startswith(key)]
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
                    model_parts = mod.split('/')
                    AttackTPsum,    AttackTNsum,    AttackFPsum,     AttackFNsum , dataframeResultsForallModels, topK = falseNegativeSUMAlltech2222(vul_data_array,trainAndTestSetCVEs,key,arrayPositive , arrayNegative,CvesNotAttack, Threeshold, AttackTPsum,    AttackTNsum,    AttackFPsum,     AttackFNsum,dataframeResultsForallModels, model_parts[1])
                
            preci=AttackTPsum/(AttackTPsum+AttackFPsum)
            Recal=AttackTPsum/(AttackTPsum+AttackFNsum)
            F1score= 2*preci*Recal/(preci+Recal)
            
            dataframeResults = pd.concat([dataframeResults, pd.DataFrame({'Model':[model_parts[1]],'precision':[preci],'Recall':[Recal],'F1':[F1score]})], ignore_index=True)
            # dataframeResultsForallModels = pd.DataFrame(columns=['LintersectM','L_M','M','M_L','L_Sum'])
            # df.to_excel(f"Final{model_parts[1]}full.xlsx", index=False)
            
            print(mod)
            # dataframeResultsForallModels.to_excel(f"./Results/AllModelsJaccardN{str(Threeshold)}50.xlsx", index=False)
            # dataframeResults.to_excel(f"./Results/RResults{str(Threeshold)}50.xlsx", index=False)
            topK.to_excel(f"./Results/{model_parts[1]}TopK20CVEs.xlsx", index=False)
            # dfRes.to_excel(f"./Results/{model_parts[1]}{str(Threeshold)}50.xlsx", index=False)
#########################################################################Hijack Execution Flow: DLL Search Order Hijacking Adversaries may execute their own malicious payloads by hijacking the search order used to load DLLs. Windows systems use a common method to look for required DLLs to load into a program. [1][2] Hijacking DLL loads may be for the purpose of establishing persistence as well as elevating privileges and/or evading restrictions on file execution.There are many ways an adversary can hijack DLL loads. Adversaries may plant trojan dynamic-link library files (DLLs) in a directory that will be searched before the location of a legitimate library that will be requested by a program, causing Windows to load their malicious library when it is called for by the victim program. Adversaries may also perform DLL preloading, also called binary planting attacks, [3] by placing a malicious DLL with the same name as an ambiguously specified DLL in a location that Windows searches before the legitimate DLL. Often this location is the current working directory of the program.[4] Remote DLL preloading attacks occur when a program sets its current directory to a remote location such as a Web share before loading a DLL. [5]Adversaries may also directly modify the search order via DLL redirection, which after being enabled (in the Registry and creation of a redirection file) may cause a program to load a different DLL.[6][7][8]If a search order-vulnerable program is configured to run at a higher privilege level, then the adversary-controlled DLL that is loaded will also be executed at the higher level. In this case, the technique could be used for privilege escalation from user to administrator or SYSTEM or from administrator to SYSTEM, depending on the program. Programs that fall victim to path hijacking may appear to behave normally because malicious DLLs may be configured to also load the legitimate DLLs they were meant to replace. has used search order hijacking to force TeamViewer to load a malicious DLL is a cybercriminal group that has been active since at least 2015 and is primarily interested in users of remote banking systems in Russia and neighboring countries. The group uses a Trojan by the same name 





checkCVEUsingAllTech()



