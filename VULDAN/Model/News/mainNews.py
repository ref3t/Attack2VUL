
import pandas as pd
import re
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np
import random
import time
from sklearn.model_selection import train_test_split
from vulDataClass import VulData
from sentence_transformers import SentenceTransformer
import nltk
nltk.download('stopwords')
nltk.download('punkt')
nltk.download('wordnet')
import re


def remove_citations_and_urls(text):
    """
    Remove citations and URLs from the input text.
    
    Parameters:
    text (str): The input string containing CVE description, citations, or URLs.
    
    Returns:
    str: Cleaned text with citations, URLs, and non-alphanumeric characters removed.
    """
    
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
    """
    Applies remove_citations_and_urls on a bulk list of strings.

    Parameters:
    texts (list): A list of text strings to be cleaned.

    Returns:
    list: A list of cleaned strings with citations and URLs removed.
    """
    return [remove_citations_and_urls(text) for text in texts]

def predictCVEsFromNews():
    """
    Predicts CVEs from news titles using a SentenceTransformer model.
    Parameters:
    Returns:
    """
    dataframeResults = pd.DataFrame(columns=['Title','CVEs'])
    SentenceTransformersModels = ['sentence-transformers/multi-qa-mpnet-base-dot-v1']
    
    for mod in SentenceTransformersModels:
        # Start the timer
        start_time = time.time()
        countT = 0
        model = SentenceTransformer(mod)
        # "cve_data"
        CVE_df = './datasets/News/cve_data.xlsx'
        # CVE_df = './datasets/News/CVEVULDAT.xlsx'
        print ("Im here1")
        dataCve = pd.read_excel(CVE_df, sheet_name=0)
        descriptions = dataCve['CVEDescription'].values
        orgDescriptions = dataCve
        dataCve2= dataCve
        print ("Im here2")

        descriptions = removeURLandCitationBulk(descriptions)
        dataCve['CVEDescription'] = descriptions 
        print ("Im here3")
        
        # descriptions = dataCve['CVEDescription'].values.tolist()
        
        embeddings = model.encode(descriptions)

        News_df = pd.read_excel('./datasets/News/SecurityWeek_Vulnerabilities.xlsx', engine='openpyxl')
        # Extract titles and descriptions from the news and CVE data
        News_Titles = News_df['Title'].tolist()
        News_Descriptions = News_df['Text'].tolist()
        Threeshold = .55
        # Combine the titles and descriptions at the same index
        # merged_data = [f"{title}: {description}" for title, description in zip(News_Titles, News_Descriptions)]

        countT = 0
        print(str(Threeshold) + " Threshold")
        for key in News_Descriptions:
            print(f"ID: {key} ttttt {countT} ")              
            countT += 1
            attack_texts = removeURLandCitationBulk([f"{key}"])     
            vul_data_array = []
        
            external_embedding = model.encode(attack_texts)
            similarities = cosine_similarity(external_embedding.reshape(1, -1), embeddings)[0] 
            top_10_indices = np.argsort(similarities)[-181000:][::-1]

            finalRes = []
            array = []
            
            for index in top_10_indices:
                if orgDescriptions.loc[index] is not None:
                    if not dataCve.loc[index]['CVEID'] in array:
                        array.append(dataCve.loc[index]['CVEID'])
                        vul_data = VulData()
                        vul_data.CVE_ID = orgDescriptions.loc[index]['CVEID']
                        vul_data.Tech_ID = key
                        vul_data.CVE_Des = orgDescriptions.loc[index]['CVEDescription']
                        vul_data.CVE_Smiliraty = f"{similarities[index]:.4f}"
                        finalRes.append(vul_data.CVE_ID + "#" + vul_data.CVE_Des + "#" + vul_data.CVE_Smiliraty)
                        vul_data_array.append(vul_data)
            dataCve = dataCve2
            

            arrayPositive = []
            arrayNegative = []

            # for item in vul_data_array:
            #     if float(item.CVE_Smiliraty) > Threeshold:
            #         arrayPositive.append(item.CVE_ID)
            for item in vul_data_array:
                if float(item.CVE_Smiliraty) > Threeshold:
                    arrayPositive.append(item)
            
            arrayPositive = list(set(arrayPositive))
            # top_k = 20  # Set Top-k to 20

            # # Sort arrayPositive based on CVE_Similarty in descending order and select top 20
            # # Assuming arrayPositive contains items with a 'CVE_Similarty' attribute
            # arrayPositive = sorted(arrayPositive, key=lambda x: float(x.CVE_Smiliraty), reverse=True)[:top_k]

            # # Extract only the CVE_IDs from the top 20 results
            arrayPositive = list(set([item.CVE_ID for item in arrayPositive]))
            arrayPositive = list(set(arrayPositive))
            print(f"TP:{str(len(arrayPositive))}  {str(key)}")
            dataframeResults = pd.concat([dataframeResults, pd.DataFrame({'Title':[key], 'CVEs': [arrayPositive]})], ignore_index=True)
        print(mod)
        
    dataframeResults.to_excel(f"./Results/AttackNewsCVETopk20Threshold.xlsx", index=False)




predictCVEsFromNews()

