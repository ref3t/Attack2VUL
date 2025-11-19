import pandas as pd
import re

from sentence_transformers import SentenceTransformer
from vulDataClass import VulData
import numpy as np

from sklearn.metrics.pairwise import cosine_similarity

import spacy
from transformers import AutoTokenizer, AutoModel
from sklearn.feature_extraction.text import TfidfVectorizer


# Define a class to hold the attack data
class AttackCVE:
    def __init__(self, attack_text, related_cves, found_cves, common_cves):
        self.attack_text = attack_text  # The description of the attack
        self.related_cves = related_cves  # CVEs related to the attack (from the Excel file)
        self.found_cves = found_cves  # CVEs found in the attack text
        self.common_cves = common_cves  # CVEs found in the attack text and listed in related CVEs
    def __repr__(self):
        return f"AttackCVE(attack_text={self.attack_text}, related_cves={self.related_cves}, found_cves={self.found_cves}, common_cves={self.common_cves})"


# Define a class that will manage the CVE and attack data
class CVEManager:

    def __init__(self):
        self.attacks = []  # This will store all AttackCVE objects

    def extract_cves_from_text(self, text):
        """Extracts all CVEs (in the form of 'CVE-xxxx-yyyy') from the attack text."""
        cve_pattern = r'CVE-\d{4}-\d{4,7}'  # CVE pattern: CVE-YYYY-NNNNNN
        return re.findall(cve_pattern, text)

    def load_attack_data_from_excel(self, excel_file):
        """Reads attack data from an Excel file and stores it in the class."""
        # Read the data from Excel
        df = pd.read_excel(excel_file)

        # Iterate over the rows of the DataFrame and create AttackCVE objects
        for _, row in df.iterrows():
            attack_text = row[0]  # The attack description (first column)
            related_cves = row.dropna().iloc[1:].tolist()  # Drop NA and take the CVEs from the row
             # Format CVEs: append `$` after every CVE
            formatted_related_cves = [f"{cve}" for cve in related_cves]
            related_cves = formatted_related_cves
            # Extract CVEs from the attack text
            found_cves = self.extract_cves_from_text(attack_text)
            
            # Find the intersection (common CVEs between found_cves and related_cves)
            common_cves = list(set(found_cves) & set(related_cves))  # Intersection of the two lists
            
            # Store the attack with CVEs, found CVEs and common CVEs
            self.attacks.append(AttackCVE(attack_text, related_cves, found_cves, common_cves))

    def display_data(self):
        """Displays the stored attack and CVE data (for debugging purposes)."""
        for attack in self.attacks:
            return
            #print(f"Attack Text: {attack.attack_text}")
            #print(f"Related CVEs: {', '.join(attack.related_cves)}")
            #print(f"Found CVEs in Attack Text: {', '.join(attack.found_cves)}")
            #print(f"Common CVEs (Found & Related): {', '.join(attack.common_cves)}")
            #print()

    def save_attack_data_to_excel(self, output_file):
        """Saves the processed attack data (including common CVEs) to a new Excel file."""
        
        # Prepare data for saving
        data = []
        for attack in self.attacks:
            # Convert the data for each attack into a row (list)
            row = [
                attack.attack_text,  # Attack text
                ', '.join(attack.related_cves),  # Related CVEs
                ', '.join(attack.found_cves),  # Found CVEs
                ', '.join(attack.common_cves)  # Common CVEs
            ]
            data.append(row)
        
        # Create a DataFrame from the list of rows
        columns = ['Attack Text', 'Related CVEs', 'Found CVEs', 'Common CVEs']
        df = pd.DataFrame(data, columns=columns)
        
        # Save the DataFrame to an Excel file
        df.to_excel(output_file, index=False)
        #print(f"Processed attack data has been saved to '{output_file}'.")
    def get_cve_dictionary(self, typeCVE):
        """Returns a dictionary where each attack text is a key and its value is the specified type of CVEs."""
        cve_dict = {}
        
        # Validate typeCVE to ensure it matches an attribute
        valid_types = {"related_cves", "found_cves", "common_cves"}
        if typeCVE not in valid_types:
            raise ValueError(f"typeCVE must be one of {valid_types}")
        
        for attack in self.attacks:
            # Only include the specified CVE type in the dictionary
            cve_dict[attack.attack_text] = getattr(attack, typeCVE)
        
        return cve_dict
    def get_unique_and_common_cves(self):
        """
        Returns two dictionaries:
        1. unique_related_cves_dict: Each attack text as a key and a list of CVEs
        that are in 'related_cves' but not in 'common_cves'.
        2. common_cves_dict: Each attack text as a key and a dictionary of CVEs
        that are in both 'related_cves' and 'common_cves' (with descriptions from related_cves).
        """
        unique_related_cves_dict = {}
        common_cves_dict = {}

        for attack in self.attacks:  # Ensure `self.attacks` contains AttackCVE objects
            # Ensure attack is an instance of AttackCVE (debugging check)

            # Get the CVEs in related_cves but not in common_cves
            unique_related_cves = []
            for i in range(0, len(attack.related_cves), 2):
                if not attack.related_cves[i] in attack.common_cves:
                    unique_related_cves.append(attack.related_cves[i])
                    unique_related_cves.append(attack.related_cves[i+1])
                    
            # for cve_id in attack.related_cves:
            #     if cve_id not in attack.common_cves:
            #         unique_related_cves.append(cve_id)

            # unique_related_cves = [cve_id for cve_id in attack.related_cves if cve_id not in attack.common_cves]

            # Get the CVEs in both related_cves and common_cves
            common_related_cves2 = [cve_id for cve_id in attack.related_cves if cve_id in attack.common_cves]

            # Initialize dictionary for common CVEs with descriptions
            common_cves_with_desc = []
            # Loop through the common CVEs and get their descriptions
            for cve_id in common_related_cves2:
                # Find the index of cve_id in the related_cves array
                for i, cve in enumerate(attack.related_cves):
                    if cve == cve_id:  # cve[0] is the CVE ID
                        # Ensure there is a next index and get the description from the next entry
                        if i + 1 < len(attack.related_cves):
                            next_cve = attack.related_cves[i + 1]  # Next CVE entry
                            # common_cves_with_desc['cve_id'] = cve_id
                            common_cves_with_desc.append(cve_id)
                            common_cves_with_desc.append(next_cve)
                        break  # Exit the inner loop once the CVE ID is found
           
            unique_related_cves_dict[attack.attack_text] = unique_related_cves

            common_cves_dict[attack.attack_text] = common_cves_with_desc

        return unique_related_cves_dict, common_cves_dict

# Load the MPNet model and tokenizer
tokenizer = AutoTokenizer.from_pretrained("sentence-transformers/all-mpnet-base-v2")
model = AutoModel.from_pretrained("sentence-transformers/all-mpnet-base-v2")

# Load SpaCy model for Named Entity Recognition (NER)
nlp = spacy.load("en_core_web_sm")

def get_embeddings(text):
    """Generate embeddings for a given text using MPNet."""
    inputs = tokenizer(text, return_tensors="pt", truncation=True, padding=True)
    outputs = model(**inputs)
    embeddings = outputs.last_hidden_state.mean(dim=1).detach().numpy()
    return embeddings

def extract_keywords_entities(text):
    """Extract keywords and named entities using SpaCy."""
    doc = nlp(text)
    keywords = [chunk.text for chunk in doc.noun_chunks]
    entities = [ent.text for ent in doc.ents]
    return keywords + entities

def calculate_similarity_score(text1, text2):
    """Calculate cosine similarity score between embeddings of two texts."""
    emb1 = get_embeddings(text1)
    emb2 = get_embeddings(text2)
    score = cosine_similarity(emb1, emb2)[0][0]
    return score

def validate_cve_news_pair(cve_description, news_content, threshold=0.58):
    """Validate if a CVE matches a news article based on similarity and keyword/entity overlap."""
    
    # Step 1: Calculate initial similarity
    initial_score = calculate_similarity_score(cve_description, news_content)
    if initial_score < threshold:
        return False, initial_score  # Reject if similarity is below threshold

    # Step 2: Extract keywords and entities from both texts
    cve_keywords_entities = set(extract_keywords_entities(cve_description))
    news_keywords_entities = set(extract_keywords_entities(news_content))
    
    # Step 3: Check for overlap between keywords/entities
    overlap = cve_keywords_entities.intersection(news_keywords_entities)
    
    # Step 4: Apply a secondary validation if overlap exists
    if overlap:
        refined_score = calculate_similarity_score(" ".join(overlap), news_content)
        return refined_score >= 0.45, refined_score 

    return False, initial_score


# Helper function to check if index is odd
def is_odd(index):
    return index % 2 != 0
def just_related_with_Common_and_without_common(attack_cve_just_related_dict, attack_cve_related_dict):
    
    count = 0
    dataframeResults = pd.DataFrame(columns=['Attack','CVEs','CommonCVEs','RelatedWithoutCommonCVEs'])
    for news in attack_cve_just_related_dict:
        print (list(attack_cve_related_dict[news].keys()))
        # if count == 7:
        #     break
        count += 1
        print (f'{count} *******************')
        model = SentenceTransformer('sentence-transformers/multi-qa-mpnet-base-dot-v1')
        df_cveid = pd.DataFrame(list(attack_cve_just_related_dict[news].keys()), columns=['CVEID'])
        df_desc = pd.DataFrame(list(attack_cve_just_related_dict[news].values()), columns=['CVEDescription'])

        # Concatenate the DataFrames along columns
        dataCve = pd.concat([df_cveid, df_desc], axis=1)

        descriptions = dataCve['CVEDescription'].values
        orgDescriptions = dataCve
        dataCve2= dataCve
        print ("Im here2")

        
        # descriptions = dataCve['CVEDescription'].values.tolist()
        
        embeddings = model.encode(descriptions)

        # News_df = pd.read_excel('./datasets/News/SecurityWeek_Vulnerabilities.xlsx', engine='openpyxl')
        # # Extract titles and descriptions from the news and CVE data
        # News_Titles = News_df['Title'].tolist()
        # News_Descriptions = News_df['Text'].tolist()
        Threeshold = 0.58
        # Combine the titles and descriptions at the same index
        # merged_data = [f"{title}: {description}" for title, description in zip(News_Titles, News_Descriptions)]

        
        attack_texts = news     
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
                    vul_data.Tech_ID = news
                    vul_data.CVE_Des = orgDescriptions.loc[index]['CVEDescription']
                    vul_data.CVE_Smiliraty = f"{similarities[index]:.4f}"
                    finalRes.append(vul_data.CVE_ID + "#" + vul_data.CVE_Des + "#" + vul_data.CVE_Smiliraty)
                    vul_data_array.append(vul_data)
        dataCve = dataCve2
        

        arrayPositive = []
        arrayNegative = []


        for item in vul_data_array:
            if float(item.CVE_Smiliraty) > Threeshold:
                score = float(item.CVE_Smiliraty)
                arrayPositive.append(f"{item.CVE_ID}#{score:.2f}")
        # Remove duplicates
        # arrayPositive = list(set(arrayPositive))
        arrayPositive = sorted(set(arrayPositive))

        dataframeResults = pd.concat([dataframeResults, pd.DataFrame({'Attack':[news], 'CVEs': [arrayPositive], 'CommonCVEs': [common_cves_dict_org[news]], 'RelatedWithoutCommonCVEs': [sorted(list(attack_cve_related_dict[news].keys()))]})], ignore_index=True)
        
        
    dataframeResults.to_excel(f"./Results/NewsResults/AttackNewsCVEWithScoreCommonAndRelated.xlsx", index=False)

def get_description_found_cve(cve_ids):
    import pandas as pd

    import openpyxl
    dataCve = pd.read_excel('./datasets/News/cve_data.xlsx', sheet_name=0)
    descriptions = dataCve['CVEDescription'].values.tolist()
    cveID = dataCve['CVEID'].values.tolist()     
    # file_pathPositive = 'NewMapping/FinalResultSeperate/Techniqes/AllTechniques.xlsx'
    #     # Read the Excel file
    # dataTech = pd.read_excel(file_pathPositive, sheet_name=0)
        
    # techniquesID = dataTech['TechnqiueID'].values.tolist()
    # techniquesDes = dataTech['TechnqiueDescription'].values.tolist()
    array_cves_des = []

    for row in cve_ids:
        for indexCVe, cve in enumerate(cveID):
            if cve == row:
                # arrayDataRow.append(value)
                array_cves_des.append(descriptions[indexCVe])
                break
    return array_cves_des

def check_between_the_existing_CVEs(attack_cve_just_related_dict, attack_cve_related_dict):
    count = 0
    dataframeResults = pd.DataFrame(columns=['Attack','CVEs','CommonCVEs','RelatedWithoutCommonCVEs','ScoreswithinCommonCVEs','foundCVEs'])
    for news in attack_cve_just_related_dict:
        print (list(attack_cve_related_dict[news]))
        # if count == 3:
        #     break
        count += 1
        print (f'{count} *******************')
        model = SentenceTransformer('sentence-transformers/multi-qa-mpnet-base-dot-v1')
        df_cveid = pd.DataFrame(list(attack_cve_just_related_dict[news].keys()), columns=['CVEID'])
        df_desc = pd.DataFrame(list(attack_cve_just_related_dict[news].values()), columns=['CVEDescription'])

        # Concatenate the DataFrames along columns
        dataCve = pd.concat([df_cveid, df_desc], axis=1)

        descriptions = dataCve['CVEDescription'].values
        orgDescriptions = dataCve
        dataCve2= dataCve
        print ("Im here2")

        
        # descriptions = dataCve['CVEDescription'].values.tolist()
        
        embeddings = model.encode(descriptions)

        # News_df = pd.read_excel('./datasets/News/SecurityWeek_Vulnerabilities.xlsx', engine='openpyxl')
        # # Extract titles and descriptions from the news and CVE data
        # News_Titles = News_df['Title'].tolist()
        # News_Descriptions = News_df['Text'].tolist()
        Threeshold = 0.5
        # Combine the titles and descriptions at the same index
        # merged_data = [f"{title}: {description}" for title, description in zip(News_Titles, News_Descriptions)]

        found_cve_ids = list(set(attack_cve_related_dict[news]))
        found_Cve_descriptions = get_description_found_cve(found_cve_ids)
        # attack_texts = found_Cve_descriptions[0]
        attack_texts = " ".join(found_Cve_descriptions)
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
                    vul_data.Tech_ID = news
                    vul_data.CVE_Des = orgDescriptions.loc[index]['CVEDescription']
                    vul_data.CVE_Smiliraty = f"{similarities[index]:.4f}"
                    finalRes.append(vul_data.CVE_ID + "#" + vul_data.CVE_Des + "#" + vul_data.CVE_Smiliraty)
                    vul_data_array.append(vul_data)
        dataCve = dataCve2
        

        arrayPositive = []
        arrayNegative = []


        for item in vul_data_array:
            if float(item.CVE_Smiliraty) > Threeshold:
                score = float(item.CVE_Smiliraty)
                arrayPositive.append(f"{item.CVE_ID}#{score:.2f}")
        # Remove duplicates
        arrayPositive = sorted(set(arrayPositive))


        dataframeResults = pd.concat([dataframeResults, pd.DataFrame({'Attack':[news], 'ScoreswithinCommonCVEs': [arrayPositive], 'foundCVEs': [found_cve_ids]})], ignore_index=True)
        
        
    dataframeResults.to_excel(f"./Results/NewsResults/AttackNewsCVEWithinRelatedwithOther.xlsx", index=False)

def check_between_the_existing_CVEs_using_entity(attack_cve_just_related_dict, attack_cve_related_dict):
    count = 0
    dataframeResults = pd.DataFrame(columns=['Attack','CVEs','CommonCVEs','RelatedWithoutCommonCVEs','ScoreswithinCommonCVEsEntity','foundCVEs'])
    for news in attack_cve_just_related_dict:
        print (list(attack_cve_related_dict[news]))
        # if count == 3:
        #     break
        count += 1
        print (f'{count} *******************')

        df_cveid = pd.DataFrame(list(attack_cve_just_related_dict[news].keys()), columns=['CVEID'])
        df_desc = pd.DataFrame(list(attack_cve_just_related_dict[news].values()), columns=['CVEDescription'])

        # Concatenate the DataFrames along columns
        dataCve = pd.concat([df_cveid, df_desc], axis=1)

        descriptions = dataCve['CVEDescription'].values
        CVEs_id = dataCve['CVEID'].values
        print ("Im here2")

        found_cve_ids = list(set(attack_cve_related_dict[news]))
        found_Cve_descriptions = get_description_found_cve(found_cve_ids)
        # attack_texts = found_Cve_descriptions[0]
        attack_texts = " ".join(found_Cve_descriptions)
        results = []
        CVEs_related_using_entity = []
        for cve_description in descriptions:
            is_valid, score = validate_cve_news_pair(cve_description, attack_texts, threshold=0.58)
            results.append((cve_description, is_valid, score))
                

        # Display results
        for idx, (desc, valid, score) in enumerate(results, 1):
            if valid:
                CVEs_related_using_entity.append(f'{CVEs_id[idx-1]}#{score:.2f}')
            print(f"CVE {CVEs_id[idx-1]}:")
            print("Description:", desc)
            print("Validation Result:", valid)
            print("Score:", score)
            print("-" * 40)

        dataframeResults = pd.concat([dataframeResults, pd.DataFrame({'Attack':[news], 'ScoreswithinCommonCVEsEntity': [CVEs_related_using_entity], 'foundCVEs': [found_cve_ids]})], ignore_index=True)
        
        
    dataframeResults.to_excel(f"./Results/NewsResults/AttackNewsCVEWithinRelatedwithOtherusingEntity.xlsx", index=False)
if __name__ == "__main__":
    cve_manager = CVEManager()

    # Step 1: Load attack data from the Excel file (replace 'attack_data.xlsx' with your file)
    cve_manager.load_attack_data_from_excel('./Results/WeekNewsResultsCVEs.xlsx')

    # Step 2: Display the loaded data (optional for debugging)
    cve_manager.display_data()


    # Retrieve only related CVEs
    related_cves_dict = cve_manager.get_cve_dictionary("related_cves")
    #print(related_cves_dict)

    # Retrieve only found CVEs
    found_cves_dict = cve_manager.get_cve_dictionary("found_cves")
    #print(found_cves_dict)

    # Retrieve only common CVEs
    common_cves_dict_org = cve_manager.get_cve_dictionary("common_cves")
    # print(common_cves_dict_org.keys())

    unique_related_cves_dict, common_cves_dict = cve_manager.get_unique_and_common_cves()
    
    found_cves_not_in_related = found_cves_dict.keys() - common_cves_dict.keys()
    # print(f"Found CVEs not in related CVEs: {found_cves_not_in_related}")


    # Initialize the result dictionary
    attack_cve_related_dict = {}

    # Iterate through each attack_text and its associated CVEs
    for attack_text, cve_list in unique_related_cves_dict.items():
        # Dictionary to hold CVE: description pairs for each attack
        cve_description_dict = {}
        cve_dict = {}
        for i in range(0, len(cve_list), 2):
            cve_id = cve_list[i]  # CVE ID
            description = cve_list[i + 1]  # Description
            cve_dict[cve_id] = description
        
        # Assign the inner dictionary to the attack_text key in the main dictionary
        attack_cve_related_dict[attack_text] = cve_dict

    attack_cve_common_dict = {}

    # Iterate through each attack_text and its associated CVEs
    for attack_text, cve_list in common_cves_dict.items():
        # Dictionary to hold CVE: description pairs for each attack
        cve_description_dict = {}
        cve_dict = {}
        for i in range(0, len(cve_list), 2):
            cve_id = cve_list[i]  # CVE ID
            description = cve_list[i + 1]  # Description
            cve_dict[cve_id] = description
        
        # Assign the inner dictionary to the attack_text key in the main dictionary
        attack_cve_common_dict[attack_text] = cve_dict


    # Extract the required lists
    outer_keys_related_CVE = list(attack_cve_common_dict.keys())
    inner_keys_related_CVE = [inner_key for inner_dict in attack_cve_common_dict.values() for inner_key in inner_dict.keys()]
    inner_values_related_CVE = [inner_value for inner_dict in attack_cve_common_dict.values() for inner_value in inner_dict.values()]

    # Print results
    # print("Outer keys:", outer_keys_related_CVE)
    print("Inner keys:", inner_keys_related_CVE)
    # print("Inner values:", inner_values_related_CVE)


    # Extract the required lists
    outer_keys_common = list(attack_cve_related_dict.keys())
    inner_keys_common = [inner_key for inner_dict in attack_cve_related_dict.values() for inner_key in inner_dict.keys()]
    inner_values_common = [inner_value for inner_dict in attack_cve_related_dict.values() for inner_value in inner_dict.values()]



    # Initialize the result dictionary
    attack_cve_just_related_dict = {}

    # Iterate through each attack_text and its associated CVEs
    for attack_text, cve_list in related_cves_dict.items():
        # Dictionary to hold CVE: description pairs for each attack
        cve_description_dict = {}
        cve_dict = {}
        for i in range(0, len(cve_list), 2):
            cve_id = cve_list[i]  # CVE ID
            description = cve_list[i + 1]  # Description
            cve_dict[cve_id] = description
        
        # Assign the inner dictionary to the attack_text key in the main dictionary
        attack_cve_just_related_dict[attack_text] = cve_dict

    # just_related_with_Common_and_without_common(attack_cve_just_related_dict, attack_cve_related_dict)
    # check_between_the_existing_CVEs(attack_cve_just_related_dict, found_cves_dict)
    check_between_the_existing_CVEs_using_entity(attack_cve_just_related_dict, found_cves_dict)
    # count = 0
    
    # dataframeResults = pd.DataFrame(columns=['Attack','CVEs','CommonCVEs','RelatedWithoutCommonCVEs'])
    # for news in attack_cve_just_related_dict:
    #     print (list(attack_cve_related_dict[news].keys()))
    #     # if count == 7:
    #     #     break
    #     count += 1
    #     print (f'{count} *******************')
    #     model = SentenceTransformer('sentence-transformers/multi-qa-mpnet-base-dot-v1')
    #     df_cveid = pd.DataFrame(list(attack_cve_just_related_dict[news].keys()), columns=['CVEID'])
    #     df_desc = pd.DataFrame(list(attack_cve_just_related_dict[news].values()), columns=['CVEDescription'])

    #     # Concatenate the DataFrames along columns
    #     dataCve = pd.concat([df_cveid, df_desc], axis=1)

    #     descriptions = dataCve['CVEDescription'].values
    #     orgDescriptions = dataCve
    #     dataCve2= dataCve
    #     print ("Im here2")

        
    #     # descriptions = dataCve['CVEDescription'].values.tolist()
        
    #     embeddings = model.encode(descriptions)

    #     News_df = pd.read_excel('./datasets/News/SecurityWeek_Vulnerabilities.xlsx', engine='openpyxl')
    #     # Extract titles and descriptions from the news and CVE data
    #     News_Titles = News_df['Title'].tolist()
    #     News_Descriptions = News_df['Text'].tolist()
    #     Threeshold = 0.58
    #     # Combine the titles and descriptions at the same index
    #     # merged_data = [f"{title}: {description}" for title, description in zip(News_Titles, News_Descriptions)]

        
    #     attack_texts = news     
    #     vul_data_array = []
    
    #     external_embedding = model.encode(attack_texts)
    #     similarities = cosine_similarity(external_embedding.reshape(1, -1), embeddings)[0] 
    #     top_10_indices = np.argsort(similarities)[-181000:][::-1]

    #     finalRes = []
    #     array = []
        
    #     for index in top_10_indices:
    #         if orgDescriptions.loc[index] is not None:
    #             if not dataCve.loc[index]['CVEID'] in array:
    #                 array.append(dataCve.loc[index]['CVEID'])
    #                 vul_data = VulData()
    #                 vul_data.CVE_ID = orgDescriptions.loc[index]['CVEID']
    #                 vul_data.Tech_ID = news
    #                 vul_data.CVE_Des = orgDescriptions.loc[index]['CVEDescription']
    #                 vul_data.CVE_Smiliraty = f"{similarities[index]:.4f}"
    #                 finalRes.append(vul_data.CVE_ID + "#" + vul_data.CVE_Des + "#" + vul_data.CVE_Smiliraty)
    #                 vul_data_array.append(vul_data)
    #     dataCve = dataCve2
        

    #     arrayPositive = []
    #     arrayNegative = []


    #     for item in vul_data_array:
    #         if float(item.CVE_Smiliraty) > Threeshold:
    #             score = float(item.CVE_Smiliraty)
    #             arrayPositive.append(f"{item.CVE_ID}#{score:.2f}")
    #     # Remove duplicates
    #     arrayPositive = list(set(arrayPositive))


    #     dataframeResults = pd.concat([dataframeResults, pd.DataFrame({'Attack':[news], 'CVEs': [arrayPositive], 'CommonCVEs': [common_cves_dict_org[news]], 'RelatedWithoutCommonCVEs': [list(attack_cve_related_dict[news].keys())]})], ignore_index=True)
        
        
    # dataframeResults.to_excel(f"./Results/NewsResults/AttackNewsCVEWithScoreCommonAndRelated.xlsx", index=False)


    # Print results
    # print("Outer keys:", outer_keys_common)
    # print("Inner keys:", inner_keys_common)
    # print("Inner values:", inner_values_common)
    cve_manager.save_attack_data_to_excel('processed_attack_data2.xlsx')
