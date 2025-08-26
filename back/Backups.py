import logging
import os
import re
import random
import numpy as np
import pandas as pd

from torch.utils.data import DataLoader
from sentence_transformers import SentenceTransformer, InputExample, losses, util
from sentence_transformers.evaluation import EmbeddingSimilarityEvaluator
from sentence_transformers import LoggingHandler
from sklearn.metrics.pairwise import cosine_similarity

from vulDataClass import VulData

# Set up logging
logging.basicConfig(format='%(asctime)s - %(message)s',
                    level=logging.INFO,
                    handlers=[LoggingHandler()])

# List of models
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
    'all-roberta-large-v1',
    #'gtr-t5-xxl',
    'paraphrase-TinyBERT-L6-v2'
    #'gtr-t5-xxl'
]

df = pd.DataFrame(columns=['Threshold','TechID','TP','FP','FN','TN','AttackTP','AttackTN','AttackFP','AttackFN','CountMapping'])
dfRes = pd.DataFrame(columns=[
    'TechID','Negative','Positive','Retrieved by VULDAT','Not retrieved by VULDAT',
    'Predicted Positives (>50)','Predicted Negatives (<50)',
    'True Positives (>50)','False Positives (>50)','True Negatives ( <50)',
    'True Negatives (not retrieved)','False Negatives (<50)','False Negatives (not retrieved)',
    'AttackTP','AttackTN','AttackFP','AttackFN'
])

def trueNegativeSUM(vul_data_array, cve_ids_A_not_attack, Threeshold):
    count = 0
    if len(cve_ids_A_not_attack) > 0:
        for vuldat in vul_data_array:
            if float(vuldat.CVE_Smiliraty) < Threeshold:
                if vuldat.CVE_ID in cve_ids_A_not_attack:
                    count = count + 1

    count2 = 0
    if len(cve_ids_A_not_attack) > 0:
        for item in cve_ids_A_not_attack:
            flag = 0
            for vuldat in vul_data_array:
                if item == vuldat.CVE_ID:
                    flag = 1
                    break
            if flag == 0:
                count2 = count2 + 1
    return count, count2

def ResTrueNegatives(vul_data_array, CvesNotAttack, Threeshold):
    return trueNegativeSUM(vul_data_array, CvesNotAttack, Threeshold)

def falseNegativeSUMAlltech2222(
    vul_data_array, CVEsAttack, techniquesID, arrayPositive, arrayNegative,
    CvesNotAttack, Threeshold, AttackTPsum, AttackTNsum, AttackFPsum, AttackFNsum,
    dataframeResultsForallModels, modelName
):
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
            if vuldat.CVE_ID in CVEsAttack:
                MappingCVEsVuldatForAttack.append(vuldat.CVE_ID)
                countMapping = countMapping + 1

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
                    count = count + 1

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
            count2 = count2 + 1

    CVEsVuldatNotForAttack = list(set(CVEsVuldatNotForAttack))
    count2 = len(CVEsVuldatNotForAttack)

    trueNeativeResless, trueNeativeResNotRetrived = ResTrueNegatives(vul_data_array, CvesNotAttack, Threeshold)
    AttackTP = 0
    AttackTN = 0
    AttackFP = 0
    AttackFN = 0

    if ((arrayNegative + arrayPositive)) > 0 and countMapping > 0:
        AttackTP = 1
        AttackTPsum = AttackTPsum + 1
    elif ((arrayNegative + arrayPositive)) == 0 and countMapping == 0:
        AttackTN = 1
        AttackTNsum = AttackTNsum + 1
    elif ((arrayNegative + arrayPositive)) > 0 and countMapping == 0:
        AttackFP = 1
        AttackFPsum = AttackFPsum + 1
    elif ((arrayNegative + arrayPositive)) == 0 and countMapping > 0:
        AttackFN = 1
        AttackFNsum = AttackFNsum + 1

    LintersectM = len(arrayPositive2)
    M = countMapping
    L_M = len(arrayNegative2)
    M_L = M - LintersectM
    L_Sum = LintersectM + L_M
    if L_Sum == 0 and M_L == 0:
        jaccard = 0
    else:
        jaccard = LintersectM / (L_Sum + M_L)

    dataframeResultsForallModels = pd.concat(
        [dataframeResultsForallModels,
         pd.DataFrame({'modelName':[modelName],
                       'LintersectM':[LintersectM],
                       'L_M':[L_M],
                       'M':[M],
                       'M_L':[M_L],
                       'L_Sum':[L_Sum],
                       'Jaccard':[jaccard]})],
        ignore_index=True
    )
    dataframeResultsForallModels = pd.concat([dataframeResultsForallModels, pd.DataFrame({'modelName':[modelName],'LintersectM':[LintersectM],'L_M':[L_M],'M':[M],'M_L':[M_L],'L_Sum':[L_Sum],'Jaccard':[jaccard]})], ignore_index=True)
    df = pd.concat([df, pd.DataFrame({'Threshold':[Threeshold*100],'TechID':[techniquesID],'TP': [arrayPositive], 'FP': [arrayNegative], 'FN': [(count2+count)], 'TN': [(trueNeativeResless+trueNeativeResNotRetrived)], 'AttackTP': [(AttackTP)], 'AttackTN': [(AttackTN)], 'AttackFP': [(AttackFP)], 'AttackFN': [(AttackFN)],'CountMapping':[(countMapping)]})], ignore_index=True)
    # dfRes = pd.concat([dfRes, pd.DataFrame({'TechID':[capecID], 'AttackTP': [(AttackTP)], 'AttackTN': [(AttackTN)], 'AttackFP': [(AttackFP)], 'AttackFN': [(AttackFN)],'CountMapping':[(countMapping)],'Lpositive':[arrayPositive2],'LNegatives':[arrayNegative2],"Mapping":[MappingCVEsVuldatForAttack]})], ignore_index=True)
    dfRes = pd.concat([dfRes, pd.DataFrame({'TechID':[techniquesID],'TP': [arrayPositive], 'FP': [arrayNegative], 'FN': [(count2+count)], 'TN': [(trueNeativeResless+trueNeativeResNotRetrived)],  'AttackTP': [(AttackTP)], 'AttackTN': [(AttackTN)], 'AttackFP': [(AttackFP)], 'AttackFN': [(AttackFN)],'CountMapping':[(countMapping)],'Lpositive':[arrayPositive2],'countLpositive' :[len(arrayPositive2)],'LNegatives':[arrayNegative2],'countLNegatives' :[len(arrayNegative2)],"Mapping":[MappingCVEsVuldatForAttack]})], ignore_index=True)
    return AttackTPsum,    AttackTNsum,    AttackFPsum,     AttackFNsum ,dataframeResultsForallModels

def remove_citations_and_urls(text):
    citation_pattern = r'\(Citation:.*?\)'
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    citations = re.findall(citation_pattern, text)
    for citation in citations:
        text = text.replace(citation, '')
    urls = re.findall(url_pattern, text)
    for url in urls:
        text = text.replace(url, '')
    regex = "^<code>.*</code>$"
    text = re.sub(regex, "", text, flags=re.MULTILINE)
    text = " ".join(text.split())  # remove extra spaces
    text = re.sub("[^A-Za-z0-9]", " ", text)  # replace anything not alphanumeric
    return text

def removeURLandCitationBulk(texts):
    return [remove_citations_and_urls(text) for text in texts]

def getTechniqueID(attackDes):
    allLinksFile3 = "./FinalResultSeperate/Techniqes/AllTechniques.xlsx"
    dataCve = pd.read_excel(allLinksFile3, sheet_name=0)
    for _, row in dataCve.iterrows():
        attack = clean_attack_description(row['TechniqueDescription'])
        attackDes = clean_attack_description(attackDes)
        attack = re.sub(r'\s+', ' ', attack)
        attackDes = re.sub(r'\s+', ' ', attackDes)
        if attack.rstrip() == attackDes.rstrip():
            return row['TechniqueID']
    return None

def clean_attack_description(attackDes):
    cleaned = re.sub(r'^[\[\]"\s]+|[\[\]"\s]+$', '', attackDes)
    attackDes = cleaned.replace("\\xa0\\n\\n", "")
    attackDes = attackDes.replace("\n", "")
    attackDes = re.sub(r'\s+', ' ', attackDes)
    attackDes = attackDes.replace("\\n", " ")
    attackDes = re.sub(r'\s+', ' ', attackDes)
    attackDes = attackDes.replace("\\xa0", " ")
    attackDes = re.sub(r'\s+', ' ', attackDes)
    attackDes = attackDes.strip()
    return remove_citations_and_urls(attackDes)

def readCVEData(file):
    dataCve = pd.read_excel(file, sheet_name=0)
    descriptions = dataCve['CVEDescription'].values
    dataCve['CVEDescription'] = removeURLandCitationBulk(descriptions)
    return dataCve

def read_excel_file(file_path, attack_info):
    df_file = pd.read_excel(file_path, sheet_name=0)
    data = []
    for _, row in df_file.iterrows():
        if attack_info == 'CAPEC' or attack_info == 'CAPECImbalanced':
            attack_desc = row['CAPECDescription']
            idv = row['CAPECID']
        elif attack_info == 'Tactic' or attack_info == 'TacticImbalanced':
            attack_desc = row['TacticDescription']
            idv = row['TacticId']
        elif attack_info == 'Procedure' or attack_info == 'ProcedureImbalanced':
            attack_desc = row['ProcedureDescription']
            idv = row['ProcedureID']
        else:
            attack_desc = row['TechniqueDescription']
            idv = row['TechniqueID']
        cve_desc = row['CVEDescription']
        label = row['Label']
        data.append((idv, attack_desc, [cve_desc], label))
    return data

informationData = [
    "Technique","Tactic", "Technique", "Procedure", "CAPEC",
    "TacticImbalanced", "TechniqueImbalanced", "ProcedureImbalanced", "CAPECImbalanced"
]
informationData = [
    "Technique","Tactic", "Procedure", "CAPEC"]
dataframeResults = pd.DataFrame(columns=['Data','Model','precision','Recall','F1'])
dataframeResultsForallModels = pd.DataFrame(columns=['LintersectM','L_M','M','M_L','L_Sum','Jaccard'])

for infoData in informationData:
    if infoData == "TacticImbalanced":
        train_file = 'dataset/attackInfo/Tactics/Tactic_train_data_Imbalanced.xlsx'
        val_file   = 'dataset/attackInfo/Tactics/Tactic_val_data_Imbalanced.xlsx'
        test_file  = 'dataset/attackInfo/Tactics/Tactic_test_data_ImBalanced.xlsx'
    elif infoData == "ProcedureImbalanced":
        train_file = 'dataset/attackInfo/Procedures/Proc_train_data_Imbalanced.xlsx'
        val_file   = 'dataset/attackInfo/Procedures/Proc_val_data_Imbalanced.xlsx'
        test_file  = 'dataset/attackInfo/Procedures/Proc_test_data_Imbalanced.xlsx'
    elif infoData == "TechniqueImbalanced":
        train_file = 'dataset/attackInfo/Techniques/Tech_train_data_ImBalanced.xlsx'
        val_file   = 'dataset/attackInfo/Techniques/Tech_val_data_ImBalanced.xlsx'
        test_file  = 'dataset/attackInfo/Techniques/Tech_test_data_ImBalanced.xlsx'
    elif infoData == "CAPECImbalanced":
        train_file = 'dataset/attackInfo/CAPECs/Capec_train_data_ImBalanced.xlsx'
        val_file   = 'dataset/attackInfo/CAPECs/Capec_val_data_ImBalanced.xlsx'
        test_file  = 'dataset/attackInfo/CAPECs/Capec_test_data_ImBalanced.xlsx'
    elif infoData == "Tactic":
        train_file = 'dataset/attackInfo/Tactics/Tactic_train_data_Balanced.xlsx'
        val_file   = 'dataset/attackInfo/Tactics/Tactic_val_data_Balanced.xlsx'
        test_file  = 'dataset/attackInfo/Tactics/Tactic_test_data_Balanced.xlsx'
    elif infoData == "Technique":
        train_file = 'dataset/attackInfo/Techniques/Tech_train_data_Balanced.xlsx'
        val_file   = 'dataset/attackInfo/Techniques/Tech_val_data_Balanced.xlsx'
        test_file  = 'dataset/attackInfo/Techniques/Tech_test_data_Balanced.xlsx'
    elif infoData == "CAPEC":
        train_file = 'dataset/attackInfo/CAPECs/Capec_train_data_Balanced.xlsx'
        val_file   = 'dataset/attackInfo/CAPECs/Capec_val_data_Balanced.xlsx'
        test_file  = 'dataset/attackInfo/CAPECs/Capec_test_data_Balanced.xlsx'
    elif infoData == "Procedure":
        train_file = 'dataset/attackInfo/Procedures/Proc_train_data_Balanced.xlsx'
        val_file   = 'dataset/attackInfo/Procedures/Proc_val_data_Balanced.xlsx'
        test_file  = 'dataset/attackInfo/Procedures/Proc_test_data_Balanced.xlsx'

    train_data = read_excel_file(train_file, infoData)
    val_data   = read_excel_file(val_file,   infoData)

    def prepare_input_examples(data):
        examples = []
        for idv, attack, cves, label in data:
            for cve in cves:
                examples.append(InputExample(texts=[str(attack), str(cve)], label=label))
        return examples

    def prepare_input_examples_test(file_path, attack_info):
            # Read the Excel file
        df = pd.read_excel(file_path)

        # Determine the column names based on attack_info type
        if attack_info == 'CAPEC' or attack_info == 'CAPECImbalanced':
            attack_col = 'CAPECDescription'
            id_col = 'CAPECID'
            attack_name = 'CAPECID'
        elif attack_info == 'Tactic' or attack_info == 'TacticImbalanced':
            attack_col = 'TacticDescription'
            id_col = 'TacticId'
            attack_name = 'TacticDescription'
        elif attack_info == 'Procedure' or attack_info == 'ProcedureImbalanced':
            attack_col = 'ProcedureDescription'
            id_col = 'ProcedureID'
            attack_name = 'ProcedureID'
        else:
            attack_col = 'TechniqueDescription'
            id_col = 'TechniqueID'
            attack_name = 'TechniqueName'
        
        # Group by the attack ID and aggregate descriptions & CVEs into lists
        data_dict = df.groupby(id_col).agg({
            attack_col: list,
            attack_name: list,
            'CVEDescription': list,
            'Label': list
        }).to_dict(orient='index')

        return data_dict

    train_examples = prepare_input_examples(train_data)
    val_examples   = prepare_input_examples(val_data)
    test_examples  = prepare_input_examples_test(test_file, infoData)

    train_dataloader = DataLoader(train_examples, shuffle=True, batch_size=16)
    val_dataloader   = DataLoader(val_examples,   shuffle=False, batch_size=16)

    for model_name in SentenceTransformersModels:
        print(f"Processing model: {model_name} with infodata: {infoData}")

        model = SentenceTransformer(model_name)
        train_loss = losses.CosineSimilarityLoss(model=model)
        evaluator  = EmbeddingSimilarityEvaluator.from_input_examples(val_examples, name="val-evaluator")

        output_path = f'./models/fine_tuned_{model_name.replace("/", "_")}_{infoData}'
        os.makedirs(output_path, exist_ok=True)

        model.fit(
            train_objectives=[(train_dataloader, train_loss)],
            evaluator=evaluator,
            epochs=4,
            evaluation_steps=500,
            warmup_steps=100,
            # output_path=output_path
        )

        # fine_tuned_model = SentenceTransformer(output_path)
        # model = fine_tuned_model
        allLinksFile = "./dataset/VULDATDataSet.xlsx"
        dataCVE = readCVEData(allLinksFile)
        

        descriptions   = dataCVE['CVEDescription'].values.tolist()
        techniquesName = dataCVE['TechniqueName'].values.tolist()

        descriptions   = descriptions[:len(descriptions)]
        techniquesName = techniquesName[:len(techniquesName)]
        joined_list = [techniquesName[i] + " " + descriptions[i]
                       for i in range(min(len(descriptions), len(techniquesName)))]

        orgDescriptions = dataCVE
        CVEmbeddings = model.encode(joined_list)

        countT = 0
        Threeshold = 0.58
        AttackTPsum = 0
        AttackTNsum = 0
        AttackFPsum = 0
        AttackFNsum = 0

        techIDs = []
        for key, value in test_examples.items():
            print(f"ID: {key} ttttt {countT} ")
            countT = countT + 1

            if infoData == "CAPEC" or infoData == "CAPECImBalanced":
                attack_texts = removeURLandCitationBulk([f"{value['CAPECDescription']}"])
            elif infoData == "Tactic" or infoData == "TacticImBalanced":
                attack_texts = removeURLandCitationBulk([f"{value['TacticDescription']}"])
            elif infoData == "Procedure" or infoData == "ProcedureImBalanced":
                attack_texts = removeURLandCitationBulk([f"{value['ProcedureDescription']}"])
            else:
                attack_texts = removeURLandCitationBulk([f"{value['TechniqueName']} {value['TechniqueDescription']}"])

            vul_data_array = []

            AttackEmbedding = model.encode(attack_texts)
            similarities = cosine_similarity(AttackEmbedding.reshape(1, -1), CVEmbeddings)[0]
            top_10_indices = np.argsort(similarities)[-181000:][::-1]

            finalRes = []
            array = []

            for index in top_10_indices:
                if orgDescriptions.loc[index] is not None:
                    if not dataCVE.loc[index]['CVEID'] in array:
                        array.append(dataCVE.loc[index]['CVEID'])
                        vul_data = VulData()
                        vul_data.CVE_ID = orgDescriptions.loc[index]['CVEID']
                        vul_data.CVE_Des = orgDescriptions.loc[index]['CVEDescription']
                        vul_data.CVE_Smiliraty = f"{similarities[index]:.4f}" if 'similities' in locals() else f"{similarities[index]:.4f}"
                        finalRes.append(vul_data.CVE_ID + "#" + vul_data.CVE_Des + "#" + vul_data.CVE_Smiliraty)
                        vul_data_array.append(vul_data)

            if infoData == "CAPEC" or infoData == "CAPECImBalanced":
                trainAndTestSet = dataCVE[dataCVE['CAPECID'] == key]
            elif infoData == "Tactic" or infoData == "TacticImBalanced":
                trainAndTestSet = dataCVE[dataCVE['TacticId'] == key]
            elif infoData == "Procedures" or infoData == "ProceduresImBalanced":
                trainAndTestSet = dataCVE[dataCVE['ProcedureID'] == key]
            else:
                if "." in key:
                    key = key.split(".")[0]
                trainAndTestSet = dataCVE[dataCVE['TechniqueID'].str.startswith(key)]

            trainAndTestSetCVEs = trainAndTestSet['CVEID']
            trainAndTestSetCVEs2 = trainAndTestSetCVEs.tolist()
            trainAndTestSetCVEs = list(set(trainAndTestSetCVEs2))

            if infoData == "CAPEC" or infoData == "CAPECImBalanced":
                CvesNotAttack = dataCVE[dataCVE['CAPECID'] != key]
            elif infoData == "Tactic" or infoData == "TacticImBalanced":
                CvesNotAttack = dataCVE[dataCVE['TacticId'] != key]
            elif infoData == "Procedures" or infoData == "ProceduresImBalanced":
                CvesNotAttack = dataCVE[dataCVE['ProcedureID'] != key]
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

            print(f"TP:{str(len(arrayPositive))}    FP: {str(len(arrayNegative))}   {str(key)}")

            AttackTPsum, AttackTNsum, AttackFPsum, AttackFNsum, dataframeResultsForallModels = falseNegativeSUMAlltech2222(
                vul_data_array, trainAndTestSetCVEs, key, arrayPositive, arrayNegative, CvesNotAttack,
                Threeshold, AttackTPsum, AttackTNsum, AttackFPsum, AttackFNsum, dataframeResultsForallModels, model
            )

        if (AttackTPsum + AttackFPsum) != 0:
            preci = AttackTPsum / (AttackTPsum + AttackFPsum)
            Recal = AttackTPsum / (AttackTPsum + AttackFNsum)
            F1score = 2 * preci * Recal / (preci + Recal)
            dataframeResults = pd.concat(
                [dataframeResults, pd.DataFrame({'Data':[infoData],'Model':[model_name],
                                                 'precision':[preci],'Recall':[Recal],'F1':[F1score]})],
                ignore_index=True
            )
        else:
            dataframeResults = pd.concat(
                [dataframeResults, pd.DataFrame({'Data':[infoData],'Model':[model_name],
                                                 'precision':[AttackTPsum],'Recall':[AttackFPsum],'F1':[AttackFNsum]})],
                ignore_index=True
            )

        print(model_name)
        df.to_excel(f"Results/R2/Results{model_name}_Main_{infoData}.xlsx", index=False)
        dfRes.to_excel(f"Results/R2/Results{model_name}_Details{infoData}.xlsx", index=False)
        dataframeResultsForallModels.to_excel(f"Results/R2/AllModelsNFineTuned{infoData}.xlsx", index=False)
