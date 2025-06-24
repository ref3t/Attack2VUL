import csv
import pandas as pd

Attackweaknesses = [
    "CWE-267", "CWE-552", "CWE-1258", "CWE-1272", "CWE-1330", "CWE-287", "CWE-300", "CWE-494",
    "CWE-311", "CWE-226", "CWE-312", "CWE-314", "CWE-315", "CWE-318", "CWE-1301", "CWE-285",
    "CWE-522", "CWE-308", "CWE-294", "CWE-521", "CWE-1299", "CWE-506", "CWE-923", "CWE-441",
    "CWE-330", "CWE-326", "CWE-307", "CWE-654", "CWE-916", "CWE-257", "CWE-200", "CWE-290",
    "CWE-302", "CWE-346", "CWE-384", "CWE-664", "CWE-602", "CWE-642", "CWE-565", "CWE-113",
    "CWE-20", "CWE-472", "CWE-798", "CWE-345", "CWE-288", "CWE-1188", "CWE-862", "CWE-94",
    "CWE-96", "CWE-95", "CWE-59", "CWE-282", "CWE-270", "CWE-117", "CWE-284", "CWE-74",
    "CWE-73", "CWE-162", "CWE-327", "CWE-1021", "CWE-430", "CWE-46", "CWE-172", "CWE-180",
    "CWE-181", "CWE-697", "CWE-692", "CWE-829", "CWE-732", "CWE-325", "CWE-328", "CWE-425",
    "CWE-276", "CWE-204", "CWE-205", "CWE-208", "CWE-497", "CWE-404", "CWE-770", "CWE-400",
    "CWE-412", "CWE-662", "CWE-667", "CWE-833", "CWE-451", "CWE-348", "CWE-349", "CWE-350",
]
DiverseVulWeaknesses = [    
    "CWE-264", "CWE-787", "CWE-20", "CWE-399", "CWE-200", "CWE-189", "CWE-119", "CWE-16",
    "CWE-94", "CWE-362", "CWE-269", "CWE-400", "CWE-193", "CWE-120", "CWE-287", "CWE-346",
    "CWE-476", "CWE-909", "CWE-59", "CWE-190", "CWE-310", "CWE-22", "CWE-415", "CWE-772",
    "CWE-134", "CWE-617", "CWE-79", "CWE-125", "CWE-703", "CWE-522", "CWE-284", "CWE-732",
    "CWE-89", "CWE-401", "CWE-416", "CWE-755", "CWE-369", "CWE-835", "CWE-665", "CWE-131",
    "CWE-254", "CWE-19", "CWE-77", "CWE-17", "CWE-209", "CWE-273", "CWE-241", "CWE-295",
    "CWE-18", "CWE-129", "CWE-611", "CWE-824", "CWE-502", "CWE-601", "CWE-203", "CWE-862",
    "CWE-255", "CWE-326", "CWE-347", "CWE-532", "CWE-388", "CWE-74", "CWE-770", "CWE-682",
    "CWE-93", "CWE-319", "CWE-358", "CWE-61", "CWE-404", "CWE-191", "CWE-674", "CWE-345",
    "CWE-754", "CWE-834", "CWE-943", "CWE-78", "CWE-863", "CWE-354", "CWE-681", "CWE-843",
    "CWE-290", "CWE-613", "CWE-417", "CWE-252", "CWE-88", "CWE-285", "CWE-704", "CWE-459",
    "CWE-670", "CWE-352", "CWE-668", "CWE-327", "CWE-121", "CWE-908", "CWE-444", "CWE-667",
    "CWE-320", "CWE-113", "CWE-276", "CWE-406", "CWE-662", "CWE-212", "CWE-706", "CWE-672",
    "CWE-434", "CWE-330", "CWE-281", "CWE-323", "CWE-349", "CWE-763", "CWE-565", "CWE-122",
    "CWE-294", "CWE-266", "CWE-697", "CWE-91", "CWE-297", "CWE-307", "CWE-331", "CWE-776",
    "CWE-116", "CWE-798", "CWE-1021", "CWE-924", "CWE-457", "CWE-552", "CWE-367", "CWE-786",
    "CWE-918", "CWE-823", "CWE-805", "CWE-126", "CWE-288", "CWE-303", "CWE-428", "CWE-426",
    "CWE-1187", "CWE-693", "CWE-707", "CWE-436", "CWE-913", "CWE-311"
]
attack_weaknesses_set = set(Attackweaknesses)
attack_weaknesses_set = {cwe.replace("CWE-", "") for cwe in attack_weaknesses_set}
diverse_vul_weaknesses_set = set(DiverseVulWeaknesses)
diverse_vul_weaknesses_set= {cwe.replace("CWE-", "") for cwe in diverse_vul_weaknesses_set}
print (len(Attackweaknesses))
print (len(DiverseVulWeaknesses))
intersection = attack_weaknesses_set.intersection(diverse_vul_weaknesses_set)

print(len(intersection))
print(intersection)
# Convert intersection set to a list for CSV writing (if needed)
intersection_list = list(intersection)

# print(intersection_list)
CWE_DiverseVul_exist_AttackFull = intersection_list
CWE_DiverseVul_Notexist_connectionAttack = diverse_vul_weaknesses_set - attack_weaknesses_set
CWE_attack_Notexist_DiverseVul = attack_weaknesses_set - diverse_vul_weaknesses_set



print(len(CWE_DiverseVul_exist_AttackFull))
print(len(CWE_DiverseVul_Notexist_connectionAttack))
print(len(CWE_attack_Notexist_DiverseVul))

print("################################################################################ Full Connection Attack + DiverseVul ###################################################################")
#this for full connection attack
df = pd.read_excel('./datasets/VULDATDataWithoutProcedures.xlsx')

df['CWE'] = df['CWE'].astype(str).str.strip().str.replace("CWE-", "").str.lower()

filtered_df = df[df['CWE'].isin(CWE_DiverseVul_exist_AttackFull)]

# Display the first few rows of the filtered dataframe to verify the result
CVEIDsDiverseVulAttack = filtered_df['CVE-ID'].unique()

print("CVEIDsDiverseVulAttack" , len(CVEIDsDiverseVulAttack))

# Display the first few rows of the filtered dataframe to verify the result
CAPECIDIDsDiverseVulAttack = filtered_df['CAPECID'].unique()

print("CAPECIDIDsDiverseVulAttack" , len(CAPECIDIDsDiverseVulAttack))

# Display the first few rows of the filtered dataframe to verify the result
TechnqiueIDIDsDiverseVulAttack = filtered_df['TechnqiueID'].unique()

print("TechnqiueIDsDiverseVulAttack" , len(TechnqiueIDIDsDiverseVulAttack))

# Display the first few rows of the filtered dataframe to verify the result
TacticIDsDiverseVulAttack = filtered_df['TacticID'].unique()

print("TacticIDsDiverseVulAttack" , len(TacticIDsDiverseVulAttack))

print("################################################################################ Full Connection Attack WithOut DiverseVul ###################################################################")

#this for full connection attack
df = pd.read_excel('./datasets/VULDATDataWithoutProcedures.xlsx')

df['CWE'] = df['CWE'].astype(str).str.strip().str.replace("CWE-", "").str.lower()

filtered_df_Notexist_DiverseVul = df[df['CWE'].isin(CWE_attack_Notexist_DiverseVul)]

# Display the first few rows of the filtered dataframe to verify the result
CVEIDsDiverseVulAttack_Notexist_DiverseVul = filtered_df_Notexist_DiverseVul['CVE-ID'].unique()

print("CVEIDsDiverseVulAttack" , len(CVEIDsDiverseVulAttack_Notexist_DiverseVul))

# Display the first few rows of the filtered dataframe to verify the result
CAPECIDIDsDiverseVulAttack_Notexist_DiverseVul = filtered_df_Notexist_DiverseVul['CAPECID'].unique()

print("CAPECIDIDsDiverseVulAttack" , len(CAPECIDIDsDiverseVulAttack_Notexist_DiverseVul))

# Display the first few rows of the filtered dataframe to verify the result
TechnqiueIDIDsDiverseVulAttack_Notexist_DiverseVul = filtered_df_Notexist_DiverseVul['TechnqiueID'].unique()

print("TechnqiueIDsDiverseVulAttack" , len(TechnqiueIDIDsDiverseVulAttack_Notexist_DiverseVul))

# Display the first few rows of the filtered dataframe to verify the result
TacticIDsDiverseVulAttack_Notexist_DiverseVul = filtered_df_Notexist_DiverseVul['TacticID'].unique()

print("TacticIDsDiverseVulAttack" , len(TacticIDsDiverseVulAttack_Notexist_DiverseVul))




print("$$$$$$ intersection 34 54 $$$$$")


print(len (set(CVEIDsDiverseVulAttack).intersection(set(CVEIDsDiverseVulAttack_Notexist_DiverseVul))))

print(len (set(CAPECIDIDsDiverseVulAttack).intersection(set(CAPECIDIDsDiverseVulAttack_Notexist_DiverseVul))))


print("&&&&&& capec - tech")
capec21 =set(CAPECIDIDsDiverseVulAttack).intersection(set(CAPECIDIDsDiverseVulAttack_Notexist_DiverseVul))
capec37 = set(CAPECIDIDsDiverseVulAttack)-capec21
capec28 = set(CAPECIDIDsDiverseVulAttack_Notexist_DiverseVul)-capec21
print(len(capec21))
print(len(capec37))
print(len(capec28))


filtered_df_DiverseVul = df[df['CAPECID'].isin(capec21)]

# Display the first few rows of the filtered dataframe to verify the result
TechnqiueIDDiverseVulAttack21 = filtered_df_DiverseVul['TechnqiueID'].unique()

print("TechnqiueIDDiverseVulAttack" , len(TechnqiueIDDiverseVulAttack21))

filtered_df_DiverseVul = df[df['CAPECID'].isin(capec37)]

# Display the first few rows of the filtered dataframe to verify the result
TechnqiueIDDiverseVulAttack37 = filtered_df_DiverseVul['TechnqiueID'].unique()

print("TechnqiueIDDiverseVulAttack" , len(TechnqiueIDDiverseVulAttack37))

print(len(set(TechnqiueIDDiverseVulAttack37).intersection(set(TechnqiueIDDiverseVulAttack21))))

tech4 = set(TechnqiueIDDiverseVulAttack37).intersection(set(TechnqiueIDDiverseVulAttack21))
tech24 = set(TechnqiueIDDiverseVulAttack21)-tech4
tech39 = set(TechnqiueIDDiverseVulAttack37)-tech4
# print(len(tech4))
# print(len(tech24))
# print(len(tech39))

iltered_df_DiverseVul = df[df['CAPECID'].isin(capec28)]

# Display the first few rows of the filtered dataframe to verify the result
TechnqiueIDDiverseVulAttack28 = iltered_df_DiverseVul['TechnqiueID'].unique()

print("TechnqiueIDDiverseVulAttack28" , len(TechnqiueIDDiverseVulAttack28))

tech28 = set(tech4).intersection(set(TechnqiueIDDiverseVulAttack28))
print(len(tech28))

tech28 = set(tech24).intersection(set(TechnqiueIDDiverseVulAttack28))
print(len(tech28))

tech28 = set(tech39).intersection(set(TechnqiueIDDiverseVulAttack28))
print(len(tech28))

# capec21 =set(CAPECIDIDsDiverseVulAttack).intersection(set(CAPECIDIDsDiverseVulAttack_Notexist_DiverseVul))
# print(len (set(TechnqiueIDIDsDiverseVulAttack).intersection(set(TechnqiueIDIDsDiverseVulAttack_Notexist_DiverseVul))))