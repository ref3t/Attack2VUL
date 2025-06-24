# import os
# import json
# import pandas as pd

# # Initialize an empty DataFrame
# df = pd.DataFrame(columns=['CVE_ID', 'Description'])

# # Define the root directory containing year folders
# root_dir = 'datasets/CVEList/cves/'

# # Walk through the directory structure
# for year_folder in os.listdir(root_dir):
#     year_path = os.path.join(root_dir, year_folder)
#     if os.path.isdir(year_path):
#         for sub_folder in os.listdir(year_path):
#             sub_folder_path = os.path.join(year_path, sub_folder)
#             if os.path.isdir(sub_folder_path):
#                 for file in os.listdir(sub_folder_path):
#                     if file.endswith('.json'):
#                         file_path = os.path.join(sub_folder_path, file)
#                         with open(file_path, 'r') as f:
#                             data = json.load(f)
#                             cve_id = data.get('cveMetadata', {}).get('cveId', 'N/A')
#                             description = data.get('containers', {}).get('cna', {}).get('descriptions', [{}])[0].get('value', 'N/A')
#                             df = df._append({'CVE_ID': cve_id, 'Description': description}, ignore_index=True)
#                             print(df)

# # Save the DataFrame to an Excel file
# df.to_excel('cve_data.xlsx', index=False)

# print("Data has been successfully saved to cve_data.xlsx")



import os
import json
import pandas as pd

# Initialize an empty DataFrame
df = pd.DataFrame(columns=['CVE_ID', 'Description'])

# Define the root directory containing year folders
root_dir = 'datasets/CVEList/Test'

# Counter to keep track of the number of rows added to the DataFrame
row_count = 0

# Define the maximum number of rows before saving to Excel
max_rows = 100000
count = 3
# Walk through the directory structure
for year_folder in os.listdir(root_dir):
    year_path = os.path.join(root_dir, year_folder)
    if os.path.isdir(year_path):
        for sub_folder in os.listdir(year_path):
            sub_folder_path = os.path.join(year_path, sub_folder)
            if os.path.isdir(sub_folder_path):
                for file in os.listdir(sub_folder_path):
                    if file.endswith('.json'):
                        file_path = os.path.join(sub_folder_path, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8') as f:
                                data = json.load(f)
                                cve_id = data.get('cveMetadata', {}).get('cveId', 'N/A')
                                description = data.get('containers', {}).get('cna', {}).get('descriptions', [{}])[0].get('value', 'N/A')
                                
                                # Handle the legacy record style
                                if cve_id == 'N/A':
                                    cve_id = data.get('containers', {}).get('cna', {}).get('x_legacyV4Record', {}).get('CVE_data_meta', {}).get('ID', 'N/A')
                                    description = data.get('containers', {}).get('cna', {}).get('x_legacyV4Record', {}).get('description', {}).get('description_data', [{}])[0].get('value', 'N/A')
                                
                                df = df._append({'CVE_ID': cve_id, 'Description': description}, ignore_index=True)
                                row_count += 1
                                print(df)
                                # Save to Excel if max_rows is reached
                                if row_count >= max_rows:
                                    count = count + 1 
                                    df.to_excel(f'cve_data_{count}.xlsx', index=False)
                                    df = pd.DataFrame(columns=['CVE_ID', 'Description'])
                                    row_count = 0
                        except UnicodeDecodeError:
                            print(f"Skipping file due to UnicodeDecodeError: {file_path}")
                        except json.JSONDecodeError:
                            print(f"Skipping file due to JSONDecodeError: {file_path}")

# Save any remaining data to Excel
count = count + 1 
if not df.empty:
    df.to_excel(f'cve_data_{count}2024.xlsx', index=False)

print("Data has been successfully saved to Excel files.")
