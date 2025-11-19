
import pandas as pd
import jsonlines
import os

"""
Read readDiveresVul the JSON file located at the specified path and convert its contents to a DataFrame.
"""
def readDiveresVulJsone():
    # Specify the path to your JSON file
    file_path = "./datasets/diversevul_20230702.json"

    # Open the JSON file using jsonlines
    with jsonlines.open(file_path) as reader:
        # Read JSON objects one by one and create a list of dictionaries
        data = [obj for obj in reader]

    # Convert the list of dictionaries to a DataFrame
    df = pd.DataFrame(data)
    print(df.iloc[0])
    return df

"""
Reads VuldatData from Excel files, selects specific columns from the dataframes, merges the dataframes, and then exports the merged dataframe to an Excel file.
"""
def readVuldatData():
    df = pd.read_excel('./datasets/BigFile/dfvuldatWithoutCVE.xlsx')
    return df

"""
Reads readDiveresVul from Excel files
"""
def readDiveresVulExcel():
    df = pd.read_excel('./datasets/BigFile/dfdiversevul2.xlsx')
    # df['cwe'] = df['cwe'].str.strip("[]'")
    return df

# Split DataFrame into chunks
def split_dataframe(df, chunk_size):
    chunks = []
    num_chunks = len(df) // chunk_size + 1
    for i in range(num_chunks):
        start = i * chunk_size
        end = min((i + 1) * chunk_size, len(df))
        chunks.append(df.iloc[start:end])
    return chunks



def save_in_chunks(merged_df, chunk_size_bytes=300 * 1024 * 1024, file_name='datasets/BigFile/VwDetDatasetFunctionsWithOutCVE.xlsx'):
    # Define max rows per sheet
    max_rows = 1048576  

    # Create an Excel writer object
    with pd.ExcelWriter(file_name, engine="xlsxwriter") as writer:
        for i, start in enumerate(range(0, len(merged_df), max_rows)):
            merged_df.iloc[start:start+max_rows].to_excel(writer, sheet_name=f"Sheet_{i+1}", index=False)

import ast 
"""
Main function
"""
def main():
    
    dfdiversevul = readDiveresVulExcel()
    print(dfdiversevul.iloc[120])
    dfvuldat = readVuldatData()
   
   # Check if the 'CWE' columns match in both dataframes
    print(dfdiversevul['cwe'].head())
    print(dfvuldat['CWE'].head())

    dfdiversevul['cwe'] = dfdiversevul['cwe'].astype(str)
    dfvuldat['CWE'] = dfvuldat['CWE'].astype(str)
    # Step 3: Merge on CWE
    merged_df = dfdiversevul.merge(dfvuldat, left_on='cwe', right_on='CWE', how='inner')

    print(merged_df.head())  # Check the merged dataframe
    print(merged_df.shape)  # Check the shape to see how many rows were merged
    # merged_df.to_excel("datasets/BigFile/VwDetDatasetFunctions.xlsx", index=False, engine='openpyxl')
    # Merge DataFrames on CWE ID
    # merged_df = dfdiversevul.merge(dfvuldat, left_on="cwe", right_on="CWE", how="inner")
        # dfvuldat['Related Weaknesses'] = dfvuldat['Related Weaknesses'].apply(lambda x: 'CWE-' + str(x))

    # Save the merged DataFrame as a CSV file
    save_in_chunks(merged_df)
    # merged_df.to_excel("VwDetDatasetFunctions.xlsx", index=False, engine='openpyxl')

if __name__ == "__main__":
    main()