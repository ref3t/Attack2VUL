import os
import pandas as pd

# Set the base directory (Change this to your actual folder)
base_dir = r"C:\Users\RAmneh\OneDrive - Scientific Network South Tyrol\Desktop\P.hD Stuff\SRC"  # Windows: Use r"..." to avoid issues with backslashes

# Keyword to search
keyword = "multi-qa-distilbert-cos-v1"

# List to store matching file names
matching_files = set()

# Function to search in Excel files
def search_in_excel_files(base_dir, keyword):
    for root, _, files in os.walk(base_dir):  # Walk through all subdirectories
        for file in files:
            if file.endswith((".xlsx", ".xls")):
                file_path = os.path.join(root, file)
                try:
                    # Read all sheets
                    df_dict = pd.read_excel(file_path, sheet_name=None, engine="openpyxl" if file.endswith(".xlsx") else "xlrd")

                    for sheet_name, df in df_dict.items():
                        if df.astype(str).apply(lambda x: x.str.contains(keyword, na=False, case=False)).any().any():
                            matching_files.add(file_path)  # Store only file path
                            break  # Stop checking further sheets in this file
                except Exception as e:
                    print(f"Error reading {file_path}: {e}")

    # Print matching file names
    if matching_files:
        print("\nFiles containing the keyword:")
        for fname in matching_files:
            print(fname)
    else:
        print("No files found containing the keyword.")

# Run the search function
search_in_excel_files(base_dir, keyword)
