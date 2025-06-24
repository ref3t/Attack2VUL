import pandas as pd

# Read the Excel file
file_path = "./Results/NewsResults/News/latest/finalMergeResults.xlsx" 
data = pd.read_excel(file_path)

# Process each row in the Excel file
results = []
for index, row in data.iterrows():
    attack_text = row['Attack']  # Column containing attack text
    cves = eval(row['CVEs'])  # Column containing CVEs (stored as a list in string format)
    CVEswithScore58 = eval(row['CVEs with Score58'])  # Column containing CVEs with Score58 (stored as a list in string format)row['CVEs with Score58']
    CVEsScorewithinFoundAllCVEs58 = eval(row['CVEsScorewithinFoundAllCVEs58'])  # Column containing CVEsScorewithinFoundAllCVEs58 (stored as a list in string format)
    CVEsScorewithinFoundFirstCVEs58 = eval(row['CVEsScorewithinFoundFirstCVEs58'])  # Column containing CVEsScorewithinFoundFirstCVEs58 (stored as a list in string format)
    CVEsScoreUsingEntity58 = eval(row['CVEsScoreUsingEntity58'])  # Column containing CVEsScoreUsingEntity58 (stored as a list in string format)
    CVEsUnion = eval(row['Union'])  # Column containing Union (stored as a list in string format)
    # Convert ManualValidation (comma-separated string) to a list
     # Handle NaN or missing values in ManualValidation
    if pd.isna(row['ManualValidation']):
        manual_validation = []  # Set to an empty list if the field is missing
        print(row['ManualValidation'])
        print(index )
    else:
        # Convert ManualValidation (comma-separated string) to a list
        print(index )
        manual_validation = [cve.strip() for cve in row['ManualValidation'].split(',')]  # Split and clean up spaces
    if index == 99:
        print(manual_validation)


    # Validate each CVE
    for cve in cves:
        validation = 1 if cve in manual_validation else 0
        validationCVEswithScore58 = 1 if cve in CVEswithScore58 else 0
        validationCVEsScorewithinFoundAllCVEs58 = 1 if cve in CVEsScorewithinFoundAllCVEs58 else 0
        validationCVEsScorewithinFoundFirstCVEs58 = 1 if cve in CVEsScorewithinFoundFirstCVEs58 else 0
        validationCVEsScoreUsingEntity58 = 1 if cve in CVEsScoreUsingEntity58 else 0
        CVEsUnion2 = 1 if cve in CVEsUnion else 0
        results.append({"Attack": attack_text, "CVE": cve, "ValidationManual": validation, "ValidationScore58": validationCVEswithScore58, "ValidationFoundAll": validationCVEsScorewithinFoundAllCVEs58, "ValidationFoundFirst": validationCVEsScorewithinFoundFirstCVEs58, "ValidationEntity": validationCVEsScoreUsingEntity58, "ValidationUnion": CVEsUnion2})

# Convert results to a DataFrame
results_df = pd.DataFrame(results)

# Save the results to a new Excel file
output_file_path = "./Results/NewsResults/News/latest/kappaResults.xlsx"
results_df.to_excel(output_file_path, index=False)

print(f"Validation results have been saved to: {output_file_path}")
