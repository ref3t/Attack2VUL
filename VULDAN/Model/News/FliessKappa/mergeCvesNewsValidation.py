import pandas as pd

# Load the Excel file
file_path = "./Results/NewsResults/News/latest/FinalResults.xlsx"  
df = pd.read_excel(file_path)

# Function to filter CVEs with scores greater than the given threshold
def extract_high_score_cves(cell, threshold=0.6):
    if pd.isna(cell):  # Handle empty cells
        return []
    high_score_cves = []
    # Clean up the string format to extract CVE and score
    cell = cell.replace("'", "").replace("[", "").replace("]", "")
    cve_entries = cell.split(", ")
    for entry in cve_entries:
        if "#" in entry:
            try:
                cve, score = entry.split("#")
                if float(score) >= threshold:
                    high_score_cves.append(cve)
            except ValueError:
                # Skip entries that don't match the expected format
                continue
    return high_score_cves

# Apply the function to the specified column
df["CVEs with Score58"] = df["CVEs with Score"].apply(lambda x: extract_high_score_cves(x, threshold=0.59))

df["CVEsScorewithinFoundAllCVEs58"] = df["CVEsScorewithFoundbetweenCVESwithAllFoundCVEs"].apply(lambda x: extract_high_score_cves(x, threshold=0.5))
df["CVEsScorewithinFoundFirstCVEs58"] = df["CVEsScorewithFoundFistCVE"].apply(lambda x: extract_high_score_cves(x, threshold=0.5))

df["CVEsScoreUsingEntity58"] = df["CVEsScorewithFoundEntity"].apply(lambda x: extract_high_score_cves(x, threshold=0.45))
# df["CVEsScoreUsingEntity582"] = df["CVEsScoreUsingEntity2"].apply(lambda x: extract_high_score_cves(x, threshold=0.45))

# df["CVEsScoreUsingEntity58F"] = df["CVEsScoreUsingEntity58"].astype(str) + " | " + df["CVEsScoreUsingEntity582"].astype(str)

# Calculate the union for each row
def calculate_union(row):
    # Convert each column's list to a set and calculate the union
    sets = [
        set(row["CVEs with Score58"]),
        set(row["CVEsScorewithinFoundAllCVEs58"]),
        set(row["CVEsScorewithinFoundFirstCVEs58"]),
        set(row["CVEsScoreUsingEntity58"]),
    ]
    # Return the union as a list
    return list(set.union(*sets))

# Create a new column for the union
df["Union"] = df.apply(calculate_union, axis=1)


# Function to remove CVEs in the union from the "CVEs" column
def remove_cves_from_union(cves_cell, union_set):
    if pd.isna(cves_cell):  # Handle empty cells
        return []
    # Parse the CVEs column into a list
    cves_list = cves_cell.replace("'", "").replace("[", "").replace("]", "").split(", ")
    # Remove CVEs that are in the union
    return [cve for cve in cves_list if cve not in union_set]
# Function to count the number of filtered CVEs
def count_filtered_cves(filtered_cves_list):
    length = len(filtered_cves_list)
    return length
# Apply the function to the "CVEs" column
df["Filtered CVEs"] = df.apply(lambda row: remove_cves_from_union(row["CVEs"], row["Union"]), axis=1)
df["Filtered CVEs count"] = df.apply(lambda row: count_filtered_cves(row["Filtered CVEs"]), axis=1)


# Save the filtered results to a new Excel file
output_file = "./Results/NewsResults/News/latest/finalMergeResultsNew.xlsx"
df.to_excel(output_file, index=False)

