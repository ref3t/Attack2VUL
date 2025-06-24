import pandas as pd
from sklearn.metrics import cohen_kappa_score

# Load the Excel file
file_path = "./Results/NewsResults/News/latest/kappaResults.xlsx"  # Replace with the actual file path
data = pd.read_excel(file_path)

# Specify the validation columns (raters)
validation_columns = ['ValidationManual','ValidationScore58', 'ValidationFoundAll','ValidationFoundFirst','ValidationUnion','ValidationManual2']
# validation_columns = ['ValidationFoundAll','ValidationFoundFirst']

# Initialize an empty list to store Cohen's Kappa results
kappa_results = []

# Calculate Cohen's Kappa between `ValidationManual` and each other column
for column in validation_columns[1:]:  # Skip the manual column as it's the reference
    kappa = cohen_kappa_score(data['ValidationManual'], data[column])
    kappa_results.append({'Method': column, 'CohenKappa': kappa})
    print(f"Cohen's Kappa between ValidationManual and {column}: {kappa:.4f}")

# Convert results to a DataFrame
kappa_df = pd.DataFrame(kappa_results)

# Save Cohen's Kappa results to a new Excel file
output_file_path = "cohen_kappa_results.xlsx"
kappa_df.to_excel(output_file_path, index=False)
print(f"Cohen's Kappa results saved to {output_file_path}")
