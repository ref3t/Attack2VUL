import pandas as pd
import numpy as np
from statsmodels.stats.inter_rater import fleiss_kappa

# Load the Excel file
file_path = "./Results/NewsResults/News/latest/kappaResults.xlsx"  # Replace with the actual file path
data = pd.read_excel(file_path)

# Specify the validation columns (raters)
validation_columns = ['ValidationManual','ValidationFoundAll','ValidationFoundFirst']
# validation_columns = ['ValidationFoundAll','ValidationScore58','ValidationFoundFirst']

# Prepare the rating matrix
categories = [0, 1]  # Possible ratings
rating_matrix = []

for _, row in data.iterrows():
    # Extract ratings from validation columns
    ratings = row[validation_columns].values
    counts = [list(ratings).count(cat) for cat in categories]  # Count how many 0s and 1s
    rating_matrix.append(counts)

# Convert to a numpy array
rating_matrix = np.array(rating_matrix)

# Add the rating matrix counts as a new column
data['RatingMatrix'] = [str(rm) for rm in rating_matrix]  # Convert lists to strings for storage

# Calculate Fleiss' Kappa
kappa = fleiss_kappa(rating_matrix, method='fleiss')
print(f"Fleiss' Kappa: {kappa}")

# Add Fleiss' Kappa as a new column (same value for all rows)
data['FleissKappa'] = kappa

# Save the updated dataframe to a new Excel file
output_file_path = "./Results/NewsResults/News/latest/validated_results_with_kappa22.xlsx"
data.to_excel(output_file_path, index=False)
print(f"Results saved to {output_file_path}")