import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

# Load the data from a CSV file
# Assuming the CSV file has two columns: "Lag" and "AttackCount"
# Adjust the file path accordingly
file_path = './Results/LagsAttack.xlsx'  # Replace with your actual file path
data = pd.read_excel(file_path)

# Extract lag days and attack counts from the DataFrame
lag_days = data['Lag2'].values
attack_count = data['AttackCount2'].values

# Create figure and axis
fig, ax = plt.subplots(figsize=(12, 6))

# Convert data to numpy arrays for efficient processing
lag_days = np.array(lag_days)
attack_count = np.array(attack_count)

# Mask for positive and negative values
positive_mask = lag_days >= 0
negative_mask = lag_days < 0

# Plot positive and negative bars separately
ax.bar(lag_days[positive_mask], attack_count[positive_mask], color='green', label='Positive Lag (Past)')
ax.bar(lag_days[negative_mask], attack_count[negative_mask], color='red', label='Negative Lag (Future)')

# Add labels and title
ax.set_xlabel('Lag (Days)')
ax.set_ylabel('Attack Count')
ax.set_title('Attack Count by Lag Days')
ax.legend()

# Display the graph
plt.tight_layout()
plt.show()
