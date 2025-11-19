import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

# Create a DataFrame with the new data
data = {
    'Tactic': [50, 50, 16.7, 40, 50, 28.6, 30.8, 16.7, 50, 57.1, 66.7, 40, 88, 30.8],
    'Technique': [89, 60.2, 26, 26.1, 66.9, 54.5, 43.8, 80.1, 47.2, 36.6, 79.9, 74.8, 79.9, 36.8],
    'Procedure': [44.4, 35, 3.5, 5, 2.2, 14.4, 6.5, 8.5, 10, 2.2, 66.7, 10.5, 5, 5],
    'Attack Pattern': [72.4, 69.1, 17.3, 6.4, 40.3, 47.1, 29.3, 53.2, 61.6, 48.9, 65.4, 52.9, 66.7, 49.7]
}

df = pd.DataFrame(data)

# Calculate the mean for each metric (column)
mean_values = df.mean()

# Print the mean values for each metric
print("Mean F1 Scores for each Metric:")
for metric, mean_value in mean_values.items():
    print(f"{metric}: {mean_value:.1f}")

# Reshape the data for seaborn
df_melted = df.melt(var_name='Metric', value_name='F1 Score')

# Define the custom black-to-white palette
black_palette = ['#4f4f50', '#777878', '#a2a3a3', '#d0d0d0', '#ffffff']

# Create a boxplot with your custom palette
plt.figure(figsize=(10, 6))
ax = sns.boxplot(x='Metric', y='F1 Score', data=df_melted, palette=black_palette, fliersize=6)

# Convert 1 cm to data units
offset = (df_melted['F1 Score'].max() - df_melted['F1 Score'].min()) * 0.05  # ~2% of range

# Add the mean to the boxplot at the center of each box
for i, metric in enumerate(mean_values.index):
    mean_value = mean_values[metric]
    
    # Move the mean label 1 cm (approx) upwards by adding an offset
    ax.text(i, mean_value + offset, f'Mean: {mean_value:.1f}', color='black', ha='center', va='center', fontsize=10)

# Adjust y-axis limits to accommodate the mean text placement
plt.ylim(bottom=0, top=df_melted['F1 Score'].max() + 5)

# Customize plot elements
plt.xlabel('Attack Information', fontsize=14, color='black')
plt.ylabel('F1 Score', fontsize=14, color='black')
plt.title('F1 Score Distribution for Different Metrics', fontsize=16, color='black')

# Change the tick colors to black
plt.xticks(color='black')
plt.yticks(color='black')

# Show the plot
plt.tight_layout()
plt.show()
