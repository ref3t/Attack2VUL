import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Load the data from CSV (with many columns)
file_path = './Results/multi-qa-mpnet-base-dot-v1TopK1To30.xlsx'  # Replace with the path to your file
data = pd.read_excel(file_path, sheet_name=0)

# Display the first few rows to understand the structure of the file (optional)
print(data.head())

# Assuming 'TopK', 'Precision@K', and 'Recall@K' are among the columns
# If your file has different column names, adjust them accordingly
columns_of_interest = ['TopK', 'Precision@K', 'Recall@K', 'F1@K']  # Specify the columns you're interested in

# Check if the required columns exist in the file
if not all(col in data.columns for col in columns_of_interest):
    raise ValueError("One or more required columns are missing from the file.")

# Get the unique values of TopK
topk_values = data['TopK'].unique()
# Create a boxplot
black_palette = ['#4f4f50', '#777878', '#a2a3a3', '#d0d0d0', '#ffffff']
# Set up the figure and axes for subplots (Precision, Recall, and F1)
fig, axes = plt.subplots(1, 3, figsize=(15, 5))  # Adjusted figure size

# Create boxplot for Precision@K for all TopK in the first subplot
sns.boxplot(x='TopK', y='Precision@K', data=data, ax=axes[0], width=0.8, palette=black_palette)  # Adjust width
axes[0].set_title('Precision@K')
axes[0].set_xlabel('TopK')
axes[0].set_ylabel('Precision@K')

# Create boxplot for Recall@K for all TopK in the second subplot
sns.boxplot(x='TopK', y='Recall@K', data=data, ax=axes[1], width=0.8, palette=black_palette)  # Adjust width
axes[1].set_title('Recall@K')
axes[1].set_xlabel('TopK')
axes[1].set_ylabel('Recall@K')

# Create boxplot for F1@K for all TopK in the third subplot
sns.boxplot(x='TopK', y='F1@K', data=data, ax=axes[2], width=0.8, palette=black_palette)  # Adjust width
axes[2].set_title('F1@K')
axes[2].set_xlabel('TopK')
axes[2].set_ylabel('F1@K')

# Adjust the ticks to avoid spaces between boxplots
for ax in axes:
    ax.set_xticks(range(len(data['TopK'].unique())))  # Ensure all ticks are placed correctly
    ax.set_xticklabels(data['TopK'].unique(), rotation=45)  # Set tick labels

# Reduce the space between subplots
# plt.subplots_adjust(wspace=0.1)  # Adjust horizontal space between subplots

# plt.show()
# Display the plots
plt.tight_layout()  # Adjust layout for better spacing
plt.show()

# Display the first few rows to understand the structure of the file (optional)
print(data.head())

# Specify the columns of interest
columns_of_interest = ['TopK', 'Precision@K', 'Recall@K', 'F1@K']

# Set up the figure and axes for subplots (Precision, Recall, and F1)
fig, axes = plt.subplots(1, 3, figsize=(15, 5))  # Increased figure width
black_palette = ['#4f4f50', '#777878', '#a2a3a3', '#d0d0d0', '#ffffff']

# Boxplot for Precision@K with mean lines inside the boxplot
sns.boxplot(x='TopK', y='Precision@K', data=data, ax=axes[0], width=0.8, palette=black_palette)
means_precision = data.groupby('TopK')['Precision@K'].mean().values
for i, mean in enumerate(means_precision):
    axes[0].hlines(mean, i - 0.15, i + 0.15, colors='blue', linestyles='-', linewidth=2)  # Mean as a line
axes[0].set_title('Precision@K')
axes[0].set_xlabel('TopK')
axes[0].set_ylabel('Precision@K')

# Boxplot for Recall@K with mean lines inside the boxplot
sns.boxplot(x='TopK', y='Recall@K', data=data, ax=axes[1], width=0.8, palette=black_palette)
means_recall = data.groupby('TopK')['Recall@K'].mean().values
for i, mean in enumerate(means_recall):
    axes[1].hlines(mean, i - 0.15, i + 0.15, colors='blue', linestyles='-', linewidth=2)  # Mean as a line
axes[1].set_title('Recall@K')
axes[1].set_xlabel('TopK')
axes[1].set_ylabel('Recall@K')

# Boxplot for F1@K with mean lines inside the boxplot
sns.boxplot(x='TopK', y='F1@K', data=data, ax=axes[2], width=0.8, palette=black_palette)
means_f1 = data.groupby('TopK')['F1@K'].mean().values
for i, mean in enumerate(means_f1):
    axes[2].hlines(mean, i - 0.15, i + 0.15, colors='blue', linestyles='-', linewidth=2)  # Mean as a line
axes[2].set_title('F1@K')
axes[2].set_xlabel('TopK')
axes[2].set_ylabel('F1@K')

# # Adjust ticks and display the plot
# for ax in axes:
#     ax.set_xticks(range(len(data['TopK'].unique())))
#     ax.set_xticklabels(data['TopK'].unique(), rotation=45)

plt.tight_layout()
plt.show()