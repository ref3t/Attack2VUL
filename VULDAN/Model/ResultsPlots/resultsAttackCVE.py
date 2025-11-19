import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Load the Excel file
file_path = './Results/LagsRef.xlsx'  # Replace with the path to your Excel file
data = pd.read_excel(file_path)

# Convert the 'CVECreated' column to datetime format for accurate plotting
data['CVECreated'] = pd.to_datetime(data['CVECreated'])

# Timeline Chart
plt.figure(figsize=(10, 6))
for technique, group in data.groupby('technqiueID'):
    plt.plot(group['CVECreated'], [technique] * len(group), 'o-', label=technique)

plt.xlabel('CVE Creation Date')
plt.ylabel('Technique ID')
plt.title('Timeline of CVE Creation Dates by Technique')
plt.legend(title="Technique ID")
plt.xticks(rotation=45)
plt.grid(True)
plt.tight_layout()
plt.show()

# Scatter Plot
plt.figure(figsize=(10, 6))
plt.scatter(data['CVECreated'], data['technqiueID'], color='purple')
plt.xlabel('CVE Creation Date')
plt.ylabel('Technique ID')
plt.title('Scatter Plot of CVE Creation Dates by Technique')
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()

# Step 2: Convert date columns to datetime format
data['dateCreated'] = pd.to_datetime(data['dateCreated'], format='%d.%b.%y', errors='coerce')
data['CVECreated'] = pd.to_datetime(data['CVECreated'], errors='coerce')

# Step 3: Group by techniqueID and dateCreated to count CVEs
grouped_df = data.groupby(['technqiueID', 'dateCreated']).size().reset_index(name='cve_count')

# Step 4: Plotting
plt.figure(figsize=(12, 6))
sns.barplot(data=grouped_df, x='dateCreated', y='cve_count', hue='technqiueID', dodge=True)

plt.xlabel('Date Created')
plt.ylabel('Number of CVEs')
plt.title('Number of CVEs per Technique Over Time')
plt.xticks(rotation=45)
plt.legend(title='Technique ID')
plt.grid(axis='y')
plt.tight_layout()
plt.show()