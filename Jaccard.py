import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns


data = {
    "Mapping Accuracy":[
    0.4, 0.40625, 0.631578947, 0.3, 0.285714286, 0.526315789, 0.473684211, 
    0.357142857, 0.73015873, 0.736842105, 1, 0.368421053, 0.631578947, 
    0.368421053, 0.789473684, 0, 0.428571429, 0.228571429, 0.388235294, 
    0.631578947, 0.6, 0.274509804, 0.769230769, 0.411764706, 0.941176471, 
    0, 0.684210526, 0.823529412, 0.578947368, 0.411764706, 0.333333333, 
    0.3, 0.810810811, 0.117647059, 0.4, 0.578947368, 0, 0.78, 0.923076923, 
    0.4, 0.5, 0.992, 0.947368421, 0.4, 0.730769231, 0.578947368, 0.769230769, 
    0, 0.526315789, 0.5
],
    "Detection Accuracy":    [
    0.054054054, 0.52, 0.444444444, 0.666666667, 0.25, 0.588235294, 0.36, 
    0.217391304, 0.958333333, 0.466666667, 0.03125, 0.24137931, 0.428571429, 
    0.466666667, 0.75, 0, 0.052631579, 0.8, 0.868421053, 0.545454545, 0.333333333, 
    0.875, 0.967741935, 0.7, 0.727272727, None, 0.928571429, 0.933333333, 0.785714286, 
    0.7, 0.75, 0.315789474, 0.291262136, 0.8, 0.666666667, 0.55, 0, 0.847826087, 
    0.75, 1, 0.928571429, 0.826666667, 0.72, 0.142857143, 0.904761905, 0.458333333, 
    1, 0, 0.909090909, 0.769230769
],
    "Jaccard Similarity":      [ 0.05, 0.295454545, 0.352941176, 0.260869565, 0.153846154, 0.384615385, 
    0.257142857, 0.15625, 0.707692308, 0.4, 0.03125, 0.170731707, 0.342857143, 
    0.259259259, 0.625, 0, 0.049180328, 0.216216216, 0.366666667, 0.413793103, 
    0.272727273, 0.264150943, 0.75, 0.35, 0.695652174, 0, 0.65, 0.777777778, 
    0.5, 0.35, 0.3, 0.181818182, 0.272727273, 0.114285714, 0.333333333, 
    0.392857143, 0, 0.684210526, 0.705882353, 0.4, 0.481481481, 0.821192053, 
    0.692307692, 0.117647059, 0.678571429, 0.34375, 0.769230769, 0, 0.5, 
    0.434782609
]
}

import pandas as pd
plt.rc('font', family='Times New Roman')

# Step 1: Load the Excel file
# Make sure your file has columns: "Mapping Accuracy", "Detection Accuracy", "Jaccard Similarity"
df = pd.read_excel('./Results/JaccardforMPNET.xlsx')  # Update the path if needed

# Step 2: Convert DataFrame to dictionary (keys = column names, values = lists)
data = df.to_dict(orient='list')

# Step 3: (Optional) Print the dictionary to verify
for key, values in data.items():
    print(f"{key}:")
    print(values[:5], "...")  # Print only first 5 for brevity
    print()

# Create a DataFrame
df = pd.DataFrame(data)
black_palette = ['#4f4f50', '#777878', '#a2a3a3', '#d0d0d0', '#ffffff']

# Melt the DataFrame
df_melted = df.melt(var_name='Method', value_name='Accuracy')

# Create a boxplot
plt.figure(figsize=(8, 6))
sns.boxplot(x='Method', y='Accuracy', data=df_melted, palette=black_palette)

# Calculate and display the minimum, maximum, average, and mean values
for i, method in enumerate(df_melted['Method'].unique()):
    subset = df_melted[df_melted['Method'] == method]
    min_val = subset['Accuracy'].min()
    max_val = subset['Accuracy'].max()
    avg_val = subset['Accuracy'].mean()
    mean_val = subset['Accuracy'].mean()  # Mean and average are the same in this context
    if method == 'Jaccard Similarity' or method == 'Detection Accuracy':
        min_val = 0.05
    # Display the values on the boxplot
    plt.text(i, min_val, f'Min: {min_val:.2f}', ha='center', va='bottom', color='black',fontsize=13)
    plt.text(i, max_val, f'Max: {max_val:.2f}', ha='center', va='top', color='black',fontsize=13)
    # plt.text(i, avg_val, f'Avg: {avg_val:.2f}', ha='center', va='center', color='green')
    plt.text(i, mean_val, f'Mean: {mean_val:.2f}', ha='center', va='center', color='black',fontsize=13)
    print(min_val," ", avg_val," ", mean_val," ", max_val)

plt.xlabel('Method', fontsize=14)
plt.ylabel('', fontsize=13)
plt.xticks(fontsize=14)
plt.show()

