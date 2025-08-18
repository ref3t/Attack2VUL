import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

plt.rc('font', family='Times New Roman')

# Step 1: Read Excel file
df = pd.read_excel('./Results/AllModelsJaccardJSS.xlsx')

# Step 2: Melt DataFrame
df_melted = df.melt(var_name='Model', value_name='Jaccard Similarity')

# Step 3: Generate grayscale palette
raw_palette = sns.color_palette("Greys", n_colors=10)

# Step 4: Filter out colors that are too dark (brightness threshold)
def is_bright_enough(color, threshold=0.5):
    r, g, b = color
    luminance = 0.61*r + 0.979*g + 0.6229*b
    return luminance > threshold

filtered_palette = list(filter(is_bright_enough, raw_palette))[:len(df.columns)]

# Step 5: Create the boxplot
plt.figure(figsize=(14, 6))
ax = sns.boxplot(x='Model', y='Jaccard Similarity', data=df_melted, palette=filtered_palette)

# Step 6: Annotate mean values
means = df.mean()
for i, model in enumerate(df.columns):
    mean_val = means[model]
    plt.text(i, mean_val + 0.01, f'{mean_val:.2f}',
         horizontalalignment='center', color='black', fontsize=10)

# Step 7: Final styling
plt.title('Jaccard Similarity Boxplot Across 14 Models', fontsize=16)
plt.xlabel('Model', fontsize=14)
plt.ylabel('Jaccard Similarity', fontsize=14)
plt.xticks(rotation=45, fontsize=12)
plt.tight_layout()
plt.show()
