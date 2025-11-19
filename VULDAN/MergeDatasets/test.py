
import matplotlib.pyplot as plt

# Data
technique_ids = ['T1123', 'T1115', 'T1113', 'T1125', 'T1135', 'T1119', 'T1530', 'T1213', 'T1039', 'T1555', 'T1003', 'T1005', 'T1185', 'T1111', 'T1539', 'T1083', 'T1012', 'T1021', 'T1110', 'T1092', 'T1221', 'T1087', 'T1217', 'T1615', 'T1046', 'T1120', 'T1069', 'T1057', 'T1018', 'T1082', 'T1016', 'T1049', 'T1033', 'T1007', 'T1124', 'T1590', 'T1528', 'T1027', 'T1211', 'T1070', 'T1014', 'T1080', 'T1620', 'T1176', 'T1554', 'T1614', 'T1499', 'T1566', 'T1534', 'T1598', 'T1598']
wordcounts = [70, 65, 61, 131, 125, 124, 297, 170, 62, 75, 68, 69, 222, 274, 208, 119, 95, 257, 140, 72, 328, 120, 106, 145, 155, 68, 73, 135, 135, 212, 119, 214, 203, 65, 187, 120, 361, 227, 155, 137, 97, 282, 171, 283, 167, 157, 258, 216, 226, 257, 257]

# Create bar plot
plt.figure(figsize=(12, 6))
plt.bar(technique_ids, wordcounts, color='#333333')  # Darker shade of black

# Rotate x-axis labels for better visibility
plt.xticks(rotation=90)

# Add labels and title
plt.xlabel('Technique ID')
plt.ylabel('Technique Wordcount')
# plt.title('Technique Wordcount for Each Technique ID')

# Display the plot
plt.tight_layout()
plt.show()
