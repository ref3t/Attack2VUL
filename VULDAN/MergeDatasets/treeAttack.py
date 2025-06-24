from treelib import Node, Tree
import pandas as pd

# Read data from Excel file
excel_file = "VwDetDataset2.csv"  # Replace "your_excel_file.xlsx" with the path to your Excel file
data = pd.read_csv(excel_file)

# Initialize tree
tree = Tree()

# Add root node
tree.create_node("Root", "root")

# Iterate over rows in the dataframe
for index, row in data.iterrows():
    tactic_id = row['TacticID']
    technique_id = row['TechnqiueID']
    procedures_id = row['ProceduresID']
    capec_id = row['CAPECID']
    cve_id = row['CVE-ID']
    related_weaknesses = row['Related Weaknesses']
    func = row['func']
    
    # Add nodes to the tree
    tactic_node_id = f"{tactic_id}"
    technique_node_id = f"{tactic_id}-{technique_id}"
    procedures_node_id = f"{tactic_id}-{technique_id}-{procedures_id}"
    capec_node_id = f"{tactic_id}-{technique_id}-{procedures_id}-{capec_id}"
    cve_node_id = f"{tactic_id}-{technique_id}-{procedures_id}-{capec_id}-{cve_id}"
    weakness_node_id = f"{tactic_id}-{technique_id}-{procedures_id}-{capec_id}-{cve_id}-{related_weaknesses}"
    
    # Add nodes to the tree
    if not tree.get_node(tactic_node_id):
        tree.create_node(tactic_id, tactic_node_id, parent="root")
    if not tree.get_node(technique_node_id):
        tree.create_node(technique_id, technique_node_id, parent=tactic_node_id)
    if not tree.get_node(procedures_node_id):
        tree.create_node(procedures_id, procedures_node_id, parent=technique_node_id)
    if not tree.get_node(capec_node_id):
        tree.create_node(capec_id, capec_node_id, parent=procedures_node_id)
    if not tree.get_node(cve_node_id):
        tree.create_node(cve_id, cve_node_id, parent=capec_node_id)
    if not tree.get_node(weakness_node_id):
        tree.create_node(related_weaknesses, weakness_node_id, parent=cve_node_id)
    
    # Add function as a node attribute
    tree.get_node(weakness_node_id).data = func

# Show tree
tree.show()
