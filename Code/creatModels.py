import pandas as pd
from torch.utils.data import DataLoader
from sentence_transformers import SentenceTransformer, InputExample, losses, util
from sentence_transformers.evaluation import EmbeddingSimilarityEvaluator
from sentence_transformers import LoggingHandler
import logging


# Set up logging
logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO, handlers=[LoggingHandler()])


# Load the model (ensure the model is pre-trained or fine-tuned)
model = SentenceTransformer('multi-qa-mpnet-base-dot-v1')
# Function to read the Excel file and convert to the correct format
def read_excel_file(file_path):
    df = pd.read_excel(file_path, sheet_name=0)
    data = []
    for _, row in df.iterrows():
        attack_desc = row['AttackDescription']
        cve_desc = row['CVEDescription']
        label = row['Label']
        data.append((attack_desc, [cve_desc], label))  # Create a tuple with the CVE as a list
    return data

# Load the test data from Excel file
train_data = read_excel_file('train_data.xlsx')  # Replace with the correct file paths
val_data = read_excel_file('val_data.xlsx')
test_data = read_excel_file('test_data.xlsx')

# Function to evaluate similarity for each attack and CVE pair
def evaluate_similarity(model, data):
    results = []
    for attack, cve, label in data:
        # if isinstance(attack, str) and isinstance(cve, str):
        attack_embedding = model.encode(attack, convert_to_tensor=True)
        cve_embedding = model.encode(cve, convert_to_tensor=True)
        similarity = util.pytorch_cos_sim(attack_embedding, cve_embedding)[0][0].item()  # Extract similarity value
        results.append((attack, cve, similarity, label))  # Append tuple with attack, CVE, similarity, and label
    return results

# Example Evaluation on the test data
test_results = evaluate_similarity(model, test_data)

# Convert the results into a DataFrame
results_df = pd.DataFrame(test_results, columns=["AttackDescription", "CVEDescription", "Similarity", "Label"])

# Save the results to an Excel file
output_file = "test_resultsBeforeFine2.xlsx"
results_df.to_excel(output_file, index=False, sheet_name="Similarity Results")

print(f"Results saved to {output_file}")




# Convert to InputExamples for SentenceTransformer
def prepare_input_examples(data):
    examples = []
    for attack, cves, label in data:
        for cve in cves:
            examples.append(InputExample(texts=[str(attack), str(cve)], label=float(label)))
    return examples

# Prepare InputExamples for each dataset
train_examples = prepare_input_examples(train_data)
val_examples = prepare_input_examples(val_data)
test_examples = prepare_input_examples(test_data)

# Create DataLoaders
train_dataloader = DataLoader(train_examples, shuffle=True, batch_size=16)
val_dataloader = DataLoader(val_examples, shuffle=False, batch_size=16)

# Define loss function
train_loss = losses.CosineSimilarityLoss(model=model)

# Set up evaluator
evaluator = EmbeddingSimilarityEvaluator.from_input_examples(val_examples, name="val-evaluator")

losses_functions = ["MultipleNegativesRankingLoss", "ContrastiveLoss", "BatchHardTripletLoss"]

model.fit(
    train_objectives=[(train_dataloader, train_loss)],
    evaluator=evaluator,
    epochs=4,
    evaluation_steps=500,  # Evaluate every 500 steps
    warmup_steps=100,
    output_path='./fine_tuned_mpnet'
)
# Load the fine-tuned model
fine_tuned_model = SentenceTransformer('./fine_tuned_mpnet')

# Function to evaluate similarity for each attack and CVE pair
def evaluate_similarity(model, data):
    results = []
    for attack, cves, label in data:
        attack_embedding = model.encode(attack, convert_to_tensor=True)
        for cve in cves:
            cve_embedding = model.encode(cve, convert_to_tensor=True)
            similarity = util.pytorch_cos_sim(attack_embedding, cve_embedding)[0][0].item()  # Extract similarity value
            results.append((attack, cve, similarity, label))  # Append tuple with attack, CVE, similarity, and label
    return results

# Evaluate the fine-tuned model on the test data
test_results = evaluate_similarity(fine_tuned_model, test_data)

# Convert the results into a DataFrame
results_df = pd.DataFrame(test_results, columns=["AttackDescription", "CVEDescription", "Similarity", "Label"])

# Save the results to an Excel file
output_file = "test_resultsAfterFineTune.xlsx"
results_df.to_excel(output_file, index=False, sheet_name="Similarity Results")

print(f"Test results have been saved to {output_file}")