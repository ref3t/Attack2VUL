import json

# Transformation function to convert original JSON to desired style
# Transformation function to convert original JSON to desired style
def transform_json(section_name, section_data):
    # Extract the first element
    first_key, first_value = list(section_data.items())[0]
    
    # Define the root node
    root = {
        "name": "flare",
        "children": [{
            "name": section_name,
            "children": [{
                "name": first_key,
                "value": first_value
            }]
        }]
    }

    # Convert the transformed data back to JSON string
    transformed_json = json.dumps(root, indent=2)
    return transformed_json

# Function to read JSON file
def read_json_file(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)


# Main function
def main():
    # Path to the JSON file
    json_file_path = 'output.json'

    # Read the JSON file
    data = read_json_file(json_file_path)

    # Convert each section's first element and output the transformed JSON    
    for section in data:
        section_data = data[section]
        transformed_json = transform_json(section, section_data)
        print(transformed_json)

# Entry point of the script
if __name__ == "__main__":
    main()
