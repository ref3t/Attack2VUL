import json

# Transformation function to convert original JSON to desired style
def transform_json(section_name, section_data):
    # Define the root node
    root = {
        "name": section_name,
        "children": []
    }

    # Iterate over the keys and values of the section data
    current_node = root["children"]
    for key, value in section_data.items():
        # Create a new child node for each key-value pair
        child_node = {"name": key}
        if isinstance(value, dict):
            # If the value is a dictionary, recursively add its children
            child_node["children"] = transform_json(key, value)
        else:
            # Otherwise, create a leaf node with the value
            child_node["name"] += ": " + value
        # Add the child node to the current node's children list
        current_node.append(child_node)

    return root["children"]

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

    # Initialize a list to store the transformed JSON for each section
    transformed_sections = []

    # Transform each section and store the transformed JSON
    for section_name, section_data in data.items():
        transformed_json = transform_json(section_name, section_data)
        output_json = {"name": section_name, "children": transformed_json}
        transformed_sections.append(output_json)

    # Write the transformed JSON to a new file
    output_file_path = 'transformed_data.json'
    with open(output_file_path, 'w') as output_file:
        json.dump(transformed_sections, output_file, indent=4)

    print("Transformation complete. Output saved to:", output_file_path)

# Entry point of the script
if __name__ == "__main__":
    main()
