import pandas as pd
import re
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
from nltk.stem import PorterStemmer
from nltk.stem import WordNetLemmatizer
import nltk
nltk.download('punkt')
nltk.download('punkt_tab')

# Preprocessing functions
def remove_citations_and_urls(text):
    """
    Remove citations and URLs from the input text.
    
    Parameters:
    text (str): The input string containing CVE description, citations, or URLs.
    
    Returns:
    str: Cleaned text with citations, URLs, and non-alphanumeric characters removed.
    """
    # Regular expression pattern to match citations
    citation_pattern = r'\(Citation:.*?\)'

    # Regular expression pattern to match URLs
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'

    # Remove citations and URLs from the text
    text = re.sub(citation_pattern, '', text)
    text = re.sub(url_pattern, '', text)

    # Remove other unwanted parts like <code> tags, extra spaces, and non-alphanumeric characters
    regex = "^<code>.*</code>$"
    text = re.sub(regex, "", text, flags=re.MULTILINE)
    text = " ".join(text.split())  # Remove extra spaces
    text = re.sub("[^A-Za-z0-9]", " ", text)  # Replace non-alphanumeric characters with space

    return text


def removeUrls(text):
    """
    Remove URLs and certain patterns from the input text.
    
    Parameters:
    text (str): The input string containing URLs or other undesired patterns.
    
    Returns:
    str: Cleaned text with URLs removed.
    """
    # Remove URLs
    text = re.sub(r'(https|http)?:\/\/(\w|\.|\/|\?|\=|\&|\%)*\b', '', text, flags=re.MULTILINE)
    # Remove text after 'NOTE:' pattern
    text = re.sub(r'(?i)NOTE:.*', '', text)
    # Remove digits
    text = re.sub(r'\b\d+(\.\d+)*\b', '', text)
    
    return text


def removeCitation(text):
    """
    Remove any text after a '(Citation: ...)' in the input string.
    
    Parameters:
    text (str): The input string which might contain citations.
    
    Returns:
    str: Text up to the position of the first citation, or the original text if no citation is found.
    """
    position = text.find('(Citation:')
    if position > 0:
        return text[:position]
    else:
        return text


def removeURLandCitationBulk(texts):
    """
    Apply URL and citation removal on a bulk list of strings.
    
    Parameters:
    texts (list): A list of text strings to be cleaned.
    
    Returns:
    list: A list of cleaned strings with URLs and citations removed.
    """
    return [remove_citations_and_urls(text) for text in texts]


# Additional preprocessing steps (optional)
def dataPreprocessingStopWords(texts):
    """
    Apply stop word removal to a list of text strings.
    
    Parameters:
    texts (list): A list of text strings.
    
    Returns:
    list: A list of tokenized text strings with stop words removed.
    """
    return [preprocess_text_stop_words(text) for text in texts]


def preprocess_text_stemming(text):
    """
    Apply stemming to the input text string.
    
    Parameters:
    text (str): The input text to process.
    
    Returns:
    list: A list of stemmed tokens.
    """
    tokens = word_tokenize(text)
    stemmer = PorterStemmer()
    stemmed_tokens = [stemmer.stem(token) for token in tokens]
    return stemmed_tokens

def dataPreprocessingStemming(texts):
    """
    Apply stemming to a list of text strings.
    
    Parameters:
    texts (list): A list of text strings.
    
    Returns:
    list: A list of tokenized text strings with stemmed words.
    """
    return [preprocess_text_stemming(text) for text in texts]


def dataPreprocessingLemmatization(texts):
    """
    Apply lemmatization to a list of text strings.
    
    Parameters:
    texts (list): A list of text strings.
    
    Returns:
    list: A list of tokenized text strings with lemmatized words.
    """
    return [preprocess_text_lemmatization(text) for text in texts]


def preprocess_text_stop_words(text):
    """
    Remove stop words from a text string.
    
    Parameters:
    text (str): The input text to process.
    
    Returns:
    list: A list of tokens with stop words removed.
    """
    tokens = word_tokenize(text)
    stop_words = set(stopwords.words('english'))
    tokens = [token for token in tokens if token not in stop_words]
    return tokens




def preprocess_text_lemmatization(text):
    """
    Apply lemmatization to the input text string.
    
    Parameters:
    text (str): The input text to process.
    
    Returns:
    list: A list of lemmatized tokens.
    """
    tokens = word_tokenize(text)
    lemmatizer = WordNetLemmatizer()
    lemmatized_tokens = [lemmatizer.lemmatize(token) for token in tokens]
    return lemmatized_tokens

# Function to count words in a text
def count_words(text):
    """
    Count the number of words in a given text string.

    Parameters:
    text (str): The input text to count words in.

    Returns:
    int: The number of words in the text.
    """
    return len(text.split())

# File path for the dataset
datasetInfo = "./datasets/News/infosecurity_magazine_news2.xlsx"

# Step 1: Load the data from the Excel file
print("Loading data...")
dataCve = pd.read_excel(datasetInfo, sheet_name=0)

# Step 2: Extract the CVE descriptions
descriptions = dataCve['Text'].values
cve_ids = dataCve['Title'].values
orgDescriptions = dataCve.copy()  # Keeping a copy of the original data
dataCve2 = dataCve.copy()  # Another copy for future use if needed
print("Data loaded successfully.")


word_counts_before = [count_words(description) for description in descriptions]


# Step 3: Apply preprocessing (removing URLs and citations)
descriptions = removeURLandCitationBulk(descriptions)


descriptions = dataPreprocessingStemming(descriptions)
descriptions = [' '.join(item) for item in descriptions]

descriptions = dataPreprocessingLemmatization(descriptions)
descriptions = [' '.join(item) for item in descriptions]

# Optional Preprocessing Steps:
descriptions = dataPreprocessingStopWords(descriptions)
descriptions = [' '.join(item) for item in descriptions]
# Step 4: Update the DataFrame with the processed descriptions
dataCve['Text'] = descriptions
descriptions = dataCve['Text'].values
# Step 5: Calculate word count after preprocessing
word_counts_after = [count_words(description) for description in descriptions]

# Step 6: Update the DataFrame with word counts and cleaned descriptions
result_df = pd.DataFrame({
    'Title': cve_ids,
    'NewsText': descriptions,
    'WordCountBefore': word_counts_before,
    'WordCountAfter': word_counts_after
})

# Step 7: Save the results to an Excel file
output_file = './Results/News_Word_Count_Results2.xlsx'
result_df.to_excel(output_file, index=False)
print(f"Results saved to {output_file}")
print("Descriptions have been preprocessed and updated.")
