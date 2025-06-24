import requests
from bs4 import BeautifulSoup
import pandas as pd

# Base URL of the webpage to scrape
base_url = "https://www.infosecurity-magazine.com/news/page-"

# Number of pages to scrape
num_pages = 6

# Initialize a list to store the data
data = []

# Loop through each page and scrape the content
for page_num in range(1, num_pages + 1):
    # Construct the URL for the current page
    url = f"{base_url}{page_num}/"
    
    # Send a GET request to the webpage
    response = requests.get(url)
    
    # Check if the request was successful
    if response.status_code == 200:
        # Parse the HTML content of the webpage
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Extract all article links from the webpage, excluding specific links
        article_links = [a_tag['href'] for a_tag in soup.find_all('a', href=True) 
                         if '/news/' in a_tag['href'] and not a_tag['href'].startswith(base_url) and a_tag['href'] != "https://www.securityweek.com/category/vulnerabilities/"]
        
        # Loop through each article link and scrape the content
        for article_link in article_links:
            # Send a GET request to the article page
            article_response = requests.get(article_link)
            
            # Check if the request was successful
            if article_response.status_code == 200:
                # Parse the HTML content of the article page
                article_soup = BeautifulSoup(article_response.content, 'html.parser')
                
                # Extract the full title from the article soup
                full_title = article_soup.find('title').get_text().strip()

                # Check if the title has a typical pattern where the '-' splits the title from other information
                # For example, if the title follows a pattern like "Title - Source"
                # You can adjust this logic based on your specific case
                if ' - ' in full_title and not full_title.startswith("Fortinet"):  # Adjust this condition as needed
                    title = full_title.split(' - ')[0].strip()  # Split on ' - ' and take the first part
                else:
                    title = full_title  # Keep the full title if no valid pattern to split
                # # Extract the title of the article until the "-" character
                # title = article_soup.find('title').get_text().split('-')[0].strip()
                
                # Extract all text from the article page and remove extra spaces
                article_text = ' '.join(article_soup.get_text().split())
                
                # Count the number of words in the article_text
                word_count = len(article_text.split())
                
                # Append the title, text, link, and word count to the data list
                data.append([title, article_text, article_link, word_count])
                
                print(f"Successfully extracted text from {article_link}")
            else:
                print(f"Failed to retrieve the article page {article_link}. Status code: {article_response.status_code}")
    else:
        print(f"Failed to retrieve the webpage {url}. Status code: {response.status_code}")

# Save all data to a single Excel file with each line in 4 cells: title, text, link, and word count
df = pd.DataFrame(data, columns=['Title', 'Text', 'Link', 'Word Count'])
df.to_excel("AttackNews.xlsx", index=False)

print("The text content has been successfully extracted and saved to infosecurity_magazine_news.xlsx.")
