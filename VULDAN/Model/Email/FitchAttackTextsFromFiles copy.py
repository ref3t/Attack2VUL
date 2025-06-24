import requests
from bs4 import BeautifulSoup

# URL of the webpage to scrape
url = "https://www.securityweek.com/gitlab-patches-pipeline-execution-ssrf-xss-vulnerabilities/"

# Add headers to mimic a real browser
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36'
}

# Send a GET request to the webpage
response = requests.get(url, headers=headers)

# Check if the request was successful
if response.status_code == 200:
    # Parse the HTML content of the webpage
    soup = BeautifulSoup(response.content, 'html.parser')

    # Extract all text from the article page and remove extra spaces
    article_text = ' '.join(soup.get_text().split())

    print(article_text)
else:
    print(f"Failed to retrieve the webpage. Status code: {response.status_code}")
