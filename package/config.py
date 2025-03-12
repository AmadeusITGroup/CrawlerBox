import os

CRAWLER_DB_CONN_SERVER = os.getenv("CRAWLER_DB_CONN_SERVER") # Database connection string (for logging the results)
CISCO_TOKEN =  os.getenv("CISCO_TOKEN") # Cisco Umbrella API token
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY") # Shodan API key
REPORTED_DB_BASE_URL = os.getenv("REPORTED_DB_BASE_URL") # Database base URL (for fetching newly reported emails)
REPORTED_DB_TOKEN = os.getenv("REPORTED_DB_TOKEN") # Database token (for fetching newly reported emails)
company_name='companyA' # Name of the institution running this study (useful in case, you use CrawlerBox to analyze reported emails from multiple companies)

# CrawlerBox compares the obtained screenshots with the ones of legitimate login pages. Use ref_screenshot_hashes to configure the hashes of the legitimate pages.
ref_screenshot_hashes={
    'companyA':
    {'dhash': os.getenv("dhash_companyA"),
     'phash': os.getenv("phash_companyA")
     },
    'companyB':{
        'dhash':os.getenv("dhash_companyB"),
        'phash':os.getenv("phash_companyB")
        }
    }

