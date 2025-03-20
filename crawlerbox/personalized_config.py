
from urllib.parse import unquote,urlparse,parse_qs
from .phish_logger import Phish_Logger


help_desc = '''
Main Library to fetch, parse and crawl new reported emails
'''

logger=Phish_Logger.get_phish_logger('phish_logs')


def fetch_new_emails_by_date(date:str):
    """This function fetches new emails to be analyzed, filtered by date of report.
        Replace this function with an appropriate one given yoyur setup.

    Args:
        date (str): date in str format

    Returns:
        list: a list representing an inbox. Each element in the list is a dictiory having as keys: "phish_id" and "rawUrl".
                "phish_id" represents the EmailID and "rawUrl" represents the URL from which the EML file will be downloaded.
    """
    return 0

def fetch_new_emails_by_id(id:str):
    """This function fetches a single email to be analyzed, filtered by EmailID.
        Replace this function with an appropriate one given yoyur setup.

    Args:
        id (str): EmailID

    Returns:
        list: a list representing an inbox. Each element in the list is a dictiory having as keys: "phish_id" and "rawUrl".
                "phish_id" represents the EmailID and "rawUrl" represents the URL from which the EML file will be downloaded.
    """
    return 0

def url_rewrite(url):
    try:
        # Parse the URL to extract the query parameters
        parsed_url =urlparse(url)
        query_params = parse_qs(parsed_url.query)

        # Assuming the actual link is stored in a parameter named 'url'
        if 'url' in query_params:
            decoded_url = unquote(query_params['url'][0])
            return decoded_url
        else:
            return url

    except Exception as e:
        logger.error("Error decoding URL: %s",str(e))
