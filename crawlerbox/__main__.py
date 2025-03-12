import threading
import time
from datetime import datetime
import argparse

from .phishparser import parse_data
import requests

from .personalized_config import fetch_new_emails_by_date,fetch_new_emails_by_id

from .phish_logger import Phish_Logger
logger=Phish_Logger.get_phish_logger('phish_logs')


help_desc = '''
Main Library to fetch, parse and crawl new reported emails
'''

def analyze(inbox):
    for i in range(len(inbox)):
        mail=inbox[i]
        phish_id=mail['id']
        rawUrl=mail['rawUrl']
        logger.info("[%d//%d] Parsing phish email id: %s",i+1,len(inbox),phish_id)
        rawemail_inbytes=requests.get(rawUrl, allow_redirects=True).content
        parse_data(phish_id,rawemail_inbytes)

def run_crawler():
    today=datetime.today().strftime('%Y-%m-%d')
    inbox=fetch_new_emails_by_date(today)
    analyze(inbox)

def scheduler() :
    while True:
        task_thread =threading.Thread(target=run_crawler)
        task_thread.start()
        time.sleep(600) #wait 10minutes

def main():
    parser= argparse.ArgumentParser(description=help_desc, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-id', '--phish_id', default=None, help="phish_id of the reported email" )
    parser.add_argument('-d', '--date', default=None, help="date, if specified will fetch all the reported emails"  )

    args = parser.parse_args()

    if args.phish_id:
        inbox=fetch_new_emails_by_id(id=args.phish_id)
        analyze(inbox)

    elif args.date:
        inbox=fetch_new_emails_by_date(args.date)
        analyze(inbox)
    else:
        scheduler()

if __name__ == "__main__":
    main()


