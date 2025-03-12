import whois
from .phish_logger import Phish_Logger
logger=Phish_Logger.get_phish_logger('phish_logs')

def whois_info(domain):
    w=None
    try:
        w=whois.whois(domain,flags=True)
        if w:
            try:
                date_fields=['creation_date','expiration_date','updated_date']
                for field in date_fields:
                    if field in w.keys() and isinstance(w[field],list):
                        w[field]=min([e for e in w[field] if not isinstance(e,str)])
            except Exception as e:
                logger.error('[!] Exception in whois_info :: %s ',str(e))
            try:
                if 'domain_name' in w.keys():
                    if isinstance(w['domain_name'],list):
                        w['domain_name']=list({d.lower() for d in w['domain_name']})
                    elif isinstance(w['domain_name'],str):
                        w['domain_name']=[w['domain_name']]
            except Exception as e:
                logger.error('[!] Exception in whois_info :: %s',str(e))
            try:
                if 'name_servers' in w.keys():
                    if isinstance(w['name_servers'],list):
                        w['name_servers']=list({d.lower() for d in w['name_servers']})
                    elif isinstance(w['name_servers'],str):
                        w['name_servers']=[w['name_servers']]
            except Exception as e:
                logger.error('[!] Exception in whois_info :: ',str(e))
            try:
                if 'whois_server' in w.keys():
                    if isinstance(w['whois_server'],list):
                        w['whois_server']=list({d.lower() for d in w['whois_server']})
                    elif isinstance(w['whois_server'],str):
                        w['whois_server']=[w['whois_server']]
            except Exception as e:
                logger.error('[!] Exception in whois_info :: ',str(e))
    except Exception:
        logger.error('[!] Error in fetching the whois record for :: {domain}')
    return w




