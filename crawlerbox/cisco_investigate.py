import requests
from  urllib3 import disable_warnings
from datetime import datetime,timedelta
from .config import CISCO_TOKEN
from .phish_logger import Phish_Logger


help_desc = '''
Cisco Umbrella Investigate API Python wrapper to get passive info on
ip/domains (whois, dns historical info etc.)
'''

"""
doc=https://developer.cisco.com/docs/cloud-security/#!investigate-api-request-samples/get-security-domain-information
"""


disable_warnings()
logger=Phish_Logger.get_phish_logger('phish_logs')


def investigate(query,domain):
    api_base = 'https://investigate.api.umbrella.com'
    api = { 'query_volume': '/domains/volume/',
        'domain2pdns': '/pdns/raw/',
        'subdomains':'/subdomains/',
        'related_domains':'/links/name/',
        'security_info':'/security/name/',
        'risk_score': '/domains/risk-score/',
        'top_million':'/topmillion',
        }
    headers={"Authorization": f"Bearer {CISCO_TOKEN}" }
    ses = requests.Session()
    ses.headers.update(headers)
    res = ses.get(api_base + api[query] + domain, verify=False)
    if res.status_code != 200:
        logger.error("[!] Error with the Cisco Umbrella investigate request:: Got HTTP/%d",res.status_code )
        return None
    return res.json()


def parse_query_volume(domain):
    """Cisco inverstigare Get Domain Query Volume
    Args:
        domain (string): domain
    Returns:
        dict: Returns a dictionary corresponding to the number of domain requests (query volume) per hour in the last 30 days.
    """
    qv=investigate('query_volume',domain)
    if not qv:
        return
    dates=qv['dates']
    volume=qv['queries']

    start_date=datetime.fromtimestamp(dates[0] /1000)
    dates_list=[]

    i=0
    while len(dates_list)<len(volume):
        dates_list.append(start_date+timedelta(hours=1*i))
        i+=1

    res = {dates_list[i]: volume[i] for i in range(len(dates_list))}
    return res


def parse_domain_pdns(domain):
    """Cisco inverstigare Get Passive DNS Data
    Args:
        domain (string): domain
    Returns:
        dict: Returns information from passive DNS endpoints (historical data from Cisco resolvers for domains and IPs), and other resource records.
    """
    return investigate('domain2pdns',domain)

def parse_subdomains(domain):
    """Cisco Investigate Get Subdomains of Domain
    Args:
        domain (string): domain
    Returns:
        list: Returns a list of dict date about subdomains, if any. Keys: firstSeen, name, securityCategories
    """
    return investigate('subdomains',domain)


def parse_related_domain(domain):
    """Cisco Investigate Get Related Domains
    Args:
        domain (string): domain
    Returns:
        list: Returns a list of the domain names frequently requested around the same time (up to 60 seconds before or after) as
        the given domain name, composed as follows [related_domain,count]
    """
    return investigate('related_domains',domain)['tb1']


def parse_security_info(domain):
    """Cisco Investigate Get Security Domain Information
    Args:
        domain (string): domain
    Returns:
        dict: Return domain security data
            - asn_score: ASN reputation score, ranges from -100 to 0 with -100 being very suspicious
            - attack: The name of any known attacks associated with this domain, or blank if no known threat
            - dga_score: A score generated based on the likeliness of the domain name being generated by an algorithm rather than a human
            - entropy: The number of bits required to encode the domain name, as a score
            - fastflux: associated with a fastflux
            - found: True if domain seen by Cisco Umbrella
            - geodiversity: A score representing the number of queries from clients visiting the domain, broken down by country.
                Score is a non-normalized ratio between 0 and 1.
            - geodiversity_normalized: ?
            - geoscore: A score that represents how far the different physical locations serving this name are from each other
            - ks_test: Kolmogorov–Smirnov test on geodiversity. 0 means that the client traffic matches what is expected for this TLD
            - pagerank: Popularity according to Google's pagerank algorithm
            - perplexity: A second score on the likeliness of the name to be algorithmically generated, on a scale from 0 to 1
            - popularity: The number of unique client IPs visiting this site, relative to the all requests to all sites
            - prefix_score: Prefix ranks domains given their IP prefixes (an IP prefix is the first three octets in an IP address)
                and the reputation score of these prefixes. Ranges from -100 to 0, -100 being very suspicious
            - rip_score: RIP ranks domains given their IP addresses and the reputation score of these IP addresses.
                Ranges from -100 to 0, -100 being very suspicious
            - securerank2: Suspicious rank for a domain that reviews based on the lookup behavior of client IP for the domain
            - threat_type: The type of the known attack, such as botnet or APT, or blank if no known threat
            - tld_geodiversity: A score that represents the TLD country code geodiversity as a percentage of clients visiting the domain.
                Occurs most often with domains that have a ccTLD. Score is normalized ratio between 0 and 1.

        example:
        {'asn_score': 0.0,
            'attack': '',
            'dga_score': -47.51522460008749,
            'entropy': 2.6464393446710153,
            'fastflux': False,
            'found': True,
            'geodiversity': [['IT', 0.5769],
                            ['NL', 0.1538],
                            ['ES', 0.1154],
                            ['US', 0.0385],
                            ['GB', 0.0385],
                            ['IL', 0.0385],
                            ['IN', 0.0385]],
            'geodiversity_normalized': [['IL', 0.4339678523653716],
                                        ['NL', 0.18587521379409655],
                                        ['IT', 0.18366377624050131],
                                        ['ES', 0.17207740715146919],
                                        ['IN', 0.014373440894589102],
                                        ['GB', 0.008862567407938674],
                                        ['US', 0.0011797421460334936]],
            'geoscore': 0.0,
            'ks_test': 0.0,
            'pagerank': 0.0,
            'perplexity': 0.8510542607939227,
            'popularity': 0.0,
            'prefix_score': 0.0,
            'rip_score': 0.0,
            'securerank2': 0.0,
            'threat_type': '',
            'tld_geodiversity': []}
    """
    return investigate('security_info',domain)

def parse_risk_score(domain):
    """Get the risk score for the domain. Umbrella Investigate scores the domain from 0 to 100. A score of 100 represents
    the highest risk whereas a score of 0 indicates no risk. A domain blocked by Umbrella receives a score of 100.
    Args:
        domain (string): domain
    Returns:
        dict: Returns a dictionary of risk scores associated with the domain
        - Geo Popularity Score
        - Keyword Score: if it contains words related to legitimate companies and services
        - Lexical: based on lexical characteristics of domain name
        - Popularity 1 Day
        - Popularity 7 Day
        - Popularity 30 Day
        - Popularity 90 Day
        - TLD Rank Score
        - Umbrella Block Status

        example:
            {'indicators': [{'indicator': 'Geo Popularity Score',
                                'indicator_id': 'Geo Popularity Score',
                                'normalized_score': 40,
                                'score': -0.4018111700000001},
                                {'indicator': 'Keyword Score',
                                'indicator_id': 'Keyword Score',
                                'normalized_score': 10,
                                'score': 0.10963398199526944},
                                {'indicator': 'Lexical',
                                'indicator_id': 'Lexical',
                                'normalized_score': 61,
                                'score': 0.615},
                                {'indicator': 'Popularity 1 Day',
                                'indicator_id': 'Popularity 1 Day',
                                'normalized_score': None,
                                'score': None},
                                {'indicator': 'Popularity 30 Day',
                                'indicator_id': 'Popularity 30 Day',
                                'normalized_score': None,
                                'score': None},
                                {'indicator': 'Popularity 7 Day',
                                'indicator_id': 'Popularity 7 Day',
                                'normalized_score': None,
                                'score': None},
                                {'indicator': 'Popularity 90 Day',
                                'indicator_id': 'Popularity 90 Day',
                                'normalized_score': None,
                                'score': None},
                                {'indicator': 'TLD Rank Score',
                                'indicator_id': 'TLD Rank Score',
                                'normalized_score': 0,
                                'score': 0.0031415985934513946},
                                {'indicator': 'Umbrella Block Status',
                                'indicator_id': 'Umbrella Block Status',
                                'normalized_score': 0,
                                'score': False}],
                'risk_score': 19}
    """
    return investigate('risk_score',domain)


def parse_top_domains(limit:int = None):
    if limit:
        return investigate('top_million','?limit='+str(limit))
    else:
        return investigate('top_million','')


top_domains=parse_top_domains()

