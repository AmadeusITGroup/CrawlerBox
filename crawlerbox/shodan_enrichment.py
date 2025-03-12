import shodan
from dateutil import parser as dateparser
from datetime import timezone


from .config import SHODAN_API_KEY


def shodan_data(susp_ip):
    result=[]
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        # Lookup the host
        host = api.host(susp_ip)
        # Print all banners
        for item in host['data']:
            port=item['port']
            data=item['data']
            banner={}
            details=[d.strip('\r') for d in data.split('\n')]
            banner['service']=details[0]
            banner['port']=port
            banner['error']=None

            for d in details:
                if d.startswith('Server:'):
                    banner['server']=d[8::]
                elif d.startswith('Content-Type:'):
                    banner['content_type']=d[14::]
                elif d.startswith('Content-Length:'):
                    banner['content_length']=int(d[16::])
                elif d.startswith('Connection:'):
                    banner['connection_status']=d[12::]
                elif d.startswith('Date:'):
                    banner['date']=dateparser.parse(d[6::]).astimezone(timezone.utc)
                elif d.startswith('Expires:'):
                    banner['expires']=dateparser.parse(d[9::]).astimezone(timezone.utc)
                elif d.startswith('Location:'):
                    banner['location']=d[10::]
                elif d.startswith('Set-Cookie:'):
                    banner['set_cookie']=d[12::]

            result.append(banner)
    except Exception as e:
        result.append({'error':str(e)})

    return result




