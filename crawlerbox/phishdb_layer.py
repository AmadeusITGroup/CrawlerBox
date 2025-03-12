from sqlalchemy import create_engine,and_
from sqlalchemy.orm import sessionmaker

from . import phishdb_schema
from .config import CRAWLER_DB_CONN_SERVER,company_name,ref_screenshot_hashes

from urllib.parse import urlsplit
from datetime import datetime

from dateutil import parser
import re

from . import cisco_investigate
from .shodan_enrichment import shodan_data

import tldextract
import socket

from PIL import Image
import imagehash

import hashlib
from .phish_logger import Phish_Logger

import pytesseract
pytesseract.pytesseract.tesseract_cmd =r'C:\Program Files\Tesseract-OCR\tesseract.exe'

logger=Phish_Logger.get_phish_logger('phish_logs')

help_desc = '''
Database query layer, includes the functions to communicate with PhishDB
'''

def open_session():
    db = create_engine(CRAWLER_DB_CONN_SERVER,pool_recycle=-1,pool_size=30, max_overflow=0)
    Session = sessionmaker(bind=db, expire_on_commit=False)
    return Session(),db

def close(session,db):
    session.close()
    db.dispose()


def add_header(malmsg,content_transfer_encoding,content_type,message_id,subject,return_path,session):
    header_record=session.query(phishdb_schema.Email_Header).filter_by(content_transfer_encoding=content_transfer_encoding,content_type=content_type,message_id=message_id,subject=subject,return_path=return_path).first()
    if not header_record:
        header_record=phishdb_schema.Email_Header(content_transfer_encoding=content_transfer_encoding,content_type=content_type,message_id=message_id,subject=subject,return_path=return_path)
        add_element(header_record,session)
    rel=session.query(phishdb_schema.Has_Header).filter_by(email_header=header_record,malmsg=malmsg).first()
    if not rel:
        add_element(phishdb_schema.Has_Header(email_header=header_record,malmsg=malmsg),session)
    return header_record

def add_malicious_msg(phish_id,day,time,origin,session):
    msg_exists=session.query(phishdb_schema.Malicious_Email_Message).filter_by(phish_id=phish_id).first()
    if not msg_exists:
        msg_exists=phishdb_schema.Malicious_Email_Message(phish_id=phish_id,receiving_date=day,receiving_time=time,origin=origin)
        # A new phish_id => new msg, add it
        try:
            session.add(msg_exists)
            session.commit()
        except Exception as e:
            logger.error('[!] Exception occured in add_malicious_msg : %s',str(e))

    return msg_exists

def add_element(element,session):
    try:
        session.add(element)
    except Exception as e:
        session.merge(element)
        logger.error('[!] Exception in add_element :: %s',str(e))
    session.commit()

def add_content(content_id,content,session):
    content_exists=session.query(phishdb_schema.Content).filter_by(content_id=content_id).first()
    if not content_exists:
        content_exists=phishdb_schema.Content(content_id=content_id,content=content)
        try:
            session.add(content_exists)
            session.commit()
        except Exception as e:
            logger.error('[!] Exception occured in add_content :: %s',str(e))

    return content_exists




def url_exists(url,session):
    existing_record=None
    try:
        existing_record = session.query(phishdb_schema.URL).filter_by(url=url).first()

    except Exception as e:
        logger.error('[!] Exception occured in url_exists :: %s',str(e))
    return existing_record


def domain_exists(domain,phish_message,session):
    existing_record=None
    if domain:
        if len(domain)<1000:
            domain=domain.lower()
            try:
                existing_record = session.query(phishdb_schema.Domain).filter_by(domain=domain).first()
                if not existing_record:
                    existing_record=phishdb_schema.Domain(domain=domain)
                    add_element(existing_record,session)
                rel=session.query(phishdb_schema.Associated_With_Message).filter_by(domain=existing_record,message=phish_message).first()
                if not rel:
                    add_element(phishdb_schema.Associated_With_Message(domain=existing_record,message=phish_message),session)

            except Exception as e:
                logger.error('[!] Exception occured in domain_exists :: %s',str(e))
    return existing_record

def check_ipv6(n):
    try:
        socket.inet_pton(socket.AF_INET6, n)
        return True
    except OSError:
        return False


def ipv6_exists(from_ipv6,session):
    ip_record=session.query(phishdb_schema.IPv6).filter_by(ipv6_address=from_ipv6).first()
    if not ip_record:
        ip_record=phishdb_schema.IPv6(ipv6_address=from_ipv6)
        add_element(ip_record,session)
    return ip_record

def ipv4_exists(from_ipv4,session):
    ip_record=session.query(phishdb_schema.IPv4).filter_by(ipv4_address=from_ipv4).first()
    if not ip_record:
        ip_record=phishdb_schema.IPv6(ipv6_address=from_ipv4)
        add_element(ip_record,session)
    return ip_record


def update_header(maliciousemail,header,session):
    email_header=add_header(malmsg=maliciousemail,content_transfer_encoding=header['Content-Transfer-Encoding'],content_type=header['Content-Type'],message_id=header['Message-Id'],subject=header['Subject'],return_path=header['Return-Path'],session=session)
    _,sender_address=header['From'].get('Name'),header['From'].get('Address')
    if sender_address:
        sender_exists(address=header['From'].get('Address'),
                                    name=header['From'].get('Name'),
                                    maliciousemail= maliciousemail,
                                    session=session)

    for received in header['Received']:
        try:
            received_record= phishdb_schema.Received(rcv_day=received['Day'],rcv_time=received['Time'])
            add_element(received_record,session=session)
            add_element(phishdb_schema.Has_Received_Field(received=received_record,header=email_header),session=session)
            if received['From']:
                from_domain=domain_exists(received['From'],maliciousemail,session=session)
                if from_domain:
                    add_element(phishdb_schema.Received_From(received=received_record,domain=from_domain),session=session)
                    if "From_ipv6" in received.keys():
                        from_ipv6=received['From_ipv6']
                        ip_record=ipv6_exists(from_ipv6,session)
                        rel_hasIPv6_exists(ip=ip_record,domain=from_domain,session=session)
                        add_shodan_service_banners(ip_record,'ipv6',from_ipv6,session)
                    if "From_ipv4" in received.keys():
                        from_ipv4=received['From_ipv4']
                        ip_record=ipv4_exists(from_ipv4,session)
                        rel_hasIPv4_exists(ip=ip_record,domain=from_domain,session=session)
                        add_shodan_service_banners(ip_record,'ipv4',from_ipv4,session)

            if received['By']:
                by_domain=domain_exists(received['By'],maliciousemail,session=session)
                if by_domain:
                    add_element(phishdb_schema.Received_By(received=received_record,domain=by_domain),session=session)
                    if "By_ipv6" in received.keys():
                        by_ipv6=received['By_ipv6']
                        ip_record=ipv6_exists(by_ipv6,session)
                        rel_hasIPv6_exists(ip=ip_record,domain=by_domain,session=session)
                        add_shodan_service_banners(ip_record,'ipv6',by_ipv6,session)
                    if "From_ipv4" in received.keys():
                        by_ipv4=received['From_ipv4']
                        ip_record=ipv4_exists(by_ipv4,session)
                        rel_hasIPv4_exists(ip=ip_record,domain=by_domain,session=session)
                        add_shodan_service_banners(ip_record,'ipv4',by_ipv4,session)
        except Exception as e:
            logger.error('[!] Exception in updating the Received header %s',str(e))

    rcv_spf_field=header['Received-Spf']
    received_spf=None
    if rcv_spf_field !={}:
        received_spf=phishdb_schema.Received_Spf(policy_result=rcv_spf_field['pr'],
                                                 spf_results=rcv_spf_field['Spf result'],
                                                 spf_details=rcv_spf_field['Spf details'])
        add_element(received_spf,session=session)
        add_element(phishdb_schema.Associated_Spf(spf=received_spf,header=email_header),session=session)
        client_ip=rcv_spf_field['client_ip']
        client_ip=rcv_spf_field['client_ip']
        if client_ip:
            ip_record=check_ip(client_ip,None,session=session)
            if received_spf:
                if str(ip_record.__table__)=='tbl_ipv6':
                    add_element(phishdb_schema.Has_Client_Ipv6(spf=received_spf,client_ip=ip_record),session=session)
                elif str(ip_record.__table__)=='tbl_ipv4':
                    add_element(phishdb_schema.Has_Client_Ip(spf=received_spf,client_ip=ip_record),session=session)
        receiver_domain=rcv_spf_field['receiver']
        if receiver_domain:
            domain_record=domain_exists(receiver_domain,maliciousemail,session=session)
            if received_spf:
                add_element(phishdb_schema.Receiver_Domain(spf=received_spf,receiver_domain=domain_record),session=session)
        helo=rcv_spf_field['helo']
        if helo:
            helo_record=domain_exists(helo,maliciousemail,session=session)
            if received_spf:
                add_element(phishdb_schema.Has_Helo_Domain(helo_domain=helo_record,spf=received_spf),session=session)


    auth_res=header.get('Authentication-Results')
    if auth_res:
        authresults_record=phishdb_schema.Authentication_Results(spf_check=auth_res.get('spf'),
                                                dkim_check=auth_res.get('dkim'),
                                                dmarc_check=auth_res.get('dmarc'),
                                                compauth_check=auth_res.get('compauth'),
                                                reason=auth_res.get('reason')
                                                )
        add_element(phishdb_schema.Has_Auth_Results(email_header=email_header,authresults=authresults_record),session=session)
        smtp_domain=auth_res.get('smtp.mailfrom')
        if smtp_domain:
            smtp_mailfrom=domain_exists(domain=smtp_domain,phish_message=maliciousemail,session=session)
            add_element(phishdb_schema.SMTP_Mail_From(domain=smtp_mailfrom,authresults=authresults_record),session=session)
    DKIM_signature=header.get('Dkim-Signature')
    if DKIM_signature:
        DKIM_signature_record=phishdb_schema.Dkim_Signature(version=DKIM_signature['v'],
                                    cryptographic_algorithm=DKIM_signature['a'],
                                    query_method=DKIM_signature.get('q'),
                                    canonicalization=DKIM_signature['c'],
                                    selector=DKIM_signature['s'],
                                    signature_creation_time=DKIM_signature.get('t') ,
                                    signed_headers=DKIM_signature['h'],
                                    message_hash=DKIM_signature['bh'],
                                    signature=DKIM_signature['b']
                                    )
        add_element(DKIM_signature_record,session=session)
        add_element(phishdb_schema.Has_Dkim_Signature(dkimsignature=DKIM_signature_record,authresults=authresults_record ),
                                  session=session)
        dkim_domain=DKIM_signature.get('d')
        if dkim_domain:
            associated_domain=domain_exists(DKIM_signature['d'],maliciousemail,session=session)
            add_element(phishdb_schema.Associated_Dkim_Domain(domain=associated_domain,dkimsignature= DKIM_signature_record),
                                      session=session)
    return header



def check_ip(value,domain_record,session):
    ip_record=None
    ipv4_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ipv6_pattern = r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
    try:
        ipv4_addresses = re.findall(ipv4_pattern, value)
        ipv6_addresses = re.findall(ipv6_pattern, value)


        if ipv4_addresses!=[] :#isinstance(ip, ipaddress.IPv4Address):
            for result in ipv4_addresses:
                ip_record=session.query(phishdb_schema.IPv4).filter_by(ipv4_address=result).first()
                if not ip_record:
                    ip_record=phishdb_schema.IPv4(ipv4_address=result)
                    add_element(ip_record,session)
                if domain_record:
                    rel_hasIPv4_exists(ip=ip_record,domain=domain_record,session=session)
                add_shodan_service_banners(ip_record,'ipv4',result,session)

        if ipv6_addresses!=[] :#isinstance(ip, ipaddress.IPv4Address):
            for result in ipv6_addresses:#elif isinstance(ip, ipaddress.IPv6Address):
                ip_record=session.query(phishdb_schema.IPv6).filter_by(ipv6_address=result).first()
                if not ip_record:
                    ip_record=phishdb_schema.IPv6(ipv6_address=result)
                    add_element(ip_record,session)
                if domain_record:
                    rel_hasIPv6_exists(ip=ip_record,domain=domain_record,session=session)
                add_shodan_service_banners(ip_record,'ipv6',result,session)

        if ipv6_addresses==[] and ipv4_addresses==[]:
            if check_ipv6(value):
                ip_record=session.query(phishdb_schema.IPv6).filter_by(ipv6_address=value).first()
                if not ip_record:
                    ip_record=phishdb_schema.IPv6(ipv6_address=value)
                    add_element(ip_record,session)
                if domain_record:
                    rel_hasIPv6_exists(ip=ip_record,domain=domain_record,session=session)
                add_shodan_service_banners(ip_record,'ipv6',value,session)

    except Exception as e:
        logger.error("[!] Exception in check_ip :: %s %s",  str(e),value)
    return ip_record



def request_exists(rq,crawler_instance,session):
    post_data=rq.postData.replace('\x00', '') if rq.postData else None
    url=rq.url
    request_date= datetime.fromtimestamp(rq.wallTime) #don't forget to add wallTime starting from _onRequest reaching Request in network_manager.py
    request_method=rq.method
    request_type=rq.resourceType
    post_data=post_data
    url_fragment=rq._urlFragment #don't forget to add self._urlFragment=payload.get('urlFragment') in network_manager.py (Pyppeteer code)

    url_parser=urlsplit(url)
    existing_record=None
    try:
        existing_record = session.query(phishdb_schema.Request).filter_by(request_date=request_date,
                                                           request_method=request_method,
                                                           request_type=request_type,
                                                           post_data=post_data,
                                                           url_scheme=url_parser.scheme,
                                                           url_path=url_parser.path,
                                                           url_fragment=url_fragment).first()
        if not existing_record:
            existing_record=phishdb_schema.Request(request_method=request_method,
                                    request_type=request_type,
                                    post_data=post_data,
                                    url_scheme=url_parser.scheme,
                                    url_path=url_parser.path[0:10000] if url_parser.path else None,
                                    url_query=url_parser.query[0:1000] if url_parser.query else None,
                                    url_fragment=url_fragment,
                                    request_date=request_date
                                    )
            add_element(existing_record,session)
            rel=session.query(phishdb_schema.Makes_Request).filter_by(request=existing_record,crawler_instance=crawler_instance).first()
            if not rel:
                add_element(phishdb_schema.Makes_Request(request=existing_record,crawler_instance=crawler_instance),session)

    except Exception as e:
        logger.error('[!] Exception occured in request_exists :: %s',str(e))
    return existing_record


def requests_domain(request_record,fqdn_record,session):
    rel=session.query(phishdb_schema.Requests_Domain).filter_by(requested_domain=fqdn_record,request=request_record).first()
    if not rel:
        add_element(phishdb_schema.Requests_Domain(requested_domain=fqdn_record,request=request_record),session)


def check_domaincertificate(domain_record,security_details,phish_message,session):
    try:
        valid_to=datetime.fromtimestamp(security_details.validTo)
        valid_from=datetime.fromtimestamp(security_details.validFrom)
        issuer=security_details.issuer
        subjectName=security_details.subjectName
        sanList=security_details.sanList


        cert_record = session.query(phishdb_schema.Domain_Certificate).filter_by(subjectname=subjectName,
                                                                  issuer=issuer,
                                                                  valid_from=valid_from,
                                                                  valid_to=valid_to).first()
        if not cert_record:
            cert_record=phishdb_schema.Domain_Certificate(valid_to=valid_to,
                                          valid_from=valid_from,
                                          subjectname=subjectName,
                                          issuer=issuer,
                                          protocol=security_details.protocol
                                          )
            session.add(cert_record)
            session.commit()
            rel = session.query(phishdb_schema.Has_TLS_Certificate).filter_by(domain=domain_record,certificate=cert_record).first()
            if not rel:
                add_element(phishdb_schema.Has_TLS_Certificate(domain=domain_record,certificate=cert_record),session)
            for domain in sanList:
                san_domain=domain_exists(domain,phish_message,session)
                rel = session.query(phishdb_schema.Has_Subject_Alternative_Name).filter_by(domain=san_domain,certificate=cert_record).first()
                if not rel:
                    add_element(phishdb_schema.Has_Subject_Alternative_Name(domain=san_domain,certificate=cert_record),session)

            session.commit()
    except Exception as e:
        logger.error('[!] Exception in check_domaincertificate :: %s',str(e))

    return cert_record


def rel_hasIPv4_exists(ip,domain,session):
    relation = session.query(phishdb_schema.Has_IPv4).filter_by(ip=ip,domain=domain).first()
    if not relation:
        session.add(phishdb_schema.Has_IPv4(domain=domain,ip=ip))
        session.commit()
    return relation

def rel_hasIPv6_exists(ip,domain,session):
    relation = session.query(phishdb_schema.Has_IPv6).filter_by(ipv6=ip,domain=domain).first()
    if not relation:
        session.add(phishdb_schema.Has_IPv6(domain=domain,ipv6=ip))
        session.commit()
    return relation


def add_responsebody(bodyhash,response_body,response,session):
    try:
        responsebody_record = session.query(phishdb_schema.Response_Body).filter_by(responsebody_id=bodyhash).first()
        if not responsebody_record:
            responsebody_record=phishdb_schema.Response_Body(responsebody_id=bodyhash,responsebody=response_body)
            add_element(responsebody_record,session)

        hasresponsebody_record = session.query(phishdb_schema.Has_Response_Body).filter_by(responsebody=responsebody_record,response=response).first()
        if not hasresponsebody_record:
            hasresponsebody_record=phishdb_schema.Has_Response_Body(responsebody=responsebody_record,response=response)
            add_element(hasresponsebody_record,session)
    except Exception as e:
        logger.error('Exception add_responsebody :: %s',str(e))


def sender_exists(address,name,maliciousemail,session):
    sender_record = session.query(phishdb_schema.Sender).filter_by(address=address).first()
    if not sender_record:
        sender_record=phishdb_schema.Sender(address=address,name=name)
        add_element(sender_record,session)
    rel=session.query(phishdb_schema.From_Sender).filter_by(sender=sender_record,malmsg=maliciousemail).first()
    if not rel:
        add_element(phishdb_schema.From_Sender(sender=sender_record,malmsg=maliciousemail),session)
    return sender_record


def create_whoisrecord(w,fqdn_record,phish_message,session):
    try:
        cd=w.get('creation_date')
        creation_date= ','.join(cd) if isinstance(cd,list) else cd
        expiration_date=w.get('expiration_date')
        updated_date=w.get('updated_date')
        registrar=w.get('registrar')
        orga=w.get('org')
        org=','.join(orga) if isinstance(orga,list) else orga
        country_field=w.get('country')
        country=','.join(country_field) if isinstance(country_field,list) else country_field

        whois_record= session.query(phishdb_schema.Whois).filter_by(creation_date=creation_date,
                                                        expiration_date=expiration_date,
                                                        updated_date=updated_date,
                                                        registrar=registrar,
                                                        org=org,
                                                        country=country).first()
        if not whois_record:
            whois_record=phishdb_schema.Whois(creation_date=creation_date,
                            expiration_date=expiration_date,
                            updated_date=updated_date,
                            registrar=registrar,
                            org=org,
                            country=country
                            )
            add_element(whois_record,session)

        rel=session.query(phishdb_schema.Has_Whois_Record).filter_by(whois=whois_record,domain=fqdn_record).first()
        if not rel:
            add_element(phishdb_schema.Has_Whois_Record(whois=whois_record,domain=fqdn_record),session)

        domain_names=w.get('domain_name',None)
        if domain_names:
            for domain in domain_names:
                domain_name_record=domain_exists(domain,phish_message,session)
                rel=session.query(phishdb_schema.Has_Domain_Name).filter_by(domain=domain_name_record,whois=whois_record).first()

        name_servers=w.get('name_servers',None)
        if name_servers:
            for ns in name_servers:
                if bool(re.match(r"^[A-Za-z0-9-]{1,63}\.[A-Za-z]{2,6}$", ns)):
                    ns_domain=domain_exists(ns,phish_message,session)

                    rel=session.query(phishdb_schema.Has_Name_Server).filter_by(domain=ns_domain,whois=whois_record).first()
                    if not rel:
                        add_element(phishdb_schema.Has_Name_Server(domain=ns_domain,whois=whois_record),session)

        whois_servers=w.get('whois_server',None)
        if whois_servers:
            for whois_server in whois_servers:
                whois_domain=domain_exists(whois_server,phish_message,session)
                rel=session.query(phishdb_schema.Has_Whois_Server).filter_by(domain=whois_domain,whois=whois_record).first()
                if not rel:
                    add_element(phishdb_schema.Has_Whois_Server(domain=whois_domain,whois=whois_record),session)
    except Exception as e:
        logger.error('[!] Exception in create_whoisrecord :: %s',str(e))
        pass


def check_response(res,session) :
    url_parser=urlsplit(res.url)
    url_scheme=url_parser.scheme
    url_path=url_parser.path[0:10000] if url_parser.path else None,
    response_status=res.status
    url_query=url_parser.query[0:1000] if url_parser.query else None,
    url_fragment=url_parser.fragment
    date=res.headers.get('date',None)
    response_date=parser.parse( date) if date else None

    response_record = session.query(phishdb_schema.Response).filter_by(url_scheme=url_scheme,
                                                        url_path=url_path,
                                                        response_status=response_status,
                                                        url_query=url_query,
                                                        url_fragment=url_fragment,
                                                        response_date=response_date).first()
    if not response_record:
        response_record=phishdb_schema.Response(url_scheme=url_scheme,
                                    url_path=url_path,
                                    response_status=response_status,
                                    url_query=url_query,
                                    url_fragment=url_fragment,
                                    response_date=response_date)
        add_element(response_record,session)
    return response_record

def add_redirection(response,request,session):
    rel= session.query(phishdb_schema.Redirects_To).filter_by(request=request,response=response).first()
    if not rel:
        add_element(phishdb_schema.Redirects_To(request=request,response=response),session)



def add_response(res,request,fqdn_record,session):
    response_record=None
    try:
        response_record = check_response(res,session)
        rel=session.query(phishdb_schema.Receives_Response).filter_by(request=request,response=response_record).first()
        if not rel:
            add_element(phishdb_schema.Receives_Response(request=request,response=response_record),session)

        if fqdn_record:
            rel=session.query(phishdb_schema.Response_From_FQDN).filter_by(domain=fqdn_record,response=response_record).first()
            if not rel:
                add_element(phishdb_schema.Response_From_FQDN(domain=fqdn_record,response=response_record),session)


            remoteIP=res.remoteIPAddress
            if remoteIP:
                check_ip(remoteIP,fqdn_record,session)


    except Exception as e:
        logger.error('[!] Execption in add_response :: %s',str(e))

    return response_record


def add_risk_score(domain, domain_record,session):
    today=datetime.today().date()
    #check if we already fetched the risk score of this domain today:
    exists=session.query(phishdb_schema.Has_Risk_Score).filter_by(domain=domain_record,date=today).first()
    if not exists:
        result=cisco_investigate.parse_risk_score(domain)
        risk_score=result['risk_score']
        for item in result['indicators']:
            match item['indicator']:
                case 'Geo Popularity Score':
                    geo_popularity_score=item['normalized_score']
                case 'Keyword Score':
                    keyword_score=item['normalized_score']
                case 'Lexical':
                    lexical_score=item['normalized_score']
                case 'Popularity 1 Day':
                    popularity_1_day=item['normalized_score']
                case 'Popularity 7 Day':
                    popularity_7_days=item['normalized_score']
                case 'Popularity 30 Day':
                    popularity_30_days=item['normalized_score']
                case 'Popularity 90 Day':
                    popularity_90_days=item['normalized_score']
                case 'TLD Rank Score':
                    tld_rank_scorepopularity_30_days=item['normalized_score']
                case 'Umbrella Block Status':
                    umbrella_block_status=item['score']
        rs=phishdb_schema.Risk_Score(risk_score=risk_score,
                    geo_popularity_score=geo_popularity_score,
                    keyword_score=keyword_score,
                    lexical_score=lexical_score,
                    popularity_1_day=popularity_1_day,
                    popularity_7_days=popularity_7_days,
                    popularity_30_days=popularity_30_days,
                    popularity_90_days=popularity_90_days,
                    tld_rank_scorepopularity_30_days=tld_rank_scorepopularity_30_days,
                    umbrella_block_status=umbrella_block_status
                    )
        add_element(rs,session)
        rel=phishdb_schema.Has_Risk_Score(domain=domain_record,risk_score=rs,date=today)
        add_element(rel,session)

def add_umbrella_security_information(domain,domain_record,session):
    today=datetime.today().date()
    exists=session.query(phishdb_schema.Has_Umbrella_Security_Information).filter_by(domain=domain_record,date=today).first()
    if not exists:
        result=cisco_investigate.parse_security_info(domain)
        asn_score=result['asn_score']
        associated_attack_name=result['attack']
        dga_score=result['dga_score']
        entropy=result['entropy']
        associated_with_fastflux=result['fastflux']
        found=result['found']
        geodiversity=result['geodiversity']
        geoscore=result['geoscore']
        ks_test=result['ks_test']
        pagerank=result['pagerank']
        perplexity=result['perplexity']
        popularity=result['popularity']
        prefix_score=result['prefix_score']
        rip_score=result['rip_score']
        securerank2=result['securerank2']
        associated_threat_type=result['threat_type']
        tld_geodiversity=result['tld_geodiversity']
        sec_info=phishdb_schema.Umbrella_Security_Information(asn_score=asn_score,
                                            associated_attack_name=associated_attack_name,
                                            dga_score=dga_score,
                                            entropy=entropy,
                                            associated_with_fastflux=associated_with_fastflux,
                                            found=found,
                                            geodiversity=geodiversity,
                                            geoscore=geoscore,
                                            ks_test=ks_test,
                                            pagerank=pagerank,
                                            perplexity=perplexity,
                                            popularity=popularity,
                                            prefix_score=prefix_score,
                                            rip_score=rip_score,
                                            securerank2=securerank2,
                                            associated_threat_type=associated_threat_type,
                                            tld_geodiversity=tld_geodiversity,
                                            )
        add_element(sec_info,session)
        rel=phishdb_schema.Has_Umbrella_Security_Information(date=today,umbrella_security_information=sec_info,domain=domain_record)
        add_element(rel,session)

def add_query_volume(domain,session):
    today=datetime.today().date()

    record_exists=session.query(phishdb_schema.Has_Query_Volume).filter_by(domain_id=domain,date=today).first()
    if not record_exists:

        qv=cisco_investigate.parse_query_volume(domain)
        for date, volume in qv.items():
            try:
                exists=session.query(phishdb_schema.Umbrella_Query_Volume).join(phishdb_schema.Has_Query_Volume,
                                                        and_(
                                                        phishdb_schema.Umbrella_Query_Volume.query_date==date ,
                                                        phishdb_schema.Umbrella_Query_Volume.id== phishdb_schema.Has_Query_Volume.query_volume_id
                                                        )
                                                            ).filter_by(domain_id=domain).first()
                if not exists:
                            qv_record=phishdb_schema.Umbrella_Query_Volume(query_date=date,query_volume=volume)
                            session.add(qv_record)
                            session.flush()
                            session.add(phishdb_schema.Has_Query_Volume(domain_id=domain,query_volume=qv_record,date=today))
                            session.flush()
                            session.commit()
            except Exception as e:
                logger.error('[!] Exception add_query_volume :: %s',str(e))
                #session.rollback()


def add_subdomains(domain,session):
    today=datetime.today().date()
    domain_name=tldextract.extract(domain).registered_domain.lower()
    record_exists=session.query(phishdb_schema.Has_Subdomain).filter_by(parent_domain_id=domain_name,date=today).first()
    if not record_exists:
        domain_record = session.query(phishdb_schema.Domain).filter_by(domain=domain_name).first()
        if not domain_record:
            domain_record=phishdb_schema.Domain(domain=domain_name)
            add_element(domain_record,session)
        subdomains=cisco_investigate.parse_subdomains(domain_name)
        for subdomain_element in subdomains:

            first_seen= datetime.fromtimestamp(int(subdomain_element['firstSeen']))
            subdomain=subdomain_element['name'].lower()
            subdomain_record = session.query(phishdb_schema.Domain).filter_by(domain=subdomain).first()
            if not subdomain_record:
                subdomain_record=phishdb_schema.Domain(domain=subdomain)
                add_element(subdomain_record,session)

            if not session.query(phishdb_schema.Has_Subdomain).filter_by(parent_domain=domain_record,subdomain=subdomain_record).first():
                rel=phishdb_schema.Has_Subdomain(parent_domain=domain_record,subdomain=subdomain_record,date=today,first_seen=first_seen)
                add_element(rel,session)



def add_related_domains(domain,domain_record,session):
    today=datetime.today().date()
    domain=domain.lower()
    record_exists=session.query(phishdb_schema.Has_Related_Domain).filter_by(parent_domain_id=domain,date=today).first()
    if not record_exists:
        result=cisco_investigate.parse_related_domain(domain)
        for element in result:
            rel_domain,count=element[0].lower(),element[1]
            rel_domain_record=session.query(phishdb_schema.Domain).filter_by(domain=rel_domain).first()
            if not rel_domain_record:
                rel_domain_record=phishdb_schema.Domain(domain=rel_domain)
                add_element(rel_domain_record,session)
            if not session.query(phishdb_schema.Has_Related_Domain).filter_by(parent_domain=domain_record,subdomain=rel_domain_record).first():
                rel=phishdb_schema.Has_Related_Domain(related_domain=rel_domain_record,
                                    parent_domain=domain_record,
                                    date=today,
                                    count=count)
                add_element(rel,session)


def umbrella_enrichment(fqdn,fqdn_record,session):
    fqdn=fqdn.lower()
    today=datetime.today().date()
    try:
        if fqdn not in cisco_investigate.top_domains:
            exists=session.query(phishdb_schema.Has_Umbrella_Security_Information).filter_by(domain=fqdn_record,date=today).first()
            if not exists:
                logger.info('[+] Enriching with Umbrella for domain :: %s',{str(fqdn)})
                try:
                    logger.info('[+] Adding umbrella sec info')
                    add_umbrella_security_information(domain=fqdn,domain_record=fqdn_record,session=session)
                except Exception as e:
                    logger.error('[!] umbrella_enrichment: Exception in adding the security information (umbrella):: %s',str(e))
                try:
                    logger.info('[+] Adding umbrella query volume')
                    add_query_volume(domain=fqdn,session=session)
                except Exception as e:
                    logger.error('[!] umbrella_enrichment: Exception in adding the query volume (umbrella):: %s',str(e))
                try:
                    logger.info('[+] Adding umbrella subdomains')
                    add_subdomains(fqdn,session)
                except Exception as e:
                    logger.error('[!] umbrella_enrichment: Exception in adding subdomain (umbrella):: %s',str(e))
                session.commit()
    except Exception:
        logger.error('[!] umbrella_enrichment: general exception (likely issue with the API) ')

def add_screenshot(name,imagepath,crawler_instance,time,page_url,session):
    reference_companyA_dhash=imagehash.hex_to_flathash(ref_screenshot_hashes['companyA']['dhash'],hashsize=8)
    reference_companyB_dhash=imagehash.hex_to_flathash(ref_screenshot_hashes['companyB']['dhash'],hashsize=8)
    reference_companyA_phash=imagehash.hex_to_flathash(ref_screenshot_hashes['companyA']['phash'],hashsize=8)
    reference_companyB_phash=imagehash.hex_to_flathash(ref_screenshot_hashes['companyB']['phash'],hashsize=8)

    page_domain=tldextract.extract(page_url).fqdn.lower()
    imagefile=Image.open(imagepath)

    screenshot_dhash = imagehash.dhash(imagefile)
    distance_dhash_companyA=reference_companyA_dhash-screenshot_dhash
    distance_dhash_companyB=reference_companyB_dhash-screenshot_dhash

    screenshot_phash = imagehash.phash(imagefile)
    distance_phash_companyA=reference_companyA_phash-screenshot_phash
    distance_phash_companyB=reference_companyB_phash-screenshot_phash

    image_size=''.join(str(imagefile.size))
    try:
        ocr_company_name= company_name.lower() in pytesseract.image_to_string(imagepath).lower()
    except Exception :
        ocr_company_name=False


    screenshot=phishdb_schema.Screenshot(screenshot_name=name,
                          dhash_companyA=distance_dhash_companyA,
                          phash_companyA=distance_phash_companyA,
                          phash_companyB=distance_phash_companyB,
                          dhash_companyB=distance_dhash_companyB,
                          image_size=image_size,
                          ocr_companyA=ocr_company_name)
    add_element(screenshot,session)
    add_element(phishdb_schema.Crawler_Screenshot(crawler_instance=crawler_instance,screenshot=screenshot),session)
    if page_domain:
        domain_record=session.query(phishdb_schema.Domain).filter_by(domain=page_domain).first()
        add_element(phishdb_schema.Screenshot_Of_Domain(screenshot=screenshot,domain=domain_record,date=time),session)
    if page_url:
        add_element(phishdb_schema.Screenshot_Has_Url(screenshot=screenshot,date=time,page_url=page_url),session)





def add_shodan_service_banners(ip_record,ip_type,ip,session):
    today=datetime.today().date()
    if ip_type=='ipv4':
        record_exists=session.query(phishdb_schema.Has_Service_Banner).filter_by(ipv4=ip_record,date=today).first()

    elif ip_type=='ipv6':
        record_exists=session.query(phishdb_schema.Has_Service_Banner).filter_by(ipv6=ip_record,date=today).first()

    if not record_exists:
        banners=shodan_data(ip)
        for banner in banners:
            service_banner= session.query(phishdb_schema.Service_Banner).filter_by(service=banner.get('service'),
                                            date=banner.get('date'),
                                            content_type=banner.get('content_type'),
                                            content_length=banner.get('content_length'),
                                            connection_status=banner.get('connection_status'),
                                            set_cookie= banner.get('set_cookie'),
                                            server=banner.get('connection_status'),
                                            expires=banner.get('expires'),
                                            port=banner.get('port'),
                                            error=banner.get('error')).first()
            if not service_banner:
                service_banner=phishdb_schema.Service_Banner(service=banner.get('service'),
                                                date=banner.get('date'),
                                                content_type=banner.get('content_type'),
                                                content_length=banner.get('content_length'),
                                                connection_status=banner.get('connection_status'),
                                                set_cookie= banner.get('set_cookie'),
                                                server=banner.get('connection_status'),
                                                expires=banner.get('expires'),
                                                port=banner.get('port'),
                                                error=banner.get('error'))
                add_element(service_banner,session)

            if ip_type=='ipv4':
                rel=session.query(phishdb_schema.Has_Service_Banner).filter_by(service_banner=service_banner,ipv4=ip_record,date=today).first()
                if not rel:
                    add_element(phishdb_schema.Has_Service_Banner(service_banner=service_banner,ipv4=ip_record,date=today),session)

            elif ip_type=='ipv6':
                rel=session.query(phishdb_schema.Has_Service_Banner).filter_by(service_banner=service_banner,ipv6=ip_record,date=today).first()
                if not rel:
                    add_element(phishdb_schema.Has_Service_Banner(service_banner=service_banner,ipv6=ip_record,date=today),session)


            location=banner.get('location')
            if location:
                fqdn=tldextract.extract(location).fqdn.lower()
                if fqdn:
                    domain_record = session.query(phishdb_schema.Domain).filter_by(domain=fqdn).first()
                    if not domain_record:
                        domain_record=phishdb_schema.Domain(domain=fqdn)
                        add_element(domain_record,session)

                    record_exists=session.query(phishdb_schema.Has_Location_Domain).filter_by(service_banner=service_banner,date=today,domain_id=fqdn).first()
                    if not record_exists:
                        add_element(phishdb_schema.Has_Location_Domain(service_banner=service_banner,date=today,domain_id=fqdn),session)


def rel_structure_exists(structure_id,phish_id,session):
    structure = session.query(phishdb_schema.Structure).filter_by(structure=structure_id).first()
    if not structure:
        add_element(phishdb_schema.Structure(structure=structure_id),session)

    relation=session.query(phishdb_schema.Has_Structure).filter_by(structure_id=structure_id,phish_id=phish_id).first()
    if not relation:
        add_element(phishdb_schema.Has_Structure(structure_id=structure_id,phish_id=phish_id),session)

def add_page_source(page_source,crawler_instance,session):
    if isinstance(page_source,str):
        page_source=page_source.encode()
    page_content_id=hashlib.sha256(page_source).hexdigest()
    content_record=session.query(phishdb_schema.Page_Content).filter_by(page_content_id=page_content_id).first()
    if not content_record:
        add_element(phishdb_schema.Page_Content(page_content_id=page_content_id,page_content=page_source),session)
    rel=session.query(phishdb_schema.Has_Page_Content).filter_by(page_content_id=page_content_id,crawler_instance=crawler_instance).first()
    if not rel:
        add_element(phishdb_schema.Has_Page_Content(page_content_id=page_content_id,crawler_instance=crawler_instance),session)


def update_part(mailpart,phish_id,session):
    mailpart_record=phishdb_schema.Mail_Part(content_type=mailpart['content_type'],
                                filename=mailpart['filename'],
                                content_disposition=mailpart['content_disposition'],
                                content_transfer_encoding=mailpart['content_transfer_encoding'],
                                detected_mimetypes=mailpart['detected_mimetypes']

                            )
    add_element(mailpart_record,session)
    add_element(phishdb_schema.Is_Composed_Of(phish_id=phish_id,msgpart=mailpart_record),session)


    content_id=mailpart['content_hash']
    if content_id:
        content_record=add_content(content_id=content_id, content=mailpart['content'],session=session)
        add_element(phishdb_schema.Has_Content(content=content_record,msgpart=mailpart_record),session)

def sturcture_parsed(phish_id,session):
    structure=session.query(phishdb_schema.Is_Composed_Of).filter_by(phish_id=phish_id).first()
    return structure
