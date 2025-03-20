import email
from email.policy import default as default_policy
from datetime import timezone,datetime

from dateutil import parser as dateparser
import re

import asyncio
import hashlib

import base64
import numpy as np
import cv2
from qreader import QReader
import datefinder
import ipaddress

from .crawl_page import crawl
from .personalized_config import url_rewrite

from . import phishdb_schema
from . import phishdb_layer

from pathlib import Path,os

from io import BytesIO
import zipfile
import  pikepdf

import magic

import fitz
from PIL import Image
from polyfile.magic import MagicMatcher
from bs4 import BeautifulSoup

from .config import company_name
from .phish_logger import Phish_Logger


import pytesseract
pytesseract.pytesseract.tesseract_cmd =r'C:\Program Files\Tesseract-OCR\tesseract.exe'

logger=Phish_Logger.get_phish_logger('phish_logs')

help_desc = '''
Parses a raw email aand extracts information about its header field (SPF,DMARC, DKIM, Received sequence, SMTP server,...)
and its content (mails parts, urls, embedded scripts/urls) and sends the urls and html files to the rawler to be dynamically parsed
'''


def extract_urls(text):
    urls=[]
    soup = BeautifulSoup(text, "html.parser").find_all(lambda t: t.name == "a")
    for a in soup:
        soup_url= a.get("href")
        if soup_url and soup_url not in urls:
            urls.append(soup_url)
    regx=r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    urls= list(set(re.findall(regx, text)) | set(urls))
    urls=list({url_rewrite(url) for url in urls })
    return urls

def start_crawler(phish_id,emailrecord,source_type,phish_url=None,htmlfile=None,session=None):
    try:
        asyncio.get_event_loop().run_until_complete(crawl(phish_url=phish_url,
                                                                     htmlfile=htmlfile,
                                                                     phish_id=phish_id,
                                                                     source_type=source_type,
                                                                     emailrecord=emailrecord,
                                                                     session=session))
    except Exception as e:
        if str(e).startswith('There is no current event loop in thread'):
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            asyncio.get_event_loop().run_until_complete(crawl(phish_url=phish_url,
                                                                         htmlfile=htmlfile,
                                                                         phish_id=phish_id,
                                                                         source_type=source_type,
                                                                         emailrecord=emailrecord,
                                                                         session=session))
        else:
            logger.warning('Exception embedded in crawl_url :: %s',str(e))

def decode_texthtml(msg,phish_id,emailrecord,htmlbytes=None,session=None):
    logger.info('[+] Parsing HTML MIME Type')
    try:
        content=htmlbytes if htmlbytes else msg.get_content()
        if isinstance(content,bytes):
            content=content.decode(errors='ignore')
        content=content.encode( 'utf-8', errors='ignore').decode('utf-8')


        Path(  os.path.join( os.path.abspath(os.path.dirname(__file__)), 'HTML_content') ).mkdir(parents=True, exist_ok=True)
        t=datetime.now().strftime("%Y-%m-%d_%H%M%S")
        filename=phish_id+'_'+t+'.htm'
        filepath= os.path.join( os.path.abspath(os.path.dirname(__file__)), 'HTML_content', filename)
        f = open(filepath, "a",encoding="utf-8")
        f.write(content)
        f.close()
        start_crawler(phish_id,emailrecord,'html',phish_url=filepath,session=session)



        urls=extract_urls(content)
        for url in urls:
            start_crawler(phish_id,emailrecord,'url',phish_url=url,session=session)

    except Exception as e:
        logger.error('[!] decode_texthtml :: phish_id: %s Error: %s',str(phish_id),str(e))

def decode_textplain(msg,phish_id,emailrecord,session):

    try:
        logger.info('[+] Parsing TEXT MIME Type')
        text=msg.get_content()
    except Exception:
        text=base64.b64decode(str(msg._payload))

    if isinstance(text,bytes):
        text=text.decode(errors='ignore')
    try:
        if 'html' in text or 'script' in text:
            Path(  os.path.join( os.path.abspath(os.path.dirname(__file__)), 'HTML_content') ).mkdir(parents=True, exist_ok=True)
            t=datetime.now().strftime("%Y-%m-%d_%H%M%S")
            filename=phish_id+'_'+t+'.htm'
            filepath= os.path.join( os.path.abspath(os.path.dirname(__file__)), 'HTML_content', filename)
            f = open(filepath, "a",encoding="utf-8")
            f.write(text)
            f.close()
            start_crawler(phish_id,emailrecord,'html',phish_url=filepath,session=session)



        urls=extract_urls(text)
        for url in urls:
            start_crawler(phish_id,emailrecord,'url',phish_url=url,session=session)
    except Exception as e:
        logger.error('[!] decode_textplain :: phish_id: %s Error: %s',str(phish_id),str(e))





def decode_rfc822(msg,phish_id,emailrecord,session):

    for part in (msg.iter_parts()):
        content=part.get_content()
        #decode base64 encoded attachment
        try:
            content=base64.b64decode(str(content))
        except Exception:
            pass

        try:

            if isinstance(content,str):
                content=content.encode()
            new_msg=email.message_from_bytes(content,policy=default_policy)

            parse_by_mime_type(new_msg,phish_id,emailrecord,session=session)

        except Exception as e:
            logger.error('[!] decode_rfc822 :: Error parsing phish email id: %s Error: %s',str(phish_id),str(e))


def decode_vndmsoutlook(msg,phish_id,emailrecord,session):
    logger.info('[+] Parsing VNDMSOUTLOOK MIME Type')
    content=msg.get_content()
    newnew=content[content.index(b'From'):] #Remove Break evasion bytes
    new_msg=email.message_from_bytes(newnew,policy=default_policy)
    parse_by_mime_type(new_msg,phish_id,emailrecord,session=session)


def decode_octetstream(msg,phish_id,emailrecord,session):
    logger.info('[+] Parsing Octet STREAM MIME Type')
    content=msg.get_content()

    if msg.get_filename().endswith('.eml') or '.eml.' in msg.get_filename().lower() :
        if isinstance(content,str):
            content=content.encode()
        new_msg=email.message_from_bytes(content,policy=default_policy)
        parse_by_mime_type(new_msg,phish_id,emailrecord,session=session)
    else:
        try:
            if 'pdf' in magic.from_buffer(content).lower() or msg.get_filename().endswith('.pdf') :
                decode_pdf(msg,phish_id,emailrecord,session=session)
            else:
                if isinstance(content,bytes):
                    content=content.decode(errors='ignore')

                if 'html' in content or 'script' in content:
                    decode_texthtml(msg,phish_id,emailrecord,session=session)
                else:
                    urls=extract_urls(content)
                    for url in urls:
                        start_crawler(phish_id,emailrecord,'url',phish_url=url,session=session)





        except Exception as e:
            logger.error('[!] decode_octetstream :: phish_id: %s Error %s',str(phish_id),str(e))

def extract_images_from_pdf(filename,phish_id,emailrecord,session):
    try:
        # open the file
        pdf_file = fitz.open(filename)

        # iterate over PDF pages
        for page_index in range(len(pdf_file)):

            # get the page itself
            page = pdf_file[page_index]
            image_list = page.get_images()

            # printing number of images found in this page
            if image_list:
                logger.info("[+] Found a total of %d images in page %d",len(image_list),page_index)
            else:
                logger.info("[!] No images found on page %d", page_index)
            for _, img in enumerate(page.get_images(), start=1):

                # get the XREF of the image
                xref = img[0]

                # extract the image bytes
                base_image = pdf_file.extract_image(xref)
                image_bytes = base_image["image"]

                decode_image(msg=None,phish_id=phish_id,emailrecord=emailrecord,im_bytes=image_bytes,session=session)
                # get the image extension
                #image_ext = base_image["ext"]
    except Exception as e:
        logger.error('[!] Exception extract_images_from_pdf :: phish_id: %s Error:',str(phish_id),str(e))


def extract_from_pdf(filename,phish_id,emailrecord,session):
    try:
        total_text=''

        doc = fitz.open(filename)
        zoom = 4
        mat = fitz.Matrix(zoom, zoom)

        for i in range(len(doc)):
            val = os.path.join( os.path.abspath(os.path.dirname(__file__)), f"{filename.replace('.pdf','')}_image_{i+1}.png")
            page = doc.load_page(i)
            pix = page.get_pixmap(matrix=mat)
            pix.save(val)
            with open(val,'rb') as page_screenshot:
                f=page_screenshot.read()
                decode_image(msg=None,phish_id=phish_id,emailrecord=emailrecord,im_bytes=f,session=session)

            text=pytesseract.image_to_string(Image.open(val))
            total_text+=' '+text

        doc.close()
        urls=extract_urls(total_text)

        for url in urls:
            logger.info('[+] Found url in pdf text: %s',url)
            start_crawler(phish_id,emailrecord,'url',phish_url=url,session=session)





    except Exception as e:
        logger.error('[!] Exception extract_text_from_pdf :: phish_id: %s Error :  %s',str(phish_id),str(e))


def decode_pdf(msg,phish_id,emailrecord,msg_bytes=None,session=None) :
    logger.info('[+] Parsing PDF MIME Type')
    try:
        content=msg.get_content() if msg else msg_bytes


        Path( os.path.join( os.path.abspath(os.path.dirname(__file__)), 'PDF_content')).mkdir(parents=True, exist_ok=True)
        t=datetime.now().strftime("%Y-%m-%d_%H%M%S")
        pdfname=phish_id+'_'+t+'.pdf'
        pdfpath= os.path.join( os.path.abspath(os.path.dirname(__file__)), 'PDF_content', pdfname)
        f = open(pdfpath, "wb")
        f.write(content)
        f.close()

        try:
            #Crawl embedded URLs in the PDF file
            logger.info('[+] Parsing PDf for embedded urls...')
            with pikepdf.open(pdfpath) as pdf_file:
                # iterate over PDF pages
                for page in pdf_file.pages:
                    page_annots=page.get("/Annots")
                    if page_annots:
                        for annots in page.get("/Annots"):
                            a= annots.get("/A")
                            if a:
                                uri =a.get("/URI")
                                if uri:
                                    logger.info("[+] Embedded URL Found:", uri)
                                    start_crawler(phish_id,emailrecord,'url',phish_url=str(uri),session=session)

        except Exception as e:
            logger.error('[!] Exception in extracting embedded urls:: phish_id: %s Error: %s',str(phish_id),str(e))
        #Extract text from pdf and crawl any found urls
        logger.info('[+] Parsing PDf for urls in text or in images...')
        extract_from_pdf(filename=pdfpath,phish_id=phish_id,emailrecord=emailrecord,session=session)
        logger.info('[+] Parsing PDf for images...')
        #Extract images and find QR codes if any
        extract_images_from_pdf(filename=pdfpath,phish_id=phish_id,emailrecord=emailrecord,session=session)
    except Exception as e:
        logger.error('[!] decode_pdf :: phish_id: %s Error:',str(phish_id),str(e))


def decode_zip(msg,phish_id,emailrecord,session):
    logger.info('[+] Parsing ZIP MIME Type')
    try:
        content=msg.get_content()

        zip_buffer=BytesIO(content)

        with zipfile.ZipFile(zip_buffer,"r") as zip_ref:
            for file_info in zip_ref.infolist():
                with zip_ref.open(file_info) as file:
                    new_content=file.read()
                    mime_type=magic.from_buffer(new_content).lower()
                    if 'pdf' in mime_type:
                        decode_pdf(msg=None,phish_id=phish_id,emailrecord=emailrecord,msg_bytes=new_content,session=session)
                    elif 'image' in mime_type:
                        decode_image(msg=None,phish_id=phish_id,emailrecord=emailrecord,im_bytes=new_content,session=session)
                    elif 'html' in mime_type:
                        decode_texthtml(msg=None,phish_id=phish_id,emailrecord=emailrecord,htmlbytes=new_content,session=session)


    except Exception as e:
        logger.error('[!] decode_zip :: phish_id: %s :: Error: %s, ',str(phish_id),str(e))


def decode_image(msg,phish_id,emailrecord,im_bytes=None,session=None):
    logger.info('[+] Parsing Image MIME Type')

    image_bytes=im_bytes if im_bytes else msg.get_content()

    if image_bytes:
        # read image as an numpy array
        image = np.asarray(bytearray(image_bytes), dtype="uint8")
        # use imdecode function
        image = cv2.imdecode(image, cv2.IMREAD_COLOR)

    # initialize the cv2 QRCode detector
    try:
        # detect and decode
        data=None
        detector = cv2.QRCodeDetector()
        data, vertices_array, binary_qrcode = detector.detectAndDecode(image)

    except Exception as e:
        logger.error('[!] decode_image :: phish_id: %s :: detectAndDecode :: Error: %s',str(phish_id),str(e))

    try:
        if not data or data =='':
            qreader=QReader()
            qr_result=qreader.detect_and_decode(image=image)
            if qr_result:
                data=qr_result[0]

    except Exception as e:
        logger.error('[!] decode_image :: phish_id: %s :: QReader :: Error: %s',str(phish_id),str(e))

    try:
        if data :
            if not data.startswith('http'):
                data='https://'+data
            start_crawler(phish_id,emailrecord,'QR code',phish_url=data,session=session)

    except Exception as e:
        logger.error('[!] decode_image :: phish_id: %s Error: %s',str(phish_id),str(e))




def decode_multipart(msg,phish_id,emailrecord,session):
    logger.info('[+] Parsing Multipart MIME Type')

    for part in msg.iter_parts():
        parse_by_mime_type(part,phish_id,emailrecord,session=session)




def parse_by_mime_type(emailpart,phish_id,emailrecord,session):

    content_type=emailpart.get_content_type()
    if content_type.startswith('multipart/'):
        decode_multipart(emailpart,phish_id,emailrecord,session=session)


    elif content_type=='message/rfc822':
        decode_rfc822(emailpart,phish_id,emailrecord,session=session)

    elif content_type.startswith('image/') or  content_type=='html+picture/jpg+svg' :
        decode_image(emailpart,phish_id,emailrecord,session=session)

    elif content_type =="application/octet-stream":
        decode_octetstream(emailpart,phish_id,emailrecord,session=session)

    elif content_type =="application/vnd.ms-outlook":
        decode_vndmsoutlook(emailpart,phish_id,emailrecord,session=session)

    elif content_type =="text/html" or content_type =="application/html":
        decode_texthtml(emailpart,phish_id,emailrecord,session=session)


    elif content_type =="text/plain" or content_type=='plain/text' or content_type=='text/rtf' or content_type=='application/rtf':
        decode_textplain(emailpart,phish_id,emailrecord,session=session)

    elif content_type =="application/pdf":
        decode_pdf(emailpart,phish_id,emailrecord,session=session)

    elif content_type =="application/zip" or content_type=='application/x-zip-compressed' :
        decode_zip(emailpart,phish_id,emailrecord,session=session)

    elif emailpart.get_filename():
        content= emailpart.get_content()
        if isinstance(content,bytes):
            content=content.decode(errors='ignore')
        if  emailpart.get_filename().endswith('.htm') or emailpart.get_filename().endswith('.html') or 'html' in content or 'script' in content:
            decode_texthtml(emailpart,phish_id,emailrecord,session=session)

    else:
        logger.error('[!] Unexpected email MIME type: %s',str(content_type))


def validate_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        if isinstance(ip_obj, ipaddress.IPv4Address):
            return "IPv4"
        elif isinstance(ip_obj, ipaddress.IPv6Address):
            return "IPv6"
    except ValueError:
        return "Invalid IP"
def extract_ip(field):
    matches = re.findall(r'\((.*?)\)|\[(.*?)\]', field)
    # Flatten the list and remove empty strings
    extracted = [match[0] if match[0] else match[1] for match in matches]
    for element in extracted :
        type_ip=validate_ip(element)
        if type_ip =='IPv6':
            return ('IPv6',element)
        elif type_ip =='IPv4':
            return ('IPv4',element)
    return (None,None)


def header_info(msg):
    header={}
    to={}
    if 'To' in msg.keys():
        to_v=msg.get('To')
        s=re.search(r'\<([^\s]+)\>',to_v)

        if s:
            to['Address']=s.group(1)
            to['Name']=to_v[:to_v.index('<')]
        else:
            to['Address']=to_v

    header['To']=to
    header['Received']=[]


    for key,value in msg.items():
        if key == 'Received':
            to=header.get('To')
            if to:
                if to.get('Address') not in value:
                    #ignore last Received record since it contains the target email address (confidential)

                    try:
                        raw_recv=value.lower()
                        return_recv={}
                        if raw_recv.startswith('from '):
                            split1=raw_recv.split('by ')
                            _, _, from_field = split1[0].partition("from ")
                            from_domain=from_field.split(' ')[0]
                            return_recv['From']=from_domain
                            ip_res=extract_ip(from_field)
                            if ip_res[0]=='IPv4':
                                from_ipv4=ip_res[1]
                                return_recv['From_ipv4']=from_ipv4
                            elif ip_res[0]=='IPv6':
                                from_ipv6=ip_res[1]
                                return_recv['From_ipv6']=from_ipv6
                            if 'by ' in raw_recv:
                                split2=split1[1].split(';')
                                by_field=split2[0]
                                by_domain=by_field.split(' ')[0]
                                return_recv['By']=by_domain
                                ip_res=extract_ip(by_field)
                                if ip_res[0]=='IPv4':
                                    by_ipv4=ip_res[1]
                                    return_recv['By_ipv4']=by_ipv4
                                elif ip_res[0]=='IPv6':
                                    by_ipv6=ip_res[1]
                                    return_recv['By_ipv6']=by_ipv6
                            try:
                                rcv_date=None
                                return_recv['Day']=None
                                return_recv['Time']=None
                                if len(split2)>1:
                                    date_field=split2[-1]
                                    rcv_date = dateparser.parse(date_field,fuzzy=True).astimezone(timezone.utc)
                                else:
                                    date_field=split1[1].split('\t')[-1]
                                    matches = list(datefinder.find_dates(date_field))
                                    if len(matches)==1:
                                        rcv_date=matches[0].astimezone(timezone.utc)
                                if rcv_date:
                                    return_recv['Day']=rcv_date.date()
                                    return_recv['Time']=rcv_date.time()
                            except Exception as e:
                                logger.error('[!] Exception in handling the date from the Received field in '
                                            'the message header :: %s :: Received-Field= %s',
                                            str(e),str(raw_recv))

                            header['Received'].append(return_recv)

                        elif raw_recv.startswith('by '):
                            split1=raw_recv.split(';')
                            if len(split1)>1:
                                matches = list(datefinder.find_dates(split1[-1]))
                                return_recv['rcv_date']=matches[0].astimezone(timezone.utc)
                                by_value=split1[0].split()[1]
                                by_value_check=extract_ip('('+by_value+')')
                                if by_value_check[0] == 'IPv4':
                                    return_recv['by_ipv4']=by_value_check[1]
                                elif by_value_check[0]=='IPv6':
                                    return_recv['by_ipv6']=by_value_check[1]
                                else:
                                    return_recv['by_address']=by_value
                            else:
                                logger.error('[!] Exception :: No data extracted from the Received header :: %s', raw_recv )


                        else:
                            logger.error('[!] Unexpected Received field :: %s',raw_recv)
                    except Exception as e:
                        logger.error('[!] Exception in handling Received field from the message header :: %s',str(e))

    authresults={}

    authenticationresults=None
    if 'Authentication-Results' in msg.keys():
        authenticationresults=msg.get('Authentication-Results')
    elif 'X-Ms-Exchange-Authentication-Results' in msg.keys():
        authenticationresults=msg.get('X-Ms-Exchange-Authentication-Results')
    if authenticationresults:
        s=re.search(r'spf=([^\s]+)\s',authenticationresults)
        authresults['spf']=s.group(1) if s else None
        s=re.search(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}',authenticationresults )
        authresults['sender_ip']=s.group() if s else None
        s=re.search(r'smtp\.mailfrom=([^\s]+);',authenticationresults)
        authresults['smtp.mailfrom']=s.group(1) if s else None
        s=re.search(r'dkim=([^\s]+)\s',authenticationresults)
        authresults['dkim']=s.group(1) if s else None
        s=re.search(r'dmarc=([^\s]+)\s',authenticationresults)
        authresults['dmarc']=s.group(1) if s else None
        s=re.search(r'compauth=([^\s]+)\s',authenticationresults)
        authresults['compauth']=s.group(1) if s else None
        s=re.search(r'reason=([^\s]+)',authenticationresults)
        authresults['reason']=s.group(1) if s else None

    header['Authentication-Results']=authresults

    header['Content-Transfer-Encoding']=msg.get('Content-Transfer-Encoding')
    header['Content-Type']=msg.get('Content-Type')


    dkim_signature=None
    if 'Dkim-Signature' in msg.keys():
        dkim_signature={}
        for element in msg.get('Dkim-Signature').split(';'):
            try:
                element=element.strip('\t').strip(' ')
                new_element=element.split('=',1)
                key=new_element[0].strip(' ')
                value= datetime.utcfromtimestamp(int(new_element[1])) if key=='t' else new_element[1]
                dkim_signature[key]=value
            except Exception as e:
                logger.error('[!] Exception in handling Dkim-Signature field from the message header :: %s',str(e))


    header['Dkim-Signature']=dkim_signature
    from_d={}
    if 'From' in msg.keys():
        from_v=msg.get('From')
        s=re.search(r'\<([^\s]+)\>',from_v)
        if s:
            from_d['Address']=s.group(1)
            from_d['Name']=from_v[:from_v.index(' <')]
        else:
            from_d['Address']=from_v
            from_d['Name']=None

    header['From']=from_d


    header['MIME-Version']=msg.get('MIME-Version')
    header['Message-Id']=msg.get('Message-Id')

    spf_d={}
    if 'Received-Spf' in msg.keys():
        try:
            spf=msg.get('Received-Spf')
            s=re.search(r'receiver=([^\s]+);',spf)
            spf_d['receiver']=s.group(1) if s else None
            s=re.search(r'client-ip=([^\s]+);',spf)
            spf_d['client_ip']=s.group(1) if s else None
            s=re.search(r'helo=([^\s]+);',spf)
            spf_d['helo']=s.group(1) if s else None
            spf_d['pr']=spf[spf.rfind('pr=')+3::] if 'pr=' in spf else None
            spf_d['Spf result']=spf[:spf.index(' (')]
            s=re.search(r'\(([^\)]+)\)',spf)
            spf_d['Spf details']=s.group(1) if s else None
            s=re.search(r'domain\sof\s([^\s]+)\s',spf)
            spf_d['domain']=s.group(1) if s else None
        except Exception as e:
            logger.error('[!] Exception in handling Received-Spf field from the message header :: %s',str(e))


    header['Received-Spf']=spf_d



    header['Return-Path']=msg.get('Return-Path')
    header['Subject']=msg.get('Subject')

    return header


def add_magic(content):
    mimetypes=[]
    for match in MagicMatcher.DEFAULT_INSTANCE.match(content):
        for mimetype in match.mimetypes:
            if mimetype not in mimetypes:
                mimetypes.append(mimetype)
    return mimetypes



def parse_structure(rawemail,structure,phish_id,session):
    counter=0
    for part in rawemail.iter_parts():
        counter+=1
        content_type=part.get_content_type()
        new_structure={}
        structure[str(counter)+'_'+content_type]=new_structure
        if not part.get_content_type().startswith('multipart'):
            mailpart={}
            mailpart['content_type']=content_type
            mailpart['filename']=''
            try:
                mailpart['filename']=part.get_filename()
            except Exception:
                pass
            mailpart['content_disposition']=part.get_content_disposition()
            mailpart['content_transfer_encoding']=part.get('Content-Transfer-Encoding')
            content=part.get_content()

            if isinstance(content,str):
                content=content.encode()
            elif isinstance(content,email.message.EmailMessage):
                content=content.as_bytes()

            mailpart['content']=content
            mailpart['content_hash']=hashlib.sha256(content).hexdigest()
            detected_mimetypes=add_magic(content)
            mailpart['detected_mimetypes']=','.join(detected_mimetypes)

            phishdb_layer.update_part(mailpart,phish_id,session=session)
            try:

                if content_type =='message/rfc822':
                    for subpart in part.iter_parts():
                        content=subpart.get_content()
                        #decode base64 encoded attachments
                        try:
                            content=base64.b64decode(str(content))
                        except Exception:
                            pass
                        try:
                            new_msg=email.message_from_bytes(content,policy=default_policy)
                            parse_structure(new_msg,new_structure,phish_id,session=session)
                        except Exception as e:
                            logger.error('[!] parse_structure :: rfc822, Error parsing :: ',str(e))
                elif content_type=='application/vnd.ms-outlook':
                    content=content[content.index(b'From'):] #Remove Break evasion bytes
                    new_msg=email.message_from_bytes(content,policy=default_policy)
                    parse_structure(new_msg,new_structure,phish_id,session=session)


                elif content_type =='application/octet-stream' :
                    try:
                        if part.get_filename().lower().endswith('.eml'):
                            new_msg=email.message_from_bytes(content, policy=default_policy)
                            parse_structure(new_structure,new_structure,phish_id,session=session)
                    except Exception as e:
                        logger.error('[!] parse_structure :: Error ',str(e))
            except Exception as e:
                logger.error('[!] parse_structure :: Error extracting structure :: ',str(e))
    return structure


def parse_data(phish_id,rawemail_inbytes):
    try:
        #update DB
        session,db=phishdb_layer.open_session()
        msg_exists=session.query(phishdb_schema.Malicious_Email_Message).filter_by(phish_id=phish_id).first()
        if not msg_exists:

            rawemail= email.message_from_bytes(rawemail_inbytes,policy=default_policy)

            #header
            day,time=None,None
            if 'Date' in rawemail.keys():
                date = dateparser.parse(rawemail.get('Date')).astimezone(timezone.utc)
                day=date.date()
                time=date.time()


            maliciousemail=phishdb_layer.add_malicious_msg(phish_id,day,time,origin=company_name,session=session)
            if not phishdb_layer.sturcture_parsed(phish_id,session):
                email_structure={}
                parse_structure(rawemail,email_structure,phish_id,session=session)
                phishdb_layer.rel_structure_exists(str(email_structure),phish_id,session=session)


            try:
                header=header_info(rawemail)
                phishdb_layer.update_header(maliciousemail,header,session=session)
            except Exception as e:
                logger.critical('[!] Header not extracted for phish_id %s :: %s',str(phish_id),str(e))

            try:
                parse_by_mime_type(rawemail,phish_id,maliciousemail,session=session)
            except Exception as e:
                logger.critical('[!] Analysis skipped for phish_id %s :: %s',str(phish_id),str(e))
            logger.info('[+] End parsing phish email id %s',str(phish_id))
        phishdb_layer.close(session,db)
    except Exception as e:
        logger.error('[!] Analysis skipped for %s, please inverstigate :: %s',str(phish_id), str(e))
