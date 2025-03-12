from sqlalchemy import  Integer,String,DateTime,Time, ForeignKey,Column,LargeBinary,Float,Boolean,ARRAY
from sqlalchemy.orm import relationship,declarative_base


Base = declarative_base()


help_desc = '''
PhishDB schema
'''

class Malicious_Email_Message(Base):
    __tablename__ = 'tbl_malicious_email_message'
    phish_id = Column(String, primary_key=True)
    receiving_date=Column(DateTime)
    receiving_time=Column(Time)

    hasheader=relationship('Has_Header',back_populates='malmsg')
    iscomposedof=relationship('Is_Composed_Of',back_populates='malmsg')
    crawlerinstances=relationship('Generates_Crawler_Instance',back_populates='malmsg')
    sender=relationship('From_Sender',back_populates='malmsg')
    origin=Column(String(50))

    collected_domain=relationship('Associated_With_Message',back_populates='message')

    structure=relationship('Has_Structure',back_populates='message')

    def __repr__(self):
        return f'Email id: {self.phish_id}'


class Has_Header(Base):
    __tablename__ = 'rel_has_header'

    email_header_id=Column(Integer, ForeignKey('tbl_email_header.header_id'),primary_key=True)
    email_header = relationship('Email_Header', back_populates='hasheader', uselist=False)

    phish_id=Column(String, ForeignKey('tbl_malicious_email_message.phish_id'),primary_key=True)
    malmsg = relationship('Malicious_Email_Message', back_populates='hasheader', uselist=False)

    def __repr__(self):
        return f'Has_Header id: {self.email_header_id}'


class Mail_Part(Base):
    __tablename__ = 'tbl_mail_part'
    part_id=  Column(Integer, primary_key=True)
    content_type= Column(String(150))
    filename=Column(String(150))
    content_disposition=Column(String(50))
    content_transfer_encoding=Column(String(20))
    detected_mimetypes=Column(String(1500))
    has_content=relationship('Has_Content',back_populates='msgpart')

    composes=relationship('Is_Composed_Of',back_populates='msgpart')

    def __repr__(self):
        return f'Mail_Part: id:{self.part_id}'


class Has_Content(Base):
    __tablename__ = 'rel_has_content'

    msgpart_id=Column(Integer, ForeignKey('tbl_mail_part.part_id'),primary_key=True)
    msgpart = relationship('Mail_Part', back_populates='has_content')

    content_id=Column(String, ForeignKey('tbl_content.content_id'),primary_key=True)
    content = relationship('Content', back_populates='iscontentof')

    def __repr__(self):
        return f'Has_Content: id: {self.part_id}'


class Content(Base):
    __tablename__ = 'tbl_content'
    content_id=  Column(String, primary_key=True) #hash of the content
    content=Column(LargeBinary)

    iscontentof=relationship('Has_Content',back_populates='content')

    def __repr__(self):
        return f'content: id: {self.content_id}'


class Is_Composed_Of(Base):
    __tablename__ = 'rel_is_composed_of'

    phish_id=Column(String, ForeignKey('tbl_malicious_email_message.phish_id'),primary_key=True)
    malmsg = relationship('Malicious_Email_Message', back_populates='iscomposedof', uselist=False)


    part_id=Column(Integer, ForeignKey('tbl_mail_part.part_id'),primary_key=True)
    msgpart = relationship('Mail_Part', back_populates='composes')

    def __repr__(self):
        return f'Phish {self.phish_id} is composed of {self.part_id}'



class Generates_Crawler_Instance(Base):
    __tablename__ = 'rel_generates_crawler_instance'

    phish_id=Column(String, ForeignKey('tbl_malicious_email_message.phish_id'),primary_key=True)
    malmsg = relationship('Malicious_Email_Message', back_populates='crawlerinstances', uselist=False)

    crawler_instance_id=Column(Integer, ForeignKey('tbl_crawler_instance.crawler_instance_id'),primary_key=True)
    instance = relationship('Crawler_Instance', back_populates='generatedfrom')

    def __repr__(self):
        return f'Phish {self.phish_id} generates crawler_instance id: {self.crawler_instance_id}'



class Has_Auth_Results(Base):
    __tablename__ = 'rel_has_auth_results'

    header_id=Column(Integer, ForeignKey('tbl_email_header.header_id'),primary_key=True)
    email_header = relationship('Email_Header', back_populates='hasauthresults', uselist=False)

    authresults_id=Column(Integer, ForeignKey('tbl_authentication_results.authresults_id'),primary_key=True)
    authresults = relationship('Authentication_Results', back_populates='associatedheader')

    def __repr__(self):
        return f'Header {self.header_id} has auth_results id: {self.authresults_id}'

class Domain(Base):
    __tablename__ ='tbl_domain'
    domain = Column(String(1000), primary_key = True)

    associateddkimsignature=relationship('Associated_Dkim_Domain',back_populates='domain')
    smtp_mailfrom=relationship('SMTP_Mail_From',back_populates='domain')
    received_from=relationship('Received_From',back_populates='domain')
    received_by=relationship('Received_By',back_populates='domain')
    domain_to_ip=relationship('Has_IPv4',back_populates='domain')
    domain_to_ipv6=relationship('Has_IPv6',back_populates='domain')
    helo_domain=relationship('Has_Helo_Domain',back_populates='helo_domain')
    spf_receiver_domain=relationship('Receiver_Domain',back_populates='receiver_domain')
    requested_domain=relationship('Requests_Domain',back_populates='requested_domain')
    response_domain=relationship('Response_From_FQDN',back_populates='domain')
    tls_certificate=relationship('Has_TLS_Certificate',back_populates='domain')
    is_domain_name_from_whois=relationship('Has_Domain_Name',back_populates='domain')
    is_nameserver=relationship('Has_Name_Server',back_populates='domain')
    is_whoisserver=relationship('Has_Whois_Server',back_populates='domain')
    is_subjectalternativename=relationship('Has_Subject_Alternative_Name',back_populates='domain')
    has_whois_record=relationship('Has_Whois_Record',back_populates='domain')
    message=relationship('Associated_With_Message',back_populates='domain')
    risk_score=relationship('Has_Risk_Score',back_populates='domain')
    umbrella_security_information=relationship('Has_Umbrella_Security_Information',back_populates='domain')
    query_volume=relationship('Has_Query_Volume',back_populates='domain')
    screenshot=relationship('Screenshot_Of_Domain',back_populates='domain')
    service_banner=relationship('Has_Location_Domain',back_populates='domain')


    def __repr__(self):
        return f'domain: {self.domain}'


class Has_Dkim_Signature(Base):
    __tablename__ = 'rel_has_dkim_signature'

    dkimsignature_id=Column(Integer, ForeignKey('tbl_dkim_signature.dkimsignature_id'),primary_key=True)
    dkimsignature = relationship('Dkim_Signature', back_populates='hasdkimsignature', uselist=False)

    authresults_id=Column(Integer, ForeignKey('tbl_authentication_results.authresults_id'),primary_key=True)
    authresults = relationship('Authentication_Results', back_populates='associateddkimsignature')

    def __repr__(self):
        return f'Auth Results {self.authresults_id} have dkim_signature id: {self.dkimsignature_id}'


class Dkim_Signature(Base):
    __tablename__ = 'tbl_dkim_signature'
    dkimsignature_id = Column(Integer, primary_key=True)

    hasdkimsignature=relationship('Has_Dkim_Signature',back_populates='dkimsignature')
    version=Column(String(10)) # the version of the DKIM signature specification in use
    cryptographic_algorithm=Column(String(20)) # specifies the cryptographic algorithm used for the signature
    query_method=Column(String(20)) # indicates how the public key for the signature can be retrieved
    canonicalization = Column(String(20)) # describes how the email headers and body should be prepared for signing
    selector= Column(String(150)) #a label used to choose the public key from DNS. It's essentially a named key for the domain.
    associated_domain=relationship('Associated_Dkim_Domain',back_populates='dkimsignature')
    signature_creation_time=Column(DateTime)
    signed_headers=Column(String(5000)) #Lists the email headers that are included in the signature.
    message_hash= Column(String(500)) # represents the hash of the email body content.
    signature= Column(String(500)) # The digital signature

    def __repr__(self):
        return f'dkim_signature id: {self.dkimsignature_id}'

class Associated_Dkim_Domain(Base):
    __tablename__ = 'rel_associated_dkim_domain'

    dkimsignature_id=Column(Integer, ForeignKey('tbl_dkim_signature.dkimsignature_id'),primary_key=True)
    dkimsignature = relationship('Dkim_Signature', back_populates='associated_domain', uselist=False)

    domain_id=Column(String, ForeignKey('tbl_domain.domain'),primary_key=True)
    domain = relationship('Domain', back_populates='associateddkimsignature')

    def __repr__(self):
        return f'DKIM signature {self.dkimsignature_id} associated to domain {self.domain_id}'


class IPv4(Base):
    __tablename__="tbl_ipv4"
    ipv4_address=Column(String(15), primary_key=True)
    ip_to_domain=relationship('Has_IPv4', back_populates='ip')
    spf_client_ip=relationship('Has_Client_Ip',back_populates='client_ip')

    service_banner=relationship('Has_Service_Banner',back_populates='ipv4')


    def __repr__(self):
        return f'IP: {self.ip_address}'



class SMTP_Mail_From(Base):
    __tablename__ = 'rel_smtp_mail_from'

    domain_id=Column(String, ForeignKey('tbl_domain.domain'),primary_key=True)
    domain=relationship('Domain',back_populates='smtp_mailfrom')

    authresusts_id=Column(Integer, ForeignKey('tbl_authentication_results.authresults_id'),primary_key=True)
    authresults=relationship('Authentication_Results',back_populates='smtp_mailfrom')

    def __repr__(self):
        return f'smtp_mail_from domain {self.domain_id} with authresults_id {self.authresusts_id}'


class Authentication_Results(Base):
    __tablename__ = 'tbl_authentication_results'
    authresults_id=Column(Integer, primary_key=True)
    associatedheader = relationship('Has_Auth_Results',back_populates="authresults",uselist=False)
    spf_check=Column(String(100)) #spf decision
    dkim_check=Column(String(100)) #dkim decision
    dmarc_check=Column(String(100))# dmarc decision
    compauth_check=Column(String(100)) #composite authentication (https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/email-authentication-about?view=o365-worldwide#composite-authentication)
    reason=Column(String(100)) #reason
    associateddkimsignature= relationship('Has_Dkim_Signature',back_populates="authresults")
    smtp_mailfrom=relationship("SMTP_Mail_From", back_populates='authresults')

    def __repr__(self):
        return (f'authenication results: spf: {self.spf} , '
            f'smtp_mailfrom: {self.smtp_mailfrom}, '
            f'dkim: {self.dkim} , dmarc: {self.dmarc}, compauth: {self.compauth}')


class Has_Received_Field(Base):
    __tablename__='rel_has_received_field'

    received_id=Column(Integer, ForeignKey('tbl_received.received_id'),primary_key=True)
    received=relationship('Received',back_populates='header')

    header_id=Column(Integer, ForeignKey('tbl_email_header.header_id'),primary_key=True)
    header=relationship('Email_Header',back_populates='received')

    def __repr__(self):
        return f'header {self.header_id} has Received field id {self.received_id}'

class Sender(Base):
    __tablename__='tbl_sender'
    address=Column(String(800), primary_key=True)
    name=Column(String(200))
    malmsg=relationship('From_Sender',back_populates='sender')

    def __repr__(self):
        return f'sender address id {self.address}'

class From_Sender(Base):
    __tablename__='rel_from_sender'

    sender_address=Column(String, ForeignKey('tbl_sender.address'),primary_key=True)
    sender=relationship('Sender',back_populates='malmsg')

    phish_id=Column(String, ForeignKey('tbl_malicious_email_message.phish_id'),primary_key=True)
    malmsg=relationship('Malicious_Email_Message',back_populates='sender')

    def __repr__(self):
        return f'The message {self.phish_id} is received from Sender {self.sender_address}'



class Received_From(Base):
    __tablename__='rel_received_from'

    received_id=Column(Integer, ForeignKey('tbl_received.received_id'),primary_key=True)
    received=relationship('Received',back_populates='received_from')

    domain_id=Column(String, ForeignKey('tbl_domain.domain'),primary_key=True)
    domain=relationship('Domain',back_populates='received_from')

    def __repr__(self):
        return f"Received field {self.received_id} from hop domain is {self.domain_id}"

class Received_By(Base):
    __tablename__='rel_received_by'

    received_id=Column(Integer, ForeignKey('tbl_received.received_id'),primary_key=True)
    received=relationship('Received',back_populates='received_by')

    domain_id=Column(String, ForeignKey('tbl_domain.domain'),primary_key=True)
    domain=relationship('Domain',back_populates='received_by')

    def __repr__(self):
        return f"Received field {self.received_id} to hop domain is {self.domain_id}"


class Received(Base):
    __tablename__='tbl_received'
    received_id=Column(Integer, primary_key=True)
    received_from= relationship('Received_From',back_populates='received')
    received_by= relationship('Received_By',back_populates='received')
    rcv_day=Column(DateTime)
    rcv_time=Column(Time)
    header=relationship('Has_Received_Field',back_populates='received')

    def __repr__(self):
        return (f"received: from: {self.rcv_from} , "
                f"ipv6:  {self.rcv_from_ipv6} , by: {self.rcv_by}, "
                f"with:  {self.rcv_with}, day: {self.rcv_day.strftime('%Y-%m-%d')} , "
                f"time: { self.rcv_time.strftime('%H:%M:%S')}")


class Has_IPv4(Base):
    __tablename__='rel_has_ipv4'

    ip_id=Column(String, ForeignKey('tbl_ipv4.ipv4_address'),primary_key=True)
    ip=relationship('IPv4',back_populates='ip_to_domain')

    domain_id=Column(String, ForeignKey('tbl_domain.domain'),primary_key=True)
    domain=relationship('Domain',back_populates='domain_to_ip')

    def __repr__(self):
        return f'domain {self.domain_id} has_ipv4 {self.ip_id}'

class Has_IPv6(Base):
    __tablename__='rel_has_ipv6'

    ipv6_id=Column(String, ForeignKey('tbl_ipv6.ipv6_address'),primary_key=True)
    ipv6=relationship('IPv6',back_populates='ipv6_to_domain')

    domain_id=Column(String, ForeignKey('tbl_domain.domain'),primary_key=True)
    domain=relationship('Domain',back_populates='domain_to_ipv6')

    def __repr__(self):
        return f'domain {self.domain_id} has_ipv6 {self.ipv6_id}'



class IPv6(Base):
    __tablename__='tbl_ipv6'
    ipv6_address=Column(String(50), primary_key=True)
    ipv6_to_domain=relationship('Has_IPv6', back_populates='ipv6')

    service_banner=relationship('Has_Service_Banner',back_populates='ipv6')
    spf_client_ip=relationship('Has_Client_Ipv6',back_populates='client_ip')

    def __repr__(self):
        return f'ipv6 address: {self.ipv6_address}'


class Associated_Spf(Base):
    __tablename__='rel_associated_spf'

    spf_id=Column(Integer, ForeignKey('tbl_received_spf.spf_id'),primary_key=True)
    spf=relationship('Received_Spf',back_populates='header')

    header_id=Column(Integer, ForeignKey('tbl_email_header.header_id'),primary_key=True)
    header=relationship('Email_Header',back_populates='spf')

    def __repr__(self):
        return f'header_id {self.header_id} has_spf {self.spf_id}'


class Has_Helo_Domain(Base):
    __tablename__='rel_has_helo_domain'

    spf_id=Column(Integer, ForeignKey('tbl_received_spf.spf_id'),primary_key=True)
    spf=relationship('Received_Spf',back_populates='helo_domain')

    helo_domain_id=Column(String, ForeignKey('tbl_domain.domain'),primary_key=True)
    helo_domain=relationship('Domain',back_populates='helo_domain')

    def __repr__(self):
        return f'SPF record {self.spf_id} has_helo_domain id {self.helo_domain_id}'



class Has_Client_Ip(Base):
    __tablename__='rel_has_client_ip'

    spf_id=Column(Integer, ForeignKey('tbl_received_spf.spf_id'),primary_key=True)
    spf=relationship('Received_Spf',back_populates='client_ip')

    client_ip_id=Column(String, ForeignKey('tbl_ipv4.ipv4_address'),primary_key=True)
    client_ip=relationship('IPv4',back_populates='spf_client_ip')

    def __repr__(self):
        return f'SPF record {self.spf_id} has_client_ip {self.client_ip_id}'

class Has_Client_Ipv6(Base):
    __tablename__='rel_has_client_ipv6'

    spf_id=Column(Integer, ForeignKey('tbl_received_spf.spf_id'),primary_key=True)
    spf=relationship('Received_Spf',back_populates='client_ipv6')

    client_ip_id=Column(String, ForeignKey('tbl_ipv6.ipv6_address'),primary_key=True)
    client_ip=relationship('IPv6',back_populates='spf_client_ip')

    def __repr__(self):
        return f'SPF record {self.spf_id} has_client_ipv6 {self.client_ip_id}'

class Receiver_Domain(Base):
    __tablename__='rel_receiver_domain'

    spf_id=Column(Integer, ForeignKey('tbl_received_spf.spf_id'),primary_key=True)
    spf=relationship('Received_Spf',back_populates='receiver_domain')

    receiver_domain_id=Column(String, ForeignKey('tbl_domain.domain'),primary_key=True)
    receiver_domain=relationship('Domain',back_populates='spf_receiver_domain')

    def __repr__(self):
        return f'SPF record {self.spf_id} has_receiver_domain {self.receiver_domain_id}'



class Received_Spf(Base):
    __tablename__='tbl_received_spf'
    spf_id=Column(Integer,primary_key=True)
    header=relationship('Associated_Spf',back_populates="spf")
    helo_domain=relationship('Has_Helo_Domain', back_populates='spf')
    policy_result=Column(String(100)) #pr: Spf policy result (C=continues)
    spf_results=Column(String(100)) # Pass/fail
    spf_details=Column(String(1000)) #A small description of the received spf
    client_ip=relationship('Has_Client_Ip', back_populates='spf')
    client_ipv6=relationship('Has_Client_Ipv6', back_populates='spf')
    receiver_domain=relationship('Receiver_Domain', back_populates='spf')

    def __repr__(self):
        return f'Spf: {self.spf_results} , {self.spf_details}'



class Email_Header(Base):
    __tablename__ = 'tbl_email_header'
    header_id = Column(Integer, primary_key=True)
    hasheader=relationship('Has_Header',back_populates='email_header')
    content_transfer_encoding=Column(String(20))
    content_type=Column(String(100))
    message_id=Column(String(1000))
    subject=Column(String(5000))
    return_path=Column(String(200))
    hasauthresults=relationship('Has_Auth_Results',back_populates='email_header')
    received=relationship('Has_Received_Field', back_populates='header')
    spf=relationship('Associated_Spf',back_populates='header')

    def __repr__(self):
        return f'header id: {self.header_id}'


class Makes_Request(Base):
    __tablename__='rel_makes_request'

    request_id=Column(Integer, ForeignKey('tbl_request.request_id'),primary_key=True)
    request=relationship('Request',back_populates='crawler_instance')

    crawler_instance_id=Column(Integer, ForeignKey('tbl_crawler_instance.crawler_instance_id'),primary_key=True)
    crawler_instance=relationship('Crawler_Instance',back_populates='makes_request')

    def __repr__(self):
        return f'Crawler instance {self.crawler_instance_id} makes_request id {self.request_id}'

class Requests_Domain(Base):
    __tablename__='rel_requests_domain'

    request_id=Column(Integer, ForeignKey('tbl_request.request_id'),primary_key=True)
    request=relationship('Request',back_populates='domain')

    domain_id=Column(String, ForeignKey('tbl_domain.domain'),primary_key=True)
    requested_domain=relationship('Domain',back_populates='requested_domain')

    def __repr__(self):
        return f'Request {self.request_id} requests domain {self.domain_id}'


class Request(Base):
    #Represents an HTTP request sent by a page.
    __tablename__ = 'tbl_request'
    request_id = Column(Integer, primary_key = True)
    crawler_instance=relationship('Makes_Request',back_populates='request')
    request_method = Column(String(10))
    request_type = Column(String(15))
    post_data = Column(String)
    url_scheme=Column(String(50))
    url_path=Column(String(10000))
    url_query=Column(String(1000000))
    url_fragment=Column(String(1000000))
    request_date=Column(DateTime)
    domain=relationship('Requests_Domain',back_populates='request')
    response=relationship('Receives_Response',back_populates='request')
    redirection_response=relationship('Redirects_To',back_populates='request')

    def __repr__(self):
        return f'request {self.request_url} : {self.post_data}'


class Receives_Response(Base):
    __tablename__='rel_receives_response'

    request_id=Column(Integer, ForeignKey('tbl_request.request_id'),primary_key=True)
    request=relationship('Request',back_populates='response')

    response_id=Column(Integer, ForeignKey('tbl_response.response_id'),primary_key=True)
    response=relationship('Response',back_populates='request')

    def __repr__(self):
        return f'Request {self.request_id} receives_response id {self.response_id}'


class Response_From_FQDN(Base):
    __tablename__='rel_response_from_fqdn'

    fqdn_id=Column(String, ForeignKey('tbl_domain.domain'),primary_key=True)
    domain=relationship('Domain',back_populates='response_domain')

    response_id=Column(Integer, ForeignKey('tbl_response.response_id'),primary_key=True)
    response=relationship('Response',back_populates='response_fqdn')

    def __repr__(self):
        return f'Response {self.response_id} received from domain {self.fqdn_id}'


class Response(Base):
    __tablename__ = 'tbl_response'
    response_id = Column(Integer, primary_key = True)
    request=relationship('Receives_Response',back_populates='response')

    response_status = Column(Integer)
    response_fqdn=relationship('Response_From_FQDN',back_populates='response')
    url_scheme=Column(String(15))
    url_path=Column(String(10000))
    url_query=Column(String(1000))
    url_fragment=Column(String(1000))
    response_date=Column(DateTime)
    response_body=relationship('Has_Response_Body',back_populates='response')
    redirected_request=relationship('Redirects_To',back_populates='response')

    def __repr__(self):
        return f'Response id: {self.response_id}'


class Response_Body(Base):
    __tablename__='tbl_response_body'
    responsebody_id=Column(String, primary_key=True) #response hash
    responsebody=Column(LargeBinary)
    response=relationship('Has_Response_Body',back_populates='responsebody')

    def __repr__(self):
        return f'Response_Body id: {self.responsebody_id}'

class Has_Response_Body(Base):
    __tablename__='rel_has_response_body'

    responsebody_id=Column(String, ForeignKey('tbl_response_body.responsebody_id'),primary_key=True)
    responsebody=relationship('Response_Body',back_populates='response')

    response_id=Column(Integer, ForeignKey('tbl_response.response_id'),primary_key=True)
    response=relationship('Response',back_populates='response_body')

    def __repr__(self):
        return f'Response {self.response_id} has a response body hash {self.responsebody_id}'




class Domain_Certificate(Base):
    __tablename__ ='tbl_domain_certificate'
    certificate_id = Column(Integer, primary_key = True)
    valid_to = Column(DateTime)
    valid_from = Column(DateTime)
    subjectname=Column(String(500))
    issuer=Column(String(500))
    protocol=Column(String(20))
    Error=Column(String(500))
    domain = relationship('Has_TLS_Certificate',back_populates="certificate")
    san = relationship('Has_Subject_Alternative_Name',back_populates="certificate")

    def __repr__(self):
        return f'Certificate {self.certificate_id} : {self.valid_after} {self.valid_before} {self.subject}'




class Has_TLS_Certificate(Base):
    __tablename__='rel_has_tls_certificate'

    domain_id=Column(String, ForeignKey('tbl_domain.domain'),primary_key=True)
    domain=relationship('Domain',back_populates='tls_certificate')

    certificate_id=Column(Integer, ForeignKey('tbl_domain_certificate.certificate_id'),primary_key=True)
    certificate=relationship('Domain_Certificate',back_populates='domain')

    def __repr__(self):
        return f'Domain {self.domain_id} has_tls_certificate id {self.certificate_id}'



class Screenshot(Base):
    __tablename__='tbl_screenshot'
    screenshot_name=Column(String(1000),primary_key=True)
    dhash_companyA=Column(Integer)
    dhash_companyB=Column(Integer)
    crawler_instance=relationship('Crawler_Screenshot',back_populates='screenshot')
    image_size=Column(String(50))
    phash_companyB=Column(Integer)
    phash_companyA=Column(Integer)
    ocr_companyA=Column(Boolean)

    domain=relationship('Screenshot_Of_Domain',back_populates='screenshot')
    url=relationship('Screenshot_Has_Url',back_populates='screenshot')

    def __repr__(self):
        return f'screenshot id: {self.screeshot_id}'


class Crawler_Screenshot(Base):
    __tablename__='rel_crawler_screenshot'

    screenshot_id=Column(String, ForeignKey('tbl_screenshot.screenshot_name'),primary_key=True)
    screenshot=relationship('Screenshot',back_populates='crawler_instance')

    crawler_instance_id=Column(Integer, ForeignKey('tbl_crawler_instance.crawler_instance_id'),primary_key=True)
    crawler_instance=relationship('Crawler_Instance',back_populates='screenshot')

    def __repr__(self):
        return f'Crawler_instance_id {self.crawler_instance_id} produced screenshot {self.screenshot_id}'



class Crawler_Instance(Base):
    __tablename__ = 'tbl_crawler_instance'
    crawler_instance_id=Column(Integer,primary_key=True)
    generatedfrom=relationship('Generates_Crawler_Instance',back_populates='instance')
    makes_request=relationship('Makes_Request',back_populates='crawler_instance')
    source_type=Column(String(10)) #url, html, QR code
    screenshot=relationship('Crawler_Screenshot',back_populates='crawler_instance')
    crawling_time=Column(DateTime)
    source=Column(String)

    page_content=relationship('Has_Page_Content',back_populates='crawler_instance')

    def __repr__(self):
        return f'Crawling results id: {self.result_id}'


class Whois(Base):
    __tablename__='tbl_whois'
    whois_id=Column(Integer, primary_key=True)
    domain_name=relationship('Has_Domain_Name',back_populates='whois')
    creation_date=Column(DateTime)
    expiration_date=Column(DateTime)
    updated_date=Column(DateTime)
    registrar=Column(String(150))
    org=Column(String(150))
    country=Column(String(20))

    nameserver=relationship('Has_Name_Server',back_populates='whois')
    whoisserver=relationship('Has_Whois_Server',back_populates='whois')
    fqdn=relationship('Has_Whois_Record',back_populates='whois')

    def __repr__(self):
        return f'Whois record: created on {self.creation_date}, registar {self.registrar}'


class Has_Domain_Name(Base):
    __tablename__='rel_has_domain_name'

    domain_id=Column(String, ForeignKey('tbl_domain.domain'),primary_key=True)
    domain=relationship('Domain',back_populates='is_domain_name_from_whois')

    whois_id=Column(Integer, ForeignKey('tbl_whois.whois_id'),primary_key=True)
    whois=relationship('Whois',back_populates='domain_name')

    def __repr__(self):
        return f'Whois record {self.whois_id} has domain name {self.domain_id}'

class Has_Whois_Record(Base):
    __tablename__='rel_has_whois_record'

    domain_id=Column(String, ForeignKey('tbl_domain.domain'),primary_key=True)
    domain=relationship('Domain',back_populates='has_whois_record')

    whois_id=Column(Integer, ForeignKey('tbl_whois.whois_id'),primary_key=True)
    whois=relationship('Whois',back_populates='fqdn')

    def __repr__(self):

        return f'Domain {self.domain_id} has Whois record {self.whois_id}'

class Has_Name_Server(Base):
    __tablename__='rel_has_name_server'

    domain_id=Column(String, ForeignKey('tbl_domain.domain'),primary_key=True)
    domain=relationship('Domain',back_populates='is_nameserver')

    whois_id=Column(Integer, ForeignKey('tbl_whois.whois_id'),primary_key=True)
    whois=relationship('Whois',back_populates='nameserver')

    def __repr__(self):

        return f'Whois record {self.whois_id} has nameserver {self.domain_id}'

class Has_Whois_Server(Base):
    __tablename__='rel_has_whois_server'

    domain_id=Column(String, ForeignKey('tbl_domain.domain'),primary_key=True)
    domain=relationship('Domain',back_populates='is_whoisserver')

    whois_id=Column(Integer, ForeignKey('tbl_whois.whois_id'),primary_key=True)
    whois=relationship('Whois',back_populates='whoisserver')

    def __repr__(self):
        return f'Whois record {self.whois_id} has whois server {self.domain_id}'

class Has_Subject_Alternative_Name(Base):
    __tablename__='rel_has_subject_alternative_name'

    domain_id=Column(String, ForeignKey('tbl_domain.domain'),primary_key=True)
    domain=relationship('Domain',back_populates='is_subjectalternativename')

    certificate_id=Column(Integer, ForeignKey('tbl_domain_certificate.certificate_id'),primary_key=True)
    certificate=relationship('Domain_Certificate',back_populates='san')

    def __repr__(self):
        return f'Certificate {self.certificate_id} has Subject Alternative Name {self.domain_id}'


class Redirects_To(Base):
    __tablename__='rel_redirects_to'

    request_id=Column(Integer, ForeignKey('tbl_request.request_id'),primary_key=True)
    request=relationship('Request',back_populates='redirection_response')

    response_id=Column(Integer, ForeignKey('tbl_response.response_id'),primary_key=True)
    response=relationship('Response',back_populates='redirected_request')

    def __repr__(self):
        return f'Request {self.request_id} redirects to response {self.response_id}'

class Associated_With_Message(Base):
    __tablename__='rel_associated_with_message'

    domain_id=Column(String, ForeignKey('tbl_domain.domain'),primary_key=True)
    domain=relationship('Domain',back_populates='message')

    phish_id=Column(String, ForeignKey('tbl_malicious_email_message.phish_id'),primary_key=True)
    message=relationship('Malicious_Email_Message',back_populates='collected_domain')

    def __repr__(self):
        return f'The domain {self.domain_id} to message {self.phish_id}'

class Risk_Score(Base):
    __tablename__= 'tbl_risk_score'

    risk_score_id=Column(Integer, primary_key=True)
    risk_score=Column(Integer)
    geo_popularity_score=Column(Integer)
    keyword_score=Column(Integer)
    lexical_score=Column(Integer)
    popularity_1_day=Column(Integer)
    popularity_7_days=Column(Integer)
    popularity_30_days=Column(Integer)
    popularity_90_days=Column(Integer)
    tld_rank_scorepopularity_30_days=Column(Integer)
    umbrella_block_status=Column(Boolean)

    domain=relationship('Has_Risk_Score',back_populates='risk_score')

    def __repr__(self):
        return f'Risk_Score {self.risk_score_id}'

class Has_Risk_Score(Base):
    __tablename__='rel_has_risk_score'

    id=Column(Integer,primary_key=True)
    domain_id=Column(String, ForeignKey('tbl_domain.domain'))
    domain=relationship('Domain',back_populates='risk_score')

    risk_score_id=Column(Integer, ForeignKey('tbl_risk_score.risk_score_id'))
    risk_score=relationship('Risk_Score',back_populates='domain')

    date=Column(DateTime)

    def __repr__(self):
        return f'Domain {self.domain_id} has risk_score_id {self.risk_score_id}'

class Umbrella_Security_Information(Base):
    __tablename__='tbl_umbrella_security_information'

    umbrella_sec_info_id=Column(Integer, primary_key=True)
    asn_score=Column(Float)
    associated_attack_name=Column(String)
    dga_score=Column(Float)
    entropy=Column(Float)
    associated_with_fastflux=Column(Boolean)
    found=Column(Boolean)
    geodiversity=Column(ARRAY(String))
    geoscore=Column(Float)
    ks_test=Column(Float)
    pagerank=Column(Float)
    perplexity=Column(Float)
    popularity=Column(Float)
    prefix_score=Column(Float)
    rip_score=Column(Float)
    securerank2=Column(Float)
    associated_threat_type=Column(String)
    tld_geodiversity=Column(ARRAY(String))
    domain=relationship('Has_Umbrella_Security_Information',back_populates='umbrella_security_information')

    def __repr__(self):
        return f'Umbrella_Security_Information {self.umbrella_sec_info_id}'


class Has_Umbrella_Security_Information(Base):
    __tablename__='rel_has_umbrella_security_information'

    domain_id=Column(String, ForeignKey('tbl_domain.domain'),primary_key=True)
    domain=relationship('Domain',back_populates='umbrella_security_information')

    umbrella_sec_info_id=Column(Integer, ForeignKey('tbl_umbrella_security_information.umbrella_sec_info_id'),primary_key=True)
    umbrella_security_information=relationship('Umbrella_Security_Information',back_populates='domain')

    date=Column(DateTime)

    def __repr__(self):
        return f'Domain {self.domain_id} has umbrella_sec_info_id {self.umbrella_sec_info_id}'

class Has_Related_Domain(Base):
    __tablename__='rel_has_related_domains'

    parent_domain_id = Column(String, ForeignKey('tbl_domain.domain'),primary_key=True)
    related_domain_id = Column(String, ForeignKey('tbl_domain.domain'),primary_key=True)

    parent_domain = relationship("Domain", foreign_keys=[parent_domain_id])
    related_domain = relationship("Domain", foreign_keys=[related_domain_id])

    count=Column(Integer)
    date=Column(DateTime)

    def __repr__(self):
        return f'Domain {self.related_domain_id} has parent domain {self.parent_domain_id}'

class Has_Subdomain(Base):
    __tablename__ = 'rel_has_subdomain'

    parent_domain_id = Column(String, ForeignKey('tbl_domain.domain'),primary_key=True)
    subdomain_id = Column(String, ForeignKey('tbl_domain.domain'),primary_key=True)

    parent_domain = relationship("Domain", foreign_keys=[parent_domain_id])
    subdomain = relationship("Domain", foreign_keys=[subdomain_id])

    first_seen=Column(DateTime)
    date=Column(DateTime)

    def __repr__(self):
        return f'Domain {self.parent_domain_id} has subdomain {self.subdomain_id}'

class Umbrella_Query_Volume(Base):
    __tablename__='tbl_umbrella_query_volume'
    id=Column(Integer, primary_key=True)

    query_date=Column(DateTime)
    query_volume=Column(Integer)
    domain=relationship('Has_Query_Volume',back_populates='query_volume')

    def __repr__(self):
        return f'Umbrella_Query_Volume {self.id}'

class Has_Query_Volume(Base):
    __tablename__='rel_has_query_volume'
    id=Column(Integer, primary_key=True)

    domain_id=Column(String, ForeignKey('tbl_domain.domain'))
    domain=relationship('Domain',back_populates='query_volume')

    query_volume_id=Column(Integer, ForeignKey('tbl_umbrella_query_volume.id'))
    query_volume=relationship('Umbrella_Query_Volume',back_populates='domain')

    date=Column(DateTime)

    def __repr__(self):
        return f'Domain {self.domain_id} has Umbrella_Query_Volume {self.query_volume_id}'

class Screenshot_Of_Domain(Base):
    __tablename__='rel_screenshot_of_domain'
    id=Column(Integer, primary_key=True)

    domain_id=Column(String, ForeignKey('tbl_domain.domain'))
    domain=relationship('Domain',back_populates='screenshot')

    screenshot_id=Column(String, ForeignKey('tbl_screenshot.screenshot_name'))
    screenshot=relationship('Screenshot',back_populates='domain')

    date=Column(DateTime)

    def __repr__(self):
        return f'Screenshot {self.screenshot_id} is associated to the domain {self.domain_id}'

class Screenshot_Has_Url(Base):
    __tablename__='rel_screenshot_has_url'
    id=Column(Integer, primary_key=True)

    screenshot_id=Column(String, ForeignKey('tbl_screenshot.screenshot_name'))
    screenshot=relationship('Screenshot',back_populates='url')

    date=Column(DateTime)
    page_url=Column(String)

    def __repr__(self):
        return f'Screenshot {self.screenshot_id} has url {self.page_url}'


class Service_Banner(Base):
    __tablename__='tbl_service_banner'

    id=Column(Integer, primary_key=True)

    service=Column(String(10000))
    date=Column(DateTime)
    content_type=Column(String(1000))
    content_length=Column(Integer)
    connection_status=Column(String(100))
    location=relationship('Has_Location_Domain',back_populates='service_banner')
    set_cookie= Column(String)
    server=Column(String(1000))
    expires=Column(DateTime)
    port=Column(Integer)
    error=Column(String(1000))

    associated_ip=relationship('Has_Service_Banner',back_populates='service_banner')

    def __repr__(self):
        return f'Service_Banner {self.id}'

class Has_Location_Domain(Base):
    __tablename__='rel_has_location_domain'
    id=Column(Integer, primary_key=True)

    domain_id=Column(String, ForeignKey('tbl_domain.domain'))
    domain=relationship('Domain',back_populates='service_banner')

    service_banner_id=Column(Integer, ForeignKey('tbl_service_banner.id'))
    service_banner=relationship('Service_Banner',back_populates='location')

    date=Column(DateTime)

    def __repr__(self):
        return f'Service Banner {self.service_banner_id} has location domain {self.domain_id}'

class Has_Service_Banner(Base):
    __tablename__='rel_has_service_banner'
    id=Column(Integer, primary_key=True)

    service_banner_id=Column(Integer, ForeignKey('tbl_service_banner.id'))
    service_banner=relationship('Service_Banner',back_populates='associated_ip')

    ipv4_address=Column(String, ForeignKey('tbl_ipv4.ipv4_address'))
    ipv4=relationship('IPv4',back_populates='service_banner')

    ipv6_address=Column(String, ForeignKey('tbl_ipv6.ipv6_address'))
    ipv6=relationship('IPv6',back_populates='service_banner')

    date=Column(DateTime)
    def __repr__(self):
        return f'Service Banner {self.service_banner_id} has IPV$ {self.ipv4_address}'


class Structure(Base):
    __tablename__='tbl_structure'

    structure=Column(String, primary_key=True)
    message=relationship('Has_Structure',back_populates='structure')

    def __repr__(self):
        return f'Structure {self.structure}'

class Has_Structure(Base):
    __tablename__='rel_has_structure'

    structure_id=Column(String, ForeignKey('tbl_structure.structure'),primary_key=True)
    phish_id=Column(String, ForeignKey('tbl_malicious_email_message.phish_id'),primary_key=True)

    structure=relationship('Structure',back_populates='message')
    message=relationship('Malicious_Email_Message',back_populates='structure')

    def __repr__(self):
        return f'Message {self.phish_id} has the structure {self.structure_id}'

class Page_Content(Base):
    __tablename__='tbl_page_content'
    page_content_id=Column(String, primary_key=True)
    page_content=Column(LargeBinary)

    crawler_instance=relationship('Has_Page_Content',back_populates='page_content')

    def __repr__(self):
        return f'Page_Content {self.page_content_id}'

class Has_Page_Content(Base):
    __tablename__='rel_has_page_content'

    page_content_id=Column(String, ForeignKey('tbl_page_content.page_content_id'),primary_key=True)
    page_content=relationship('Page_Content',back_populates='crawler_instance')

    crawler_instance_id=Column(Integer, ForeignKey('tbl_crawler_instance.crawler_instance_id'),primary_key=True)
    crawler_instance=relationship('Crawler_Instance',back_populates='page_content')

    def __repr__(self):
        return f"Crawler Instance {self.crawler_instance_id} leads to the page which content'id is {self.page_content_id}"
