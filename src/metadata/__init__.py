import json
import logging
from datetime import datetime
from tldextract import TLDExtract
from OpenSSL.crypto import X509
import requests
from bs4 import BeautifulSoup as bs
from elasticsearch import Elasticsearch
from trivialsec.models.domain import Domain, DomainMonitor
from trivialsec.models.job_run import JobRun
from trivialsec.helpers.transport import Metadata, download_file
from trivialsec.helpers.config import config
from trivialsec.services.domains import upsert_domain
from pprint import pprint

HIBP_VERIFY_TXT = 'have-i-been-pwned-verification'
logger = logging.getLogger(__name__)
extractor = TLDExtract(cache_dir='/tmp')
es = Elasticsearch(
    config.elasticsearch.get('hosts'),
    http_auth=(config.elasticsearch.get('user'), config.elasticsearch_password),
    scheme=config.elasticsearch.get('scheme'),
    port=config.elasticsearch.get('port'),
)
class Indexes(object):
    domaintools_reputation = "domaintools-reputation"
    whoisxmlapi_brand_alert = "whoisxmlapi-brand-alert"
    whoisxmlapi_reputation = "whoisxmlapi-reputation"
    x509 = "x509"
    domainsdb = 'domainsdb'
    hibp_monitor = 'hibp-domain-monitor'
    hibp_breaches = 'hibp-breaches'
    safe_browsing = 'safe-browsing'
    phishtank = 'phishtank'

def metadata_service(job :JobRun) -> bool:
    for index in vars(Indexes):
        if index.startswith('_'):
            continue
        es.indices.create(index=getattr(Indexes, 'index'), ignore=400) # pylint: disable=unexpected-keyword-arg

    metadata = Metadata(f'https://{job.queue_data.target}')
    try:
        metadata.head()
    except Exception as ex:
        logger.error(ex)

    if not str(metadata.code).startswith('2'):
        try:
            metadata.url = f'http://{job.queue_data.target}'
            metadata.head()
        except Exception as ex:
            logger.error(ex)

    if not save_domain_metadata(job, metadata):
        logger.error(f'metadata service failed to update {job.domain.domain_name}')
        return False

    phish_domains = []
    breaches = []
    results = check_subject_alt_name(job, metadata)
    if isinstance(results, list):
        save_domains(job, results)

    hibp_data = check_hibp_domian_monitor(job, metadata)
    breach_search_results = hibp_data.get('BreachSearchResults') or []
    for hibp_res in breach_search_results:
        user = hibp_res.get('Alias')
        domain = hibp_res.get('DomainName')
        for hibp_breach in hibp_res.get('Breaches', []) or []:
            breaches.append({
                'source': hibp_breach.get('Name'),
                'domain':  hibp_breach.get('Domain'),
                'title':  hibp_breach.get('Title'),
                'created_at': hibp_breach.get('AddedDate'),
                'breach_reported': hibp_breach.get('BreachDate'),
                'email': f"{user}@{domain}",
            })
    paste_search_results = hibp_data.get('PasteSearchResults') or []
    for hibp_res in paste_search_results:
        user = hibp_res.get('Alias')
        domain = hibp_res.get('DomainName')
        for hibp_paste in hibp_res.get('Pastes', []) or []:
            breaches.append({
                'source': hibp_paste.get('Source'),
                'title':  hibp_paste.get('Title'),
                'created_at': hibp_paste.get('Date'),
                'email': f"{user}@{domain}",
            })

    domainsdb_results = check_domainsdb(job)
    for res_dict in domainsdb_results.get('domains', []):
        if job.queue_data.target != res_dict.get('domain'):
            phish_domains.append({
                'domain_name': res_dict.get('domain'),
                'create_date': res_dict.get('create_date'),
                'source': 'domainsdb',
                'country': res_dict.get('country'),
            })
            continue
        job.domain.registered_at = res_dict.get('create_date')

    phish_results = check_whoisxmlapi_brand_alert(job)
    for res_dict in phish_results:
        # {"domainName":"sportsbetbonus.us","date":"2021-02-11","action":"added"}
        phish_domains.append({
            'domain_name': res_dict.get('domainName'),
            'create_date': res_dict.get('date'),
            'source': 'whoisxmlapi_brand_alert',
        })

    ext = extractor(f'http://{job.queue_data.target}')
    if ext.registered_domain == job.queue_data.target:
        whois_reputation = check_whoisxmlapi_reputation(job)
        if isinstance(whois_reputation, dict):
            job.domain.reputation_whoisxmlapi = whois_reputation.get('reputationScore')
        dt_reputation = check_domaintools_reputation(job)
        if isinstance(dt_reputation, dict):
            job.domain.reputation_domaintools = dt_reputation.get('response', {}).get('risk_score')

    hibp_breaches = check_hibp_breaches(job)
    for hibp_breach in hibp_breaches:
        breaches.append({
            'source': hibp_breach.get('Name'),
            'domain':  hibp_breach.get('Domain'),
            'title':  hibp_breach.get('Title'),
            'created_at': hibp_breach.get('AddedDate'),
            'breach_reported': hibp_breach.get('BreachDate'),
            'description': hibp_breach.get('Description'),
            'tags': hibp_breach.get('DataClasses', []),
        })
    if len(breaches) > 0:
        job.domain.intel_hibp_exposure = True

    job.domain.phishing_domains = list(set(phish_domains + job.domain.phishing_domains))
    return True

def save_domain_metadata(job :JobRun, metadata :Metadata) -> bool:
    domain :Domain = job.domain
    if metadata.phishtank:
        es.index(index=Indexes.phishtank, id=job.domain.domain_name, body=json.dumps(metadata.phishtank, default=str)) # pylint: disable=protected-access
        domain.intel_phishtank = True
    if metadata.safe_browsing:
        es.index(index=Indexes.safe_browsing, id=job.domain.domain_name, body=json.dumps(metadata.safe_browsing, default=str)) # pylint: disable=protected-access

    domain.assessed_at = datetime.utcnow().replace(microsecond=0)
    domain.dns_registered = metadata.dns_registered
    domain.reputation_google_safe_browsing = metadata.safe_browsing_status
    # domain.registered_at = 
    # domain.registrar = 
    # domain.registrant = 
    # domain.registrar_history = 
    domain.negotiated_cipher_suite_iana = metadata.negotiated_cipher
    domain.sha1_fingerprint = metadata.sha1_fingerprint
    domain.server_key_size = metadata.server_key_size
    domain.signature_algorithm = metadata.signature_algorithm
    domain.pubkey_type = metadata.pubkey_type
    domain.certificate_is_self_signed = metadata.certificate_is_self_signed
    domain.negotiated_protocol = metadata.protocol_version
    domain.certificate_serial_number = metadata.certificate_serial_number
    domain.certificate_issuer = metadata.certificate_issuer
    domain.certificate_issuer_country = metadata.certificate_issuer_country
    domain.certificate_not_before = metadata.certificate_not_before
    domain.certificate_not_after = metadata.certificate_not_after
    domain.http_status = metadata.code
    domain.html_size = metadata.html_size
    domain.html_title = metadata.html_title
    domain.server_banner = metadata.server_banner
    domain.application_banner = metadata.application_banner
    domain.reverse_proxy_banner = metadata.application_proxy
    domain.http_headers = metadata.headers
    domain.cookies = metadata.cookies
    domain.intel_honey_score = metadata.honey_score
    domain.intel_threat_score = metadata.threat_score
    domain.intel_threat_type = metadata.threat_type
    domain.intel_threat_type = metadata.threat_type
    metadata.javascript += domain.javascript
    domain.javascript = list({v['url']:v for v in metadata.javascript}.values())
    pprint(domain.javascript)
    exit(0)

def save_domains(job :JobRun, domains :list):
    for domain in domains:
        domain_monitor = DomainMonitor()
        domain_monitor.domain_name = domain.domain_name
        domain_monitor.enabled = False
        domain_monitor.project_id = job.project.project_id
        domain_monitor.account_id = job.account_id
        domain_monitor_exists = domain_monitor.exists(['domain_name', 'project_id'])
        if domain_monitor_exists is False and not domain_monitor.persist(exists=domain_monitor_exists):
            raise ValueError('Internal error: domain_monitor.persist')

        ext = extractor(f'http://{job.queue_data.target}')
        upsert_domain(domain, member=job.member, project=job.project, external_domain=not domain.domain_name.endswith(ext.registered_domain))

def check_subject_alt_name(job :JobRun, metadata :Metadata):
    if not isinstance(metadata.server_certificate, X509):
        logger.warning(f'Missing certificate for {job.queue_data.target}')
        return
    results = []
    cert = json.loads(metadata._json_certificate) # pylint: disable=protected-access
    serial_number = cert.get("serialNumber", metadata.server_certificate.get_serial_number()) 
    es.index(index=Indexes.x509, id=serial_number, body=metadata._json_certificate) # pylint: disable=protected-access
    domains = set()
    for subject, subject_alt_name in cert['subjectAltName'][0]:
        if subject != 'DNS':
            continue
        if ' ' in subject_alt_name:
            for name in subject_alt_name.split(' '):
                domains.add(name)
        else:
            domains.add(subject_alt_name)
    for domain_name in domains:
        domain = Domain(domain_name=domain_name)
        domain.source = f'TLS Certificate Serial Number {serial_number}'
        results.append(domain)
    return results

def check_whoisxmlapi_brand_alert(job :JobRun):
    try:
        ext = tldextract.extract(f'http://{job.queue_data.target}')
        url = 'https://brand-alert.whoisxmlapi.com/api/v2'
        data = {
            'search': ext.domain,
            'responseFormat': 'json',
            'searchType': 'historic',
            'punycode': True,
            'mode': 'preview'
        }
        logger.debug(f'{url} {json.dumps(data)}')
        res = requests.post(url, timeout=3, json=data, headers={
            'Content-type': 'application/json; charset=UTF-8',
            'X-Authentication-Token': config.whoisxmlapi_key
        })
        if res.status_code == 200:
            res_json = res.json()
            logger.debug(res_json)
            domains_count: int = int(res_json.get('domainsCount', 0))
            if domains_count == 0:
                logger.info(f'[{job.queue_data.target}] no phishing domains recorded in whoisxmlapi')
                return
        else:
            logger.warning(f'[{job.queue_data.target}] {url} status_code {res.status_code} {res.reason} {res.text}')
            return

        data['mode'] = 'purchase'
        res = requests.post(url, timeout=3, json=data, headers={
            'content-type': 'application/json;charset=UTF-8',
            'X-Authentication-Token': config.whoisxmlapi_key
        })
        if res.status_code == 200:
            res_json = res.json()
            logger.debug(res_json)
            es.index(index=Indexes.whoisxmlapi_brand_alert, id=ext.domain, body=json.dumps(res_json, default=str))
            return res_json.get('domainsList', [])

    except Exception as err:
        logger.warning(err)

def check_whoisxmlapi_reputation(job :JobRun):
    """
    reputationScore: 0 is dangerous, and 100 is safe
    Tests performed and warnings: https://domain-reputation.whoisxmlapi.com/api/documentation/output-format#test-codes
    """
    try:
        url = 'https://domain-reputation.whoisxmlapi.com/api/v1'
        data = {
            'domainName': job.queue_data.target,
            'outputFormat': 'json',
            'mode': 'fast',
            'apiKey': config.whoisxmlapi_key
        }
        logger.debug(f'{url} {data}')
        res = requests.post(url, json=data, headers={'content-type': 'application/json;charset=UTF-8'})
        if res.status_code == 200:
            res_json = res.json()
            logger.debug(res_json)
            es.index(index=Indexes.whoisxmlapi_reputation, id=job.queue_data.target, body=json.dumps(res_json, default=str))
            return res_json
        else:
            logger.warning(f'[{job.queue_data.target}] {url} status_code {res.status_code} {res.reason} {res.text}')
            return

    except Exception as err:
        logger.warning(err)

def check_domaintools_reputation(job :JobRun):
    """
    risk_score 0 (least risk) 100 (known risk)
    reasons 'blocklist', 'dns', 'realtime', 'registrant', 'zerolist'
    """
    try:
        url = f'https://api.domaintools.com/v1/reputation/?api_username={config.domaintools_user}&api_key={config.domaintools_key}&domain={job.queue_data.target}'
        logger.debug(f'{url}')
        res = requests.get(url, headers={'User-Agent': config.user_agent})
        if res.status_code == 200:
            res_json = res.json()
            logger.debug(res_json)
            es.index(index=Indexes.domaintools_reputation, id=job.queue_data.target, body=json.dumps(res_json, default=str))
            return res_json
        else:
            logger.warning(f'[{job.queue_data.target}] {url} status_code {res.status_code} {res.reason} {res.text}')
            return

    except Exception as err:
        logger.warning(err)

def check_domainsdb(job :JobRun):
    try:
        domain_part = job.domain.apex.replace(job.domain.tld, '')
        url = f'https://api.domainsdb.info/v1/domains/search?domain={domain_part}&api_key={config.domainsdb_key}'
        logger.debug(url)
        res = requests.get(url)
        if res.status_code == 200:
            res_json = res.json()
            logger.debug(res_json)
            es.index(index=Indexes.domainsdb, id=job.queue_data.target, body=json.dumps(res_json, default=str))
            return res_json
        else:
            logger.warning(f'[{job.queue_data.target}] api.domainsdb.info/v1/domains/search status_code {res.status_code} {res.reason} {res.text}')
            return

    except Exception as err:
        logger.warning(err)

def get_domian_monitor_token_dns(job :JobRun):
    hibp_token = None
    try:
        hibp_verify, _ = Metadata.get_txt_value(job.queue_data.target, HIBP_VERIFY_TXT)
        if hibp_verify is not None:
            verify_txt_record_url = 'https://haveibeenpwned.com/api/domainverification/verifytxtrecord'
            verify_txt_record_data = f'Token={hibp_verify}'
            logger.debug(f'{verify_txt_record_url} <= {verify_txt_record_data}')
            res = requests.post(
                verify_txt_record_url,
                data=verify_txt_record_data,
                headers={
                    'authority': 'haveibeenpwned.com',
                    'User-Agent': config.user_agent,
                    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                    'Origin': 'https://haveibeenpwned.com',
                    'Referer': 'https://haveibeenpwned.com/DomainSearch',
                    'X-Requested-With': 'XMLHttpRequest',
                },
                timeout=3
            )
            if res.status_code == 200:
                hibp_json = res.json()
                logger.debug(hibp_json)
                hibp_token = hibp_json.get('Token')
            else:
                logger.warning(f'[{job.queue_data.target}] haveibeenpwned.com/api/domainverification/verifytxtrecord status_code {res.status_code}')
    except Exception as err:
        logger.warning(err)

    return hibp_token

def get_domian_monitor_token_file(job :JobRun):
    hibp_token = None
    hibp_verify = None
    try:
        verify_url = f'http://{job.queue_data.target}/{HIBP_VERIFY_TXT}.txt'
        logger.debug(verify_url)
        temp_path = download_file(verify_url, f'{job.queue_data.target}-hibp-verification.txt')
        if temp_path is not None:
            with open(temp_path, 'r', encoding='utf8') as handle:
                hibp_verify = handle.read().strip()
        if hibp_verify is not None:
            verify_txt_record_url = 'https://haveibeenpwned.com/api/domainverification/verifyfileupload'
            verify_txt_record_data = f'Token={hibp_verify}'
            logger.debug(f'{verify_txt_record_url} <= {verify_txt_record_data}')
            res = requests.post(
                verify_txt_record_url,
                data=verify_txt_record_data,
                headers={
                    'authority': 'haveibeenpwned.com',
                    'User-Agent': config.user_agent,
                    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                    'Origin': 'https://haveibeenpwned.com',
                    'Referer': 'https://haveibeenpwned.com/DomainSearch',
                    'X-Requested-With': 'XMLHttpRequest',
                },
                timeout=3
            )
            if res.status_code == 200:
                hibp_json = res.json()
                logger.debug(hibp_json)
                hibp_token = hibp_json.get('Token')
            else:
                logger.warning(f'[{job.queue_data.target}] haveibeenpwned.com/api/domainverification/verifyfileupload status_code {res.status_code}')
    except Exception as err:
        logger.warning(err)

    return hibp_token

def get_domian_monitor_token_meta(job :JobRun, html_content :str):
    hibp_token = None
    if html_content is not None:
        soup = bs(html_content, 'html.parser')
        meta_tag = soup.find(name=HIBP_VERIFY_TXT)
        hibp_verify = None
        if meta_tag:
            hibp_verify = meta_tag.get("content")
        if hibp_verify is not None:
            try:
                verify_txt_record_url = 'https://haveibeenpwned.com/api/domainverification/verifymetatag'
                verify_txt_record_data = f'Token={hibp_verify}'
                logger.debug(f'{verify_txt_record_url} <= {verify_txt_record_data}')
                res = requests.post(
                    verify_txt_record_url,
                    data=verify_txt_record_data,
                    headers={
                        'authority': 'haveibeenpwned.com',
                        'User-Agent': config.user_agent,
                        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                        'Origin': 'https://haveibeenpwned.com',
                        'Referer': 'https://haveibeenpwned.com/DomainSearch',
                        'X-Requested-With': 'XMLHttpRequest',
                    },
                    timeout=3
                )
                if res.status_code == 200:
                    hibp_json = res.json()
                    logger.debug(hibp_json)
                    hibp_token = hibp_json.get('Token')
                else:
                    logger.warning(f'[{job.queue_data.target}] haveibeenpwned.com/api/domainverification/verifymetatag status_code {res.status_code}')
            except Exception as err:
                logger.warning(err)

    return hibp_token

def check_hibp_domian_monitor(job :JobRun, metadata :Metadata):
    html_content = metadata.website_content()
    hibp_token = get_domian_monitor_token_dns(job)
    if hibp_token is None:
        hibp_token = get_domian_monitor_token_meta(job, html_content)
    if hibp_token is None:
        hibp_token = get_domian_monitor_token_file(job)
    if hibp_token is not None:
        try:
            verify_url = f'https://haveibeenpwned.com/DomainSearch/{hibp_token}/Json'
            logger.debug(verify_url)
            res = requests.get(verify_url, timeout=3)
            if res.status_code == 200:
                hibp_json = res.json()
                logger.debug(hibp_json)
                es.index(index=Indexes.hibp_monitor, id=job.queue_data.target, body=json.dumps(hibp_json, default=str))
                return hibp_json
        except Exception as err:
            logger.warning(err)

def check_hibp_breaches(job :JobRun):
    """
    [{"Name": "LinkedIn", "Title": "LinkedIn", "Domain": "linkedin.com", "BreachDate": "2012-05-05", "AddedDate": "2016-05-21T21:35:40Z", "ModifiedDate": "2016-05-21T21:35:40Z",
    "PwnCount": 164611595, "Description": "In May 2016, <a href=\"https://www.troyhunt.com/observations-and-thoughts-on-the-linkedin-data-breach\" target=\"_blank\" rel=\"noopener\">LinkedIn had 164 million email addresses and passwords exposed</a>. Originally hacked in 2012, the data remained out of sight until being offered for sale on a dark market site 4 years later. The passwords in the breach were stored as SHA1 hashes without salt, the vast majority of which were quickly cracked in the days following the release of the data.",
    "LogoPath": "https://haveibeenpwned.com/Content/Images/PwnedLogos/LinkedIn.png",
    "DataClasses": ["Email addresses", "Passwords"],
    "IsVerified": true, "IsFabricated": false, "IsSensitive": false, "IsRetired": false, "IsSpamList": false}]
    """
    try:
        breaches_url = f'https://haveibeenpwned.com/api/v3/breaches?domain={job.queue_data.target}'
        logger.debug(breaches_url)
        res = requests.get(breaches_url, timeout=3)
        if res.status_code == 200:
            hibp_json = res.json()
            logger.debug(hibp_json)
            if isinstance(hibp_json, list) and len(hibp_json) > 0:
                es.index(index=Indexes.hibp_breaches, id=job.queue_data.target, body=json.dumps(hibp_json, default=str))
                return hibp_json
        else:
            logger.warning(f'[{job.queue_data.target}] haveibeenpwned.com/api/v3/breaches status_code {res.status_code}')
    except Exception as err:
        logger.warning(err)
