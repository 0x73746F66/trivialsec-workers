import json
import logging
import ipaddress
from datetime import datetime
from tldextract import TLDExtract
from OpenSSL.crypto import X509
import requests
from requests.status_codes import _codes
import whois
from base64 import urlsafe_b64encode
from urllib.parse import urlencode
from socket import gethostbyname
from bs4 import BeautifulSoup as bs
from elasticsearch import Elasticsearch
from retry.api import retry
from trivialsec.models.notification import Notification
from trivialsec.models.domain import Domain, DomainMonitor
from trivialsec.models.job_run import JobRun
from trivialsec.helpers.transport import Metadata, SafeBrowsing, ip_for_host, download_file, get_dns_value, try_zone_transfer
from trivialsec.helpers.elasticsearch_adapter import Indexes
from trivialsec.helpers.config import config
from trivialsec.services.domains import upsert_domain


HIBP_VERIFY_TXT = 'have-i-been-pwned-verification'
logger = logging.getLogger(__name__)
extractor = TLDExtract(cache_dir='/tmp')
es = Elasticsearch(
    config.elasticsearch.get('hosts'),
    http_auth=(config.elasticsearch.get('user'), config.elasticsearch_password),
    scheme=config.elasticsearch.get('scheme'),
    port=config.elasticsearch.get('port'),
)

def should_fetch_api(doc :dict, days :int = 7) -> bool:
    if doc is None:
        return True
    chk = doc.get('_source', {}).get('metadata_checked')
    if chk:
        metadata_checked = datetime.fromisoformat(chk)
        return (datetime.utcnow() - metadata_checked).days >= days
    return True

def metadata_service(job :JobRun) -> bool:
    metadata = Metadata(f'https://{job.queue_data.target}/')
    try:
        metadata.get()
    except Exception as ex:
        logger.exception(ex)

    if not str(metadata.code).startswith('2'):
        try:
            metadata.url = f'http://{job.queue_data.target}/'
            metadata.get()
        except Exception as ex:
            logger.exception(ex)

    breaches = []
    try:
        res, _ = check_hibp_domain_monitor(job, metadata.website_content())
        if isinstance(res, list):
            breaches += res
    except Exception as ex:
        logger.exception(ex)
    try:
        res, _ = check_hibp_breaches(job.domain.domain_name)
        if isinstance(res, list):
            breaches += res
    except Exception as ex:
        logger.exception(ex)

    if len(breaches) > 0:
        job.domain.intel_hibp_exposure = True
    job.domain.breaches = list({v['created_at']:v for v in job.domain.breaches or []}.values())

    try:
        honey_score, _ = honeyscore_check(job.domain.domain_name)
        if honey_score is not None:
            job.domain.intel_honey_score = honey_score
    except Exception as ex:
        logger.exception(ex)
    try:
        safe_browsing_status, _ = safe_browsing_check(job.domain.domain_name)
        if safe_browsing_status is not None:
            job.domain.reputation_google_safe_browsing = safe_browsing_status
    except Exception as ex:
        logger.exception(ex)
    try:
        phishtank_status, _ = phishtank_check(job.domain.domain_name)
        if phishtank_status is not None:
            job.domain.intel_phishtank = phishtank_status
    except Exception as ex:
        logger.exception(ex)
    try:
        projecthoneypot = project_honeypot(job.domain.domain_name)
        if projecthoneypot is None:
            job.domain.intel_threat_score = 0
            job.domain.intel_threat_type = 'Not a known threat'
        else:
            job.domain.intel_threat_score = projecthoneypot.get('threat_score')
            job.domain.intel_threat_type = projecthoneypot.get('threat_type')

    except Exception as ex:
        logger.exception(ex)
    try:
        metadata.verification_check(job.account.verification_hash)
    except Exception as ex:
        logger.exception(ex)

    phish_domains = []
    domainsdb_results = check_domainsdb(job)
    if domainsdb_results is not None:
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
    doc = None
    res = es.get(index=Indexes.whoisxmlapi_brand_alert, id=job.domain.domain_name, ignore=404) # pylint: disable=unexpected-keyword-arg
    if '_source' in res:
        doc = res['_source']
    if should_fetch_api(doc):
        phish_results = check_whoisxmlapi_brand_alert(job) or []
        for res_dict in phish_results:
            # {"domainName":"sportsbetbonus.us","date":"2021-02-11","action":"added"}
            phish_domains.append({
                'domain_name': res_dict.get('domainName'),
                'create_date': res_dict.get('date'),
                'source': 'whoisxmlapi_brand_alert',
            })
    job.domain.phishing_domains = list(set(phish_domains + job.domain.phishing_domains or []))
    doc = None
    res = es.get(index=Indexes.whoisxmlapi_reputation, id=job.domain.domain_name, ignore=404) # pylint: disable=unexpected-keyword-arg
    if '_source' in res:
        doc = res['_source']
    if should_fetch_api(doc):
        whois_reputation = check_whoisxmlapi_reputation(job)
        if isinstance(whois_reputation, dict):
            job.domain.reputation_whoisxmlapi = whois_reputation.get('reputationScore')
    doc = None
    res = es.get(index=Indexes.domaintools_reputation, id=job.domain.domain_name, ignore=404) # pylint: disable=unexpected-keyword-arg
    if '_source' in res:
        doc = res['_source']
    if should_fetch_api(doc):
        dt_reputation = check_domaintools_reputation(job)
        if isinstance(dt_reputation, dict):
            job.domain.reputation_domaintools = dt_reputation.get('response', {}).get('risk_score')

    zone_transfer_allowed, _ = try_zone_transfer(job.domain.domain_name)
    job.domain.dns_transfer_allowed = zone_transfer_allowed

    hosting_history = False
    registrar, registered, registrant, registrar_alt, registered_alt = (None, None, None, None, None)
    pywhois = whois.query(job.domain.domain_name)
    if pywhois:
        registered = pywhois.creation_date
        registrar = pywhois.registrar
        if pywhois.expiration_date is not None:
            job.domain.domain_registration_expiry = pywhois.expiration_date
        hosting_history = registered is not None and registrar is not None
    doc = None
    res = es.get(index=Indexes.domaintools, id=job.domain.domain_name, ignore=404) # pylint: disable=unexpected-keyword-arg
    if '_source' in res:
        doc = res['_source']
    if should_fetch_api(doc):
        registrar, registered, registrant = check_domaintools(job)
        if registrant is not None:
            job.domain.registrant = registrant
        hosting_history = registered is not None and registrar is not None
    if hosting_history is False:
        doc = None
        res = es.get(index=Indexes.domaintools_hosting_history, id=job.domain.domain_name, ignore=404) # pylint: disable=unexpected-keyword-arg
        if '_source' in res:
            doc = res['_source']
        if should_fetch_api(doc):
            registrar_alt, registered_alt = check_domaintools_hosting_history(job)
            hosting_history = True
    if hosting_history is True:
        if registrar is None:
            registrar = registrar_alt
        if registered is None:
            registered = registered_alt
        job.domain.registered_at = registered
        job.domain.registrar = registrar
        if registered:
            job.domain.dns_registered = True

    if job.domain.domain_name in job.domain.apex and job.domain.domain_name != job.domain.apex:
        job.domain.dns_registered = True
    if job.domain.domain_name == job.domain.apex:
        err, ns = get_dns_value(job.domain.domain_name, 2)
        if not err:
            job.domain.dns_answer = ns
            job.domain.dns_registered = True

    if not job.domain.dns_answer and metadata.dns_answer:
        job.domain.dns_answer = metadata.dns_answer
    job.domain.assessed_at = datetime.utcnow().replace(microsecond=0)
    job.domain.txt_verification = metadata.txt_verification
    job.domain.negotiated_cipher_suite_openssl = metadata.negotiated_cipher
    job.domain.sha1_fingerprint = metadata.sha1_fingerprint
    job.domain.server_key_size = metadata.server_key_size
    job.domain.signature_algorithm = metadata.signature_algorithm
    job.domain.pubkey_type = metadata.pubkey_type
    job.domain.negotiated_protocol = metadata.protocol_version
    job.domain.revocation_ocsp_revoked = metadata.certificate_chain_revoked
    job.domain.certificate_valid = metadata.certificate_valid
    job.domain.certificate_san = metadata.certificate_san
    job.domain.certificate_common_name = metadata.certificate_common_name
    job.domain.certificate_validation_result = metadata.certificate_verify_message
    job.domain.certificate_chain_trust = metadata.certificate_chain_trust
    job.domain.certificate_chain_valid = metadata.certificate_chain_valid
    job.domain.certificate_chain_validation_result = metadata.certificate_chain_validation_result
    metadata.certificate_chain += job.domain.certificates
    job.domain.certificates = list({v['serialNumber']:v for v in metadata.certificate_chain or []}.values())
    metadata.certificate_extensions += job.domain.tls_extensions
    for ext in metadata.certificate_extensions:
        if ext['name'] == 'TLSFeature' and 'rfc6066' in ext['features']:
            job.domain.revocation_ocsp_stapling = True
            job.domain.revocation_ocsp_must_staple = True
    job.domain.tls_extensions = list({v['name']:v for v in metadata.certificate_extensions or []}.values())
    job.domain.certificate_is_self_signed = metadata.certificate_is_self_signed
    job.domain.certificate_serial_number = metadata.certificate_serial_number
    job.domain.certificate_issuer = metadata.certificate_issuer
    job.domain.certificate_issuer_country = metadata.certificate_issuer_country
    job.domain.certificate_not_before = metadata.certificate_not_before
    job.domain.certificate_not_after = metadata.certificate_not_after
    job.domain.http_status = metadata.code
    job.domain.html_size = metadata.html_size
    job.domain.html_title = metadata.html_title
    job.domain.server_banner = metadata.server_banner
    job.domain.application_banner = metadata.application_banner
    job.domain.reverse_proxy_banner = metadata.application_proxy
    job.domain.http_headers = metadata.headers
    job.domain.cookies = metadata.cookies
    metadata.javascript += job.domain.javascript
    job.domain.javascript = list({v['url']:v for v in metadata.javascript or []}.values())
    job.domain.asn = ', '.join(set([v['as_name'] for v in metadata.asn_data or []]))
    if metadata.certificate_is_self_signed is True:
        job.domain.trust_store_mozilla = False
        job.domain.trust_store_apple = False
        job.domain.trust_store_android = False
        job.domain.trust_store_java = False
        job.domain.trust_store_windows = False
        job.domain.certificate_chain_trust = False
        job.domain.certificate_valid = False
    return persist_results(job, metadata)

def persist_results(job :JobRun, metadata :Metadata) -> bool:
    results = check_subject_alt_name(job, metadata)
    if isinstance(results, list):
        save_domains(job, results)
    ret = job.domain.persist()
    Notification(
        account_id=job.account_id,
        description=f'Domain {job.domain.domain_name} saved via {job.queue_data.service_type_category}',
        url=f'/domain/{job.domain.domain_name}'
    ).persist(exists=False)
    return ret

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
        upsert_domain(domain, member=job.member, project=job.project, external_domain=not domain.domain_name.endswith(ext.registered_domain), on_demand=False)
        Notification(
            account_id=job.account_id,
            description=f'Domain {domain.domain_name} saved via {job.queue_data.service_type_category}',
            url=f'/domain/{domain.domain_name}'
        ).persist(exists=False)

def check_subject_alt_name(job :JobRun, metadata :Metadata) -> list:
    results = []
    if not isinstance(metadata.server_certificate, X509):
        logger.warning(f'Missing certificate for {job.queue_data.target}')
        return results

    serial_number = metadata.server_certificate.get_serial_number()
    body = {
        'domain': job.queue_data.target,
        'date_checked': datetime.utcnow().replace(microsecond=0),
        'certificate_chain': metadata.certificate_chain,
        'metadata_checked': datetime.utcnow()
    }
    es.index(index=Indexes.x509, id=serial_number, body=body)
    domains = set()
    for subject_alt_name in metadata.certificate_san or []:
        if ' ' in subject_alt_name:
            for name in subject_alt_name.split(' '):
                if name.startswith('*.'):
                    name = name.replace('*.', '')
                domains.add(name.strip())
        else:
            if subject_alt_name.startswith('*.'):
                subject_alt_name = subject_alt_name.replace('*.', '')
            domains.add(subject_alt_name.strip())
    for domain_name in domains:
        if domain_name == job.domain.domain_name:
            continue
        domain = Domain(domain_name=domain_name)
        domain.source = f'TLS Certificate Serial Number {serial_number}'
        results.append(domain)
    return results

def check_whoisxmlapi_brand_alert(job :JobRun):
    try:
        ext = extractor(f'http://{job.queue_data.target}')
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
            res_json['metadata_checked'] = datetime.utcnow()
            logger.debug(res_json)
            es.index(index=Indexes.whoisxmlapi_brand_alert, id=ext.domain, body=json.dumps(res_json, default=str))
            return res_json.get('domainsList', [])

        else:
            logger.warning(f'[{job.queue_data.target}] {url} status_code {res.status_code} {res.reason} {res.text}')

    except Exception as err:
        logger.warning(err)
    return None

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
            res_json['metadata_checked'] = datetime.utcnow()
            es.index(index=Indexes.whoisxmlapi_reputation, id=job.queue_data.target, body=json.dumps(res_json, default=str))
            return res_json
        else:
            logger.warning(f'[{job.queue_data.target}] {url} status_code {res.status_code} {res.reason} {res.text}')

    except Exception as err:
        logger.warning(err)
    return None

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
            res_json['metadata_checked'] = datetime.utcnow()
            es.index(index=Indexes.domaintools_reputation, id=job.queue_data.target, body=json.dumps(res_json, default=str))
            return res_json
        else:
            logger.warning(f'[{job.queue_data.target}] {url} status_code {res.status_code} {res.reason} {res.text}')

    except Exception as err:
        logger.warning(err)
    return None

def check_domaintools(job :JobRun):
    try:
        url = f'https://api.domaintools.com/v1/{job.queue_data.target}/?api_username={config.domaintools_user}&api_key={config.domaintools_key}'
        logger.debug(f'{url}')
        res = requests.get(url, headers={'User-Agent': config.user_agent})
        if res.status_code == 200:
            res_json = res.json()
            logger.debug(res_json)
            res_json['metadata_checked'] = datetime.utcnow()
            es.index(index=Indexes.domaintools, id=job.queue_data.target, body=json.dumps(res_json, default=str))
            registrant = res_json.get('response', {}).get('registrant', {}).get('name')
            registrar = None
            registered = None
            if 'whois' in registrant:
                registrar = res_json.get('response', {}).get('registration', {}).get('registrar')
                registered = res_json.get('response', {}).get('registration', {}).get('created')

            return registrar, registered, registrant

        else:
            logger.warning(f'[{job.queue_data.target}] {url} status_code {res.status_code} {res.reason} {res.text}')

    except Exception as err:
        logger.warning(err)
    return None, None, None

def check_domaintools_hosting_history(job :JobRun):
    try:
        url = f'https://api.domaintools.com/v1/{job.queue_data.target}/hosting-history/?api_username={config.domaintools_user}&api_key={config.domaintools_key}'
        logger.debug(f'{url}')
        res = requests.get(url, headers={'User-Agent': config.user_agent})
        if res.status_code == 200:
            res_json = res.json()
            logger.debug(res_json)
            res_json['metadata_checked'] = datetime.utcnow()
            es.index(index=Indexes.domaintools_hosting_history, id=job.queue_data.target, body=json.dumps(res_json, default=str))
            registered = None
            registrar = None
            if len(res_json.get('response', {}).get('registrar_history', [])) > 0:
                for hist in res_json['response']['registrar_history']:
                    if registrar is None:
                        registrar = hist.get('registrar')
                    if registered is None:
                        registered = hist.get('date_created')
            if len(res_json.get('response', {}).get('nameserver_history', [])) > 0:
                for hist in res_json['response']['nameserver_history']:
                    if hist['action_in_words'] == 'New':
                        if registrar is None:
                            registrar = hist.get('post_mns')
                        if registered is None:
                            registered = hist.get('actiondate')

            return registrar, registered

        else:
            logger.warning(f'[{job.queue_data.target}] {url} status_code {res.status_code} {res.reason} {res.text}')

    except Exception as err:
        logger.warning(err)
    return None, None

def check_domainsdb(job :JobRun, data :dict = None) -> dict:
    if data is None or not isinstance(data, dict):
        res = es.get(index=Indexes.domainsdb, id=job.domain.domain_name, ignore=404) # pylint: disable=unexpected-keyword-arg
        if '_source' in res:
            data = res['_source']
    if should_fetch_api(data):
        try:
            domain_part = job.domain.apex.replace(f'.{job.domain.tld}', '')
            url = f'https://api.domainsdb.info/v1/domains/search?domain={domain_part}&api_key={config.domainsdb_key}'
            logger.debug(url)
            res = requests.get(url)
            if res.status_code == 200:
                data = res.json()
                logger.debug(data)
                data['metadata_checked'] = datetime.utcnow()
                es.index(index=Indexes.domainsdb, id=job.queue_data.target, body=json.dumps(data, default=str))

            else:
                logger.warning(f'[{job.queue_data.target}] api.domainsdb.info/v1/domains/search status_code {res.status_code} {res.reason} {res.text}')

        except Exception as err:
            logger.warning(err)

    return data

def get_domain_monitor_token_dns(job :JobRun) -> str:
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

def get_domain_monitor_token_file(job :JobRun) -> str:
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

def get_domain_monitor_token_meta(job :JobRun, html_content :str) -> str:
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

def check_hibp_domain_monitor(job :JobRun, html_content :str = None):
    breaches = []
    hibp_data = None
    res = es.get(index=Indexes.hibp_monitor, id=job.domain.domain_name, ignore=404) # pylint: disable=unexpected-keyword-arg
    if '_source' in res:
        hibp_data = res['_source']
    if should_fetch_api(hibp_data, 1):
        hibp_token = get_domain_monitor_token_dns(job)
        if hibp_token is None and html_content:
            hibp_token = get_domain_monitor_token_meta(job, html_content)
        if hibp_token is None:
            hibp_token = get_domain_monitor_token_file(job)
        if hibp_token is not None:
            try:
                proxies = None
                if config.http_proxy or config.https_proxy:
                    proxies = {
                        'http': f'http://{config.http_proxy}',
                        'https': f'https://{config.https_proxy}'
                    }
                verify_url = f'https://haveibeenpwned.com/DomainSearch/{hibp_token}/Json'
                logger.debug(verify_url)
                res = requests.get(verify_url, proxies=proxies, timeout=3)
                if res.status_code == 200:
                    hibp_data = res.json()
                    logger.debug(hibp_data)
                    hibp_data['metadata_checked'] = datetime.utcnow()
                    es.index(index=Indexes.hibp_monitor, id=job.queue_data.target, body=json.dumps(hibp_data, default=str))

                else:
                    logger.warning(f'[{job.queue_data.target}] {verify_url} status_code {res.status_code} {res.reason} {res.text}')

            except Exception as ex:
                logger.warning(ex)

    if isinstance(hibp_data, dict):
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

    return breaches, hibp_data

def check_hibp_breaches(domain_name, data = None):
    """
    [{"Name": "LinkedIn", "Title": "LinkedIn", "Domain": "linkedin.com", "BreachDate": "2012-05-05", "AddedDate": "2016-05-21T21:35:40Z", "ModifiedDate": "2016-05-21T21:35:40Z",
    "PwnCount": 164611595, "Description": "In May 2016, <a href=\"https://www.troyhunt.com/observations-and-thoughts-on-the-linkedin-data-breach\" target=\"_blank\" rel=\"noopener\">LinkedIn had 164 million email addresses and passwords exposed</a>. Originally hacked in 2012, the data remained out of sight until being offered for sale on a dark market site 4 years later. The passwords in the breach were stored as SHA1 hashes without salt, the vast majority of which were quickly cracked in the days following the release of the data.",
    "LogoPath": "https://haveibeenpwned.com/Content/Images/PwnedLogos/LinkedIn.png",
    "DataClasses": ["Email addresses", "Passwords"],
    "IsVerified": true, "IsFabricated": false, "IsSensitive": false, "IsRetired": false, "IsSpamList": false}]
    """
    breaches = []
    if data is None:
        res = es.get(index=Indexes.hibp_breaches, id=domain_name, ignore=404) # pylint: disable=unexpected-keyword-arg
        if '_source' in res:
            data = res['_source']
    if should_fetch_api(data, 1):
        proxies = None
        if config.http_proxy or config.https_proxy:
            proxies = {
                'http': f'http://{config.http_proxy}',
                'https': f'https://{config.https_proxy}'
            }
        breaches_url = f'https://haveibeenpwned.com/api/v3/breaches?domain={domain_name}'
        logger.debug(breaches_url)
        res = requests.get(breaches_url, proxies=proxies, timeout=3)
        if res.status_code == 200:
            data = {
                'breaches': res.json(),
                'metadata_checked': datetime.utcnow(),
            }
            if isinstance(data['breaches'], list) and len(data['breaches']) > 0:
                es.index(index=Indexes.hibp_breaches, id=domain_name, body=json.dumps(data, default=str))
                for hibp_breach in data['breaches']:
                    breaches.append({
                        'source': hibp_breach.get('Name'),
                        'domain':  hibp_breach.get('Domain'),
                        'title':  hibp_breach.get('Title'),
                        'created_at': hibp_breach.get('AddedDate'),
                        'breach_reported': hibp_breach.get('BreachDate'),
                        'description': hibp_breach.get('Description'),
                        'tags': hibp_breach.get('DataClasses', []),
                    })
        else:
            logger.warning(f'[{domain_name}] {breaches_url} status_code {res.status_code}')

    return breaches, data

def safe_browsing_check(domain_name, data = None):
    if data is None:
        res = es.get(index=Indexes.safe_browsing, id=domain_name, ignore=404) # pylint: disable=unexpected-keyword-arg
        if '_source' in res:
            data = res['_source']
    if should_fetch_api(data):
        gcp_sb = SafeBrowsing(config.google_api_key)
        try:
            data = gcp_sb.lookup_urls([
                f'http://{domain_name}',
                f'https://{domain_name}'
            ])
            data['metadata_checked'] = datetime.utcnow()
            es.index(index=Indexes.safe_browsing, id=domain_name, body=json.dumps(data, default=str)) # pylint: disable=protected-access
        except Exception as ex:
            logger.exception(ex)

    safe_browsing_status = None
    if isinstance(data, dict):
        threat, platform = ('', '')
        for match in data.get('matches', []):
            threat = match.get('threatType', threat)
            platform = match.get('platformType', platform)

        safe_browsing_status = 'Safe'
        if platform or threat:
            safe_browsing_status = f'{platform} {threat}'.strip()

    return safe_browsing_status, data

def phishtank_check(domain_name, data = None):
    if data is None:
        res = es.get(index=Indexes.phishtank, id=domain_name, ignore=404) # pylint: disable=unexpected-keyword-arg
        if '_source' in res:
            data = res['_source']
    if should_fetch_api(data, 1):
        proxies = None
        if config.http_proxy or config.https_proxy:
            proxies = {
                'http': f'http://{config.http_proxy}',
                'https': f'https://{config.https_proxy}'
            }
        try:
            resp = requests.post(
                'https://checkurl.phishtank.com/checkurl/',
                data=urlencode({
                    'url': urlsafe_b64encode(bytes(f'https://{domain_name}', 'utf8')),
                    'format': 'json',
                    'app_key': config.phishtank_key
                }),
                headers={
                    'User-Agent': f'phishtank/{config.phishtank_username}',
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                proxies=proxies,
                timeout=3
            )
            data = resp.json()
            data['metadata_checked'] = datetime.utcnow()
            es.index(index=Indexes.phishtank, id=domain_name, body=json.dumps(data, default=str)) # pylint: disable=protected-access

        except Exception as err:
            logger.exception(err)

    phishtank_status = None
    if isinstance(data, dict):
        phishtank_results = data.get('results', {})
        phishtank_status = 'Unclassified'
        if phishtank_results.get('in_database'):
            phishtank_status = 'Reported Phish'
        elif phishtank_results.get('verified'):
            phishtank_status = 'Verified Phish'

    return phishtank_status, data

@retry((IOError, ConnectionError), tries=3, delay=5, backoff=5)
def honeyscore_check(domain_name, data = None):
    honey_score = None
    if data is None:
        res = es.get(index=Indexes.shodan_honeyscore, id=domain_name, ignore=404) # pylint: disable=unexpected-keyword-arg
        if '_source' in res:
            data = res['_source']
    if should_fetch_api(data, 1):
        proxies = None
        if config.http_proxy or config.https_proxy:
            proxies = {
                'http': f'http://{config.http_proxy}',
                'https': f'https://{config.https_proxy}'
            }
        url = f'https://api.shodan.io/labs/honeyscore/{gethostbyname(domain_name)}?key={config.honeyscore_key}'
        resp = requests.get(url,
            proxies=proxies,
            timeout=3
        )
        if resp.status_code == 200:
            honey_score = resp.text
            data = {
                'honey_score': honey_score,
                'metadata_checked': datetime.utcnow()
            }
            es.index(index=Indexes.shodan_honeyscore, id=domain_name, body=json.dumps(data, default=str)) # pylint: disable=protected-access

        else:
            logger.warning(f'[{domain_name}] {url} status_code {resp.status_code} {resp.reason} resp {resp.text}')

    return honey_score, data

def project_honeypot(domain_name, data = None):
    visitor_types = {
        0: 'Spider',
        1: 'Suspicious',
        2: 'Harvester',
        3: 'Suspicious & Harvester',
        4: 'Comment Spammer',
        5: 'Suspicious & Comment Spammer',
        6: 'Harvester & Comment Spammer',
        7: 'Suspicious & Harvester & Comment Spammer',
    }
    if data is None:
        res = es.get(index=Indexes.project_honeypot, id=domain_name, ignore=404) # pylint: disable=unexpected-keyword-arg
        if '_source' in res:
            data = res['_source']
    if should_fetch_api(data, 1):
        for addr in ip_for_host(domain_name):
            reverse_octet = ipaddress.ip_address(addr).reverse_pointer.replace('.in-addr.arpa', '').replace('.ip6.arpa', '')
            query = f'{reverse_octet}.dnsbl.httpbl.org'
            logger.info(query)
            res, err = Metadata.dig(f'{config.projecthoneypot_key}.{query}', rdtype=1)
            if err:
                logger.error(err)
            if res is not None:
                dns_answer = str(res.response.answer[0][0])
                logger.info(f'projecthoneypot dns_answer {dns_answer}')
                check, last_activity_days, threat_score, visitor_type = dns_answer.split('.') # pylint: disable=unused-variable
                threat_type = visitor_types[int(visitor_type)]
                threat_score = int(threat_score)
                data = {
                    'dns_answer': dns_answer,
                    'check_code': int(check),
                    'last_activity_days': last_activity_days,
                    'query': query,
                    'visitor_type': visitor_type,
                    'threat_type': threat_type,
                    'threat_score': threat_score,
                }
                if int(check) == 127:
                    es.index(index=Indexes.project_honeypot, id=domain_name, body=json.dumps(data, default=str)) # pylint: disable=protected-access
                    break

    return data
