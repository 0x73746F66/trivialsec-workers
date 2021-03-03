from datetime import datetime
import re
import json
import requests
import tldextract
from bs4 import BeautifulSoup as bs
from trivialsec.models.domain import Domain, DomainStat
from trivialsec.models.program import Program, InventoryItem
from trivialsec.helpers import extract_server_version
from trivialsec.helpers.transport import Metadata, download_file
from trivialsec.helpers.log_manager import logger
from trivialsec.helpers.config import config
from worker import WorkerInterface, queue_job


class Worker(WorkerInterface):
    updated = False
    def __init__(self, job, config: dict):
        super().__init__(job, config)

    def get_result_filename(self) -> str:
        return ''

    def get_log_filename(self) -> str:
        return ''

    def get_archive_files(self) -> dict:
        return {}

    def get_job_exe_path(self) -> str:
        return 'echo'

    def pre_job_exe(self) -> bool:
        self.job.domain.fetch_metadata()
        self.updated = isinstance(self.job.domain._http_metadata.code, int) # pylint: disable=protected-access
        return self.updated

    def get_exe_args(self) -> list:
        return [('metadata',)]

    def post_job_exe(self) -> bool:
        return True

    def build_report_summary(self, output: str, log_output: str) -> str:
        return 'Updated metadata' if self.updated else 'No metadata'

    def build_report(self, cmd_output: str, log_output: str) -> bool:
        self.report['domain_stats'] = self.job.domain.gather_stats()
        self.check_subject_alt_name()
        self.check_headers()
        self.check_hibp_breaches()
        # self.check_hibp_domian_monitor()
        self.check_domainsdb()
        self.check_whoisxmlapi_brand_alert()
        is_tld = False
        if self.job.domain.parent_domain_id is None:
            is_tld = True
        else:
            ext = tldextract.extract(f'http://{self.job.domain.name}')
            if ext.registered_domain == self.job.domain.name:
                self.job.domain.parent_domain_id = None
                self.job.domain.persist()
                is_tld = True
        if is_tld:
            self.check_whoisxmlapi_reputation()

        return True

    def check_subject_alt_name(self):
        if not hasattr(self.job.domain, DomainStat.HTTP_CERTIFICATE):
            logger.warning(f'Missing {DomainStat.HTTP_CERTIFICATE} for {self.job.domain.name}')
            return

        cert = getattr(self.job.domain, DomainStat.HTTP_CERTIFICATE)
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
            domain = Domain(name=domain_name)
            domain.source = f'TLS Certificate Serial Number {cert["serialNumber"]}'
            domain.enabled = False
            self.report['domains'].append(domain)

    def check_headers(self):
        server_headers = ['x-powered-by', 'server']
        proxy_headers = ['via']
        for header_name, header_value in self.job.domain._http_metadata.headers.items(): # pylint: disable=protected-access
            server_name, server_version = extract_server_version(header_value)
            if server_name is None:
                continue
            source_description = f'HTTP Header [{header_name}] of {self.job.domain.name}'
            if header_name in server_headers:
                program = Program(name=server_name)
                program.hydrate('name')
                if program.category is None:
                    program.category = 'server'
                if program.program_id is None:
                    program.persist()
                self.report['inventory_items'].append(InventoryItem(
                    program_id=program.program_id,
                    project_id=self.job.domain.project_id,
                    domain_id=self.job.domain.domain_id,
                    version=server_version,
                    source_description=source_description,
                ))
            elif header_name in proxy_headers:
                program = Program(name=server_name)
                program.hydrate('name')
                if program.category is None:
                    program.category = 'proxy'
                if program.program_id is None:
                    program.persist()
                self.report['inventory_items'].append(InventoryItem(
                    program_id=program.program_id,
                    project_id=self.job.domain.project_id,
                    domain_id=self.job.domain.domain_id,
                    version=server_version,
                    source_description=source_description,
                ))

    def check_whoisxmlapi_brand_alert(self):
        try:
            ext = tldextract.extract(f'http://{self.job.domain.name}')
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
                    logger.warning(f'[{self.job.domain.name}] no phishing domains recorded in whoisxmlapi')
                    return
            else:
                logger.warning(f'[{self.job.domain.name}] {url} status_code {res.status_code} {res.reason} {res.text}')
                return

            data['mode'] = 'purchase'
            logger.debug(f'{url} {data}')
            res = requests.post(url, timeout=3, json=data, headers={
                'content-type': 'application/json;charset=UTF-8',
                'X-Authentication-Token': config.whoisxmlapi_key
            })
            if res.status_code == 200:
                res_json = res.json()
                logger.debug(res_json)
                for res_dict in res_json.get('domainsList', []):
                    # {"domainName":"sportsbetbonus.us","date":"2021-02-11","action":"added"}
                    res_dict['_source'] = 'whoisxmlapi-brand-alert'
                    self.report['domain_stats'].append(DomainStat(
                        domain_id=self.job.domain.domain_id,
                        domain_stat=DomainStat.PHISH_DOMAIN,
                        domain_value=res_dict.get('domainName'),
                        domain_data=res_dict,
                        created_at=datetime.utcnow()
                    ))

        except Exception as err:
            logger.warning(err)

    def check_whoisxmlapi_reputation(self):
        try:
            url = 'https://domain-reputation.whoisxmlapi.com/api/v1'
            data = {
                'domainName': self.job.domain.name,
                'outputFormat': 'json',
                'mode': 'fast',
                'apiKey': config.whoisxmlapi_key
            }
            logger.debug(f'{url} {data}')
            res = requests.post(url, json=data, headers={'content-type': 'application/json;charset=UTF-8'})
            if res.status_code == 200:
                res_json = res.json()
                logger.debug(res_json)
                res_json['_source'] = 'whoisxmlapi-domain-reputation'
                self.report['domain_stats'].append(DomainStat(
                    domain_id=self.job.domain.domain_id,
                    domain_stat=DomainStat.DOMAIN_REPUTATION,
                    domain_value=res_json.get('reputationScore'),
                    domain_data=res_json,
                    created_at=datetime.utcnow()
                ))
            else:
                logger.warning(f'[{self.job.domain.name}] {url} status_code {res.status_code} {res.reason} {res.text}')
                return

        except Exception as err:
            logger.warning(err)

    def check_domainsdb(self):
        try:
            url = f'https://api.domainsdb.info/v1/domains/search?domain={self.job.domain.name}'
            logger.debug(url)
            res = requests.get(url)
            if res.status_code == 200:
                res_json = res.json()
                logger.debug(res_json)
                for domain_json in res_json.get('domains', []):
                    if self.job.domain.name != domain_json.get('domain'):
                        continue
                    domain_json['_source'] = 'domainsdb'
                    self.report['domain_stats'].append(DomainStat(
                        domain_id=self.job.domain.domain_id,
                        domain_stat=DomainStat.DOMAIN_REGISTRATION,
                        domain_value=domain_json.get('create_date'),
                        domain_data=domain_json,
                        created_at=datetime.utcnow()
                    ))
            else:
                logger.warning(f'[{self.job.domain.name}] api.domainsdb.info/v1/domains/search status_code {res.status_code} {res.reason} {res.text}')
                return

        except Exception as err:
            logger.warning(err)

    def get_domian_monitor_token_dns(self, hibp_verify_txt: str):
        hibp_token, _ = Metadata.get_txt_value(self.job.domain.name, hibp_verify_txt)
        return hibp_token

    def get_domian_monitor_token_meta(self, hibp_verify_txt: str):
        hibp_token = None
        try:
            verify_url = f'http://{self.job.domain.name}/{hibp_verify_txt}.txt'
            logger.debug(verify_url)
            temp_path = download_file(verify_url, f'{self.job.domain.name}-hibp-verification.txt')
            if temp_path is not None:
                with open(temp_path, 'r') as handle:
                    hibp_token = handle.read().strip()
        except Exception as err:
            logger.warning(err)
        return hibp_token

    def get_domian_monitor_token_file(self, hibp_verify_txt: str):
        hibp_token = None
        html_content = self.job.domain._http_metadata._content # pylint: disable=protected-access
        if html_content is not None:
            soup = bs(html_content, 'html.parser')
            meta_tag = soup.find(name=hibp_verify_txt)
            hibp_verify = None
            if meta_tag:
                hibp_verify = meta_tag.get("content")
            if hibp_verify is not None:
                try:
                    verifytxtrecord_url = 'https://haveibeenpwned.com/api/domainverification/verifytxtrecord'
                    verifytxtrecord_data = f'Token={hibp_verify}'
                    logger.debug(f'{verifytxtrecord_url} <= {verifytxtrecord_data}')
                    res = requests.post(
                        verifytxtrecord_url,
                        data=verifytxtrecord_data,
                        headers={'Content-type': 'application/x-www-form-urlencoded; charset=UTF-8'},
                        timeout=3
                    )
                    if res.status_code == 200:
                        hibp_json = res.json()
                        logger.debug(hibp_json)
                        hibp_token = hibp_json.get('Token')
                    else:
                        logger.warning(f'[{self.job.domain.name}] haveibeenpwned.com/api/domainverification/verifytxtrecord status_code {res.status_code}')
                except Exception as err:
                    logger.warning(err)

        return hibp_token

    def check_hibp_domian_monitor(self):
        hibp_verify_txt = 'have-i-been-pwned-verification'
        hibp_token = self.get_domian_monitor_token_dns(hibp_verify_txt)
        if hibp_token is None:
            hibp_token = self.get_domian_monitor_token_meta(hibp_verify_txt)
        if hibp_token is None:
            hibp_token = self.get_domian_monitor_token_file(hibp_verify_txt)

        breach_search_results = []
        paste_search_results = []
        if hibp_token is not None:
            try:
                verify_url = f'https://haveibeenpwned.com/DomainSearch/{hibp_token}/Json'
                logger.debug(verify_url)
                res = requests.get(verify_url, timeout=3)
                if res.status_code == 200:
                    hibp_json = res.json()
                    logger.debug(hibp_json)
                    breach_search_results = hibp_json.get('BreachSearchResults') or []
                    paste_search_results = hibp_json.get('PasteSearchResults') or []
            except Exception as err:
                logger.warning(err)

        for hibp_res in breach_search_results:
            for hibp_breach in hibp_res['Breaches']:
                self.report['domain_stats'].append(DomainStat(
                    domain_id=self.job.domain.domain_id,
                    domain_stat=DomainStat.HIBP_EXPOSURE,
                    domain_value=hibp_breach.get('Domain'),
                    domain_data=hibp_breach
                ))
        for hibp_res in paste_search_results:
            for hibp_paste in hibp_res['Pastes']:
                self.report['domain_stats'].append(DomainStat(
                    domain_id=self.job.domain.domain_id,
                    domain_stat=DomainStat.HIBP_DISCLOSURE,
                    domain_value=hibp_paste.get('Source'),
                    domain_data=hibp_paste
                ))

    def check_hibp_breaches(self):
        try:
            breaches_url = f'https://haveibeenpwned.com/api/v3/breaches?domain={self.job.domain.name}'
            logger.debug(breaches_url)
            res = requests.get(breaches_url, timeout=3)
            if res.status_code == 200:
                hibp_breaches = res.json()
                logger.debug(hibp_breaches)
                for hibp_breach in hibp_breaches:
                    self.report['domain_stats'].append(DomainStat(
                        domain_id=self.job.domain.domain_id,
                        domain_stat=DomainStat.HIBP_BREACH,
                        domain_value=hibp_breach.get('BreachDate'),
                        domain_data=hibp_breach
                    ))
            else:
                logger.warning(f'[{self.job.domain.name}] haveibeenpwned.com/api/v3/breaches status_code {res.status_code}')
        except Exception as err:
            logger.warning(err)
