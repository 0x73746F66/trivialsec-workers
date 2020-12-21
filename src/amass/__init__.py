import os
import errno
import time
import re
import json
from socket import getaddrinfo, AF_INET6, AF_INET
from os import path, getcwd
from datetime import datetime
from trivialsec.models import JobRun, Domain, KnownIp
from trivialsec.helpers import is_valid_ipv4_address, is_valid_ipv6_address, default
from trivialsec.helpers.log_manager import logger
from worker import WorkerInterface


class Worker(WorkerInterface):
    def __init__(self, job, config: dict):
        super().__init__(job, config)

    def get_result_filename(self) -> str:
        scan_type = 'active'
        if self.job.queue_data.is_passive:
            scan_type = 'passive'
        filename = path.realpath(path.join(self.config['job_path'], self.job.queue_data.service_type_name, f'{scan_type}-{self.domain.name}-{self.config.get("worker_id")}.json'))

        return filename

    def get_log_filename(self) -> str:
        scan_type = 'active'
        if self.job.queue_data.is_passive:
            scan_type = 'passive'
        filename = path.realpath(path.join(self.config['job_path'], self.job.queue_data.service_type_name, f'{scan_type}-{self.domain.name}-{self.config.get("worker_id")}.log'))

        return filename

    def get_archive_files(self) -> dict:
        return {
            'results.json': self.get_result_filename(),
            'output.log': self.get_log_filename(),
            'amass.ini': self._make_conf_path(),
        }

    def get_job_exe_path(self) -> str:
        return path.realpath(path.join(getcwd(), 'lib', 'bin', 'run-amass'))

    def _make_conf_path(self) -> str:
        return path.realpath(path.join(self.config['job_path'], f'{self.job.queue_data.scan_type}-{self.domain.name}.ini'))

    def pre_job_exe(self) -> bool:
        config_filepath = self._make_conf_path()
        amass_config = []
        if self.job.queue_data.is_passive:
            amass_config.append('mode = passive')
        elif self.job.queue_data.is_active:
            amass_config.append('mode = active')
        amass_config.extend([
            f'output_directory = {self.config["amass"].get("output_directory")}',
            f'maximum_dns_queries = {self.config["amass"].get("maximum_dns_queries", 20000)}',
            '[scope]',
            '[scope.domains]',
            f'domain = {self.domain.name}',
            '[resolvers]',
            f'public_dns_resolvers = {"true" if self.config["amass"].get("public_dns_resolvers") else "false"}',
            f'monitor_resolver_rate = {"true" if self.config["amass"].get("monitor_resolver_rate") else "false"}',
        ])
        dns_resolvers = self.config.get('nameservers')
        if self.job.account.config.nameservers and len(self.job.account.config.nameservers.split(',')) > 0:
            dns_resolvers = self.job.account.config.nameservers.splitlines()
        for nameserver in dns_resolvers:
            amass_config.append(f'resolver = {nameserver}')

        if self.job.account.config.blacklisted_domains is not None:
            amass_config.append('[scope.blacklisted]')
            for blacklisted in self.job.account.config.blacklisted_domains.splitlines():
                amass_config.append(f'subdomain = {blacklisted}')

        if self.job.queue_data.is_active and self.config["amass"].get("bruteforce", {}).get("enabled"):
            amass_config.extend([
                '[bruteforce]',
                'enabled = true',
            ])
            if self.config["amass"].get("bruteforce", {}).get("wordlist_file"):
                amass_config.append(f'wordlist_file = {self.config["amass"].get("bruteforce", {}).get("wordlist_file")}')

        if self.job.queue_data.is_active and self.config["amass"].get("alterations", {}).get("enabled"):
            amass_config.extend([
                '[alterations]',
                'enabled = true',
                f'add_numbers = {"true" if self.config["amass"].get("alterations", {}).get("add_numbers") else "false"}',
            ])
        amass_config.extend([
            '[data_sources]',
            f'minimum_ttl = {self.config["amass"].get("sources_minimum_ttl", 1440)}'
        ])
        open_data_sources = [
            'bufferover',
            'builtwith',
            'dnstable',
            'hackerone',
            'hackertarget',
            'rapiddns',
            'riddler',
            'sitedossier',
        ]
        disabled = []
        sources = self.config['amass'].get('sources')
        for source, conf in sources.items():
            if source in open_data_sources:
                amass_config.extend([
                    f'[data_sources.{conf.get("name")}]',
                    f'ttl = {conf.get("ttl")}',
                ])

            if conf.get('disabled'):
                disabled.append(conf.get('name'))

        if len(disabled) > 0:
            amass_config.append('[data_sources.disabled]')
            for data_source in disabled:
                amass_config.append(f'data_source = {data_source}')


        if self.job.account.config.alienvault:
            amass_config.extend([
                '[data_sources.AlienVault]',
                f'ttl = {sources["alienvault"].get("ttl")}',
                '[data_sources.AlienVault.Credentials]',
                f'apikey = {self.job.account.config.alienvault}',
            ])
        if self.job.account.config.binaryedge:
            amass_config.extend([
                '[data_sources.BinaryEdge]',
                f'ttl = {sources["binaryedge"].get("ttl")}',
                '[data_sources.BinaryEdge.Credentials]',
                f'apikey = {self.job.account.config.binaryedge}',
            ])
        if self.job.account.config.c99:
            amass_config.extend([
                '[data_sources.C99]',
                f'ttl = {sources["c99"].get("ttl")}',
                '[data_sources.C99.account1]',
                f'apikey = {self.job.account.config.c99}',
            ])
        if self.job.account.config.censys_key and self.job.account.config.censys_secret:
            amass_config.extend([
                '[data_sources.Censys]',
                f'ttl = {sources["censys"].get("ttl")}',
                '[data_sources.Censys.Credentials]',
                f'apikey = {self.job.account.config.censys_key}',
                f'secret = {self.job.account.config.censys_secret}',
            ])
        if self.job.account.config.chaos:
            amass_config.extend([
                '[data_sources.Chaos]',
                f'ttl = {sources["chaos"].get("ttl")}'
                '[data_sources.Chaos.Credentials]',
                f'apikey = {self.job.account.config.chaos}',
            ])
        if self.job.account.config.cloudflare:
            amass_config.extend([
                '[data_sources.Cloudflare]',
                '[data_sources.Cloudflare.Credentials]',
                f'apikey = {self.job.account.config.cloudflare}',
            ])
        if self.job.account.config.circl_user and self.job.account.config.circl_pass:
            amass_config.extend([
                '[data_sources.CIRCL]',
                f'ttl = {sources["circl"].get("ttl")}'
                '[data_sources.CIRCL.Credentials]',
                f'username = {self.job.account.config.circl_user}',
                f'password = {self.job.account.config.circl_pass}',
            ])
        if self.job.account.config.dnsdb:
            amass_config.extend([
                '[data_sources.DNSDB]',
                f'ttl = {sources["dnsdb"].get("ttl")}',
                '[data_sources.DNSDB.Credentials]',
                f'apikey = {self.job.account.config.dnsdb}',
            ])
        if self.job.account.config.facebookct_key and self.job.account.config.facebookct_secret:
            amass_config.extend([
                '[data_sources.FacebookCT]',
                f'ttl = {sources["facebookct"].get("ttl")}',
                '[data_sources.FacebookCT.app1]',
                f'apikey = {self.job.account.config.facebookct_key}',
                f'secret = {self.job.account.config.facebookct_secret}',
            ])
        if self.job.account.config.github_user and self.job.account.config.github_key:
            amass_config.extend([
                '[data_sources.GitHub]',
                f'ttl = {sources["github"].get("ttl")}',
                f'[data_sources.GitHub.{self.job.account.config.github_user}]',
                f'apikey = {self.job.account.config.github_key}',
            ])
        if self.job.account.config.networksdb:
            amass_config.extend([
                '[data_sources.NetworksDB]',
                f'ttl = {sources["networksdb"].get("ttl")}',
                '[data_sources.NetworksDB.Credentials]',
                f'apikey = {self.job.account.config.networksdb}',
            ])
        if self.job.account.config.passivetotal_key and self.job.account.config.passivetotal_user:
            amass_config.extend([
                '[data_sources.PassiveTotal]',
                f'ttl = {sources["passivetotal"].get("ttl")}',
                '[data_sources.PassiveTotal.Credentials]',
                f'apikey = {self.job.account.config.passivetotal_key}',
                f'username = {self.job.account.config.passivetotal_user}',
            ])
        if self.job.account.config.recondev_free or self.job.account.config.recondev_paid:
            amass_config.append('[data_sources.ReconDev]')
        if self.job.account.config.recondev_free:
            amass_config.extend([
                '[data_sources.ReconDev.free]',
                f'apikey = {self.job.account.config.recondev_free}',
            ])
        if self.job.account.config.recondev_paid:
            amass_config.extend([
                '[data_sources.ReconDev.paid]',
                f'apikey = {self.job.account.config.recondev_paid}',
            ])
        if self.job.account.config.securitytrails:
            amass_config.extend([
                '[data_sources.SecurityTrails]',
                f'ttl = {sources["securitytrails"].get("ttl")}',
                '[data_sources.SecurityTrails.Credentials]',
                f'apikey = {self.job.account.config.securitytrails}',
            ])
        if self.job.account.config.shodan:
            amass_config.extend([
                '[data_sources.Shodan]',
                f'ttl = {sources["shodan"].get("ttl")}',
                '[data_sources.Shodan.Credentials]',
                f'apikey = {self.job.account.config.shodan}',
            ])
        if self.job.account.config.spyse:
            amass_config.extend([
                '[data_sources.Spyse]',
                f'ttl = {sources["spyse"].get("ttl")}',
                '[data_sources.Spyse.Credentials]',
                f'apikey = {self.job.account.config.spyse}',
            ])
        if self.job.account.config.twitter_key:
            amass_config.extend([
                '[data_sources.Twitter]',
                f'ttl = {sources["twitter"].get("ttl")}',
                '[data_sources.Twitter.account1]',
                f'apiget_exe_argskey = {self.job.account.config.twitter_key}',
                f'secret = {self.job.account.config.twitter_secret}',
            ])
        if self.job.account.config.umbrella:
            amass_config.extend([
                '[data_sources.Umbrella]',
                f'ttl = {sources["umbrella"].get("ttl")}',
                '[data_sources.Umbrella.Credentials]',
                f'apikey = {self.job.account.config.umbrella}',
            ])
        if self.job.account.config.urlscan:
            amass_config.extend([
                '[data_sources.URLScan]',
                f'ttl = {sources["urlscan"].get("ttl")}',
                '[data_sources.URLScan.Credentials]',
                f'apikey = {self.job.account.config.urlscan}',
            ])
        if self.job.account.config.virustotal:
            amass_config.extend([
                '[data_sources.VirusTotal]',
                f'ttl = {sources["virustotal"].get("ttl")}',
                '[data_sources.VirusTotal.Credentials]',
                f'apikey = {self.job.account.config.virustotal}',
            ])
        if self.job.account.config.whoisxml:
            amass_config.extend([
                '[data_sources.WhoisXML]',
                f'ttl = {sources["whoisxml"].get("ttl")}',
                '[data_sources.WhoisXML.Credentials]',
                f'apikey = {self.job.account.config.whoisxml}',
            ])
        if self.job.account.config.zetalytics:
            amass_config.extend([
                '[data_sources.ZETAlytics]',
                f'ttl = {sources["zetalytics"].get("ttl")}',
                '[data_sources.ZETAlytics.Credentials]',
                f'apikey = {self.job.account.config.zetalytics}',
            ])
        if self.job.account.config.zoomeye:
            amass_config.extend([
                '[data_sources.ZoomEye]',
                f'ttl = {sources["zoomeye"].get("ttl")}',
                '[data_sources.ZoomEye.Credentials]',
                f'apikey = {self.job.account.config.zoomeye}',
            ])

        if not os.path.exists(os.path.dirname(config_filepath)):
            try:
                os.makedirs(os.path.dirname(config_filepath))
            except OSError as exc: # EEXIST race condition
                if exc.errno != errno.EEXIST:
                    raise
        with open(config_filepath, 'w') as buff:
            buff.write("\n".join(amass_config))

        return  True

    def get_exe_args(self) -> list:
        config_filepath = self._make_conf_path()
        return [(config_filepath,)]

    def post_job_exe(self) -> bool:
        report_path = self.get_result_filename()
        if not path.isfile(report_path):
            raise ValueError(f'File not found {report_path}')

        return True

    def build_report_summary(self) -> str:
        summary = 'Scan completed without any new results'
        summary_parts = []
        if len(self.report["domains"]) > 0:
            summary_parts.append(f'{len(self.report["domains"])} domains')
            if len(self.report["known_ips"]) > 0:
                summary_parts.append(f' with {len(self.report["known_ips"])} IP Addresses')
        if summary_parts:
            summary = f"Found {''.join(summary_parts)}"
        return summary

    def build_report(self, cmd_output: str, log_output: str) -> bool:
        logger.info(f'json_output {cmd_output}')
        logger.info(f'log_output {log_output}')
        ip_list = set()
        ip_dict = {}
        domains = set()
        domains_dict = {}
        # amass produces poorly formed json, each line is an individual json object
        for line in cmd_output.splitlines():
            result = json.loads(line)
            for domain_name in result['name'].splitlines():
                domains.add(domain_name)
                if domain_name not in domains_dict:
                    domains_dict[domain_name] = result
            if not isinstance(result.get('addresses'), list):
                continue
            for address in result.get('addresses'):
                address['source'] = result['source']
                if is_valid_ipv4_address(address['ip']):
                    ip_list.add(address['ip'])
                    if address['ip'] not in ip_dict:
                        ip_dict[address['ip']] = address
                if is_valid_ipv6_address(address['ip']):
                    ip_list.add(address['ip'])
                    if address['ip'] not in ip_dict:
                        ip_dict[address['ip']] = address

        for domain_name in domains:
            if self.domain.name == domain_name \
                or domain_name.startswith('www.www.')\
                or domain_name.endswith('.arpa'):
                continue
            new_domain = Domain(name=domain_name)
            if not domain_name.endswith(self.domain.name):
                new_domain.parent_domain_id = self.domain.domain_id
            new_domain.source = ','.join(domains_dict[domain_name].get('sources'))
            new_domain.enabled = False
            self.report['domains'].append(new_domain)
            try:
                for family, _, _, _, sock_addr in getaddrinfo(new_domain.name, 443):
                    if family == AF_INET6:
                        ip_list.add(sock_addr[0])
                    if family == AF_INET:
                        ip_list.add(sock_addr[0])
                    ip_dict[sock_addr[0]] = {}
            except IOError:
                pass
            try:
                for family, _, _, _, sock_addr in getaddrinfo(new_domain.name, 80):
                    if family == AF_INET6:
                        ip_list.add(sock_addr[0])
                    if family == AF_INET:
                        ip_list.add(sock_addr[0])
                    ip_dict[sock_addr[0]] = {}
            except IOError:
                pass

        for ip_addr in ip_list:
            self.report['known_ips'].append(KnownIp(
                domain_id=self.domain.domain_id,
                ip_address=ip_addr,
                source=ip_dict[ip_addr].get('source', 'DNS'),
                asn_code=ip_dict[ip_addr].get('asn'),
                asn_name=ip_dict[ip_addr].get('desc'),
            ))

        return True
