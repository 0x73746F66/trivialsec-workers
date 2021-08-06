from os import path, getcwd
from xml.etree import ElementTree # nosemgrep: python.lang.security.use-defused-xml.use-defused-xml
import logging
import requests
from trivialsec.models.domain import Domain
from trivialsec.models.known_ip import KnownIp
from trivialsec.models.dns_record import DnsRecord
from trivialsec.models.finding_detail import FindingDetail
from trivialsec.models.finding import Finding
from trivialsec.helpers import oneway_hash, is_valid_ipv4_address, is_valid_ipv6_address, check_domain_rules
from trivialsec.helpers.transport import Metadata
from trivialsec.helpers.config import config
from worker import WorkerInterface


logger = logging.getLogger(__name__)

class Worker(WorkerInterface):
    providers = [
        ('.clients.turbobytes.net', 'TurboBytes', [], None),
        ('.turbobytes-cdn.com', 'TurboBytes', [], None),
        ('.afxcdn.net', 'afxcdn.net', [], None),
        ('.akamai.net', 'Akamai', [], None),
        ('.akamaiedge.net', 'Akamai', [], None),
        ('.akadns.net', 'Akamai', [], None),
        ('.akamaitechnologies.com', 'Akamai', [], None),
        ('.gslb.tbcache.com', 'Alimama', [], None),
        ('.cloudfront.net', 'Amazon Cloudfront', [], 'check_missing_bucket'),
        ('.s3-website-', 'Amazon S3 Website', [], 'check_missing_bucket'),
        ('.s3-website.', 'Amazon S3 Website', [], 'check_missing_bucket'),
        ('.s3.', 'Amazon S3 Bucket', [], 'check_missing_bucket'),
        ('.s3-accesspoint.', 'Amazon S3 Bucket', [], 'check_missing_bucket'),
        ('.anankecdn.com.br', 'Ananke', [], None),
        ('.att-dsa.net', 'AT&T', [], None),
        ('.azioncdn.net', 'Azion', [], None),
        ('.belugacdn.com', 'BelugaCDN', [], None),
        ('.bluehatnetwork.com', 'Blue Hat Network', [], None),
        ('.systemcdn.net', 'EdgeCast', [], None),
        ('.cachefly.net', 'Cachefly', [], None),
        ('.cdn77.net', 'CDN77', [], None),
        ('.cdn77.org', 'CDN77', [], None),
        ('.panthercdn.com', 'CDNetworks', [], None),
        ('.cdngc.net', 'CDNetworks', [], None),
        ('.gccdn.net', 'CDNetworks', [], None),
        ('.gccdn.cn', 'CDNetworks', [], None),
        ('.cdnify.io', 'CDNify', [], None),
        ('.ccgslb.com', 'ChinaCache', [], None),
        ('.ccgslb.net', 'ChinaCache', [], None),
        ('.c3cache.net', 'ChinaCache', [], None),
        ('.chinacache.net', 'ChinaCache', [], None),
        ('.c3cdn.net', 'ChinaCache', [], None),
        ('.lxdns.com', 'ChinaNetCenter', [], None),
        ('.speedcdns.com', 'QUANTIL/ChinaNetCenter', [], None),
        ('.mwcloudcdn.com', 'QUANTIL/ChinaNetCenter', [], None),
        ('.cloudflare.com', 'Cloudflare', [], None),
        ('.cloudflare.net', 'Cloudflare', [], None),
        ('.edgecastcdn.net', 'EdgeCast', [], None),
        ('.adn.', 'EdgeCast', [], None),
        ('.wac.', 'EdgeCast', [], None),
        ('.wpc.', 'EdgeCast', [], None),
        ('.fastly.net', 'Fastly', [], None),
        ('.fastlylb.net', 'Fastly', [], None),
        ('.google.', 'Google', [], None),
        ('googlesyndication.', 'Google', [], None),
        ('youtube.', 'Google', [], None),
        ('.googleusercontent.com', 'Google', [], None),
        ('.l.doubleclick.net', 'Google', [], None),
        ('d.gcdn.co', 'G-core', [], None),
        ('.hiberniacdn.com', 'Hibernia', [], None),
        ('.hwcdn.net', 'Highwinds', [], None),
        ('.incapdns.net', 'Incapsula', [], None),
        ('.inscname.net', 'Instartlogic', [], None),
        ('.insnw.net', 'Instartlogic', [], None),
        ('.internapcdn.net', 'Internap', [], None),
        ('.kxcdn.com', 'KeyCDN', [], None),
        ('.lswcdn.net', 'LeaseWeb CDN', [], None),
        ('.footprint.net', 'Level3', [], None),
        ('.llnwd.net', 'Limelight', [], None),
        ('.lldns.net', 'Limelight', [], None),
        ('.netdna-cdn.com', 'MaxCDN', [], None),
        ('.netdna-ssl.com', 'MaxCDN', [], None),
        ('.netdna.com', 'MaxCDN', [], None),
        ('.stackpathdns.com', 'StackPath', [], None),
        ('.mncdn.com', 'Medianova', [], None),
        ('.instacontent.net', 'Mirror Image', [], None),
        ('.mirror-image.net', 'Mirror Image', [], None),
        ('.cap-mii.net', 'Mirror Image', [], None),
        ('.rncdn1.com', 'Reflected Networks', [], None),
        ('.simplecdn.net', 'Simple CDN', [], None),
        ('.swiftcdn1.com', 'SwiftCDN', [], None),
        ('.swiftserve.com', 'SwiftServe', [], None),
        ('.gslb.taobao.com', 'Taobao', [], None),
        ('.cdn.bitgravity.com', 'Tata communications', [], None),
        ('.cdn.telefonica.com', 'Telefonica', [], None),
        ('.vo.msecnd.net', 'Windows Azure', [], None),
        ('.ay1.b.yahoo.com', 'Yahoo', [], None),
        ('.yimg.', 'Yahoo', [], None),
        ('.zenedge.net', 'Zenedge', [], None),
        ('.b-cdn.net', 'BunnyCDN', [], None),
        ('.ksyuncdn.com', 'Kingsoft', [], None),
        ('.stackpathcdn.', 'StackPath Edge', [], None),
        ('.herokuapp.', 'Heroku', [], None),
        ('.myshopify.com', 'Shopify', [], None),
        ('.azurewebsites.net', 'Azure App Service', [], None),
        ('.cloudapp.net', 'Azure App Service', [], None),
        ('.blob.core.windows.net', 'Azure Blob Storage', [], None),
        ('.web.core.windows.net', 'Azure static website', [], None),
        ('.netlify.app', 'Netlify', [], None),
        ('.hubspot.net', 'HubSpot', [], None),
        ('.github.io', 'GitHub Pages', [], None),
        ('.pythonanywhere.com', 'PythonAnywhere', [], None),
        ('.gitlab.io', 'Gitlab Pages', [], None),
        ('.section.io', 'section.io', [], None),
        ('.ghost.org', 'Ghost', [], None),
        ('.anvilapp.net', 'Anvil', [], None),
        ('.apphb.com', 'AppHarbor', [], None),
    ]
    managed_dns = [
        ('.netdc.', 'NetDC', [], None),
        ('.ovh.', 'OVHcloud', [], None),
        ('.digitalocean.com', 'Digital Ocean', [], None),
        ('.awsdns-', 'Amazon Route 53', ['cloudfront.net'], 'check_missing_bucket'),
        ('.akam.net', 'Akamai Edge DNS', [], None),
        ('.akadns.net', 'Akamai Edge DNS', [], None),
        ('.ak-adns.net', 'Akamai Edge DNS', [], None),
        ('.akamaiedge.net', 'Akamai Edge DNS', [], None),
        ('.akamaitech.net', 'Akamai', [], None),
        ('.akagtm.net', 'Akamai', [], None),
        ('.akamaistream.net', 'Akamai', [], None),
        ('.akamaihd.net', 'Akamai', [], None),
        ('.akamai.com', 'Akamai', [], None),
        ('.azure-dns.', 'Azure DNS', [], None),
        ('.cdnetworks.', 'CDNetworks', [], None),
        ('.googledomains.com', 'Google Cloud Platform', [], None),
        ('.cloudflare.', 'Cloudflare', [], None),
        ('.dnsimple.com', 'DNSimple', [], None),
        ('.mydyndns.', 'Dyn DNS', [], None),
        ('.dynect.net', 'Dyn DNS', [], None),
        ('.easydns.', 'easyDNS', [], None),
        ('.no-ip.', 'No-IP', [], None),
        ('.telindus.', 'Telindus', [], None),
        ('.ultradns.', 'UltraDNS', [], None),
        ('.verisign-grs.', 'Verisign', [], None),
        ('.verisign.', 'Verisign', [], None),
        ('.zonomi.com', 'Zonomi', [], None),
        ('.worldwidedns.net', 'WorldwideDNS', [], None),
        ('.uberns.', 'Total Uptime Technologies', [], None),
        ('.pointhq.com', 'PointDNS', [], None),
        ('.netriplex.', 'Netriplex', [], None),
        ('.loaddns.', 'LoadDNS', [], None),
        ('.glbs.me', 'GSLB.me', [], None),
        ('.geoscaling.', 'GeoScaling DNS2', [], None),
        ('.flexdns.', 'FlexDNS', [], None),
        ('.durabledns.', 'DurableDNS', [], None),
        ('.dnspod.', 'DNSPod', [], None),
        ('.linode.com', 'Linode', [], None),
        ('.csc.com', 'CSC', [], None),
        ('.name-s.net', 'CloudfloorDNS', [], None),
        ('.mtgsy.', 'CloudfloorDNS', [], None),
        ('.softlayer.', 'IBM Cloud', [], None),
        ('.stackpathdns.', 'Stackpath', [], None),
        ('.rackspace.', 'Rackspace', [], None),
        ('.dnspackage.', 'Premium DNS', [], None),
        ('.syrahost.', 'WordPress Hosting', [], None),
        ('.premium.exchange', 'Crazy Domains Exchange Manager', [], None),
        ('.bluehost.com', 'Bluehost', [], None),
        ('.siteground.biz', 'SiteGround', [], None),
        ('.zeit.world', 'Zeit', [], None),
        ('.zeit-world.', 'Zeit', [], None),
        ('.ipmanagerinc.', 'IPM.Domains', [], None),
        ('.domaincontrol.com', 'GoDaddy', [], None),
        ('.cloudns.net', 'ClouDNS', [], None),
        ('.dnsmadeeasy.com', 'DNSMadeEasy', [], None),
        ('.zilore.net', 'Zilore', [], None),
        ('.nsone.net', 'NS1', [], None),
        ('.oraclevcn.com', 'Oracle Cloud Infrastructure', [], None),
        ('.constellix.com', 'Constellix', [], None),
        ('.name-services.com', 'Namecheap Hosting', [], None),
        ('.registrar-servers.com', 'Namecheap Hosting', [], None),
        ('.namecheaphosting.com', 'Namecheap Hosting', [], None),
        ('.powerdns.net', 'PowerDNS', [], None),
        ('.zoneedit.com', 'ZoneEdit', [], None),
        ('.yahoo.com', 'Yahoo!', [], None),
        ('.garanntor.', 'Garanntor', [], None),
        ('.upperlink.', 'Upperlink', [], None),
        ('.terra.', 'Terra Domínio', [], None),
        ('.registro.br', 'Registro.br', [], None),
        ('.register.com', 'Register.com', [], None),
        ('.myhosting.com', 'myhosting.com', [], None),
        ('.hover.com', 'Hover', [], None),
        ('.gandi.net', 'Gandi', [], None),
        ('.charlestonroadregistry.com', 'Google Registry', [], None),
        ('.eurodns.com', 'EuroDNS', [], None),
        ('.enom.com', 'eNom', [], None),
        ('.justhost.com', 'justhost', [], None),
        ('.melbourneit.net', 'Melbourne IT', [], None),
        ('.ezyreg.com', 'Melbourne IT', [], None),
        ('.namesecure.com', 'NameSecure', [], None),
        ('.dreamhost.com', 'DreamHost', [], None),
        ('everydns.net', 'EveryDNS', [], None),
        ('.worldnic.com', 'Network Solutions DNS', [], None),
        ('.blacknight.com', 'Blacknight DNS', [], None),
        ('.blacknightsolutions.com', 'Blacknight DNS', [], None),
        ('1and1.com', '1&1 DNS', [], None),
        ('.123-reg.', '123 Reg', [], None),
        ('.upcloud.com', 'UPCloud', [], None),
        ('.vultr.com', 'Vultr', [], None),
        ('.aliyun.com', 'Alibaba Cloud DNS', [], None),
        ('.ramnode.com', 'RamNode', [], None),
        ('.ddos-guard.net', 'DDOS-GUARD', [], None),
        ('.networktransit.net', 'NetDepot', [], None),
        ('.hostingholdings.com', 'NetDepot', [], None),
        ('.digitalpacific.',  'Digital Pacific', [], None),
        ('.aussiedns.',  'Digital Pacific', [], None),
        ('.auserver.',  'Digital Pacific', [], None),
    ]
    a_takeovers = [
        ('185.203.72.17', 'Tilda', [], None),
        ('52.56.203.177', 'Anvil', [], None),
    ]
    _raw = None

    def __init__(self, job, paths :dict):
        super().__init__(job, paths)

    def get_result_filename(self) -> str:
        target = self.job.queue_data.target
        filename = path.realpath(path.join(
            self.paths.get('job_path'),
            self.job.queue_data.service_type_name,
            f'{self.job.queue_data.scan_type}-{target}-{self.paths.get("worker_id")}.txt',
        ))

        return filename

    def get_log_filename(self) -> str:
        return path.realpath(path.join(
            self.paths.get('job_path'),
            self.job.queue_data.service_type_name,
            f'{self.job.queue_data.scan_type}-{self.job.queue_data.target}-{self.paths.get("worker_id")}.log',
        ))

    def get_archive_files(self) -> dict:
        return {
            'output.txt': self.get_result_filename(),
            'error.log': self.get_log_filename(),
        }

    def get_job_exe_path(self) -> str:
        return path.realpath(path.join(getcwd(), 'lib', 'bin', 'run-drill'))

    def pre_job_exe(self) -> bool:
        if is_valid_ipv4_address(self.job.queue_data.target) or is_valid_ipv6_address(self.job.queue_data.target):
            return False
        target = Domain(name=self.job.queue_data.target, project_id=self.job.project_id)
        if not target.exists(['name', 'project_id']):
            raise ValueError(f'Could not load Domain using {self.job.queue_data}')

        return True

    def get_exe_args(self) -> list:
        if self.job.account.config.nameservers and len(self.job.account.config.nameservers.splitlines()) > 0:
            args = []
            for dns_resolver in self.job.account.config.nameservers.splitlines():
                args.append((self.job.queue_data.target, dns_resolver))
            return args

        dns_resolver = self.paths.get('external_dsn_provider')
        return [(self.job.queue_data.target, dns_resolver)]

    def post_job_exe(self) -> bool:
        report_path = self.get_result_filename()
        if not path.isfile(report_path):
            raise ValueError(f'File not found {report_path}')

        return True

    def build_report_summary(self, output :str, log_output :str) -> str:
        summary = 'Scan completed without any new results'
        summary_parts = []
        if len(self.report["dns_records"]) > 0:
            summary_parts.append(f'{len(self.report["dns_records"])} dns records')
        if len(self.report["domains"]) > 0:
            summary_parts.append(f'{len(self.report["domains"])} domains')
            if len(self.report["known_ips"]) > 0:
                summary_parts.append(f'with {len(self.report["known_ips"])} IP Addresses')
        if summary_parts:
            summary = f"Found {' '.join(summary_parts)}"
        return summary

    def build_report(self, cmd_output :str, log_output :str) -> bool:
        for dns_record_raw in cmd_output.splitlines():
            fqdn, ttl, dns_class, resource, *answer = dns_record_raw.split()
            answer = " ".join(answer)
            fqdn = fqdn.strip('.')
            if self.job.domain.name != fqdn\
                and not fqdn.endswith('.arpa')\
                and check_domain_rules(fqdn):
                self.report['domains'].append(Domain(
                    name=fqdn,
                    project_id=self.job.project_id,
                    source=f'DNS {self.job.domain.name}',
                ))

            dns_record = DnsRecord(
                ttl=ttl,
                dns_class=dns_class,
                resource=resource,
                answer=answer,
                raw=dns_record_raw
            )
            if isinstance(self.job.domain, Domain):
                dns_record.domain_id = self.job.domain.domain_id
            self.report['dns_records'].append(dns_record)

            if dns_record.resource.upper() == 'CNAME':
                domain_name = dns_record.answer.strip() if not dns_record.answer.endswith('.') else dns_record.answer[:-1].strip()
                if self.job.domain.name != domain_name and not domain_name.endswith('.arpa'):
                    new_domain = Domain(name=domain_name, project_id=self.job.project_id)
                    if domain_name.endswith(self.job.domain.name) and not self.job.domain.name == domain_name:
                        new_domain.parent_domain_id = self.job.domain.domain_id
                    new_domain.source = f'DNS {dns_record.raw}'
                    new_domain.enabled = False
                    self.report['domains'].append(new_domain)

            if is_valid_ipv4_address(fqdn) or is_valid_ipv6_address(fqdn):
                known_ip = KnownIp(ip_address=fqdn.strip(), source=f'DNS {dns_record.raw}')
                if isinstance(self.job.domain, Domain):
                    known_ip.domain_id = self.job.domain.domain_id
                self.report['known_ips'].append(known_ip)
            if is_valid_ipv4_address(answer) or is_valid_ipv6_address(answer):
                known_ip = KnownIp(ip_address=answer.strip(), source=f'DNS {dns_record.raw}')
                if isinstance(self.job.domain, Domain):
                    known_ip.domain_id = self.job.domain.domain_id
                self.report['known_ips'].append(known_ip)

        for dns_record in self.report.get('dns_records'):
            if dns_record.resource.upper() not in ['CNAME', 'NS']:
                continue
            host = dns_record.answer if not dns_record.answer.endswith('.') else dns_record.answer[:-1]
            if dns_record.resource.upper() == 'CNAME':
                self._check_cname(host, dns_record)
            if dns_record.resource.upper() == 'NS':
                self._check_ns(host, dns_record)
            if dns_record.resource.upper() == 'A':
                self._check_a(host, dns_record)

        return True

    def _check_cname(self, host, dns_record: DnsRecord):
        metadata = Metadata(url=f'https://{host}')
        metadata.verification_check()
        if metadata.dns_answer:
            logger.info(f'DNS {host} {metadata.dns_answer}')
        if metadata.registered:
            return
        for host_segment, provider, ignore_list, verification_check in self.providers:
            if ignore_list and self._matches_in_list(host, ignore_list):
                continue
            if host_segment not in host:
                continue

            evidence = ''
            base_confidence = 20
            confidence = base_confidence
            if isinstance(verification_check, str):
                verification_check_method = getattr(self, verification_check)
                verified, evidence = verification_check_method(self.job.domain.name, host_segment, provider, dns_record)
                if not verified:
                    continue
                confidence = 90

            finding = Finding()
            finding.domain_id = self.job.domain.domain_id
            finding.source_description = metadata.dns_answer
            finding.evidence = f'dig CNAME {self.job.domain.name}\n{evidence}'.strip()
            finding_detail = FindingDetail()
            finding_detail.title = f'Subdomain Takeover - {provider}'
            finding_detail.finding_detail_id = oneway_hash(finding_detail.title)
            if finding_detail.exists():
                finding_detail.hydrate()
            else:
                finding_detail.severity_product = 50
                finding_detail.confidence = base_confidence
                finding_detail.type_namespace = 'Software and Configuration Checks'
                finding_detail.type_category = 'Vulnerabilities'
                finding_detail.type_classifier = 'DNS'
                finding_detail.persist(exists=False)

            finding.cvss_vector = finding_detail.cvss_vector
            finding.confidence = confidence
            finding.severity_normalized = finding_detail.severity_product
            finding.finding_detail_id = finding_detail.finding_detail_id
            self.report['findings'].append(finding)

    def _check_ns(self, host, dns_record: DnsRecord):
        for host_segment, provider, ignore_list, verification_check in self.managed_dns:
            if host_segment not in host:
                continue
            if ignore_list and self._matches_in_list(host, ignore_list):
                continue

            evidence = ''
            base_confidence = 10
            confidence = base_confidence
            if isinstance(verification_check, str):
                verification_check_method = getattr(self, verification_check)
                verified, evidence = verification_check_method(self.job.domain.name, host_segment, provider, dns_record)
                if not verified:
                    continue
                confidence = 90

            finding = Finding()
            finding.domain_id = self.job.domain.domain_id
            finding.source_description = dns_record.raw
            finding.evidence = f'dig NS {self.job.domain.name}\n{evidence}'.strip()
            finding_detail = FindingDetail()
            finding_detail.title = f'DNS Hijacking - {provider}'
            finding_detail.finding_detail_id = oneway_hash(finding_detail.title)
            if finding_detail.exists():
                finding_detail.hydrate()
            else:
                finding_detail.severity_product = 80
                finding_detail.confidence = base_confidence
                finding_detail.type_namespace = 'Software and Configuration Checks'
                finding_detail.type_category = 'Vulnerabilities'
                finding_detail.type_classifier = 'DNS'
                finding_detail.persist(exists=False)

            finding.cvss_vector = finding_detail.cvss_vector
            finding.confidence = confidence
            finding.severity_normalized = finding_detail.severity_product
            finding.finding_detail_id = finding_detail.finding_detail_id
            self.report['findings'].append(finding)

    def _check_a(self, ip_addr, dns_record: DnsRecord):
        for a_record, provider, ignore_list, verification_check in self.a_takeovers:
            if a_record != ip_addr:
                continue
            if ignore_list and self._matches_in_list(ip_addr, ignore_list):
                continue

            evidence = ''
            base_confidence = 50
            confidence = base_confidence
            if isinstance(verification_check, str):
                verification_check_method = getattr(self, verification_check)
                verified, evidence = verification_check_method(self.job.domain.name, a_record, provider, dns_record)
                if not verified:
                    continue
                confidence = 90

            metadata = Metadata(url=f'https://{self.job.domain.name}')
            metadata.verification_check()
            if str(metadata.code).startswith('2'):
                continue
            if metadata.dns_answer:
                logger.info(f'DNS {self.job.domain.name} {metadata.dns_answer}')
            finding = Finding()
            finding.domain_id = self.job.domain.domain_id
            finding.source_description = metadata.dns_answer or dns_record.raw
            finding.evidence = f'dig A {self.job.domain.name}\n{ip_addr} resolves for any customer of {provider}\n{evidence}'.strip()
            finding_detail = FindingDetail()
            finding_detail.title = f'Second-order Subdomain Takeover - Broken Link Hijacking - {provider}'
            finding_detail.finding_detail_id = oneway_hash(finding_detail.title)
            if finding_detail.exists():
                finding_detail.hydrate()
            else:
                finding_detail.severity_product = 80
                finding_detail.confidence = base_confidence
                finding_detail.type_namespace = 'Software and Configuration Checks'
                finding_detail.type_category = 'Vulnerabilities'
                finding_detail.type_classifier = 'DNS'
                finding_detail.persist(exists=False)

            finding.cvss_vector = finding_detail.cvss_vector
            finding.confidence = confidence
            finding.severity_normalized = finding_detail.severity_product
            finding.finding_detail_id = finding_detail.finding_detail_id
            self.report['findings'].append(finding)

    @staticmethod
    def _matches_in_list(search_within :str, substring_list :list) -> bool:
        matched = False
        for substring in substring_list:
            if substring in search_within:
                matched = True
                break
        return matched

    @staticmethod
    def check_missing_bucket(domain_name :str, host_segment :str, provider :str, dns_record: DnsRecord):
        evidence = None
        proxies = None
        if config.http_proxy or config.https_proxy:
            proxies = {
                'http': config.http_proxy,
                'https': config.https_proxy
            }
        try:
            xml_content = requests.get(f'http://{domain_name}',
                allow_redirects=True,
                proxies=proxies,
                timeout=3
            ).content
            error = ElementTree.fromstring(xml_content)
            if error.find('Code').text != 'NoSuchBucket':
                return False, evidence
            evidence = f"curl -sL http://{domain_name}\n# {error.find('Message').text} {error.find('BucketName').text}"

        except Exception:
            return False, None

        return True, evidence
