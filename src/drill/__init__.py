from os import path, getcwd
from trivialsec.models import Domain, KnownIp, DnsRecord, Finding, FindingDetail
from trivialsec.helpers import oneway_hash, is_valid_ipv4_address, is_valid_ipv6_address, check_domain_rules
from trivialsec.helpers.transport import HTTPMetadata
from trivialsec.helpers.log_manager import logger
from worker import WorkerInterface


class Worker(WorkerInterface):
    providers = [
        ('.clients.turbobytes.net', 'TurboBytes',),
        ('.turbobytes-cdn.com', 'TurboBytes',),
        ('.afxcdn.net', 'afxcdn.net',),
        ('.akamai.net', 'Akamai',),
        ('.akamaiedge.net', 'Akamai',),
        ('.akadns.net', 'Akamai',),
        ('.akamaitechnologies.com', 'Akamai',),
        ('.gslb.tbcache.com', 'Alimama',),
        ('.cloudfront.net', 'Amazon Cloudfront',),
        ('.s3-website-', 'Amazon S3 Website',),
        ('.s3-website.', 'Amazon S3 Website',),
        ('.s3.', 'Amazon S3 Bucket',),
        ('.s3-accesspoint.', 'Amazon S3 Bucket',),
        ('.anankecdn.com.br', 'Ananke',),
        ('.att-dsa.net', 'AT&T',),
        ('.azioncdn.net', 'Azion',),
        ('.belugacdn.com', 'BelugaCDN',),
        ('.bluehatnetwork.com', 'Blue Hat Network',),
        ('.systemcdn.net', 'EdgeCast',),
        ('.cachefly.net', 'Cachefly',),
        ('.cdn77.net', 'CDN77',),
        ('.cdn77.org', 'CDN77',),
        ('.panthercdn.com', 'CDNetworks',),
        ('.cdngc.net', 'CDNetworks',),
        ('.gccdn.net', 'CDNetworks',),
        ('.gccdn.cn', 'CDNetworks',),
        ('.cdnify.io', 'CDNify',),
        ('.ccgslb.com', 'ChinaCache',),
        ('.ccgslb.net', 'ChinaCache',),
        ('.c3cache.net', 'ChinaCache',),
        ('.chinacache.net', 'ChinaCache',),
        ('.c3cdn.net', 'ChinaCache',),
        ('.lxdns.com', 'ChinaNetCenter',),
        ('.speedcdns.com', 'QUANTIL/ChinaNetCenter',),
        ('.mwcloudcdn.com', 'QUANTIL/ChinaNetCenter',),
        ('.cloudflare.com', 'Cloudflare',),
        ('.cloudflare.net', 'Cloudflare',),
        ('.edgecastcdn.net', 'EdgeCast',),
        ('.adn.', 'EdgeCast',),
        ('.wac.', 'EdgeCast',),
        ('.wpc.', 'EdgeCast',),
        ('.fastly.net', 'Fastly',),
        ('.fastlylb.net', 'Fastly',),
        ('.google.', 'Google',),
        ('googlesyndication.', 'Google',),
        ('youtube.', 'Google',),
        ('.googleusercontent.com', 'Google',),
        ('.l.doubleclick.net', 'Google',),
        ('d.gcdn.co', 'G-core',),
        ('.hiberniacdn.com', 'Hibernia',),
        ('.hwcdn.net', 'Highwinds',),
        ('.incapdns.net', 'Incapsula',),
        ('.inscname.net', 'Instartlogic',),
        ('.insnw.net', 'Instartlogic',),
        ('.internapcdn.net', 'Internap',),
        ('.kxcdn.com', 'KeyCDN',),
        ('.lswcdn.net', 'LeaseWeb CDN',),
        ('.footprint.net', 'Level3',),
        ('.llnwd.net', 'Limelight',),
        ('.lldns.net', 'Limelight',),
        ('.netdna-cdn.com', 'MaxCDN',),
        ('.netdna-ssl.com', 'MaxCDN',),
        ('.netdna.com', 'MaxCDN',),
        ('.stackpathdns.com', 'StackPath',),
        ('.mncdn.com', 'Medianova',),
        ('.instacontent.net', 'Mirror Image',),
        ('.mirror-image.net', 'Mirror Image',),
        ('.cap-mii.net', 'Mirror Image',),
        ('.rncdn1.com', 'Reflected Networks',),
        ('.simplecdn.net', 'Simple CDN',),
        ('.swiftcdn1.com', 'SwiftCDN',),
        ('.swiftserve.com', 'SwiftServe',),
        ('.gslb.taobao.com', 'Taobao',),
        ('.cdn.bitgravity.com', 'Tata communications',),
        ('.cdn.telefonica.com', 'Telefonica',),
        ('.vo.msecnd.net', 'Windows Azure',),
        ('.ay1.b.yahoo.com', 'Yahoo',),
        ('.yimg.', 'Yahoo',),
        ('.zenedge.net', 'Zenedge',),
        ('.b-cdn.net', 'BunnyCDN',),
        ('.ksyuncdn.com', 'Kingsoft',),
        ('.stackpathcdn.', 'StackPath Edge',),
        ('.herokuapp.', 'Heroku',),
        ('.myshopify.com', 'Shopify',),
        ('.azurewebsites.net', 'Azure App Service'),
        ('.cloudapp.net', 'Azure App Service'),
        ('.blob.core.windows.net', 'Azure Blob Storage'),
        ('.web.core.windows.net', 'Azure static website'),
        ('.netlify.app', 'Netlify'),
        ('.hubspot.net', 'HubSpot'),
        ('.github.io', 'GitHub Pages'),
        ('.pythonanywhere.com', 'PythonAnywhere'),
        ('.gitlab.io', 'Gitlab Pages'),
        ('.section.io', 'section.io'),
        ('.ghost.org', 'Ghost'),
        ('.anvilapp.net', 'Anvil'),
        ('.apphb.com', 'AppHarbor'),
    ]
    managed_dns = [
        ('.netdc.', 'NetDC',),
        ('.ovh.', 'OVHcloud',),
        ('.digitalocean.com', 'Digital Ocean',),
        ('.awsdns-', 'Amazon Route 53', ['cloudfront.net']),
        ('.akam.net', 'Akamai Edge DNS',),
        ('.akadns.net', 'Akamai Edge DNS',),
        ('.ak-adns.net', 'Akamai Edge DNS',),
        ('.akamaiedge.net', 'Akamai Edge DNS',),
        ('.akamaitech.net', 'Akamai',),
        ('.akagtm.net', 'Akamai',),
        ('.akamaistream.net', 'Akamai',),
        ('.akamaihd.net', 'Akamai',),
        ('.akamai.com', 'Akamai',),
        ('.azure-dns.', 'Azure DNS',),
        ('.cdnetworks.', 'CDNetworks',),
        ('.googledomains.com', 'Google Cloud Platform',),
        ('.cloudflare.', 'Cloudflare',),
        ('.dnsimple.com', 'DNSimple',),
        ('.mydyndns.', 'Dyn DNS',),
        ('.dynect.net', 'Dyn DNS',),
        ('.easydns.', 'easyDNS',),
        ('.no-ip.', 'No-IP',),
        ('.telindus.', 'Telindus',),
        ('.ultradns.', 'UltraDNS',),
        ('.verisign-grs.', 'Verisign',),
        ('.verisign.', 'Verisign',),
        ('.zonomi.com', 'Zonomi',),
        ('.worldwidedns.net', 'WorldwideDNS',),
        ('.uberns.', 'Total Uptime Technologies',),
        ('.pointhq.com', 'PointDNS',),
        ('.netriplex.', 'Netriplex',),
        ('.loaddns.', 'LoadDNS',),
        ('.glbs.me', 'GSLB.me',),
        ('.geoscaling.', 'GeoScaling DNS2',),
        ('.flexdns.', 'FlexDNS',),
        ('.durabledns.', 'DurableDNS',),
        ('.dnspod.', 'DNSPod',),
        ('.linode.com', 'Linode',),
        ('.csc.com', 'CSC',),
        ('.name-s.net', 'CloudfloorDNS',),
        ('.mtgsy.', 'CloudfloorDNS',),
        ('.softlayer.', 'IBM Cloud',),
        ('.stackpathdns.', 'Stackpath',),
        ('.rackspace.', 'Rackspace',),
        ('.dnspackage.', 'Premium DNS',),
        ('.syrahost.', 'WordPress Hosting',),
        ('.premium.exchange', 'Crazy Domains Exchange Manager',),
        ('.bluehost.com', 'Bluehost',),
        ('.siteground.biz', 'SiteGround',),
        ('.zeit.world', 'Zeit',),
        ('.zeit-world.', 'Zeit',),
        ('.ipmanagerinc.', 'IPM.Domains',),
        ('.domaincontrol.com', 'GoDaddy',),
        ('.cloudns.net', 'ClouDNS',),
        ('.dnsmadeeasy.com', 'DNSMadeEasy',),
        ('.zilore.net', 'Zilore',),
        ('.nsone.net', 'NS1',),
        ('.oraclevcn.com', 'Oracle Cloud Infrastructure',),
        ('.constellix.com', 'Constellix',),
        ('.name-services.com', 'Namecheap Hosting',),
        ('.registrar-servers.com', 'Namecheap Hosting',),
        ('.namecheaphosting.com', 'Namecheap Hosting',),
        ('.powerdns.net', 'PowerDNS',),
        ('.zoneedit.com', 'ZoneEdit',),
        ('.yahoo.com', 'Yahoo!',),
        ('.garanntor.', 'Garanntor',),
        ('.upperlink.', 'Upperlink',),
        ('.terra.', 'Terra Domínio',),
        ('.registro.br', 'Registro.br',),
        ('.register.com', 'Register.com',),
        ('.myhosting.com', 'myhosting.com',),
        ('.hover.com', 'Hover',),
        ('.gandi.net', 'Gandi',),
        ('.charlestonroadregistry.com', 'Google Registry',),
        ('.eurodns.com', 'EuroDNS',),
        ('.enom.com', 'eNom',),
        ('.justhost.com', 'justhost',),
        ('.melbourneit.net', 'Melbourne IT',),
        ('.ezyreg.com', 'Melbourne IT',),
        ('.namesecure.com', 'NameSecure',),
        ('.dreamhost.com', 'DreamHost',),
        ('everydns.net', 'EveryDNS',),
        ('.worldnic.com', 'Network Solutions DNS',),
        ('.blacknight.com', 'Blacknight DNS',),
        ('.blacknightsolutions.com', 'Blacknight DNS',),
        ('1and1.com', '1&1 DNS',),
        ('.123-reg.', '123 Reg',),
        ('.upcloud.com', 'UPCloud'),
        ('.vultr.com', 'Vultr'),
        ('.aliyun.com', 'Alibaba Cloud DNS'),
        ('.ramnode.com', 'RamNode'),
        ('.ddos-guard.net', 'DDOS-GUARD'),
        ('.networktransit.net', 'NetDepot'),
        ('.hostingholdings.com', 'NetDepot'),
        ('.digitalpacific.',  'Digital Pacific'),
        ('.aussiedns.',  'Digital Pacific'),
        ('.auserver.',  'Digital Pacific'),
    ]
    a_takeovers = [
        ('185.203.72.17', 'Tilda'),
        ('52.56.203.177', 'Anvil'),
    ]
    _raw = None

    def __init__(self, job, config: dict):
        super().__init__(job, config)

    def get_result_filename(self) -> str:
        target = self.job.queue_data.target
        filename = path.realpath(path.join(
            self.config['job_path'],
            self.job.queue_data.service_type_name,
            f'{self.job.queue_data.scan_type}-{target}-{self.config.get("worker_id")}.txt',
        ))

        return filename

    def get_log_filename(self) -> str:
        return path.realpath(path.join(
            self.config['job_path'],
            self.job.queue_data.service_type_name,
            f'{self.job.queue_data.scan_type}-{self.job.queue_data.target}-{self.config.get("worker_id")}.log',
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

        dns_resolver = self.config.get('external_dsn_provider')
        return [(self.job.queue_data.target, dns_resolver)]

    def post_job_exe(self) -> bool:
        report_path = self.get_result_filename()
        if not path.isfile(report_path):
            raise ValueError(f'File not found {report_path}')

        return True

    def build_report_summary(self, output: str, log_output: str) -> str:
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

    def build_report(self, cmd_output: str, log_output: str) -> bool:
        for dns_record_raw in cmd_output.splitlines():
            fqdn, ttl, dns_class, resource, *answer = dns_record_raw.split()
            answer = " ".join(answer)
            fqdn = fqdn.strip('.')
            if self.domain.name != fqdn\
                and not fqdn.endswith('.arpa')\
                and check_domain_rules(fqdn):
                self.report['domains'].append(Domain(
                    name=fqdn,
                    project_id=self.job.project_id,
                    source=f'DNS {self.domain.name}',
                ))

            dns_record = DnsRecord(
                ttl=ttl,
                dns_class=dns_class,
                resource=resource,
                answer=answer,
                raw=dns_record_raw
            )
            if isinstance(self.domain, Domain):
                dns_record.domain_id = self.domain.domain_id
            self.report['dns_records'].append(dns_record)

            if dns_record.resource.upper() == 'CNAME':
                domain_name = dns_record.answer if not dns_record.answer.endswith('.') else dns_record.answer[:-1]
                if self.domain.name != domain_name and not domain_name.endswith('.arpa'):
                    new_domain = Domain(name=domain_name, project_id=self.job.project_id)
                    if domain_name.endswith(self.domain.name):
                        new_domain.parent_domain_id = self.domain.domain_id
                    new_domain.source = f'DNS {dns_record.raw}'
                    new_domain.enabled = False
                    self.report['domains'].append(new_domain)

            if is_valid_ipv4_address(fqdn) or is_valid_ipv6_address(fqdn):
                known_ip = KnownIp(ip_address=fqdn, source=f'DNS {dns_record.raw}')
                if isinstance(self.domain, Domain):
                    known_ip.domain_id = self.domain.domain_id
                self.report['known_ips'].append(known_ip)
            if is_valid_ipv4_address(answer) or is_valid_ipv6_address(answer):
                known_ip = KnownIp(ip_address=answer, source=f'DNS {dns_record.raw}')
                if isinstance(self.domain, Domain):
                    known_ip.domain_id = self.domain.domain_id
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
        metadata = HTTPMetadata(url=f'https://{host}')
        metadata.verification_check()
        if metadata.dns_answer:
            logger.info(f'DNS {host} {metadata.dns_answer}')
        if metadata.registered:
            return
        for host_segment, provider, *ignore_list in self.providers:
            if host_segment not in host:
                continue
            if ignore_list and self._matches_in_list(host, ignore_list[0]):
                continue

            finding = Finding()
            finding.domain_id = self.domain.domain_id
            finding.source_description = metadata.dns_answer
            finding.evidence = f'dig CNAME {self.domain.name}'
            finding_detail = FindingDetail()
            finding_detail.title = f'Subdomain Takeover - {provider}'
            finding_detail.finding_detail_id = oneway_hash(finding_detail.title)
            if finding_detail.exists():
                finding_detail.hydrate()
            else:
                finding_detail.severity_product = 80
                finding_detail.confidence = 50
                finding_detail.criticality = 80
                finding_detail.type_namespace = 'Software and Configuration Checks'
                finding_detail.type_category = 'Vulnerabilities'
                finding_detail.type_classifier = 'DNS'
                finding_detail.persist(exists=False)

            finding.severity_normalized = finding_detail.severity_product
            finding.finding_detail_id = finding_detail.finding_detail_id
            self.report['findings'].append(finding)

    def _check_ns(self, host, dns_record: DnsRecord):
        for host_segment, provider, *ignore_list in self.managed_dns:
            if host_segment not in host:
                continue
            if ignore_list and self._matches_in_list(host, ignore_list[0]):
                continue

            finding = Finding()
            finding.domain_id = self.domain.domain_id
            finding.source_description = dns_record.raw
            finding.evidence = f'dig NS {self.domain.name}'
            finding_detail = FindingDetail()
            finding_detail.title = f'DNS Hijacking - {provider}'
            finding_detail.finding_detail_id = oneway_hash(finding_detail.title)
            if finding_detail.exists():
                finding_detail.hydrate()
            else:
                finding_detail.severity_product = 80
                finding_detail.confidence = 10
                finding_detail.criticality = 80
                finding_detail.type_namespace = 'Software and Configuration Checks'
                finding_detail.type_category = 'Vulnerabilities'
                finding_detail.type_classifier = 'DNS'
                finding_detail.persist(exists=False)

            finding.severity_normalized = finding_detail.severity_product
            finding.finding_detail_id = finding_detail.finding_detail_id
            self.report['findings'].append(finding)

    def _check_a(self, ip_addr, dns_record: DnsRecord):
        for a_record, provider, *ignore_list in self.a_takeovers:
            if a_record != ip_addr:
                continue
            if ignore_list and self._matches_in_list(ip_addr, ignore_list[0]):
                continue
            metadata = HTTPMetadata(url=f'https://{self.domain.name}')
            metadata.verification_check()
            if str(metadata.code).startswith('2'):
                continue
            if metadata.dns_answer:
                logger.info(f'DNS {self.domain.name} {metadata.dns_answer}')
            finding = Finding()
            finding.domain_id = self.domain.domain_id
            finding.source_description = metadata.dns_answer or dns_record.raw
            finding.evidence = f'dig A {self.domain.name}\n{ip_addr} resolves for any customer of {provider}'
            finding_detail = FindingDetail()
            finding_detail.title = f'Second-order Subdomain Takeover - Broken Link Hijacking - {provider}'
            finding_detail.finding_detail_id = oneway_hash(finding_detail.title)
            if finding_detail.exists():
                finding_detail.hydrate()
            else:
                finding_detail.severity_product = 80
                finding_detail.confidence = 50
                finding_detail.criticality = 80
                finding_detail.type_namespace = 'Software and Configuration Checks'
                finding_detail.type_category = 'Vulnerabilities'
                finding_detail.type_classifier = 'DNS'
                finding_detail.persist(exists=False)

            finding.severity_normalized = finding_detail.severity_product
            finding.finding_detail_id = finding_detail.finding_detail_id
            self.report['findings'].append(finding)

    @staticmethod
    def _matches_in_list(search_within: str, substring_list: list) -> bool:
        matched = False
        for substring in substring_list:
            if substring in search_within:
                matched = True
                break
        return matched
