import re
from csv import reader
from io import StringIO
from os import path, getcwd
from trivialsec.models.domain import Domain
from trivialsec.models.finding_detail import FindingDetail
from trivialsec.models.finding import Finding
from trivialsec.models.inventory import InventoryItem
from trivialsec.models.program import Program
from trivialsec.helpers import extract_server_version, oneway_hash, is_valid_ipv4_address, is_valid_ipv6_address
from gunicorn.glogging import logging
from worker import WorkerInterface


logger = logging.getLogger(__name__)

class Worker(WorkerInterface):
    def __init__(self, job, config: dict):
        super().__init__(job, config)

    def get_result_filename(self) -> str:
        target = self.job.queue_data.target
        filename = path.realpath(path.join(
            self.config['job_path'],
            self.job.queue_data.service_type_name,
            f'{self.job.queue_data.scan_type}-{target}-{self.config.get("worker_id")}.csv',
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
            'output.csv': self.get_result_filename(),
            'error.log': self.get_log_filename(),
        }

    def get_job_exe_path(self) -> str:
        return path.realpath(path.join(getcwd(), 'lib', 'bin', 'run-testssl'))

    def pre_job_exe(self) -> bool:
        if is_valid_ipv4_address(self.job.queue_data.target) or is_valid_ipv6_address(self.job.queue_data.target):
            return False

        return True

    def get_exe_args(self) -> list:
        args = [self.job.queue_data.target]
        # --bugs enables the "-bugs" option of s_client, needed e.g. for some buggy F5s
        if self.job.queue_data.is_active:
            args.append('-active')
        return [args]

    def post_job_exe(self) -> bool:
        report_path = self.get_result_filename()
        if not path.isfile(report_path):
            raise ValueError(f'File not found {report_path}')

        return True

    def build_report_summary(self, output: str, log_output: str) -> str:
        summary = 'Scan completed without any new results'
        summary_parts = []
        if len(self.report["findings"]) > 0:
            summary_parts.append(f'{len(self.report["findings"])} issues')
            if len(self.report['inventory_items']) > 0:
                summary_parts.append(f' with {len(self.report["inventory_items"])} inventory_items')
            if len(self.report["domains"]) > 0:
                summary_parts.append(f' and {len(self.report["domains"])} domains')
        if summary_parts:
            summary = f"Found {''.join(summary_parts)}"

        if len(self.report["findings"]) > 0:
            summary = f'Found {len(self.report["findings"])} issues'

        return summary

    def build_report(self, cmd_output: str, log_output: str) -> bool:
        tls_tests = [ # match_text, bad test or title if good test, good
            ('Session Ticket RFC 5077 hint', 'no lifetime advertised', None, '96nX6l2Ee9sSmVg0e8KPa1u9fJL8tFirL6LVdyPplDg'),
            ('SSL Session ID support', None, 'no', '5GcfdkNtrLBU1ib..tTJ65af.goMx7RXV8ZUNxMj09M'),
            ('Session Resumption', None, 'Tickets: no', '84aycqbFXGGc8f9esHflBlTUG2S7zoFnWSjyI6NlS8'),
            ('Triple DES Ciphers', None, 'not offered', 'JNKHQADXdp8kWu9EQUgAiIXvzBYJ8JKn0pcm8xCI15c'),
            ('Trust \(hostname\)', None, 'Ok via', 'EZlMoKbKvzj.Z34Yw7Us9PgHDnGzHG2SIA4hWlIT3iU'),
            ('Chain of trust', None, 'Ok', 'Hae5wl1hC3VHxHjYh5QaoVPajcfiW9kMBnUxkAtkPSU'),
            ('EV cert \(experimental\)', None, 'yes', '0JQmn7m1ell7jziyN.dsKzp7whog49205rmxDdl4Uac'),
            ('OCSP stapling', None, 'offered, not revoked', 'D8pl9iybC6eUDVm8zwG40nkS6QK6zz3pSqofC71vo'),
            ('NULL ciphers \(no encryption\)', None, 'not offered', 'v3McSkyQN1LDtmEIAWIVeVpynzcaczih88O0hXAA5k'),
            ('Anonymous NULL Ciphers \(no authentication\)', None, 'not offered', 'pVZzNzIbafhC9zaqz0aYVSaDdLDf.hGySLo3QsmkEoY'),
            ('Export ciphers', None, 'not offered', 'CYoUsvYyRadsDpDdcV7YXSDz7e44FnW0TrzboHiKyU'),
            ('Obsoleted CBC ciphers', None, 'not offered', 'ZOHbqGmDtlX6Htnug2y1xYP0kE3nSOEmmmYYafk54tU'),
        ]
        owasp_tests = [ # match_text, bad test or title if good test, good
            ('Strict Transport Security', 'not offered', None, None),
            ('X-Frame-Options', 'potential clickjacking risk', 'deny', None),
            ('X-XSS-Protection', 'site allows XSS', 'mode=block', None),
            ('X-Content-Type-Options', 'malicious code delivery', 'nosniff', None),
            ('Referrer-Policy', 'sensitive information leakage risk', 'no-referrer', None),
            ('Expect-CT', None, 'enforce', 'UzsKjFqFS2WSwQwhJfG9yDoKFBheSsnTMvDL.qKWgE'),
            ('Content-Security-Policy', 'Risk of XSS', 'block-all-mixed-content', None),
            ('Content-Security-Policy', 'Risk of XSS', 'reflected-xss', None),
            ('Content-Security-Policy', 'Risk of XSS', 'script-src', None),
            ('X-Content-Security-Policy', 'Risk of XSS', 'block-all-mixed-content', None),
            ('X-Content-Security-Policy', 'Risk of XSS', 'reflected-xss', None),
            ('X-Content-Security-Policy', 'Risk of XSS', 'script-src', None),
            ('X-WebKit-CSP', 'Risk of XSS', 'block-all-mixed-content', None),
            ('X-WebKit-CSP', 'Risk of XSS', 'reflected-xss', None),
            ('X-WebKit-CSP', 'Risk of XSS', 'script-src', None),
            ('Content-Security-Policy-Report-Only', 'Risk of XSS', None, None),
        ]
        extra_tests = [ # match_text, bad test or title if good test, good, evidence
            ('In pwnedkeys.com DB', 'Certificate private key has been exposed', 'not in database', 'wget https://v1.pwnedkeys.com/$(echo $spki | openssl dgst -sha256 -hex).json'),
        ]
        pattern = re.compile('^\s(Start).+-->>\s((\d+\.+)+\d+:\d+).+(<<--)$', re.MULTILINE)
        matches = re.search(pattern, log_output)
        if matches is None:
            logger.warning(log_output)
            return True

        ip_addr, port = matches.group(2).split(':')
        openssl_evidence = f'opensll s_client -cipher $pfs_cipher_list -connect {ip_addr}:{port} -servername {self.job.domain.name} </dev/null'
        http_header_evidence = f'curl -sSL -D - {self.job.domain.name} -o /dev/null'

        pfs_not_supported = 'No ciphers supporting Forward Secrecy offered'
        if pfs_not_supported in log_output:
            finding = Finding()
            finding.domain_id = self.job.domain.domain_id
            finding.source_description = pfs_not_supported
            finding.evidence = openssl_evidence
            finding_detail = FindingDetail()
            finding_detail.title = pfs_not_supported
            finding_detail.finding_detail_id = oneway_hash(finding_detail.title)
            if finding_detail.exists():
                finding_detail.hydrate()
            else:
                finding_detail.severity_product = 80
                finding_detail.confidence = 100
                finding_detail.type_namespace = 'Software and Configuration Checks'
                finding_detail.type_category = 'Vulnerabilities'
                finding_detail.type_classifier = 'SSL/TLS'
                finding_detail.persist(exists=False)

            finding.cvss_vector = finding_detail.cvss_vector
            finding.confidence = finding_detail.confidence
            finding.severity_normalized = finding_detail.severity_product
            finding.finding_detail_id = finding_detail.finding_detail_id
            self.report['findings'].append(finding)

        tls_ok = ['TLSv1.2', 'TLSv1.3']
        for match in re.findall(r'^\s(.+)\s(TLSv\d.\d)\s+([a-zA-Z0-9\-\_]+)\s+(.+)$', log_output):
            client_sim = match.group(1)
            client_tls = match.group(2)
            client_cipher = match.group(3)
            client_detail = match.group(4)
            if client_tls in tls_ok:
                continue

            finding = Finding()
            finding.domain_id = self.job.domain.domain_id
            finding.source_description = f'{client_cipher} {client_detail}'
            finding.evidence = openssl_evidence
            finding_detail = FindingDetail()
            finding_detail.title = f'Insecure downgrade of deprecated protocol {client_tls} for {client_sim}'
            finding_detail.finding_detail_id = oneway_hash(finding_detail.title)
            if finding_detail.exists():
                finding_detail.hydrate()
            else:
                finding_detail.severity_product = 100
                finding_detail.confidence = 100
                finding_detail.type_namespace = 'Software and Configuration Checks'
                finding_detail.type_category = 'Vulnerabilities'
                finding_detail.type_classifier = 'SSL/TLS'
                finding_detail.persist(exists=False)

            finding.cvss_vector = finding_detail.cvss_vector
            finding.confidence = finding_detail.confidence
            finding.severity_normalized = finding_detail.severity_product
            finding.finding_detail_id = finding_detail.finding_detail_id
            self.report['findings'].append(finding)

        for match_text, bad, good, finding_detail_id in tls_tests:
            matches = None
            pattern = re.compile(f'({match_text})\W*(.*$)', re.MULTILINE)
            matches = re.findall(pattern, log_output)
            if not matches:
                continue
            key, match = matches[0]
            test = key.strip()
            if isinstance(bad, str) and bad in match:
                matched_term = bad
            elif isinstance(good, str) and good not in match:
                matched_term = good
            else:
                continue
            finding = Finding()
            finding.domain_id = self.job.domain.domain_id
            finding.evidence = openssl_evidence

            finding_detail = FindingDetail()
            finding_detail.finding_detail_id = finding_detail_id
            if finding_detail.exists():
                finding_detail.hydrate()
                finding.source_description = matched_term
                finding.severity_normalized = finding_detail.severity_product
                finding.finding_detail_id = finding_detail.finding_detail_id
                self.report['findings'].append(finding)
            else:
                logger.error(f'FindingDetails missing for {finding_detail_id} {match_text}')

        for match_text, bad, good, finding_detail_id in owasp_tests:
            matches = None
            pattern = re.compile(f'({match_text})\W*(.*$)', re.MULTILINE)
            matches = re.findall(pattern, log_output)
            if not matches:
                continue
            key, match = matches[0]
            test = key.strip()
            if isinstance(bad, str) and bad in match:
                matched_term = bad
            elif isinstance(good, str) and good not in match:
                matched_term = good
            else:
                continue

            finding = Finding()
            finding.domain_id = self.job.domain.domain_id
            finding.source_description = f'{test} {match}'
            finding.evidence = http_header_evidence

            finding_detail = FindingDetail()
            finding_detail.title = f"{test} {bad}".strip()
            finding_detail.finding_detail_id = oneway_hash(finding_detail.title) if finding_detail_id is None else finding_detail_id
            if finding_detail.exists():
                finding_detail.hydrate()
            else:
                finding_detail.severity_product = 50
                finding_detail.confidence = 90
                finding_detail.type_namespace = 'Software and Configuration Checks'
                finding_detail.type_category = 'Industry and Regulatory Standards'
                finding_detail.type_classifier = 'OWASP'
                finding_detail.persist(exists=False)

            finding.cvss_vector = finding_detail.cvss_vector
            finding.confidence = finding_detail.confidence
            finding.severity_normalized = finding_detail.severity_product
            finding.finding_detail_id = finding_detail.finding_detail_id
            self.report['findings'].append(finding)

        for match_text, bad, good, evidence in extra_tests:
            matches = None
            pattern = re.compile(f'({match_text})\W*(.*$)', re.MULTILINE)
            matches = re.findall(pattern, log_output)
            if not matches:
                continue
            key, match = matches[0]
            test = key.strip()
            if isinstance(bad, str) and bad in match:
                matched_term = bad
            elif isinstance(good, str) and good not in match:
                matched_term = good
            else:
                continue
            finding = Finding()
            finding.domain_id = self.job.domain.domain_id
            finding.source_description = f'{test} {match}'
            finding.evidence = evidence

            finding_detail = FindingDetail()
            finding_detail.title = f"{test} {bad}".strip()
            finding_detail.finding_detail_id = oneway_hash(finding_detail.title)
            if finding_detail.exists():
                finding_detail.hydrate()
            else:
                finding_detail.severity_product = 100
                finding_detail.confidence = 90
                finding_detail.type_namespace = 'Software and Configuration Checks'
                finding_detail.type_category = 'Vulnerabilities'
                finding_detail.type_classifier = 'SSL/TLS'
                finding_detail.persist(exists=False)

            finding.cvss_vector = finding_detail.cvss_vector
            finding.confidence = finding_detail.confidence
            finding.severity_normalized = finding_detail.severity_product
            finding.finding_detail_id = finding_detail.finding_detail_id
            self.report['findings'].append(finding)

        reverse_proxy_banner = 'Reverse Proxy banner'
        server_banner = 'Server banner'
        application_banner = 'Application banner'
        programs_mapping = [server_banner, application_banner, reverse_proxy_banner]
        for match_text in programs_mapping:
            matches = None
            pattern = re.compile(f'({match_text})(.*$)', re.MULTILINE)
            matches = re.findall(pattern, log_output)
            if not matches:
                continue
            key, match = matches[0]
            test = key.strip()
            program_value = match.strip().replace(" -- inconclusive test, matching cipher in list missing, better see below", "")
            if '--' in program_value:
                continue

            server_name, program_version = extract_server_version(program_value)
            if server_name is None:
                continue
            program = Program(name=server_name)
            program.hydrate('name')
            if program.category is None:
                if match_text == reverse_proxy_banner:
                    program.category = 'proxy'
                elif match_text == server_banner:
                    program.category = 'server'
                elif match_text == application_banner:
                    program.category = 'application'
            if program.program_id is None:
                program.persist()
            self.report['inventory_items'].append(InventoryItem(
                program_id=program.program_id,
                project_id=self.job.domain.project_id,
                domain_id=self.job.domain.domain_id,
                version=program_version,
                source_description=f'HTTP Header [{program.category}] of {self.job.domain.name}'
            ))

        san_matched = re.findall(r'(subjectAltName)(.*$)', log_output, re.MULTILINE)
        if san_matched:
            key, match = san_matched[0]
            test = key.strip()
            domains_expr = r'(?=.{4,253}$)(((?!-)[a-zA-Z0-9-]{0,62}[a-zA-Z0-9]\.)+[a-zA-Z]{2,63})'
            domain_matches = re.findall(domains_expr, match, re.MULTILINE)
            subject_alt_names = set()
            for match in domain_matches:
                full_match, *_ = match
                if ' ' in full_match:
                    for part in full_match.split(' '):
                        subject_alt_names.add(part.strip())
                else:
                    subject_alt_names.add(full_match.strip())
            for san_name in subject_alt_names:
                san_domain = Domain(name=san_name)
                if not san_name.endswith(self.job.domain.name) and not self.job.domain.name == san_name:
                    san_domain.parent_domain_id = self.job.domain.domain_id
                san_domain.source = f'TLS Certificate of {self.job.domain.name}'
                self.report['domains'].append(san_domain)

        for row in reader(StringIO(cmd_output), delimiter=','):
            finding_id = row[0].strip()
            test_target = row[1].strip()
            _, ip_addr = test_target.split('/')
            severity = row[3].strip()
            finding_desc = row[4].strip()
            cve = row[5].strip()
            cwe = row[6].strip()
            hint = row[7].strip()
            if finding_id == 'scanProblem':
                break
            if finding_id in ['id', 'engine_problem']:
                continue
            if severity == 'OK':
                continue
            if finding_id in ['TLS1_1', 'TLS1'] and 'deprecated' in finding_desc:
                continue
            if finding_id == 'service' and not finding_desc:
                continue
            if finding_id == 'protocol_negotiated' and 'Default protocol empty' in finding_desc:
                continue
            if finding_id == 'cipher_negotiated' and 'limited sense as client will pick' in finding_desc:
                continue
            if finding_id in ['unexpected result', 'skipping all HTTP checks', 'cipher_order', "couldn't connect", 'fallback_SCSV', 'proceeding with next IP (if any)']:
                continue
            finding = Finding()
            finding.domain_id = self.job.domain.domain_id
            source_description = f'{finding_desc} {hint}'.strip()
            if 'offered' in finding_desc:
                source_description = f'{finding_id} {source_description}'
            finding.source_description = source_description[:255]
            finding_detail = FindingDetail()
            finding_detail.description = finding.source_description

            if cve:
                finding_detail.title = cve
                finding_detail.type_namespace = 'Software and Configuration Checks'
                finding_detail.type_category = 'Vulnerabilities'
                finding_detail.type_classifier = 'CVE'
                finding.evidence = f'lynx --dump "https://www.ssllabs.com/ssltest/analyze.html?d={self.job.domain.name}&s={ip_addr}&hideResults=on"'
            elif cwe:
                finding_detail.title = cwe
                finding_detail.type_namespace = 'Software and Configuration Checks'
                finding_detail.type_category = 'Vulnerabilities'
                finding_detail.type_classifier = 'CWE'
                finding.evidence = f'lynx --dump "https://www.ssllabs.com/ssltest/analyze.html?d={self.job.domain.name}&s={ip_addr}&hideResults=on"'
            else:
                finding_detail.title = finding_id.strip()
                finding_detail.type_namespace = 'Sensitive Data Identifications'
                finding_detail.type_category = 'Security'
                finding_detail.type_classifier = finding_id
                if 'TLS' in source_description:
                    finding.evidence = openssl_evidence
                else:
                    finding.evidence = http_header_evidence

            finding_detail.finding_detail_id = oneway_hash(finding_detail.title)
            if finding_detail.exists():
                finding_detail.hydrate()
            else:
                finding_detail.confidence = 100
                if severity == 'INFO':
                    finding_detail.severity_product = 0
                elif severity == 'LOW':
                    finding_detail.severity_product = 30
                elif severity == 'MEDIUM':
                    finding_detail.severity_product = 60
                elif severity == 'HIGH':
                    finding_detail.severity_product = 80
                elif severity == 'CRITICAL':
                    finding_detail.severity_product = 90
                finding_detail.persist(exists=False)

            finding.cvss_vector = finding_detail.cvss_vector
            finding.confidence = finding_detail.confidence
            finding.severity_normalized = finding_detail.severity_product
            finding.finding_detail_id = finding_detail.finding_detail_id
            self.report['findings'].append(finding)

        return True

    def _generate_json(self):
        return {
            'Protocols': {
                'SSL v2': None,
                'SSL v3': None,
                'TLS 1.0': None,
                'TLS 1.1': None,
                'TLS 1.2': None,
                'TLS 1.3': None,
                'HTTP2': None
            },
            'Cipher Categories': {
                'NULL ciphers (no encryption)': None,
                'Anonymous NULL Ciphers (no authentication)': None,
                'Export ciphers (excluding ADH+NULL)': None,
                'LOW: 64 Bit + DES, RC[2,4] (excluding export)': None,
                'Triple DES Ciphers / IDEA': None,
                'Obsolete CBC ciphers (AES, ARIA)': None,
                'Strong encryption (AEAD ciphers)': None
            },
            'Forward Anonymity': {
                'Offered': None,
                'Ciphers': None,
                'ECDHE Curves': None
            },
            'Server Preferences': {
                'Cipher Order': None,
                'Protocol Negotiated': None,
                'Cipher Negotiated': None,
                'Cipher TLS v1.0': None,
                'Cipher TLS v1.1': None,
                'Cipher TLS v1.2': None
            },
            'Server Defaults': {
                'TLS Extensions': [],
                'TLS Session Ticket': None,
                'SSL Session-ID Support': None,
                'Session Resumption Ticket': None,
                'Session Resumption ID': None,
                'TLS Timestamp': None,
                'Number of Certificates': None
            },
            'Certificate': {
                'Signature Algorithm': None,
                'Key Size': None,
                'Key Usage': [],
                'Extended Key Usage': [],
                'Serial Number': None,
                'SHA1 Fingerprint': None,
                'SHA256 Fingerprint': None,
                'X.509 Certificate': None,
                'Common Name (CN)': None,
                'Subject Alternative Name (SAN)': [],
                'CA Issuer': None,
                'Certificate Trust': None,
                'Chain Of Trust': None,
                'Extended-Validation Policies': None,
                'ETS / eTLS': None,
                'Expiration Status': None,
                'Valid Not Before': None,
                'Valid Not After': None,
                'Validity Period': None,
                'Certificate Count Server': None,
                'Certs List Ordering Problem': None,
                'Leaked Key (pwnedkeys.com)': None,
                'CRL Distribution Points': None,
                'OCSP Revoked': None,
                'OCSP URL': None,
                'OCSP Stapling': None,
                'OCSP Must Staple Extension': None,
                'DNS CAA Record': None,
                'Certificate Transparency': None
            },
            'HTTP response': {
                'HTTP Status Code': None,
                'HTTP Clock Skew': None,
                'HSTS Expiration Time': None,
                'HSTS Subdomains': None,
                'HSTS Preload': None,
                'Server Banner': None,
                'Banner Application': None
            }
        }
