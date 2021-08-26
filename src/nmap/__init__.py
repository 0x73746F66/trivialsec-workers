import logging
import json
import re
from os import path, getcwd, stat
import xmltodict
from trivialsec.models.domain import Domain
from trivialsec.models.finding import Finding
from trivialsec.models.finding_detail import FindingDetail
from trivialsec.helpers.config import config
from trivialsec.helpers import is_valid_ipv4_address, is_valid_ipv6_address
from worker import WorkerInterface


logger = logging.getLogger(__name__)

class Worker(WorkerInterface):
    _prefix_path :str
    def __init__(self, job, paths :dict):
        self._prefix_path = path.realpath(path.join(
            paths.get('job_path'),
            job.queue_data.service_type_name,
            f'{job.queue_data.scan_type}-{paths.get("worker_id")}',
        ))
        super().__init__(job, paths)

    def get_result_filename(self) -> str:
        return path.realpath(path.join(
            self.paths.get('job_path'),
            self.job.queue_data.service_type_name,
            f'{self.job.queue_data.scan_type}-{self.paths.get("worker_id")}.xml'
        ))

    def get_log_filename(self) -> str:
        return path.realpath(path.join(
            self.paths.get('job_path'),
            self.job.queue_data.service_type_name,
            f'{self.job.queue_data.scan_type}-{self.paths.get("worker_id")}.log',
        ))

    def get_archive_files(self) -> dict:
        return {
            'nmap.xml': self.get_result_filename(),
            'nmap.json': f'{self._prefix_path}-nmap.json',
            'error.log': self.get_log_filename(),
        }

    def get_job_exe_path(self) -> str:
        return path.realpath(path.join(getcwd(), 'lib', 'bin', 'run-nmap'))

    def pre_job_exe(self) -> bool:
        if is_valid_ipv4_address(self.job.queue_data.target) or is_valid_ipv6_address(self.job.queue_data.target):
            return False # domain name here for reports, yes nmap supports IP, but will rDNS to hosting the provider domain
        target = Domain(name=self.job.queue_data.target, project_id=self.job.project_id)
        if not target.exists(['name', 'project_id']):
            raise ValueError(f'Could not load Domain using {self.job.queue_data}')

        return True

    def get_exe_args(self) -> list:
        min_cvss = config.nmap.get('min_cvss', 0)
        nameservers = config.external_dsn_provider
        if self.job.account.config.nameservers and len(self.job.account.config.nameservers.splitlines()) > 0:
            nameservers = ','.join(self.job.account.config.nameservers.splitlines())

        return [(self.job.queue_data.target, nameservers, str(min_cvss))]

    def post_job_exe(self) -> bool:
        report_path = self.get_result_filename()
        if not path.isfile(report_path):
            raise ValueError(f'File not found {report_path}')

        return True

    def build_report_summary(self, output :str, log_output :str) -> str:
        runstats = xmltodict.parse(output)['nmaprun']['runstats']
        return ' '.join([
            runstats['finished']['@exit'],
            'elapsed',
            runstats['finished']['@elapsed'],
            'seconds',
            runstats['hosts']['@total'],
            'total',
            runstats['hosts']['@up'],
            'up',
            runstats['hosts']['@down'],
            'down',
        ])

    @staticmethod
    def _normalise_vulscan(lines :list) -> dict:
        normalised = {
            'vuldb': [],
            'mitre': [],
            'securityfocus': [],
            'xforce': [],
            'exploitdb': [],
            'openvas': [],
            'securitytracker': [],
            'osvdb': [],
        }
        key = None
        for line in lines:
            if not line:
                continue
            if line.strip().lower().startswith('vuldb'):
                key = 'vuldb'
                continue
            if line.strip().lower().startswith('mitre'):
                key = 'mitre'
                continue
            if line.strip().lower().startswith('securityfocus'):
                key = 'securityfocus'
                continue
            if line.strip().lower().startswith('ibm'):
                key = 'xforce'
                continue
            if line.strip().lower().startswith('exploit-db'):
                key = 'exploitdb'
                continue
            if line.strip().lower().startswith('securitytracker'):
                key = 'securitytracker'
                continue
            if line.strip().lower().startswith('osvdb'):
                key = 'osvdb'
                continue
            if key is None or key in ['securityfocus', 'osvdb']:
                continue

            id_pattern = r"^\[(\d*)\]\s(.*)$"
            cve_pattern = r"^\[(CVE\-\d{4}\-\d*)\]\s(.*)$"
            if key == 'vuldb':
                matches = re.search(id_pattern, line)
                if matches is None:
                    logger.warning(line)
                ref_id = matches.group(1)
                title = matches.group(2)
                # https://vuldb.com/?id.108732
            if key == 'mitre':
                matches = re.search(cve_pattern, line)
                if matches is None:
                    logger.warning(line)
                ref_id = matches.group(1)
                title = matches.group(2)
                # https://nvd.nist.gov/vuln/detail/{ref_id}
            if key == 'xforce':
                matches = re.search(id_pattern, line)
                if matches is None:
                    logger.warning(line)
                ref_id = matches.group(1)
                title = matches.group(2)
                # xforce/vulnerabilities/{ref_id}.json
                # https://exchange.xforce.ibmcloud.com/vulnerabilities/{ref_id}
            if key == 'exploitdb':
                matches = re.search(id_pattern, line)
                if matches is None:
                    logger.warning(line)
                ref_id = matches.group(1)
                title = matches.group(2)
                # exploit-db/submissions/{ref_id}.json
                # exploit-db/raw/{ref_id}.json
            if key == 'securitytracker':
                matches = re.search(id_pattern, line)
                if matches is None:
                    logger.warning(line)
                ref_id = matches.group(1)
                title = matches.group(2)
                # https://securitytracker.com/id/{ref_id}

            normalised[key].append(line)
        return normalised

    def build_report(self, cmd_output :str, log_output :str) -> bool:
        with open(f'{self._prefix_path}-nmap.json', 'w', encoding='utf8') as buf:
            buf.write(json.dumps(xmltodict.parse(cmd_output), default=str))

        nmap_results = xmltodict.parse(cmd_output)
        if 'host' not in nmap_results['nmaprun']:
            return True

        if 'osmatch' in nmap_results['nmaprun']['host']['os']:
            osmatch = nmap_results['nmaprun']['host']['os']['osmatch']
            if isinstance(osmatch, list):
                osmatch = osmatch[0]
            os_name = osmatch.get('@name')
            os_accuracy = int(osmatch.get('@accuracy'))
            osclass = osmatch['osclass']
            if isinstance(osclass, list):
                osclass = osclass[0]
            os_type = osclass.get('@type')
            os_vendor = osclass.get('@vendor')
            os_family = osclass.get('@osfamily')
            os_gen = osclass.get('@osgen')
            os_cpe = osclass.get('cpe')

        for hostscript in nmap_results['nmaprun']['host']['hostscript']['script']:
             hostscript_output = hostscript['@output'].strip().splitlines()
             if hostscript['@id'] == 'firewalk':
                 pass
             if hostscript['@id'] == 'whois-ip':
                 pass

        ports = nmap_results['nmaprun']['host']['ports']['port']
        if not isinstance(ports, list):
            ports = [ports]

        for port in ports:
            reason = port['state'].get('@reason')
            protocol = port['@protocol']
            portid = port['@portid']
            state = port['state'].get('@state')
            cpe = port['service'].get('cpe')
            method = port['service'].get('@method')
            name = port['service'].get('@name')
            product = port['service'].get('@product')
            version = port['service'].get('@version')
            extrainfo = port['service'].get('@extrainfo')
            if state == 'closed':
                continue
            for script in port['script']:
                output = script['@output'].strip().splitlines()
                if script['@id'] == 'http-xssed':
                    pass
                if script['@id'] == 'ssl-ccs-injection':
                    pass
                if script['@id'] == 'vulscan':
                    logger.info(json.dumps(self._normalise_vulscan(output)))

            # finding = Finding()
            # finding.domain_id = self.job.domain.domain_id
            # finding.source_description = f'{test} {match}'
            # finding.evidence = http_header_evidence

            # finding_detail = FindingDetail()
            # finding_detail.title = f"{test} {bad}".strip()
            # finding_detail.finding_detail_id = oneway_hash(finding_detail.title) if finding_detail_id is None else finding_detail_id
            # if finding_detail.exists():
            #     finding_detail.hydrate()
            # else:
            #     finding_detail.severity_product = 50
            #     finding_detail.confidence = 90
            #     finding_detail.type_namespace = 'Software and Configuration Checks'
            #     finding_detail.type_category = 'Industry and Regulatory Standards'
            #     finding_detail.type_classifier = 'OWASP'
            #     finding_detail.persist(exists=False)

            # finding.cvss_vector = finding_detail.cvss_vector
            # finding.confidence = finding_detail.confidence
            # finding.severity_normalized = finding_detail.severity_product
            # finding.finding_detail_id = finding_detail.finding_detail_id
            # self.report['findings'].append(finding)

        return True
