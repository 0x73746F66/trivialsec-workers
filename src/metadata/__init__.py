import re
from datetime import datetime
from trivialsec.models.domain import Domain, DomainStat
from trivialsec.models.program import Program
from worker import WorkerInterface, queue_job
from trivialsec.helpers.log_manager import logger


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
        if hasattr(self.job.domain, DomainStat.HTTP_CERTIFICATE):
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

        server_headers = ['x-powered-by', 'server']
        proxy_headers = ['via']
        for header_name, header_value in self.job.domain._http_metadata.headers.items(): # pylint: disable=protected-access
            source_description = f'HTTP Header [{header_name}] of {self.job.domain.name}'
            if header_name in server_headers:
                server_name, server_version = self.split_version(header_value)
                program = Program(
                    project_id=self.job.domain.project_id,
                    domain_id=self.job.domain.domain_id,
                    name=server_name,
                    version=server_version,
                    source_description=source_description,
                    category='server',
                )
                self.report['programs'].append(program)
            elif header_name in proxy_headers:
                server_name, server_version = self.split_version(header_value)
                program = Program(
                    project_id=self.job.domain.project_id,
                    domain_id=self.job.domain.domain_id,
                    name=server_name,
                    version=server_version,
                    source_description=source_description,
                    category='proxy',
                )
                self.report['programs'].append(program)

        return True

    @staticmethod
    def split_version(header_value: str) -> tuple:
        server_name = header_value
        server_version = None
        if '/' in header_value and len(header_value.split('/')) == 2:
            server_name, server_version = header_value.split('/')
            try:
                matches = re.search(r'\d+(=?\.(\d+(=?\.(\d+)*)*)*)*', server_version)
                if matches:
                    server_version = matches.group()
            except Exception:
                server_version = None

        return server_name, server_version

    def analyse_report(self):
        self.job.domain.get_stats()
        scan_next = False
        http_last_checked = datetime.fromisoformat(getattr(self.job.domain, 'http_last_checked')).replace(microsecond=0)
        for domain_stat in self.job.domain.stats:
            created_at = datetime.fromisoformat(domain_stat.created_at)
            if created_at == http_last_checked and domain_stat.domain_stat == DomainStat.HTTP_CODE and int(str(domain_stat.domain_value)[0]) in [2,3]:
                scan_next = True
                break
            if domain_stat.domain_stat == DomainStat.DNS_REGISTERED and domain_stat.domain_value == '1':
                scan_next = True
                break

        if scan_next is True:
            queue_job(self.job, 'amass', self.job.domain.name)
            queue_job(self.job, 'testssl', self.job.domain.name)
