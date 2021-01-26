import tldextract
import re
from datetime import datetime
from trivialsec.helpers.log_manager import logger
from trivialsec.helpers import is_valid_ipv4_address, is_valid_ipv6_address
from trivialsec.services.jobs import QueueData
from trivialsec.models import UpdateTable
from trivialsec.models.service_type import ServiceType
from trivialsec.models.notification import Notification
from trivialsec.models.job_run import JobRun, JobRuns
from trivialsec.models.domain import Domain, DomainStats
from trivialsec.models.finding import Finding
from trivialsec.models.security_alert import SecurityAlert
from trivialsec.models.known_ip import KnownIp
from trivialsec.models.dns_record import DnsRecord
from trivialsec.models.program import Program
from worker.sockets import send_event


class WorkerInterface:
    config = None
    domain: Domain = None
    job: JobRun = None
    report_template_types = {
        'findings': Finding,
        'security_alerts': SecurityAlert,
        'known_ips': KnownIp,
        'dns_records': DnsRecord,
        'domains': Domain,
        'domain_stats': DomainStats,
        'programs': Program,
        'updates': UpdateTable,
    }
    report = {
        'findings': [],
        'security_alerts': [],
        'known_ips': [],
        'dns_records': [],
        'domains': [],
        'domain_stats': [],
        'programs': [],
        'updates': [],
    }

    def __init__(self, job: JobRun, config: dict):
        if isinstance(job, JobRun):
            self.job = job
        if isinstance(config, dict):
            self.config = config
        if hasattr(job.queue_data, 'target'):
            self.domain = Domain(
                name=job.queue_data.target,
                project_id=job.project_id
            )
            if self.domain.exists(['name', 'project_id']):
                self.domain.hydrate()

    def analyse_report(self):
        "Some final tasks after everything else has finished"

    def validate_report(self) -> bool:
        result = False
        for index, model in self.report_template_types.items():
            if index not in self.report:
                logger.info(f'validate_report: {index} not a key in report object')
                continue
            if not isinstance(self.report[index], list):
                logger.warning(f'validate_report: {index} is not a list')
                continue
            logger.info(f'Found {len(self.report[index])} {model} in report')
            for item in self.report[index]:
                if not isinstance(item, model):
                    logger.warning(f'validate_report: item is not of type {model}')
                    continue
                result = True # at least 1 match found

        return result

    def _save_findings(self, findings: list):
        for finding in findings:
            finding.account_id = self.job.account_id
            finding.project_id = self.job.project_id
            finding.is_passive = self.job.queue_data.is_passive
            finding.service_type_id = self.job.queue_data.service_type_id
            finding.verification_state = Finding.VERIFY_UNKNOWN
            finding.workflow_state = Finding.WORKFLOW_NEW
            finding.state = Finding.STATE_ACTIVE
            exists_params = [
                ('project_id', finding.project_id),
                ('finding_detail_id', finding.finding_detail_id),
            ]
            if finding.domain_id:
                exists_params.append(('domain_id', finding.domain_id))
            exists = finding.exists(exists_params)
            if exists:
                old_finding = Finding(finding_id=finding.finding_id)
                old_finding.hydrate()
                finding.severity_normalized = old_finding.severity_normalized
                finding.verification_state = old_finding.verification_state
                finding.workflow_state = old_finding.workflow_state
                finding.state = old_finding.state
                finding.created_at = old_finding.created_at
                finding.updated_at = old_finding.updated_at
                finding.defer_to = old_finding.defer_to
                finding.archived = old_finding.archived
                if not finding.source_description:
                    finding.source_description = old_finding.source_description
            finding.last_observed_at = datetime.utcnow().isoformat()
            finding.persist(exists=exists)
            finding_dict = {}
            for col in finding.cols():
                finding_dict[col] = getattr(finding, col)
            send_event('finding_changes', {
                'socket_key': self.job.account.socket_key,
                'finding': finding_dict,
            })

    def _save_security_alerts(self, security_alerts: list):
        for security_alert in security_alerts:
            security_alert.account_id = self.job.account_id
            exists_params = []
            if security_alert.security_alert_id:
                exists_params.append(('security_alert_id', security_alert.security_alert_id))
            else:
                exists_params.extend([
                    ('account_id', security_alert.account_id),
                    ('type', security_alert.type)
                ])

            exists = security_alert.exists(exists_params)
            security_alert.last_observed_at = datetime.utcnow().isoformat()
            security_alert.persist(exists=exists)
            alert_dict = {}
            for col in security_alert.cols():
                alert_dict[col] = getattr(security_alert, col)
            send_event('security_alert', {
                'socket_key': self.job.account.socket_key,
                'alert': alert_dict,
            })

    def _save_domain_stats(self, domain_stats: list):
        for domain_stat in domain_stats:
            exists_params = []
            if domain_stat.domain_stats_id:
                exists_params.append(('domain_stats_id', domain_stat.domain_stats_id))
            else:
                exists_params.extend([
                    ('domain_id', domain_stat.domain_id),
                    ('domain_stat', domain_stat.domain_stat)
                ])

            exists = domain_stat.exists(exists_params)
            domain_stat.created_at = datetime.utcnow().isoformat()
            domain_stat.persist(exists=exists)

    def _save_programs(self, programs: list):
        for program in programs:
            program.account_id = self.job.account_id
            program.project_id = self.job.project_id
            checks = [('name', program.name), ('source_description', program.source_description)]
            if program.domain_id:
                checks.append(('domain_id', program.domain_id))
            if not program.version:
                ver_expr = r'(?:(\d+\.(?:\d+\.)*\d+))'
                matches = re.findall(ver_expr, program.name)
                if matches:
                    program.version = matches[0]
            if program.version:
                checks.append(('version', program.version))

            exists = program.exists(checks)
            if exists:
                old_program = Program(program_id=program.program_id)
                old_program.hydrate()
                program.created_at = old_program.created_at
            program.last_checked = datetime.utcnow().isoformat()
            program.persist(exists=exists)
            program_dict = {}
            for col in program.cols():
                program_dict[col] = getattr(program, col)
            send_event('program_changes', {
                'socket_key': self.job.account.socket_key,
                'program': program_dict,
            })

    def _save_domains(self, domains: list):
        utcnow = datetime.utcnow()
        for domain in domains:
            if domain.name in ('localhost', self.domain.name) or domain.name.endswith('.arpa'):
                continue
            if domain.name.startswith('*.'):
                domain.name = domain.name[2:]

            ext = tldextract.extract(f'http://{domain.name}')
            if ext.registered_domain != domain.name:
                tld = Domain(
                    name=ext.registered_domain,
                    account_id=self.job.account_id,
                    project_id=self.job.project_id,
                    source=domain.source,
                    created_at=utcnow,
                    updated_at=utcnow,
                    deleted=False,
                    enabled=False
                )
                tld_exists = tld.exists(['name', 'project_id'])
                domain.parent_domain_id = tld.domain_id
                if not tld_exists:
                    tld.persist(exists=tld_exists)
                    Notification(
                        account_id=self.job.account_id,
                        description=f'Apex domain {tld.name} saved via {self.job.queue_data.service_type_category}',
                        url=f'/domain/{tld.domain_id}'
                    ).persist()
                    tld_dict = {}
                    for col in domain.cols():
                        tld_dict[col] = getattr(tld, col)
                    send_event('domain_changes', {
                        'socket_key': self.job.account.socket_key,
                        'domain': tld_dict,
                    })

            domain.account_id = self.job.account_id
            domain.project_id = self.job.project_id
            domain.enabled = False
            exists = domain.exists(['name', 'project_id'])
            if exists:
                original_domain = Domain(domain_id=domain.domain_id)
                original_domain.hydrate()
                domain.source = original_domain.source
                domain.created_at = original_domain.created_at
                domain.enabled = original_domain.enabled
                domain.schedule = original_domain.schedule
                if domain.screenshot is None:
                    domain.screenshot = original_domain.screenshot
            domain.deleted = False
            domain.updated_at = utcnow

            if domain.persist(exists=exists):
                Notification(
                    account_id=self.job.account_id,
                    description=f'Domain {domain.name} saved via {self.job.queue_data.service_type_category}',
                    url=f'/domain/{domain.domain_id}'
                ).persist()
                queue_job(self.job, 'metadata', domain.name)
                queue_job(self.job, 'drill', domain.name)
                domain_dict = {}
                for col in domain.cols():
                    domain_dict[col] = getattr(domain, col)

                send_event('domain_changes', {
                    'socket_key': self.job.account.socket_key,
                    'domain': domain_dict,
                })

    def _save_known_ips(self, known_ips: list):
        for known_ip in known_ips:
            if known_ip.ip_address in ('127.0.0.1', '::1', '::', '0:0:0:0:0:0:0:1'):
                continue

            known_ip.account_id = self.job.account_id
            known_ip.project_id = self.job.project_id
            exists_params = ['ip_address']
            if known_ip.domain_id:
                exists_params.append('domain_id')
            else:
                exists_params.append('account_id')
            exists = known_ip.exists(exists_params)
            if exists:
                known_ip.updated_at = datetime.utcnow()
            if is_valid_ipv4_address(known_ip.ip_address):
                known_ip.ip_version = 'ipv4'
            elif is_valid_ipv6_address(known_ip.ip_address):
                known_ip.ip_version = 'ipv6'
            known_ip.persist(exists=exists)
            ip_dict = {}
            for col in known_ip.cols():
                ip_dict[col] = getattr(known_ip, col)
            send_event('ipaddr_changes', {
                'socket_key': self.job.account.socket_key,
                'ipaddr': ip_dict,
            })

    def _save_dns_records(self, dns_records: list):
        for dns_record in dns_records:
            if dns_record.answer in ('127.0.0.1', '::1', '::', '0:0:0:0:0:0:0:1'):
                continue
            if not dns_record.domain_id:
                logger.warning(f'domain_id missing from dns_record {dns_record.raw}')
                continue
            dns_record.last_checked = datetime.utcnow()
            exists = dns_record.exists(['domain_id', 'raw'])
            if dns_record.raw:
                dns_record.persist(exists=exists)
                dns_dict = {}
                for col in dns_record.cols():
                    dns_dict[col] = getattr(dns_record, col)
                send_event('dns_changes', {
                    'socket_key': self.job.account.socket_key,
                    'dns': dns_dict,
                })

    def _save_update_fields(self, updates: list):
        for update_table in updates:
            update_table.persist()

    def save_report(self) -> bool:
        if 'findings' in self.report:
            self._save_findings(self.report['findings'])
        if 'security_alerts' in self.report:
            self._save_security_alerts(self.report['security_alerts'])
        if 'programs' in self.report:
            self._save_programs(self.report['programs'])
        if 'domains' in self.report:
            self._save_domains(self.report['domains'])
        if 'known_ips' in self.report:
            self._save_known_ips(self.report['known_ips'])
        if 'dns_records' in self.report:
            self._save_dns_records(self.report['dns_records'])
        if 'updates' in self.report:
            self._save_update_fields(self.report['updates'])
        if 'domain_stats' in self.report:
            self._save_domain_stats(self.report['domain_stats'])

        return True

    def get_result_filename(self) -> str:
        "returns path for worker command output file"

    def get_log_filename(self) -> str:
        "returns path for worker command log file"

    def get_job_exe_path(self) -> str:
        "returns path for worker command"

    def pre_job_exe(self) -> bool:
        "returns True when validations pass"

    def get_exe_args(self) -> list:
        "returns a list of arguments to pass to work command"

    def post_job_exe(self) -> bool:
        "returns True when successful command verification passes"

    def build_report(self, cmd_output: str, log_output: str) -> bool:
        "returns data to persist"

    def get_archive_files(self) -> dict:
        "returns file name amd paths of files to send to S3"

    def build_report_summary(self, output: str, log_output: str) -> str:
        "returns a human readable summary"

def update_state(job: JobRun, state: str, message: str = None):
    if message is not None:
        job.worker_message = message
    job.updated_at = datetime.utcnow().isoformat()
    job.state = state
    update_job(job)

def update_job(job: JobRun) -> bool:
    logger.info(f'update_job state {job.state} Job {job.job_run_id} Worker {job.worker_id} Service {job.node_id}')
    job.persist(invalidations=[
        f'job_runs/{job.queue_data.target}'
    ])
    send_event('update_job_state', {
        'id': job.job_run_id,
        'account_id': job.account_id,
        'queue_data': job.queue_data,
        'state': job.state,
        'service_category': job.service_type.category,
        'worker_message': job.worker_message,
        'created': job.created_at if not isinstance(job.created_at, datetime) else job.created_at.isoformat(),
        'started': job.started_at if not isinstance(job.started_at, datetime) else job.started_at.isoformat(),
        'updated': job.updated_at if not isinstance(job.updated_at, datetime) else job.updated_at.isoformat(),
        'completed': job.completed_at if not isinstance(job.completed_at, datetime) else job.completed_at.isoformat(),
        'socket_key': job.account.socket_key
    })

    return True

def handle_error(err, job: JobRun):
    if isinstance(err, Exception):
        logger.exception(err)
    else:
        logger.error(err)
    update_state(job, ServiceType.STATE_ERROR, err)
    Notification(
        account_id=job.account_id,
        description=f'Job {job.queue_data.service_type_category} failed',
        url='/app'
    ).persist()

def queue_job(original_job: JobRuns, name: str, target: str = None):
    target = target or original_job.queue_data.target
    service_type = ServiceType(name=name)
    service_type.hydrate(['name'])
    job_runs = JobRuns()
    job_runs.query_json([
        ('service_type_id', service_type.service_type_id),
        ('state', ['queued', 'starting', 'processing', 'finalising']),
        ('$.target', target),
    ])
    if len(job_runs) == 0:
        new_job_run = JobRun(
            account_id=original_job.account_id,
            project_id=original_job.project_id,
            service_type_id=service_type.service_type_id,
            queue_data=str(QueueData(
                scan_type=original_job.queue_data.scan_type,
                service_type_id=service_type.service_type_id,
                service_type_name=service_type.name,
                service_type_category=service_type.category,
                target=target
            )),
            state=ServiceType.STATE_QUEUED,
            priority=0
        )
        new_job_run.persist()
