from datetime import datetime
import logging
import tldextract
from trivialsec.models.member import Member
from trivialsec.services.jobs import queue_job as service_queue_job
from trivialsec.models import UpdateTable
from trivialsec.models.service_type import ServiceType
from trivialsec.models.notification import Notification
from trivialsec.models.job_run import JobRun, JobRuns
from trivialsec.models.domain import Domain
from trivialsec.models.finding import Finding
from trivialsec.models.security_alert import SecurityAlert
from worker.sockets import send_event


logger = logging.getLogger(__name__)

class WorkerInterface:
    paths :dict
    job: JobRun = None
    report_template_types = {
        'findings': Finding,
        'security_alerts': SecurityAlert,
        'domains': Domain,
        'updates': UpdateTable,
    }
    report = {
        'findings': [],
        'security_alerts': [],
        'updates': [],
    }
    invalidations = {
        'findings': ['findings/finding_id/{finding_id}'],
        'security_alerts': ['security_alerts/security_alert_id/{security_alert_id}'],
        'domains': ['domains/domain_name/{domain_name}'],
        'updates': [],
    }

    def __init__(self, job: JobRun, paths :dict):
        if isinstance(job, JobRun):
            self.job = job
        if isinstance(paths, dict):
            self.paths = paths

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

    def _save_findings(self, findings :list):
        for finding in findings:
            cache_keys = []
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
            if finding.domain_name:
                exists_params.append(('domain_name', finding.domain_name))
            exists = finding.exists(exists_params)
            if exists:
                for cache_key in self.invalidations['findings']:
                    if '{finding_id}' in cache_key:
                        cache_keys.append(cache_key.format(finding_id=finding.finding_id))
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
            finding.persist(exists=exists, invalidations=cache_keys)
            finding_dict = {}
            for col in finding.cols():
                finding_dict[col] = getattr(finding, col)
            send_event('finding_changes', {
                'socket_key': self.job.account.socket_key,
                'finding': finding_dict,
            })

    def _save_security_alerts(self, security_alerts :list):
        for security_alert in security_alerts:
            cache_keys = []
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
            if exists:
                for cache_key in self.invalidations['security_alerts']:
                    if '{security_alert_id}' in cache_key:
                        cache_keys.append(cache_key.format(security_alert_id=security_alert.security_alert_id))
            security_alert.last_observed_at = datetime.utcnow().isoformat()
            security_alert.persist(exists=exists, invalidations=cache_keys)
            alert_dict = {}
            for col in security_alert.cols():
                alert_dict[col] = getattr(security_alert, col)
            send_event('security_alert', {
                'socket_key': self.job.account.socket_key,
                'alert': alert_dict,
            })

    # def _save_domain_stats(self, domain_stats :list):
    #     for domain_stat in domain_stats:
    #         cache_keys = []
    #         exists_params = []
    #         if domain_stat.domain_stats_id:
    #             exists_params.append(('domain_stats_id', domain_stat.domain_stats_id))
    #         else:
    #             exists_params.extend([
    #                 ('domain_id', domain_stat.domain_id),
    #                 ('domain_stat', domain_stat.domain_stat),
    #                 ('domain_value', domain_stat.domain_value)
    #             ])

    #         exists = domain_stat.exists(exists_params)
    #         if exists:
    #             old_domain_stat = DomainStat()
    #             old_domain_stat.domain_stats_id = domain_stat.domain_stats_id
    #             old_domain_stat.hydrate()
    #             domain_stat.created_at = old_domain_stat.created_at
    #             for cache_key in self.invalidations['domain_stats']:
    #                 if '{domain_id}' in cache_key:
    #                     cache_keys.append(cache_key.format(domain_id=domain_stat.domain_id))
    #         domain_stat.persist(exists=exists, invalidations=cache_keys)

    # def _save_inventory_items(self, inventory_items :list):
    #     for inventory_item in inventory_items:
    #         cache_keys = []
    #         inventory_item.account_id = self.job.account_id
    #         inventory_item.project_id = self.job.project_id

    #         checks = [('program_id', inventory_item.program_id), ('source_description', inventory_item.source_description)]
    #         if inventory_item.domain_id:
    #             checks.append(('domain_id', inventory_item.domain_id))
    #         original_version = None
    #         if inventory_item.version:
    #             original_version = inventory_item.version

    #         exists = inventory_item.exists(checks)
    #         if exists:
    #             inventory_item.hydrate()
    #             if original_version is not None:
    #                 inventory_item.version = original_version
    #             for cache_key in self.invalidations['inventory_items']:
    #                 if '{program_id}' in cache_key:
    #                     cache_keys.append(cache_key.format(program_id=inventory_item.program_id))
    #             old_program = InventoryItem(inventory_item_id=inventory_item.inventory_item_id)
    #             old_program.hydrate()
    #             inventory_item.created_at = old_program.created_at
    #         inventory_item.last_checked = datetime.utcnow().isoformat()
    #         inventory_item.persist(exists=exists, invalidations=cache_keys)
    #         inventory_dict = {}
    #         for col in inventory_item.cols():
    #             inventory_dict[col] = getattr(inventory_item, col)
    #         send_event('inventory_changes', {
    #             'socket_key': self.job.account.socket_key,
    #             'inventory': inventory_dict,
    #         })

    def _save_domains(self, domains :list):
        pass

    # def _save_known_ips(self, known_ips :list):
    #     for known_ip in known_ips:
    #         cache_keys = []
    #         if known_ip.ip_address in ('127.0.0.1', '::1', '::', '0:0:0:0:0:0:0:1'):
    #             continue

    #         known_ip.account_id = self.job.account_id
    #         known_ip.project_id = self.job.project_id
    #         exists_params = ['ip_address']
    #         if known_ip.domain_id:
    #             exists_params.append('domain_id')
    #         else:
    #             exists_params.append('account_id')
    #         exists = known_ip.exists(exists_params)
    #         if exists:
    #             for cache_key in self.invalidations['known_ips']:
    #                 if '{known_ip_id}' in cache_key:
    #                     cache_keys.append(cache_key.format(known_ip_id=known_ip.known_ip_id))
    #             known_ip.updated_at = datetime.utcnow()
    #         if is_valid_ipv4_address(known_ip.ip_address):
    #             known_ip.ip_version = 'ipv4'
    #         elif is_valid_ipv6_address(known_ip.ip_address):
    #             known_ip.ip_version = 'ipv6'
    #         known_ip.persist(exists=exists, invalidations=cache_keys)
    #         ip_dict = {}
    #         for col in known_ip.cols():
    #             ip_dict[col] = getattr(known_ip, col)
    #         send_event('ipaddr_changes', {
    #             'socket_key': self.job.account.socket_key,
    #             'ipaddr': ip_dict,
    #         })

    # def _save_dns_records(self, dns_records :list):
    #     for dns_record in dns_records:
    #         if dns_record.answer in ('127.0.0.1', '::1', '::', '0:0:0:0:0:0:0:1'):
    #             continue
    #         if not dns_record.domain_id:
    #             logger.warning(f'domain_id missing from dns_record {dns_record.raw}')
    #             continue
    #         cache_keys = []
    #         dns_record.last_checked = datetime.utcnow()
    #         exists = dns_record.exists([
    #                 'domain_id',
    #                 'resource',
    #                 'answer',
    #             ])
    #         if exists:
    #             for cache_key in self.invalidations['dns_records']:
    #                 if '{dns_record_id}' in cache_key:
    #                     cache_keys.append(cache_key.format(dns_record_id=dns_record.dns_record_id))
    #         if dns_record.raw:
    #             dns_record.persist(exists=exists, invalidations=cache_keys)
    #             dns_dict = {}
    #             for col in dns_record.cols():
    #                 dns_dict[col] = getattr(dns_record, col)
    #             send_event('dns_changes', {
    #                 'socket_key': self.job.account.socket_key,
    #                 'dns': dns_dict,
    #             })

    def _save_update_fields(self, updates :list):
        for update_table in updates:
            update_table.persist()

    def save_report(self) -> bool:
        if 'findings' in self.report:
            self._save_findings(self.report['findings'])
        if 'security_alerts' in self.report:
            self._save_security_alerts(self.report['security_alerts'])
        if 'domains' in self.report:
            self._save_domains(self.report['domains'])
        if 'updates' in self.report:
            self._save_update_fields(self.report['updates'])

        if isinstance(self.job.queue_data.scan_next, list):
            for job_name in self.job.queue_data.scan_next:
                queue_job(self.job, job_name, self.job.domain.name, target_type='domain')

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

    def build_report(self, cmd_output :str, log_output :str) -> bool:
        "returns data to persist"

    def get_archive_files(self) -> dict:
        "returns file name amd paths of files to send to S3"

    def build_report_summary(self, output :str, log_output :str) -> str:
        "returns a human readable summary"

def update_state(job: JobRun, state :str, message :str = None):
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
    if hasattr(job, 'domain'):
        url=f'/domain/{job.domain.domain_name}'
    else:
        url=f'/project/{job.project_id}'

    Notification(
        account_id=job.account_id,
        description=f'Job {job.queue_data.service_type_category} failed',
        url=url,
    ).persist()

def queue_job(original_job: JobRuns, name :str, target :str = None, target_type :str = None):
    target = target or original_job.queue_data.target
    target_type = target_type or original_job.queue_data.target_type
    service_type = ServiceType(name=name)
    service_type.hydrate(['name'])
    job_runs = JobRuns()
    job_runs.query_json([
        ('service_type_id', service_type.service_type_id),
        ('state', ['queued', 'starting', 'processing', 'finalising']),
        ('$.target', target),
    ])
    if len(job_runs) > 0:
        return

    member = Member()
    if original_job.queue_data.queued_by_member_id:
        member.member_id = original_job.queue_data.queued_by_member_id
        member.hydrate()

    service_queue_job(
        service_type=service_type,
        member=member,
        project=original_job.project,
        priority=0,
        params={'target': target, 'target_type': target_type},
        on_demand=False
    )
