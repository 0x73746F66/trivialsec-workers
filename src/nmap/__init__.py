from os import path, getcwd
from trivialsec.models.job_run import JobRun
from trivialsec.models.domain import Domain
from trivialsec.models.known_ip import KnownIp
from trivialsec.models.dns_record import DnsRecord
from trivialsec.helpers import is_valid_ipv4_address, is_valid_ipv6_address, check_domain_rules


def get_result_filename(job: JobRun, config :dict) -> str:
    target = job.queue_data.target
    filename = path.realpath(path.join(config['job_path'], f'{job.queue_data.scan_type}-{target}-{config.get("worker_id")}.xml'))

    return filename

def get_log_filename(job: JobRun, config :dict) -> str:
    return path.realpath(path.join(
        config['job_path'],
        f'{job.queue_data.scan_type}-{job.queue_data.target}-{config.get("worker_id")}.log',
    ))

def get_archive_files(job: JobRun, config :dict) -> dict:
    return {
        'results.json': get_result_filename(job, config),
        'output.log': get_log_filename(job, config),
    }

def get_job_exe_path(job: JobRun, config :dict) -> str:
    return path.realpath(path.join(getcwd(), 'lib', 'bin', 'run-drill'))

def pre_job_exe(job: JobRun, config :dict) -> bool:
    if is_valid_ipv4_address(job.queue_data.target) or is_valid_ipv6_address(job.queue_data.target):
        return  False
    target = Domain(name=job.queue_data.target, project_id=job.project_id)
    if not target.exists(['name', 'project_id']):
        raise ValueError(f'Could not load Domain using {job.queue_data}')

    return  True

def get_exe_args(job: JobRun, config :dict) -> list:
    mincvss = config.get('mincvss', '3.0')
    nameservers = ','.join(config.get('nameservers', []))
    if job.account.config.nameservers and len(job.account.config.nameservers.split(',')) > 0:
        nameservers = job.account.config.nameservers
    return [(job.queue_data.target, mincvss, nameservers)]

def post_job_exe(job: JobRun, config :dict) -> bool:
    report_path = get_result_filename(job, config=config)
    if not path.isfile(report_path):
        raise ValueError(f'File not found {report_path}')

    return True

def build_report_summary(report :dict, output :str, log_output :str) -> str:
    return f'Found {len(report["dns_records"])} dns records {len(report["domains"])} domains with {len(report["known_ips"])} IP Addresses'

def build_report(job: JobRun, output :str, log_output :str, report :dict, config :dict) -> dict:
    for dns_record in output.splitlines():
        fqdn, ttl, dns_class, resource, *answer = dns_record.split()
        answer = " ".join(answer)

        if check_domain_rules(job.queue_data.target):
            domain = Domain(name=job.queue_data.target, project_id=job.project_id)
        elif check_domain_rules(fqdn):
            domain = Domain(
                name=fqdn,
                project_id=job.project_id,
                source='DNS',
            )
            report['domains'].append(domain)
        else:
            domain = Domain()

        if is_valid_ipv4_address(fqdn) or is_valid_ipv6_address(fqdn):
            report['known_ips'].append(KnownIp(ip_address=fqdn.strip()))

        if domain.exists(['name', 'project_id']):
            report['dns_records'].append(DnsRecord(
                domain_id=domain.domain_id,
                ttl=ttl,
                dns_class=dns_class,
                resource=resource,
                answer=answer,
                raw=dns_record
            ))

    return report
