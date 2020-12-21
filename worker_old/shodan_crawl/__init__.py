import time, re, json, urllib3
from os import path, getcwd
from datetime import datetime
from retry.api import retry
from models import Job, Domain, KnownIP, DnsRecord
from config import config, default
from helpers import is_valid_ipv4_address, is_valid_ipv6_address
from helpers import log


def get_result_filename(job: Job)->(str, str):
    try:
        domain_name = job.queue_data.split(',')[0]
        base_path = '/tmp'
        if job.job_name == Job.TYPE_PASSIVE_CRAWL_NETWORK:
            filename = path.realpath(path.join(base_path, f'shodan-{domain_name}.json'))
    except Exception as e:
        log.exception(e)
        return None, str(e)

    return filename, None

def get_job_exe_path(job: Job)->(str, str):
    try:
        pathname = path.realpath(path.join(getcwd(), 'lib', 'bin', 'shodan'))
    except Exception as e:
        log.exception(e)
        return None, str(e)

    return pathname, None

def pre_job_exe(job: Job)->(bool, str):
    domain_name = job.queue_data.split(',')[0]
    target = Domain()
    if not target.hydrate(by_column='name', value=domain_name):
        error = f'Could not load Domain using {job.queue_data}'
        log.error(error)
        return False, error

    return True, None

def get_exe_args(job: Job)->(list, str):
    domain_name, *script_conf = job.queue_data.split(',')
    script_path, _ = get_job_exe_path(job)
    report_path, _ = get_result_filename(job)
    target = None
    if len(script_conf) == 1:
        target = script_conf[0].strip()
    if target and is_valid_ipv4_address(target):
        return [script_path, '-d', domain_name, '-4', target, '-r', report_path, '-l'], None
    if target and is_valid_ipv6_address(target):
        return [script_path, '-d', domain_name, '-6', target, '-r', report_path, '-l'], None

    return [script_path, '-d', domain_name, '-r', report_path, '-l'], None

def post_job_exe(job: Job)->(bool, str):
    report_path, _ = get_result_filename(job)
    if not path.isfile(report_path):
        err = f'File not found {report_path}'
        log.error(err)
        return False, err

    return True, None

def build_report(job: Job, output: str, log_output: str, report: dict)->(dict, str):
    return report, None
