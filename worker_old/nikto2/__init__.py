from os import path, getcwd
from subprocess import Popen, TimeoutExpired

from models import Job, Domain
from config import config
from helpers import log


def get_result_filename(job: Job)->(str, str):
    try:
        domain_name = job.queue_data.split(',')[0]
        base_path = '/tmp'
        scan_type = 'active'
        if job.job_name == Job.TYPE_PASSIVE_RECON_DAST:
            scan_type = 'passive'
        filename = path.realpath(path.join(base_path, f'{scan_type}_nikto_{domain_name}.csv'))
    except Exception as e:
        log.exception(e)
        return None, str(e)

    return filename, None

def get_job_exe_path(job: Job)->(str, str):
    try:
        scan_type = 'active-scanner'
        if job.job_name == Job.TYPE_PASSIVE_RECON_DAST:
            scan_type = 'passive-scanner'

        pathname = path.realpath(path.join(getcwd(), 'lib', 'bin', scan_type))
    except Exception as e:
        log.exception(e)
        return None, str(e)

    return pathname, None

def pre_job_exe(job: Job)->(bool, str):
    domain_name = job.queue_data.split(',')[0]
    target = Domain()
    if not target.hydrate(by_column='name', value=domain_name):
        error = f'Could not load Domain {job.queue_data}'
        log.error(error)
        return False, error

    return True, None

def post_job_exe(job: Job)->(bool, str):
    tls_file_path, _ = get_result_filename(job)
    if not path.isfile(tls_file_path):
        err = f'File not found {tls_file_path}'
        log.error(err)
        return False, err

    return True, None

def passive_recon_dast(job: Job)->(bool, str):
    domain_name = job.queue_data.split(',')[0]
    target = Domain()
    target.hydrate(by_column='name', value=domain_name)
    exe_script, _ = get_job_exe_path(job)
    report_file_path, _ = get_result_filename(job)
    
    retcode = None
    p = Popen([exe_script, target.name, report_file_path])
    try:
        retcode = p.wait(timeout=config.queue_wait_timeout)
    except TimeoutExpired:
        msg = f'Timeout. Aborting job {job.id}'
        log.warning(msg)
        return False, msg
    except Exception as e:
        log.exception(e)
        return False, str(e)
    finally:
        error = f"{p.stdout or ''}\n{p.stderr or ''}".strip()
        p.terminate()

    if retcode != 0:
        err = f'passive_recon_dast {retcode} {error}'
        log.error(err)
        return False, err

    if error:
        log.info(error)

    return True, None


def active_recon_dast(job: Job)->(bool, str):
    domain_name = job.queue_data.split(',')[0]
    target = Domain()
    target.hydrate(by_column='name', value=domain_name)
    exe_script, _ = get_job_exe_path(job)
    report_file_path, _ = get_result_filename(job)
    
    retcode = None
    p = Popen([exe_script, target.name, report_file_path])
    try:
        retcode = p.wait(timeout=config.queue_wait_timeout)
    except TimeoutExpired:
        msg = f'Timeout. Aborting job {job.id}'
        log.warning(msg)
        return False, msg
    except Exception as e:
        log.exception(e)
        return False, str(e)
    finally:
        error = f"{p.stdout or ''}\n{p.stderr or ''}".strip()
        p.terminate()

    if retcode != 0:
        err = f'active_recon_dast {retcode} {error}'
        log.error(err)
        return False, err

    if error:
        log.info(error)

    return True, None

def gather_report(job: Job, report: dict) -> tuple:
    report_file_path, _ = get_result_filename(job)
    with open(report_file_path, 'r') as r:
        log.info('reading report lines')
        for line in r.readlines():
            log.info(line)

    return report, None
