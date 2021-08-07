from os import getenv, path, makedirs
from subprocess import Popen
from datetime import datetime
import logging
import errno
import signal
import time
import importlib
import sys
import json
from trivialsec.helpers import check_domain_rules, oneway_hash
from trivialsec.services.jobs import QueueData
from trivialsec.models.job_run import JobRun, JobRuns
from trivialsec.models.service_type import ServiceType
from trivialsec.models.account import Account
from trivialsec.models.account_config import AccountConfig
from trivialsec.models.project import Project
from trivialsec.models.domain import Domain
from trivialsec.helpers.config import config
from worker import update_state, handle_error
from worker.cli import get_options, s3_upload
from worker.sockets import close_socket


logger = logging.getLogger(__name__)
options = get_options()

def handle_signals(job: JobRun):
    def handler(signum, stack_frame):
        msg = f'Signal handler called with signal {signum}'
        logger.warning(msg)
        logger.debug(stack_frame)
        logger.info(f'Fetching {job.queue_data.service_type_category}')
        if job.hydrate() and job.state not in [ServiceType.STATE_ERROR, ServiceType.STATE_COMPLETED]:
            job.queue_data = QueueData(**json.loads(job.queue_data))
            update_state(job, ServiceType.STATE_QUEUED if signum == 15 else ServiceType.STATE_ABORT, msg)
        close_socket()
        sys.exit(0)

    signal.signal(signal.SIGQUIT, handler)
    signal.signal(signal.SIGTERM, handler)
    signal.signal(signal.SIGTSTP, handler) # ctrl+z
    signal.signal(signal.SIGINT, handler) # ctrl+c

def process(job: JobRun, job_args :list) -> bool:
    retcode = None
    error = 'Unknown'
    logger.info(' '.join(job_args))
    try:
        proc = Popen(job_args)
        retcode = proc.poll()
        while retcode is None:
            time.sleep(config.queue_wait_timeout or 3)
            retcode = proc.poll()
    except Exception as err:
        logger.critical(err)
    finally:
        if proc:
            msg = f"{proc.stdout or ''}".strip()
            logger.info(msg)
            error = f"{proc.stderr or ''}".strip()
            proc.terminate()

    if retcode != 0:
        handle_error(f'Job {job.queue_data.service_type_category} exited with {retcode} {error}', job)
        return False

    return True

def mkpath(filepath :str):
    try:
        makedirs(path.dirname(filepath))
    except OSError as exc: # EEXIST race condition
        if exc.errno != errno.EEXIST:
            raise

def complete_job(job: JobRuns, report_summary :str, queue_data_path :str, queue_data_object_path :str):
    job.completed_at = datetime.utcnow().isoformat()
    job.queue_data.completed_at = job.completed_at
    job.queue_data.report_summary = report_summary[:255]
    with open(queue_data_path, 'w') as buff:
        buff.write(str(job.queue_data))
    update_state(job, ServiceType.STATE_COMPLETED, job.queue_data.report_summary)
    s3_upload(
        queue_data_path,
        queue_data_object_path
    )

def main(job: JobRun) -> bool:
    try:
        job_uuid = oneway_hash(''.join([str(job.job_run_id), str(job.worker_id), job.node_id]))
        job.queue_data.job_uuid = job_uuid
        options['job_path'] = path.join(
            '/tmp',
            job.queue_data.target
        )
        s3_path_prefix = path.join(
            'reports',
            config.aws.get("env_prefix", "dev").strip(),
            f'account-{job.account_id}',
            f'project-{job.project_id}',
            f'{job.queue_data.service_type_category}-{job.queue_data.service_type_id}'
        )
        queue_data_path = path.join(options['job_path'], f'queue_data_{job_uuid}.json')
        queue_data_object_path = path.join(s3_path_prefix, job_uuid, 'queue_data.json')
        mkpath(queue_data_path)
        with open(queue_data_path, 'w') as buff:
            buff.write(str(job.queue_data))
        s3_upload(
            queue_data_path,
            queue_data_object_path,
        )
        logger.info(f'Starting JobRun {job.job_run_id} {job_uuid} {job.queue_data.target} {job.queue_data.service_type_category}')
        handle_signals(job)
        module = importlib.import_module(job.queue_data.service_type_name)
        worker_class = getattr(module, 'Worker')
        worker = worker_class(job, options)

        report_path = worker.get_result_filename()
        if report_path:
            mkpath(report_path)
        log_path = worker.get_log_filename()
        if log_path:
            mkpath(log_path)
        job_exe_path = worker.get_job_exe_path()
        if not worker.pre_job_exe():
            msg = f'Failed pre_job {job.queue_data.service_type_category}'
            handle_error(msg, job)
            update_state(job, ServiceType.STATE_QUEUED, f'retrying {job.queue_data.service_type_category}')
            return False

        for args in worker.get_exe_args():
            update_state(job, ServiceType.STATE_PROCESSING, f'processing {job.queue_data.service_type_category}')
            job_args = [job_exe_path]
            if report_path is not None:
                job_args.append(report_path)
            if log_path is not None:
                job_args.append(log_path)
            job_args.extend(list(args))
            logger.info(f'job_args {repr(job_args)}')
            logger.info(f'args {repr(args)}')
            logger.debug(' '.join(job_args))
            if not process(job, job_args):
                msg = f'Failed processing job {" ".join(job_args)}'
                handle_error(msg, job)

            update_state(job, ServiceType.STATE_FINALISING)
            if not worker.post_job_exe():
                msg = f'Failed post_job {job.queue_data.service_type_category}'
                handle_error(msg, job)
                return False

            output_file = None
            log_output = None
            if report_path:
                with open(report_path, 'r') as buff:
                    output_file = buff.read()
            if log_path:
                with open(log_path, 'r') as buff:
                    log_output = buff.read()

            logger.info(f'build report {job.queue_data.target} {job.queue_data.service_type_category}')
            if not worker.build_report(output_file, log_output):
                err = 'report could not be generated'
                handle_error(err, job)
                return False
            logger.info(f'validate report {job.queue_data.target} {job.queue_data.service_type_category}')
            if not worker.validate_report():
                complete_job(job, worker.build_report_summary(output_file, log_output), queue_data_path, queue_data_object_path)
                return True

            archive_files = worker.get_archive_files()
            if archive_files:
                for archive_name, archive_file in archive_files.items():
                    if not path.exists(archive_file):
                        logger.warning(f'archive_file {archive_file} not found {job.queue_data.target} {job.queue_data.service_type_category}')
                    s3_upload(
                        archive_file,
                        path.join(s3_path_prefix, job_uuid, archive_name),
                    )
            logger.info(f'saving report {job.queue_data.target} {job.queue_data.service_type_category} {worker.build_report_summary(output_file, log_output)}')
            if not worker.save_report():
                err = 'report was not saved to the database'
                handle_error(err, job)
                return False

            logger.info(f'analyse report {job.queue_data.target} {job.queue_data.service_type_category}')
            worker.analyse_report()
            logger.info(f'completed {job.queue_data.target} {job.queue_data.service_type_category}')
            complete_job(job, worker.build_report_summary(output_file, log_output), queue_data_path, queue_data_object_path)
    except Exception as ex:
        if not isinstance(job, JobRun):
            raise
        handle_error(ex, job)
        return False

    return True

if __name__ == "__main__":
    loglevel = getenv('LOG_LEVEL', 'WARNING')
    logging.basicConfig(
        format='%(asctime)s - %(name)s - [%(levelname)s] %(message)s',
        level=getattr(logging, loglevel.upper())
    )
    # Get service
    current_service_type = ServiceType(name=options.get('service'))
    current_service_type.hydrate('name')
    # Find job
    logger.info(f'checking {current_service_type.name} queue for service {config.node_id} worker {options.get("worker_id")}')
    job_params = [('state', ServiceType.STATE_QUEUED), ('service_type_id', current_service_type.service_type_id)]
    if options.get('account_id') is not None:
        # validate plan
        job_params.append(('account_id', options.get('account_id')))

    jobs: JobRuns = JobRuns().find_by(
        job_params,
        order_by=['priority', 'DESC'],
        limit=1,
    )
    if len(jobs) != 1 or not isinstance(jobs[0], JobRun):
        logger.info(f'{current_service_type.name} queue is empty')
        sys.exit(0)

    current_job: JobRun = jobs[0]
    setattr(current_job, 'service_type', current_service_type)
    current_job.worker_id = options.get('worker_id')
    current_job.node_id = config.node_id
    current_job.type_id = current_service_type.service_type_id
    current_job.started_at = datetime.utcnow().isoformat()
    current_job.updated_at = current_job.started_at
    current_job.state = ServiceType.STATE_STARTING
    data = json.loads(current_job.queue_data)
    data['worker_id'] = current_job.worker_id
    data['service_node_id'] = current_job.node_id
    data['started_at'] = current_job.started_at
    current_job.queue_data = QueueData(**data)
    current_job.persist()
    account = Account(account_id=current_job.account_id)
    if not account.hydrate():
        handle_error(f'Error loading account {current_job.account_id}', current_job)
    account_config = AccountConfig(account_id=current_job.account_id)
    if not account_config.hydrate():
        handle_error(f'Error loading account config {current_job.account_id}', current_job)
    setattr(account, 'config', account_config)
    setattr(current_job, 'account', account)
    project = Project(project_id=current_job.project_id)
    if not project.hydrate():
        handle_error(f'Error loading project {current_job.project_id}', current_job)
    setattr(current_job, 'project', project)

    if check_domain_rules(current_job.queue_data.target):
        domain = Domain(
            name=current_job.queue_data.target,
            project_id=current_job.project_id,
        )
        if domain.hydrate(['name', 'project_id']):
            setattr(current_job, 'domain', domain)

    try:
        main(current_job)
        logger.info(f'Finished service {current_job.node_id} worker {current_job.worker_id}')
    except Exception as ex:
        logger.error(ex)
        update_state(current_job, ServiceType.STATE_ERROR, ex)

    close_socket()
    sys.exit(0)
