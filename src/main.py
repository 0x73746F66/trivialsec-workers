import logging
import signal
import sys
import json
from datetime import datetime
from trivialsec.helpers import oneway_hash
from trivialsec.services.jobs import QueueData, get_next_job
from trivialsec.models.job_run import JobRun
from trivialsec.models.service_type import ServiceType
from worker import update_state, handle_error
from worker.cli import get_options
from worker.sockets import close_socket
from metadata import metadata_service


logger = logging.getLogger(__name__)
options = get_options()
logging.basicConfig(
    format='%(asctime)s - %(name)s - [%(levelname)s] %(message)s',
    level=options.get('log_level', logging.CRITICAL)
)

def handle_signals(job: JobRun):
    def handler(signum, stack_frame):
        msg = f'Signal handler called with signal {signum}'
        logger.info(msg)
        logger.debug(stack_frame)
        if job.hydrate() and job.state not in [ServiceType.STATE_ERROR, ServiceType.STATE_COMPLETED]:
            job.queue_data = QueueData(**json.loads(job.queue_data))
            update_state(job, ServiceType.STATE_QUEUED if signum == 15 else ServiceType.STATE_ABORT, msg)
        close_socket()
        sys.exit(0)
    signal.signal(signal.SIGQUIT, handler)
    signal.signal(signal.SIGTERM, handler)
    signal.signal(signal.SIGTSTP, handler) # ctrl+z
    signal.signal(signal.SIGINT, handler) # ctrl+c

def handle_metadata(job: JobRun):
    if not metadata_service(job):
        handle_error('Failed processing job', job)
        return

    job.completed_at = datetime.utcnow().isoformat()
    job.queue_data.completed_at = job.completed_at
    job.queue_data.report_summary = 'metadata service complete'
    update_state(job, ServiceType.STATE_COMPLETED, job.queue_data.report_summary)

def main(job: JobRun) -> bool:
    try:
        if job.service_type.name == 'metadata':
            handle_metadata(job)

    except Exception as ex:
        if not isinstance(job, JobRun):
            raise
        handle_error(ex, job)
        return False

    return True

if __name__ == "__main__":
    current_job: JobRun = get_next_job(
        service_type_id=options.get('service_type_id'),
        service_type_name=options.get('service_type_name'),
        account_id=options.get('account_id'),
    )
    if not isinstance(current_job, JobRun):
        if current_job is None:
            logging.info('Encountered errors initialising the job from queue data')
        close_socket()
        sys.exit(0)

    current_job.worker_id = options.get('worker_id')
    current_job.queue_data.worker_id = options.get('worker_id')
    current_job.queue_data.job_uuid = oneway_hash(''.join([str(current_job.job_run_id), str(current_job.worker_id), current_job.node_id]))
    current_job.state = ServiceType.STATE_STARTING
    current_job.persist()
    logger.info(f'Starting JobRun {current_job.job_run_id} {current_job.queue_data.job_uuid} {current_job.queue_data.target} {current_job.queue_data.service_type_category}')
    handle_signals(current_job)
    try:
        main(current_job)
        logger.info(f'Finished service {current_job.node_id} worker {current_job.worker_id}')
    except Exception as err:
        logger.exception(err)
        update_state(current_job, ServiceType.STATE_ERROR, err)

    close_socket()
    sys.exit(0)
