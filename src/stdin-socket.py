from os import path, isatty, makedirs
# from datetime import datetime
# import errno
# import time
import sys
import json
import argparse
from gunicorn.glogging import logging
from trivialsec import models
# from worker.sockets import close_socket


logger = logging.getLogger(__name__)

def main(job: models.JobRun) -> bool:
    for line in sys.stdin:
        # send to browser via sockets
        print(line)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-j', '--job-id', dest='job_id', required=True)
    args = parser.parse_args()

    current_job = models.JobRun(job_run_id=args.job_id)
    current_job.hydrate()

    try:
        main(current_job)
        logger.info(f'Finished service {current_job.node_id} worker {current_job.worker_id}')
    except Exception as ex:
        logger.exception(ex)

    # close_socket()
    # sys.exit(0)
